use std::{collections::HashMap, sync::OnceLock};

use base64::{Engine, engine::general_purpose::STANDARD};
use mail_parser::MessageParser;
use mail_auth::{
	common::crypto::{RsaKey, Sha256},
	dkim::DkimSigner,
	hickory_resolver::name_server::TokioConnectionProvider,
};
use mail_builder::MessageBuilder;
use mail_send::{SmtpClient, SmtpClientBuilder, smtp::message::Message};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::instrument;

use crate::{
	config::{Config, DkimConfig},
	db,
	protocols::smtp::{
		error::OutgoingError,
		handler::{
			attachment::find_oversized_attachment,
			tls::{
			DomainTlsPolicy, TlsFailureContext, dane, evaluate_domain_tls_policy,
			host_allowed_by_policy, prioritize_targets,
			write_tls_failure_report,
			},
		},
		transaction::Transaction,
	},
};

pub const OUTBOUND_MAX_MESSAGE_BYTES: usize = 25 * 1024 * 1024;
pub const OUTBOUND_MAX_ATTACHMENT_BYTES: usize = 18 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct OutgoingRequest {
	pub from: String,
	pub to: Vec<String>,
	pub subject: String,
	pub text_body: Option<String>,
	pub html_body: Option<String>,
	pub idempotency_key: Option<String>,
	pub actor_account: Option<String>,
	pub shared_inbox: Option<String>,
}

#[instrument(skip_all, fields(from = %request.from, recipients = request.to.len()))]
pub async fn send_outgoing(request: OutgoingRequest, config: &Config) -> Result<(), OutgoingError> {
	if request.to.is_empty() {
		return Err(OutgoingError::NoRecipients);
	}
	enforce_quota_for_sender_domain(&request.from, request.to.len() as u32).await?;
	let selected_dkim = resolve_outbound_dkim(&request.from, config).await;

	let recipients = recipients_by_domain(request.to).await?;
	for (domain, domain_recipients) in recipients {
		let mut builder = MessageBuilder::new()
			.from(request.from.clone())
			.subject(request.subject.clone());

		for rcpt in &domain_recipients {
			builder = builder.to(rcpt.clone());
		}
		if let Some(text_body) = request.text_body.as_ref() {
			builder = builder.text_body(text_body.clone());
		}
		if let Some(html_body) = request.html_body.as_ref() {
			builder = builder.html_body(html_body.clone());
		}

		let rfc822 = builder
			.write_to_vec()
			.map_err(|e| OutgoingError::Build(e.to_string()))?;
		if rfc822.len() > OUTBOUND_MAX_MESSAGE_BYTES {
			return Err(OutgoingError::QuotaExceeded(format!(
				"message size {} exceeds fixed outbound limit {}",
				rfc822.len(),
				OUTBOUND_MAX_MESSAGE_BYTES
			)));
		}
		let message = Message::new(request.from.clone(), domain_recipients, rfc822);
		deliver_to_domain(&domain, message, config, selected_dkim.as_ref()).await?;
	}

	Ok(())
}

#[instrument(skip_all, fields(recipients = txn.rcpt_to.len()))]
pub async fn relay_transaction(txn: &Transaction, config: &Config) -> Result<(), OutgoingError> {
	let from = txn
		.mail_from
		.as_ref()
		.ok_or(OutgoingError::InvalidSender)?
		.clone();
	if txn.rcpt_to.is_empty() {
		return Err(OutgoingError::NoRecipients);
	}
	enforce_quota_for_sender_domain(&from, txn.rcpt_to.len() as u32).await?;

	let data = txn
		.data
		.as_ref()
		.ok_or_else(|| OutgoingError::Build("empty DATA payload".into()))?
		.clone();
	if data.len() > OUTBOUND_MAX_MESSAGE_BYTES {
		return Err(OutgoingError::QuotaExceeded(format!(
			"message size {} exceeds fixed outbound limit {}",
			data.len(),
			OUTBOUND_MAX_MESSAGE_BYTES
		)));
	}
	let parser = MessageParser::default();
	let parsed = parser
		.parse(&data)
		.ok_or_else(|| OutgoingError::Build("failed to parse outbound MIME payload".into()))?;
	if let Some(actual) = find_oversized_attachment(&parsed, OUTBOUND_MAX_ATTACHMENT_BYTES)
	{
		return Err(OutgoingError::QuotaExceeded(format!(
			"attachment size {actual} exceeds configured outbound limit {}",
			OUTBOUND_MAX_ATTACHMENT_BYTES
		)));
	}
	let selected_dkim = resolve_outbound_dkim(&from, config).await;

	let recipients = recipients_by_domain(txn.rcpt_to.clone()).await?;
	for (domain, domain_recipients) in recipients {
		let message = Message::new(from.clone(), domain_recipients, data.clone());
		deliver_to_domain(&domain, message, config, selected_dkim.as_ref()).await?;
	}

	Ok(())
}

async fn deliver_to_domain(
	domain: &str,
	mail: Message<'_>,
	config: &Config,
	dkim: Option<&DkimConfig>,
) -> Result<(), OutgoingError> {
	let targets = resolve_delivery_targets(domain).await?;
	let dnssec_validate = resolve_domain_dnssec_validate(domain, config).await;
	let policy = evaluate_domain_tls_policy(domain, &targets, dnssec_validate, config).await?;
	let targets = prioritize_targets(&policy, targets);
	let mut last_error: Option<OutgoingError> = None;

	for target in targets {
		if !host_allowed_by_policy(&policy, &target) {
			let context = TlsFailureContext {
				source: "mta-sts",
				mta_sts_mode: policy.mta_sts_mode.clone(),
				dane_required: !policy.dane_required_hosts.is_empty(),
			};
			write_tls_failure_report(
				config,
				domain,
				&target,
				"mx host rejected by MTA-STS policy",
				&context,
			)
			.await;
			continue;
		}

		match send_via_host(
			domain,
			&target,
			mail.clone(),
			config,
			dkim,
			policy.require_tls,
			&policy,
			dnssec_validate,
		)
		.await
		{
			Ok(()) => return Ok(()),
			Err(err) => last_error = Some(err),
		}
	}

	Err(last_error.unwrap_or_else(|| OutgoingError::Relay("no delivery targets available".into())))
}

async fn resolve_delivery_targets(domain: &str) -> Result<Vec<String>, OutgoingError> {
	let resolver =
		mail_auth::hickory_resolver::TokioResolver::builder(TokioConnectionProvider::default())
			.map(|builder| builder.build())
			.map_err(|e| OutgoingError::Relay(format!("resolver init failed: {e}")))?;
	let mx_records = resolver.mx_lookup(domain).await;
	let mut hosts = Vec::new();

	if let Ok(mx_records) = mx_records {
		for mx in mx_records.iter() {
			let host = mx.exchange().to_utf8();
			let host = host.trim_end_matches('.').to_string();
			if !host.is_empty() {
				hosts.push(host);
			}
		}
	}

	if hosts.is_empty() {
		hosts.push(domain.to_string());
	}

	Ok(hosts)
}

async fn send_via_host(
	domain: &str,
	host: &str,
	mail: Message<'_>,
	config: &Config,
	dkim: Option<&DkimConfig>,
	tls_required: bool,
	policy: &DomainTlsPolicy,
	dnssec_validate: bool,
) -> Result<(), OutgoingError> {
	ensure_rustls_crypto_provider();

	let outbound = &config.smtp.outbound;
	let require_tls = tls_required || outbound.require_starttls;
	let mut builder = SmtpClientBuilder::new(host.to_string(), outbound.default_port)
		.implicit_tls(false)
		.helo_host(config.server.hostname.clone())
		.timeout(outbound.timeout);

	if outbound.allow_invalid_certs && !require_tls {
		builder = builder.allow_invalid_certs();
	}

	if require_tls {
		let mut client = match builder.connect().await {
			Ok(c) => c,
			Err(err) => {
				let reason = format!("starttls delivery to {host} failed: {err}");
				let context = TlsFailureContext {
					source: "smtp-starttls",
					mta_sts_mode: policy.mta_sts_mode.clone(),
					dane_required: policy.dane_required_hosts.contains(&host.to_ascii_lowercase()),
				};
				write_tls_failure_report(config, domain, host, &reason, &context).await;
				return Err(OutgoingError::Relay(reason));
			}
		};
		if policy.dane_required_hosts.contains(&host.to_ascii_lowercase()) {
			let Some(peer_chain) = client.tls_connection().peer_certificates() else {
				let err = OutgoingError::Relay(format!(
					"DANE validation failed for {host}: no peer certificates"
				));
				let context = TlsFailureContext {
					source: "smtp-dane",
					mta_sts_mode: policy.mta_sts_mode.clone(),
					dane_required: true,
				};
				write_tls_failure_report(config, domain, host, &err.to_string(), &context).await;
				return Err(err);
			};
			if let Err(err) = dane::verify_peer_chain_against_tlsa(
				host,
				peer_chain,
				dnssec_validate,
			)
			.await
			{
				let context = TlsFailureContext {
					source: "smtp-dane",
					mta_sts_mode: policy.mta_sts_mode.clone(),
					dane_required: true,
				};
				write_tls_failure_report(config, domain, host, &err.to_string(), &context).await;
				return Err(err);
			}
		}
		match send_with_client(&mut client, mail, dkim).await {
			Ok(()) => Ok(()),
			Err(err) => {
				let context = TlsFailureContext {
					source: "smtp-send",
					mta_sts_mode: policy.mta_sts_mode.clone(),
					dane_required: policy.dane_required_hosts.contains(&host.to_ascii_lowercase()),
				};
				write_tls_failure_report(config, domain, host, &err.to_string(), &context).await;
				Err(err)
			}
		}
	} else {
		match builder.connect().await {
			Ok(mut client) => send_with_client(&mut client, mail, dkim).await,
			Err(_) if outbound.allow_plaintext_fallback => {
				let mut client = builder.connect_plain().await.map_err(|e| {
					OutgoingError::Relay(format!("plaintext delivery to {host} failed: {e}"))
				})?;
				send_with_client(&mut client, mail, dkim).await
			}
			Err(err) => Err(OutgoingError::Relay(format!(
				"delivery to {host} failed: {err}"
			))),
		}
	}
}

fn ensure_rustls_crypto_provider() {
	static INIT: OnceLock<()> = OnceLock::new();
	let _ = INIT.get_or_init(|| {
		let _ = rustls::crypto::ring::default_provider().install_default();
	});
}

async fn send_with_client<T: AsyncRead + AsyncWrite + Unpin>(
	client: &mut SmtpClient<T>,
	mail: Message<'_>,
	dkim: Option<&DkimConfig>,
) -> Result<(), OutgoingError> {
	if let Some(dkim) = dkim {
		let signer = build_rsa_dkim_signer(dkim)?;
		client
			.send_signed(mail, &signer)
			.await
			.map_err(|e| OutgoingError::Relay(e.to_string()))?;
	} else {
		client
			.send(mail)
			.await
			.map_err(|e| OutgoingError::Relay(e.to_string()))?;
	}
	Ok(())
}

async fn recipients_by_domain(
	recipients: Vec<String>,
) -> Result<HashMap<String, Vec<String>>, OutgoingError> {
	let mut grouped = HashMap::<String, Vec<String>>::new();
	for rcpt in recipients {
		if db::is_recipient_suppressed(&rcpt).await {
			continue;
		}
		let domain = extract_domain(&rcpt)
			.ok_or_else(|| OutgoingError::Build(format!("invalid recipient address: {rcpt}")))?;
		grouped.entry(domain.to_string()).or_default().push(rcpt);
	}
	if grouped.is_empty() {
		return Err(OutgoingError::Suppressed);
	}
	Ok(grouped)
}

fn extract_domain(address: &str) -> Option<&str> {
	let (_, domain) = address.trim().rsplit_once('@')?;
	if domain.is_empty() {
		return None;
	}
	Some(domain)
}

fn build_rsa_dkim_signer(
	dkim: &DkimConfig,
) -> Result<DkimSigner<RsaKey<Sha256>, mail_auth::dkim::Done>, OutgoingError> {
	let private_key = STANDARD
		.decode(dkim.private_key_b64_pkcs8.trim())
		.map_err(|e| OutgoingError::Dkim(format!("invalid base64 key: {e}")))?;

	let key = RsaKey::<Sha256>::from_pkcs8_der(&private_key)
		.or_else(|_| RsaKey::<Sha256>::from_der(&private_key))
		.map_err(|e| {
			OutgoingError::Dkim(format!(
				"invalid private key (expected PKCS8 or PKCS1 DER): {e}"
			))
		})?;

	Ok(DkimSigner::from_key(key)
		.domain(dkim.domain.clone())
		.selector(dkim.selector.clone())
		.headers(dkim.headers.clone()))
}

async fn resolve_outbound_dkim(sender: &str, config: &Config) -> Option<DkimConfig> {
	let sender_domain = extract_domain(sender)?;
	if let Some(settings) = db::domain_settings(sender_domain).await
		&& let Some(dkim) = settings.dkim
	{
		return Some(dkim);
	}
	config.smtp.outbound.dkim.clone()
}

async fn resolve_domain_dnssec_validate(domain: &str, config: &Config) -> bool {
	if let Some(settings) = db::domain_settings(domain).await
		&& let Some(v) = settings.outbound_dnssec_validate
	{
		return effective_dnssec_validate(config.smtp.outbound.dnssec_validate, Some(v));
	}
	effective_dnssec_validate(config.smtp.outbound.dnssec_validate, None)
}

fn effective_dnssec_validate(default_value: bool, domain_override: Option<bool>) -> bool {
	domain_override.unwrap_or(default_value)
}

async fn enforce_quota_for_sender_domain(
	sender: &str,
	recipients: u32,
) -> Result<(), OutgoingError> {
	let Some((_, sender_domain)) = sender.rsplit_once('@') else {
		return Ok(());
	};
	let Some(settings) = db::domain_settings(sender_domain).await else {
		return Ok(());
	};
	let Some(quota) = settings.quota.as_ref() else {
		return Ok(());
	};

	if let Some(max_recipients) = quota.max_recipients_per_message
		&& recipients > max_recipients
	{
		return Err(OutgoingError::QuotaExceeded(format!(
			"recipient count {recipients} exceeds max {max_recipients}"
		)));
	}

	let Some(org_id) = settings.org_id.as_deref() else {
		return Ok(());
	};
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs();

	if let Some(hourly_limit) = quota.hourly_send_limit {
		let since = now.saturating_sub(3600);
		let sent = db::count_outbound_deliveries_since(org_id, since)
			.await
			.map_err(OutgoingError::Relay)?;
		if sent >= hourly_limit as u64 {
			return Err(OutgoingError::QuotaExceeded(format!(
				"hourly send limit reached ({hourly_limit})"
			)));
		}
	}
	if let Some(daily_limit) = quota.daily_send_limit {
		let since = now.saturating_sub(86_400);
		let sent = db::count_outbound_deliveries_since(org_id, since)
			.await
			.map_err(OutgoingError::Relay)?;
		if sent >= daily_limit as u64 {
			return Err(OutgoingError::QuotaExceeded(format!(
				"daily send limit reached ({daily_limit})"
			)));
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::effective_dnssec_validate;

	#[test]
	fn dnssec_override_prefers_tenant_setting() {
		assert!(!effective_dnssec_validate(true, Some(false)));
		assert!(effective_dnssec_validate(false, Some(true)));
		assert!(effective_dnssec_validate(true, None));
	}
}
