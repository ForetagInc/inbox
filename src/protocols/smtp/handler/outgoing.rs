use std::{collections::HashMap, sync::OnceLock};

use base64::{Engine, engine::general_purpose::STANDARD};
use mail_auth::{
	common::crypto::{RsaKey, Sha256},
	dkim::DkimSigner,
	hickory_resolver::name_server::TokioConnectionProvider
};
use mail_builder::MessageBuilder;
use mail_send::{SmtpClient, SmtpClientBuilder, smtp::message::Message};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
	config::{Config, DkimConfig},
	db,
	protocols::smtp::{error::OutgoingError, transaction::Transaction}
};

#[derive(Debug, Clone)]
pub struct OutgoingRequest {
	pub from: String,
	pub to: Vec<String>,
	pub subject: String,
	pub text_body: Option<String>,
	pub html_body: Option<String>,
}

pub async fn send_outgoing(request: OutgoingRequest, config: &Config) -> Result<(), OutgoingError> {
	if request.to.is_empty() {
		return Err(OutgoingError::NoRecipients);
	}
	let selected_dkim = resolve_outbound_dkim(&request.from, config).await;

	let recipients = recipients_by_domain(request.to)?;
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
		let message = Message::new(request.from.clone(), domain_recipients, rfc822);
		deliver_to_domain(&domain, message, config, selected_dkim.as_ref()).await?;
	}

	Ok(())
}

pub async fn relay_transaction(txn: &Transaction, config: &Config) -> Result<(), OutgoingError> {
	let from = txn
		.mail_from
		.as_ref()
		.ok_or(OutgoingError::InvalidSender)?
		.clone();
	if txn.rcpt_to.is_empty() {
		return Err(OutgoingError::NoRecipients);
	}

	let data = txn
		.data
		.as_ref()
		.ok_or_else(|| OutgoingError::Build("empty DATA payload".into()))?
		.clone();
	let selected_dkim = resolve_outbound_dkim(&from, config).await;

	let recipients = recipients_by_domain(txn.rcpt_to.clone())?;
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
	let mut last_error: Option<OutgoingError> = None;

	for target in targets {
		match send_via_host(&target, mail.clone(), config, dkim).await {
			Ok(()) => return Ok(()),
			Err(err) => last_error = Some(err),
		}
	}

	Err(last_error.unwrap_or_else(|| OutgoingError::Relay("no delivery targets available".into())))
}

async fn resolve_delivery_targets(domain: &str) -> Result<Vec<String>, OutgoingError> {
	let resolver = mail_auth::hickory_resolver::TokioResolver::builder(TokioConnectionProvider::default())
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
	host: &str,
	mail: Message<'_>,
	config: &Config,
	dkim: Option<&DkimConfig>,
) -> Result<(), OutgoingError> {
	ensure_rustls_crypto_provider();

	let outbound = &config.smtp.outbound;
	let mut builder = SmtpClientBuilder::new(host.to_string(), outbound.default_port)
		.implicit_tls(false)
		.helo_host(config.server.hostname.clone())
		.timeout(outbound.timeout);

	if outbound.allow_invalid_certs {
		builder = builder.allow_invalid_certs();
	}

	if outbound.require_starttls {
		let mut client = builder
			.connect()
			.await
			.map_err(|e| OutgoingError::Relay(format!("starttls delivery to {host} failed: {e}")))?;
		send_with_client(&mut client, mail, dkim).await
	} else {
		match builder.connect().await {
			Ok(mut client) => send_with_client(&mut client, mail, dkim).await,
			Err(_) if outbound.allow_plaintext_fallback => {
				let mut client = builder
					.connect_plain()
					.await
					.map_err(|e| OutgoingError::Relay(format!("plaintext delivery to {host} failed: {e}")))?;
				send_with_client(&mut client, mail, dkim).await
			}
			Err(err) => Err(OutgoingError::Relay(format!("delivery to {host} failed: {err}"))),
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

fn recipients_by_domain(recipients: Vec<String>) -> Result<HashMap<String, Vec<String>>, OutgoingError> {
	let mut grouped = HashMap::<String, Vec<String>>::new();
	for rcpt in recipients {
		let domain = extract_domain(&rcpt)
			.ok_or_else(|| OutgoingError::Build(format!("invalid recipient address: {rcpt}")))?;
		grouped.entry(domain.to_string()).or_default().push(rcpt);
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
		.map_err(|e| OutgoingError::Dkim(format!("invalid private key (expected PKCS8 or PKCS1 DER): {e}")))?;

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
