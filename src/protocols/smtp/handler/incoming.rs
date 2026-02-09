use std::net::IpAddr;

use mail_auth::{
	AuthenticatedMessage, DkimResult, DmarcResult, MessageAuthenticator, SpfResult,
	dmarc::verify::DmarcParameters, spf::verify::SpfParameters,
};
use mail_parser::MimeHeaders;

use crate::{
	config::Config,
	db::{self, TenantEncryptionMode},
	protocols::smtp::error::IncomingError,
	storage::{self, EncryptionMode, StoragePolicy},
};

#[derive(Debug, Clone)]
pub struct MailAuthVerdict {
	pub spf: SpfResult,
	pub dkim: DkimResult,
	pub dmarc: DmarcResult,
}

impl MailAuthVerdict {
	pub fn accepted(&self, policy: &crate::config::MailAuthConfig) -> bool {
		let spf_ok = !policy.require_spf_pass || self.spf == SpfResult::Pass;
		let dkim_ok = !policy.require_dkim_pass || self.dkim == DkimResult::Pass;
		let dmarc_ok = !policy.require_dmarc_pass || self.dmarc == DmarcResult::Pass;
		spf_ok && dkim_ok && dmarc_ok
	}
}

pub async fn verify_mail(
	ip: IpAddr,
	helo_domain: &str,
	host_domain: &str,
	sender: &str,
	message: &[u8],
	allow_header_override: bool,
) -> Result<MailAuthVerdict, IncomingError> {
	if allow_header_override && let Some(verdict) = parse_test_auth_header(message) {
		return Ok(verdict);
	}

	let authenticator = MessageAuthenticator::new_cloudflare_tls()
		.map_err(|e| IncomingError::Auth(format!("resolver init failed: {e}")))?;

	let authenticated_message = AuthenticatedMessage::parse(message).ok_or(IncomingError::Parse)?;

	let dkim_output = authenticator.verify_dkim(&authenticated_message).await;
	let spf_output = authenticator
		.verify_spf(SpfParameters::verify_mail_from(
			ip,
			helo_domain,
			host_domain,
			sender,
		))
		.await;

	let sender_domain = extract_header_from_domain(&authenticated_message)
		.or_else(|| extract_domain(sender).map(str::to_string))
		.ok_or_else(|| IncomingError::Auth("unable to determine sender domain".to_string()))?;

	let dmarc_output = authenticator
		.verify_dmarc(
			DmarcParameters::new(
				&authenticated_message,
				&dkim_output,
				&sender_domain,
				&spf_output,
			)
			.with_domain_suffix_fn(|domain| psl::domain_str(domain).unwrap_or(domain)),
		)
		.await;

	Ok(MailAuthVerdict {
		spf: spf_output.result(),
		dkim: dkim_result(&dkim_output),
		dmarc: dmarc_result(&dmarc_output),
	})
}

pub async fn persist_incoming_message(
	message: &[u8],
	parsed: &mail_parser::Message<'_>,
	recipients: &[String],
) -> Result<Vec<String>, IncomingError> {
	let message_id = storage::sanitize_path_component(parsed.message_id().unwrap_or("message"));
	let mut stored = Vec::new();

	for recipient in recipients {
		let Some((mailbox, domain)) = split_recipient(recipient) else {
			continue;
		};

		let domain_settings = db::domain_settings(domain).await;
		let policy = storage_policy_for_recipient(mailbox, domain, domain_settings.as_ref());

		let msg_key = storage::put_raw_message(&policy, &message_id, message).await?;
		stored.push(msg_key);

		// E2EE tenants are metadata-only server-side: no parsed body indexing blobs.
		if policy.mode == EncryptionMode::E2ee {
			continue;
		}

		for (idx, part) in parsed.attachments().enumerate() {
			let content_type = part.content_type().map(|ct| {
				format!(
					"{}/{}",
					ct.c_type,
					ct.c_subtype.as_deref().unwrap_or("octet-stream")
				)
			});
			let part_id = format!("p{idx}");
			let _ = storage::put_attachment(
				&policy,
				&message_id,
				&part_id,
				content_type.as_deref(),
				part.contents(),
			)
			.await?;
		}

		if storage::store_parsed_parts() {
			for (idx, part) in parsed.text_bodies().enumerate() {
				let mime_path = format!("text/{idx}");
				let _ = storage::put_part_blob(
					&policy,
					&message_id,
					&mime_path,
					Some("text/plain; charset=utf-8"),
					part.contents(),
				)
				.await?;
			}

			for (idx, part) in parsed.html_bodies().enumerate() {
				let mime_path = format!("html/{idx}");
				let _ = storage::put_part_blob(
					&policy,
					&message_id,
					&mime_path,
					Some("text/html; charset=utf-8"),
					part.contents(),
				)
				.await?;
			}
		}
	}

	if stored.is_empty() {
		return Err(IncomingError::Storage(
			"no valid recipient mailbox/domain to store message".to_string(),
		));
	}

	Ok(stored)
}

fn extract_header_from_domain(message: &AuthenticatedMessage<'_>) -> Option<String> {
	message
		.from
		.first()
		.and_then(|address| extract_domain(address))
		.map(str::to_string)
}

fn extract_domain(address: &str) -> Option<&str> {
	let (_, domain) = address.trim().rsplit_once('@')?;
	if domain.is_empty() {
		return None;
	}
	Some(domain)
}

fn dkim_result(outputs: &[mail_auth::DkimOutput<'_>]) -> DkimResult {
	if outputs.iter().any(|o| o.result() == &DkimResult::Pass) {
		return DkimResult::Pass;
	}
	outputs
		.first()
		.map(|o| o.result().clone())
		.unwrap_or(DkimResult::None)
}

fn dmarc_result(output: &mail_auth::DmarcOutput) -> DmarcResult {
	match (output.spf_result(), output.dkim_result()) {
		(DmarcResult::Pass, _) | (_, DmarcResult::Pass) => DmarcResult::Pass,
		(DmarcResult::TempError(err), _) | (_, DmarcResult::TempError(err)) => {
			DmarcResult::TempError(err.clone())
		}
		(DmarcResult::PermError(err), _) | (_, DmarcResult::PermError(err)) => {
			DmarcResult::PermError(err.clone())
		}
		(DmarcResult::Fail(err), _) | (_, DmarcResult::Fail(err)) => DmarcResult::Fail(err.clone()),
		_ => DmarcResult::None,
	}
}

pub async fn accepted_for_recipients(
	config: &Config,
	recipients: &[String],
	verdict: &MailAuthVerdict,
) -> bool {
	let mut matched_domain = false;
	for recipient in recipients {
		let Some(domain) = extract_domain(recipient) else {
			continue;
		};
		let overrides = db::domain_settings(domain)
			.await
			.and_then(|settings| settings.auth);
		let policy = config.merged_auth_policy(overrides.as_ref());
		if !verdict.accepted(&policy) {
			return false;
		}
		matched_domain = true;
	}

	if !matched_domain {
		return verdict.accepted(&config.auth);
	}

	true
}

fn parse_test_auth_header(raw: &[u8]) -> Option<MailAuthVerdict> {
	let text = String::from_utf8_lossy(raw);
	let line = text
		.lines()
		.find(|l| l.to_ascii_lowercase().starts_with("x-inbox-test-auth:"))?;
	let value = line.split_once(':')?.1.trim().to_ascii_lowercase();

	let spf = if value.contains("spf=pass") {
		SpfResult::Pass
	} else {
		SpfResult::Fail
	};
	let dkim = if value.contains("dkim=pass") {
		DkimResult::Pass
	} else {
		DkimResult::Fail(mail_auth::Error::ParseError)
	};
	let dmarc = if value.contains("dmarc=pass") {
		DmarcResult::Pass
	} else {
		DmarcResult::Fail(mail_auth::Error::ParseError)
	};

	Some(MailAuthVerdict { spf, dkim, dmarc })
}

fn split_recipient(recipient: &str) -> Option<(&str, &str)> {
	let (mailbox, domain) = recipient.trim().rsplit_once('@')?;
	if mailbox.is_empty() || domain.is_empty() {
		return None;
	}
	Some((mailbox, domain))
}

fn storage_policy_for_recipient(
	mailbox: &str,
	domain: &str,
	settings: Option<&db::DomainSettings>,
) -> StoragePolicy {
	let org = settings
		.and_then(|s| s.org_id.clone())
		.unwrap_or_else(|| domain.to_string());
	let enc = settings.and_then(|s| s.encryption.as_ref());
	let mode = match enc.map(|e| e.mode) {
		Some(TenantEncryptionMode::E2ee) => EncryptionMode::E2ee,
		_ => EncryptionMode::Standard,
	};

	StoragePolicy {
		org,
		mailbox: mailbox.to_string(),
		mode,
		sse_c_key_b64: enc.and_then(|e| e.sse_c_key_b64.clone()),
		wrapped_dek_customer: enc.and_then(|e| e.wrapped_dek_customer.clone()),
	}
}
