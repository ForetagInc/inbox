use std::{net::IpAddr, path::PathBuf};

use mail_auth::{
	AuthenticatedMessage, DkimResult, DmarcResult, MessageAuthenticator, SpfResult,
	dmarc::verify::DmarcParameters, spf::verify::SpfParameters
};
use tokio::{fs, io::AsyncWriteExt};

use crate::{config::Config, db, protocols::smtp::error::IncomingError};

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
		.verify_spf(SpfParameters::verify_mail_from(ip, helo_domain, host_domain, sender))
		.await;

	let sender_domain = extract_header_from_domain(&authenticated_message)
		.or_else(|| extract_domain(sender).map(str::to_string))
		.ok_or_else(|| IncomingError::Auth("unable to determine sender domain".to_string()))?;

	let dmarc_output = authenticator
		.verify_dmarc(
			DmarcParameters::new(&authenticated_message, &dkim_output, &sender_domain, &spf_output)
				.with_domain_suffix_fn(|domain| psl::domain_str(domain).unwrap_or(domain))
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
	message_id_hint: &str,
) -> Result<PathBuf, IncomingError> {
	let dir = std::env::var("INBOX_INCOMING_DIR")
		.map(PathBuf::from)
		.unwrap_or_else(|_| PathBuf::from("data/incoming"));
	fs::create_dir_all(&dir)
		.await
		.map_err(|e| IncomingError::Storage(e.to_string()))?;

	let safe_hint = sanitize_path_component(message_id_hint);
	let filename = format!("{}_{}.eml", chrono::Utc::now().timestamp_millis(), safe_hint);
	let path = dir.join(filename);
	let mut file = fs::File::create(&path)
		.await
		.map_err(|e| IncomingError::Storage(e.to_string()))?;

	file.write_all(message)
		.await
		.map_err(|e| IncomingError::Storage(e.to_string()))?;
	file.flush()
		.await
		.map_err(|e| IncomingError::Storage(e.to_string()))?;

	Ok(path)
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

fn sanitize_path_component(input: &str) -> String {
	let mut out = String::with_capacity(input.len());
	for c in input.chars() {
		if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
			out.push(c);
		}
	}
	if out.is_empty() {
		"mail".to_string()
	} else {
		out
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
		let overrides = db::domain_settings(domain).await.and_then(|settings| settings.auth);
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
