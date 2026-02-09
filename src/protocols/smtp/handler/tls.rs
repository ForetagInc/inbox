use std::path::PathBuf;

use chrono::Utc;
use serde::Serialize;

use crate::{
	config::{Config, OutboundTlsMode},
	protocols::smtp::error::OutgoingError,
};

#[derive(Serialize)]
struct TlsFailureReport<'a> {
	timestamp: String,
	domain: &'a str,
	host: &'a str,
	reason: &'a str,
	mode: &'a str,
}

pub async fn tls_required_for_domain(domain: &str, config: &Config) -> Result<bool, OutgoingError> {
	if config.smtp.outbound.tls_mode == OutboundTlsMode::Required {
		return Ok(true);
	}
	if config.smtp.outbound.mta_sts_enforce && domain_advertises_mta_sts(domain).await? {
		return Ok(true);
	}
	Ok(false)
}

pub async fn write_tls_failure_report(config: &Config, domain: &str, host: &str, reason: &str) {
	let report = TlsFailureReport {
		timestamp: Utc::now().to_rfc3339(),
		domain,
		host,
		reason,
		mode: match config.smtp.outbound.tls_mode {
			OutboundTlsMode::Required => "required",
			OutboundTlsMode::Opportunistic => "opportunistic",
		},
	};
	let Ok(line) = serde_json::to_string(&report) else {
		return;
	};

	let report_dir = PathBuf::from(&config.smtp.outbound.tls_report_dir);
	if tokio::fs::create_dir_all(&report_dir).await.is_err() {
		return;
	}
	let date = Utc::now().format("%Y-%m-%d").to_string();
	let file = report_dir.join(format!("{date}.jsonl"));
	let mut with_newline = line;
	with_newline.push('\n');
	let _ = append_line(&file, with_newline.as_bytes()).await;
}

async fn append_line(path: &PathBuf, line: &[u8]) -> Result<(), std::io::Error> {
	use tokio::io::AsyncWriteExt;
	let mut f = tokio::fs::OpenOptions::new()
		.create(true)
		.append(true)
		.open(path)
		.await?;
	f.write_all(line).await?;
	f.flush().await
}

async fn domain_advertises_mta_sts(domain: &str) -> Result<bool, OutgoingError> {
	let resolver = mail_auth::hickory_resolver::TokioResolver::builder(
		mail_auth::hickory_resolver::name_server::TokioConnectionProvider::default(),
	)
	.map(|builder| builder.build())
	.map_err(|e| OutgoingError::Relay(format!("resolver init failed: {e}")))?;

	let name = format!("_mta-sts.{domain}");
	let lookup = match resolver.txt_lookup(name.clone()).await {
		Ok(lookup) => lookup,
		Err(_) => return Ok(false),
	};

	for record in lookup.as_lookup().record_iter() {
		if let Some(txt) = record.data().as_txt() {
			let mut blob = Vec::new();
			for part in txt.txt_data() {
				blob.extend_from_slice(part);
			}
			let text = String::from_utf8_lossy(&blob).to_ascii_lowercase();
			if text.contains("v=stsv1") {
				return Ok(true);
			}
		}
	}

	Ok(false)
}
