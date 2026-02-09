use std::path::PathBuf;

use chrono::Utc;
use serde::Serialize;

use crate::config::{Config, OutboundTlsMode};

use super::TlsFailureContext;

#[derive(Serialize)]
struct TlsFailureReport<'a> {
	timestamp: String,
	domain: &'a str,
	host: &'a str,
	reason: &'a str,
	mode: &'a str,
	source: &'a str,
	mta_sts_mode: Option<String>,
	dane_required: bool,
}

pub async fn write_tls_failure_report(
	config: &Config,
	domain: &str,
	host: &str,
	reason: &str,
	context: &TlsFailureContext,
) {
	let report = TlsFailureReport {
		timestamp: Utc::now().to_rfc3339(),
		domain,
		host,
		reason,
		mode: match config.smtp.outbound.tls_mode {
			OutboundTlsMode::Required => "required",
			OutboundTlsMode::Opportunistic => "opportunistic",
		},
		source: context.source,
		mta_sts_mode: context.mta_sts_mode.clone(),
		dane_required: context.dane_required,
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
	let mut line = line;
	line.push('\n');
	let _ = append_line(&file, line.as_bytes()).await;
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
