use std::{collections::BTreeMap, path::PathBuf};

use chrono::{DateTime, Duration, Timelike, Utc};
use serde::Deserialize;
use tracing::{Level, event, warn};

use crate::{
	config::Config,
	db,
	protocols::smtp::handler::outgoing::{OutgoingRequest, send_outgoing},
};

#[derive(Debug, Deserialize)]
struct TlsFailureLine {
	domain: String,
	host: Option<String>,
	reason: Option<String>,
}

#[derive(Debug, Clone)]
struct DomainAggregate {
	total_failures: usize,
	samples: Vec<String>,
}

pub async fn maybe_send_daily_tls_rpt(
	config: &Config,
	now: DateTime<Utc>,
	last_run_date: &mut Option<String>,
) {
	if !config.smtp.outbound.tls_rpt_enabled {
		return;
	}
	if now.hour() as u8 != config.smtp.outbound.tls_rpt_send_hour_utc {
		return;
	}
	let today = now.format("%Y-%m-%d").to_string();
	if last_run_date.as_deref() == Some(today.as_str()) {
		return;
	}

	let report_date = (now - Duration::days(1)).format("%Y-%m-%d").to_string();
	if let Err(err) = send_reports_for_date(config, &report_date).await {
		warn!("tls-rpt daily send failed: {err}");
	}
	*last_run_date = Some(today);
}

async fn send_reports_for_date(config: &Config, report_date: &str) -> Result<(), String> {
	let report_path = PathBuf::from(&config.smtp.outbound.tls_report_dir)
		.join(format!("{report_date}.jsonl"));
	let body = match tokio::fs::read_to_string(&report_path).await {
		Ok(body) => body,
		Err(_) => return Ok(()),
	};

	let mut aggregates = BTreeMap::<String, DomainAggregate>::new();
	for line in body.lines() {
		let line = line.trim();
		if line.is_empty() {
			continue;
		}
		let Ok(entry) = serde_json::from_str::<TlsFailureLine>(line) else {
			continue;
		};
		let domain = entry.domain.trim().to_ascii_lowercase();
		if domain.is_empty() {
			continue;
		}
		let aggregate = aggregates.entry(domain).or_insert_with(|| DomainAggregate {
			total_failures: 0,
			samples: Vec::new(),
		});
		aggregate.total_failures += 1;
		if aggregate.samples.len() < 10 {
			let sample = format!(
				"host={} reason={}",
				entry.host.unwrap_or_else(|| "unknown".to_string()),
				entry.reason.unwrap_or_else(|| "unknown".to_string())
			);
			aggregate.samples.push(sample);
		}
	}

	for (domain, aggregate) in aggregates {
		if db::tls_rpt_checkpoint_exists(&domain, report_date)
			.await
			.map_err(|e| format!("tls-rpt checkpoint lookup failed: {e}"))?
		{
			event!(
				target: "smtp.tlsrpt.skip",
				Level::INFO,
				domain = %domain,
				reason = "already_sent",
				report_date = report_date
			);
			continue;
		}

		let recipients = discover_rua_mailto_targets(
			&domain,
			config.smtp.outbound.tls_rpt_max_recipients_per_domain,
		)
		.await?;
		if recipients.is_empty() {
			event!(
				target: "smtp.tlsrpt.skip",
				Level::INFO,
				domain = %domain,
				reason = "no_rua",
				report_date = report_date
			);
			continue;
		}

		let from = choose_report_sender(config, &domain)?;
		let payload = serde_json::json!({
			"organization-name": domain,
			"date-range": {"start-datetime": format!("{report_date}T00:00:00Z"), "end-datetime": format!("{report_date}T23:59:59Z")},
			"contact-info": from,
			"report-id": format!("{}-{}", domain, report_date),
			"policies": [{
				"policy": {"policy-type": "sts", "policy-domain": domain, "mx-host": []},
				"summary": {"total-successful-session-count": 0, "total-failure-session-count": aggregate.total_failures},
				"failure-details": aggregate.samples
			}]
		});

		send_outgoing(
			OutgoingRequest {
				from: from.clone(),
				to: recipients.clone(),
				subject: format!("TLS-RPT for {} ({})", domain, report_date),
				text_body: Some(payload.to_string()),
				html_body: None,
				idempotency_key: Some(format!("tlsrpt:{}:{}", domain, report_date)),
				actor_account: None,
				shared_inbox: None,
			},
			config,
		)
		.await
		.map_err(|e| format!("tls-rpt send failed for {domain}: {e}"))?;

		db::record_tls_rpt_checkpoint(&domain, report_date, Utc::now().timestamp() as u64, recipients.len())
			.await
			.map_err(|e| format!("tls-rpt checkpoint write failed: {e}"))?;
		event!(
			target: "smtp.tlsrpt.sent",
			Level::INFO,
			domain = %domain,
			recipient_count = recipients.len() as i64,
			report_date = report_date
		);
	}

	Ok(())
}

fn choose_report_sender(config: &Config, domain: &str) -> Result<String, String> {
	let preferred = format!("tls-report@{domain}");
	if preferred.contains('@') {
		return Ok(preferred);
	}
	if let Some(fallback) = config.smtp.outbound.tls_rpt_fallback_from.as_ref()
		&& fallback.contains('@')
	{
		return Ok(fallback.clone());
	}
	Err("tls-rpt sender unavailable and fallback not configured".to_string())
}

async fn discover_rua_mailto_targets(
	domain: &str,
	max_recipients: usize,
) -> Result<Vec<String>, String> {
	let resolver = mail_auth::hickory_resolver::TokioResolver::builder(
		mail_auth::hickory_resolver::name_server::TokioConnectionProvider::default(),
	)
	.map(|builder| builder.build())
	.map_err(|e| format!("resolver init failed: {e}"))?;
	let owner = format!("_smtp._tls.{domain}");
	let lookup = match resolver.txt_lookup(owner).await {
		Ok(lookup) => lookup,
		Err(_) => return Ok(Vec::new()),
	};

	let mut out = Vec::new();
	for record in lookup.as_lookup().record_iter() {
		let Some(txt) = record.data().as_txt() else {
			continue;
		};
		let mut blob = Vec::new();
		for part in txt.txt_data() {
			blob.extend_from_slice(part);
		}
		let value = String::from_utf8_lossy(&blob).to_string();
		for uri in parse_rua_uris(&value) {
			if let Some(address) = uri.strip_prefix("mailto:") {
				let address = address.trim().to_ascii_lowercase();
				if !address.is_empty() && !out.contains(&address) {
					out.push(address);
					if out.len() >= max_recipients {
						return Ok(out);
					}
				}
			}
		}
	}
	Ok(out)
}

fn parse_rua_uris(record: &str) -> Vec<String> {
	for token in record.split(';') {
		let token = token.trim();
		if token.to_ascii_lowercase().starts_with("rua=") {
			let values = token[4..]
				.split(',')
				.map(|v| v.trim().to_string())
				.filter(|v| !v.is_empty())
				.collect::<Vec<_>>();
			return values;
		}
	}
	Vec::new()
}
