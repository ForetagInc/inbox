use std::{
	collections::HashMap,
	sync::OnceLock,
	time::{Duration, Instant},
};

use reqwest::Client;
use tokio::sync::RwLock;

use crate::{config::Config, protocols::smtp::error::OutgoingError};

#[derive(Debug, Clone)]
pub struct MtaStsPolicy {
	pub mode: String,
	pub mx_patterns: Vec<String>,
	pub max_age_secs: u64,
}

#[derive(Debug, Clone)]
struct CachedPolicy {
	policy: Option<MtaStsPolicy>,
	expires_at: Instant,
}

static CACHE: OnceLock<RwLock<HashMap<String, CachedPolicy>>> = OnceLock::new();

pub async fn resolve_policy(
	domain: &str,
	config: &Config,
) -> Result<Option<MtaStsPolicy>, OutgoingError> {
	let cache = CACHE.get_or_init(|| RwLock::new(HashMap::new()));
	let key = domain.to_ascii_lowercase();
	{
		let read = cache.read().await;
		if let Some(entry) = read.get(&key)
			&& entry.expires_at > Instant::now()
		{
			return Ok(entry.policy.clone());
		}
	}

	let id = match lookup_policy_id(domain).await? {
		Some(id) => id,
		None => {
			cache.write().await.insert(
				key,
				CachedPolicy {
					policy: None,
					expires_at: Instant::now() + Duration::from_secs(300),
				},
			);
			return Ok(None);
		}
	};

	let policy = fetch_policy_file(domain, &id, config).await?;
	let max_age = policy.max_age_secs.clamp(300, 86_400);
	cache.write().await.insert(
		domain.to_ascii_lowercase(),
		CachedPolicy {
			policy: Some(policy.clone()),
			expires_at: Instant::now() + Duration::from_secs(max_age),
		},
	);
	Ok(Some(policy))
}

async fn lookup_policy_id(domain: &str) -> Result<Option<String>, OutgoingError> {
	let resolver = mail_auth::hickory_resolver::TokioResolver::builder(
		mail_auth::hickory_resolver::name_server::TokioConnectionProvider::default(),
	)
	.map(|builder| builder.build())
	.map_err(|e| OutgoingError::Relay(format!("resolver init failed: {e}")))?;

	let owner = format!("_mta-sts.{domain}");
	let lookup = match resolver.txt_lookup(owner.clone()).await {
		Ok(lookup) => lookup,
		Err(_) => return Ok(None),
	};

	for record in lookup.as_lookup().record_iter() {
		let Some(txt) = record.data().as_txt() else {
			continue;
		};
		let mut blob = Vec::new();
		for part in txt.txt_data() {
			blob.extend_from_slice(part);
		}
		let text = String::from_utf8_lossy(&blob).to_string();
		if let Some(id) = parse_mta_sts_id(&text) {
			return Ok(Some(id));
		}
	}

	Ok(None)
}

async fn fetch_policy_file(
	domain: &str,
	_id: &str,
	config: &Config,
) -> Result<MtaStsPolicy, OutgoingError> {
	let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
	let client = Client::builder()
		.timeout(config.smtp.outbound.timeout)
		.build()
		.map_err(|e| OutgoingError::Relay(format!("mta-sts http client init failed: {e}")))?;
	let body = client
		.get(url.clone())
		.send()
		.await
		.map_err(|e| OutgoingError::Relay(format!("mta-sts policy fetch failed for {url}: {e}")))?
		.error_for_status()
		.map_err(|e| OutgoingError::Relay(format!("mta-sts policy http status error for {url}: {e}")))?
		.text()
		.await
		.map_err(|e| OutgoingError::Relay(format!("mta-sts policy body read failed for {url}: {e}")))?;

	parse_policy_file(&body)
}

fn parse_mta_sts_id(txt: &str) -> Option<String> {
	let lowered = txt.to_ascii_lowercase();
	if !lowered.contains("v=stsv1") {
		return None;
	}
	for part in txt.split(';') {
		let part = part.trim();
		if let Some(value) = part.strip_prefix("id=") {
			let trimmed = value.trim();
			if !trimmed.is_empty() {
				return Some(trimmed.to_string());
			}
		}
	}
	None
}

fn parse_policy_file(content: &str) -> Result<MtaStsPolicy, OutgoingError> {
	let mut mode = None;
	let mut mx_patterns = Vec::new();
	let mut max_age_secs = None;
	let mut version_ok = false;

	for line in content.lines() {
		let line = line.trim();
		if line.is_empty() || line.starts_with('#') {
			continue;
		}
		let Some((k, v)) = line.split_once(':') else {
			continue;
		};
		let key = k.trim().to_ascii_lowercase();
		let value = v.trim();
		match key.as_str() {
			"version" if value.eq_ignore_ascii_case("stsv1") => version_ok = true,
			"mode" => mode = Some(value.to_ascii_lowercase()),
			"mx" => mx_patterns.push(value.to_ascii_lowercase()),
			"max_age" => {
				if let Ok(v) = value.parse::<u64>() {
					max_age_secs = Some(v);
				}
			}
			_ => {}
		}
	}

	if !version_ok {
		return Err(OutgoingError::Relay("invalid mta-sts policy: missing version STSv1".to_string()));
	}
	let mode = mode.unwrap_or_else(|| "none".to_string());

	Ok(MtaStsPolicy {
		mode,
		mx_patterns,
		max_age_secs: max_age_secs.unwrap_or(3600),
	})
}
