use std::{
	env,
	sync::{
		LazyLock,
		atomic::{AtomicBool, Ordering},
	},
};

use serde::Deserialize;
use surrealdb::{
	Surreal,
	engine::remote::http::{Client, Http},
	opt::auth::Database,
};
use surrealdb_types::{RecordIdKey, SurrealValue, Value};
use tracing::{info, warn};

use crate::config::{DkimConfig, TenantMailAuthConfig};

pub static DB: LazyLock<Surreal<Client>> = LazyLock::new(Surreal::init);
static DB_READY: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
pub struct DomainSettings {
	pub org_id: Option<String>,
	pub dkim: Option<DkimConfig>,
	pub auth: Option<TenantMailAuthConfig>,
	pub encryption: Option<TenantEncryptionConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantEncryptionMode {
	Standard,
	E2ee,
}

#[derive(Debug, Clone)]
pub struct TenantEncryptionConfig {
	pub mode: TenantEncryptionMode,
	pub sse_c_key_b64: Option<String>,
	pub wrapped_dek_customer: Option<String>,
}

#[derive(Debug, Deserialize, surrealdb_types::SurrealValue)]
struct HasDomainRow {
	organization: Option<Value>,
	dkim_selector: Option<String>,
	dkim_private_key_b64_pkcs8: Option<String>,
	dkim_headers: Option<Vec<String>>,
	require_spf_pass: Option<bool>,
	require_dkim_pass: Option<bool>,
	require_dmarc_pass: Option<bool>,
	enc_mode: Option<String>,
	enc_sse_c_key_b64: Option<String>,
	enc_wrapped_dek_customer: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OutboundQueueInsert {
	pub job_id: String,
	pub created_at_epoch_secs: u64,
	pub expires_at_epoch_secs: u64,
	pub next_attempt_at_epoch_secs: u64,
	pub attempts: u32,
	pub status: String,
	pub payload_kind: String,
	pub payload_json: String,
}

#[derive(Debug, Clone, Deserialize, surrealdb_types::SurrealValue)]
struct OutboundQueueIdRow {
	job_id: String,
}

#[derive(Debug, Clone, Deserialize, surrealdb_types::SurrealValue)]
struct OutboundDeliveryIdRow {
	job_id: String,
}

#[derive(Debug, Clone, Deserialize, surrealdb_types::SurrealValue)]
pub struct OutboundQueueRow {
	pub job_id: String,
	pub created_at_epoch_secs: u64,
	pub expires_at_epoch_secs: u64,
	pub next_attempt_at_epoch_secs: u64,
	pub attempts: u32,
	pub status: String,
	pub lease_owner: Option<String>,
	pub lease_until_epoch_secs: Option<u64>,
	pub last_error: Option<String>,
	pub payload_kind: String,
	pub payload_json: String,
}

pub async fn init() -> Result<(), surrealdb::Error> {
	DB.connect::<Http>(env::var("DATABASE_HOSTNAME").unwrap_or(String::from("localhost:8000")))
		.await?;

	DB.signin(Database {
		namespace: env::var("DATABASE_NAMESPACE").unwrap_or_else(|_| "foretag".to_string()),
		database: env::var("DATABASE_DATABASE").unwrap_or_else(|_| "workshop".to_string()),
		username: env::var("DATABASE_USERNAME").unwrap_or_else(|_| "email".to_string()),
		password: env::var("DATABASE_PASSWORD").unwrap_or_else(|_| "email".to_string()),
	})
	.await?;

	DB_READY.store(true, Ordering::Relaxed);
	info!("Database initialized successfully");
	Ok(())
}

pub async fn domain_settings(domain: &str) -> Option<DomainSettings> {
	if !DB_READY.load(Ordering::Relaxed) {
		return None;
	}

	let sql = r#"
		SELECT
			in AS organization,
			dkim_selector,
			dkim_private_key_b64_pkcs8,
			dkim_headers,
			require_spf_pass,
			require_dkim_pass,
			require_dmarc_pass,
			enc_mode,
			enc_sse_c_key_b64,
			enc_wrapped_dek_customer
		FROM has_domain
		WHERE out = type::thing("domain", $domain)
		  AND is_active = true
		LIMIT 1;
	"#;

	let mut response = match DB.query(sql).bind(("domain", domain.to_string())).await {
		Ok(response) => response,
		Err(err) => {
			warn!("has_domain lookup failed for domain {domain}: {err}");
			return None;
		}
	};

	let row: Option<HasDomainRow> = match response.take(0) {
		Ok(row) => row,
		Err(err) => {
			warn!("has_domain decode failed for domain {domain}: {err}");
			return None;
		}
	};

	row.map(|row| {
		let dkim = row.dkim_selector.and_then(|selector| {
			row.dkim_private_key_b64_pkcs8
				.map(|private_key_b64_pkcs8| DkimConfig {
					domain: domain.to_string(),
					selector,
					private_key_b64_pkcs8,
					headers: row.dkim_headers.unwrap_or_else(|| {
						vec!["From".into(), "To".into(), "Subject".into(), "Date".into()]
					}),
				})
		});

		let auth = if row.require_spf_pass.is_some()
			|| row.require_dkim_pass.is_some()
			|| row.require_dmarc_pass.is_some()
		{
			Some(TenantMailAuthConfig {
				require_spf_pass: row.require_spf_pass,
				require_dkim_pass: row.require_dkim_pass,
				require_dmarc_pass: row.require_dmarc_pass,
			})
		} else {
			None
		};

		let encryption = row.enc_mode.and_then(|mode| {
			let mode = if mode.eq_ignore_ascii_case("e2ee") {
				TenantEncryptionMode::E2ee
			} else {
				TenantEncryptionMode::Standard
			};
			Some(TenantEncryptionConfig {
				mode,
				sse_c_key_b64: row.enc_sse_c_key_b64,
				wrapped_dek_customer: row.enc_wrapped_dek_customer,
			})
		});

		DomainSettings {
			org_id: row.organization.and_then(extract_org_id),
			dkim,
			auth,
			encryption,
		}
	})
}

pub fn is_ready() -> bool {
	DB_READY.load(Ordering::Relaxed)
}

pub async fn enqueue_outbound_job(job: &OutboundQueueInsert) -> Result<(), String> {
	if !is_ready() {
		return Err("database not initialized".to_string());
	}
	let sql = r#"
		CREATE type::thing("outbound_queue", $job_id) SET
			job_id = $job_id,
			created_at_epoch_secs = $created_at_epoch_secs,
			expires_at_epoch_secs = $expires_at_epoch_secs,
			next_attempt_at_epoch_secs = $next_attempt_at_epoch_secs,
			attempts = $attempts,
			status = $status,
			lease_owner = NONE,
			lease_until_epoch_secs = NONE,
			last_error = NONE,
			payload_kind = $payload_kind,
			payload_json = $payload_json;
	"#;
	DB.query(sql)
		.bind(("job_id", job.job_id.clone()))
		.bind(("created_at_epoch_secs", job.created_at_epoch_secs))
		.bind(("expires_at_epoch_secs", job.expires_at_epoch_secs))
		.bind(("next_attempt_at_epoch_secs", job.next_attempt_at_epoch_secs))
		.bind(("attempts", job.attempts as u64))
		.bind(("status", job.status.clone()))
		.bind(("payload_kind", job.payload_kind.clone()))
		.bind(("payload_json", job.payload_json.clone()))
		.await
		.map_err(|e| format!("enqueue outbound job failed: {e}"))?;
	Ok(())
}

pub async fn list_due_outbound_job_ids(
	now_epoch_secs: u64,
	limit: usize,
) -> Result<Vec<String>, String> {
	if !is_ready() {
		return Ok(Vec::new());
	}
	let sql = r#"
		SELECT job_id
		FROM outbound_queue
		WHERE status = "queued"
		  AND next_attempt_at_epoch_secs <= $now
		  AND (lease_until_epoch_secs = NONE OR lease_until_epoch_secs < $now)
		ORDER BY next_attempt_at_epoch_secs ASC
		LIMIT $limit;
	"#;
	let mut response = DB
		.query(sql)
		.bind(("now", now_epoch_secs))
		.bind(("limit", limit as u64))
		.await
		.map_err(|e| format!("fetch due outbound job ids failed: {e}"))?;
	let rows: Vec<OutboundQueueIdRow> = response
		.take(0)
		.map_err(|e| format!("decode due outbound job ids failed: {e}"))?;
	Ok(rows.into_iter().map(|r| r.job_id).collect())
}

pub async fn claim_outbound_job(
	job_id: &str,
	worker_id: &str,
	now_epoch_secs: u64,
	lease_until_epoch_secs: u64,
) -> Result<Option<OutboundQueueRow>, String> {
	if !is_ready() {
		return Ok(None);
	}
	let sql = r#"
		UPDATE type::thing("outbound_queue", $job_id)
		SET
			status = "processing",
			lease_owner = $worker_id,
			lease_until_epoch_secs = $lease_until_epoch_secs
		WHERE status = "queued"
		  AND next_attempt_at_epoch_secs <= $now
		  AND (lease_until_epoch_secs = NONE OR lease_until_epoch_secs < $now)
		RETURN AFTER;
	"#;
	let mut response = DB
		.query(sql)
		.bind(("job_id", job_id.to_string()))
		.bind(("worker_id", worker_id.to_string()))
		.bind(("lease_until_epoch_secs", lease_until_epoch_secs))
		.bind(("now", now_epoch_secs))
		.await
		.map_err(|e| format!("claim outbound job failed: {e}"))?;
	response
		.take(0)
		.map_err(|e| format!("decode claimed outbound job failed: {e}"))
}

pub async fn mark_outbound_job_done(job_id: &str) -> Result<(), String> {
	if !is_ready() {
		return Ok(());
	}
	let sql = r#"
		DELETE type::thing("outbound_queue", $job_id);
	"#;
	DB.query(sql)
		.bind(("job_id", job_id.to_string()))
		.await
		.map_err(|e| format!("delete outbound job failed: {e}"))?;
	Ok(())
}

pub async fn retry_outbound_job(
	job_id: &str,
	attempts: u32,
	next_attempt_at_epoch_secs: u64,
	last_error: &str,
) -> Result<(), String> {
	if !is_ready() {
		return Err("database not initialized".to_string());
	}
	let sql = r#"
		UPDATE type::thing("outbound_queue", $job_id) SET
			attempts = $attempts,
			next_attempt_at_epoch_secs = $next_attempt_at_epoch_secs,
			last_error = $last_error,
			lease_owner = NONE,
			lease_until_epoch_secs = NONE,
			status = "queued";
	"#;
	DB.query(sql)
		.bind(("job_id", job_id.to_string()))
		.bind(("attempts", attempts as u64))
		.bind(("next_attempt_at_epoch_secs", next_attempt_at_epoch_secs))
		.bind(("last_error", last_error.to_string()))
		.await
		.map_err(|e| format!("retry outbound job update failed: {e}"))?;
	Ok(())
}

pub async fn dead_letter_outbound_job(job_id: &str, reason: &str) -> Result<(), String> {
	if !is_ready() {
		return Ok(());
	}
	let sql = r#"
		UPDATE type::thing("outbound_queue", $job_id) SET
			status = "dead",
			last_error = $reason,
			lease_owner = NONE,
			lease_until_epoch_secs = NONE;
	"#;
	DB.query(sql)
		.bind(("job_id", job_id.to_string()))
		.bind(("reason", reason.to_string()))
		.await
		.map_err(|e| format!("dead-letter outbound job update failed: {e}"))?;
	Ok(())
}

pub async fn outbound_delivery_exists(job_id: &str) -> Result<bool, String> {
	if !is_ready() {
		return Ok(false);
	}
	let sql = r#"
		SELECT job_id
		FROM outbound_delivery
		WHERE job_id = $job_id
		LIMIT 1;
	"#;
	let mut response = DB
		.query(sql)
		.bind(("job_id", job_id.to_string()))
		.await
		.map_err(|e| format!("outbound delivery exists query failed: {e}"))?;
	let rows: Vec<OutboundDeliveryIdRow> = response
		.take(0)
		.map_err(|e| format!("outbound delivery exists decode failed: {e}"))?;
	Ok(!rows.is_empty())
}

pub async fn record_outbound_delivery(
	job_id: &str,
	delivered_at_epoch_secs: u64,
) -> Result<(), String> {
	if !is_ready() {
		return Err("database not initialized".to_string());
	}
	let sql = r#"
		CREATE type::thing("outbound_delivery", $job_id) SET
			job_id = $job_id,
			delivered_at_epoch_secs = $delivered_at_epoch_secs;
	"#;
	match DB
		.query(sql)
		.bind(("job_id", job_id.to_string()))
		.bind(("delivered_at_epoch_secs", delivered_at_epoch_secs))
		.await
	{
		Ok(_) => Ok(()),
		Err(err) => {
			let text = err.to_string().to_ascii_lowercase();
			if text.contains("already") || text.contains("exist") || text.contains("duplicate") {
				Ok(())
			} else {
				Err(format!("record outbound delivery failed: {err}"))
			}
		}
	}
}

fn extract_org_id(value: Value) -> Option<String> {
	if let Value::RecordId(record) = value {
		return Some(match record.key {
			RecordIdKey::String(key) => key,
			RecordIdKey::Number(key) => key.to_string(),
			RecordIdKey::Uuid(key) => key.to_string(),
			_ => "unknown".to_string(),
		});
	}
	None
}
