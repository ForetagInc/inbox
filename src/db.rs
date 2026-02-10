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
	pub outbound_dnssec_validate: Option<bool>,
	pub quota: Option<TenantQuotaConfig>,
	pub addressing: TenantAddressingConfig,
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

#[derive(Debug, Clone)]
pub struct TenantQuotaConfig {
	pub max_recipients_per_message: Option<u32>,
	pub hourly_send_limit: Option<u32>,
	pub daily_send_limit: Option<u32>,
	pub max_queued_jobs: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct TenantAddressingConfig {
	pub plus_addressing_enabled: bool,
	pub plus_delimiter: char,
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
	outbound_dnssec_validate: Option<bool>,
	quota_max_recipients_per_message: Option<u64>,
	quota_hourly_send_limit: Option<u64>,
	quota_daily_send_limit: Option<u64>,
	quota_max_queued_jobs: Option<u64>,
	plus_addressing_enabled: Option<bool>,
	plus_delimiter: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OutboundQueueInsert {
	pub job_id: String,
	pub created_at_epoch_secs: u64,
	pub expires_at_epoch_secs: u64,
	pub next_attempt_at_epoch_secs: u64,
	pub attempts: u32,
	pub status: String,
	pub org_id: Option<String>,
	pub idempotency_key: Option<String>,
	pub actor_account: Option<String>,
	pub shared_inbox: Option<String>,
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
struct SuppressionRow {
	id: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, surrealdb_types::SurrealValue)]
struct SmtpRateLimitCounterRow {
	count: u64,
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
	pub org_id: Option<String>,
	pub idempotency_key: Option<String>,
	pub actor_account: Option<String>,
	pub shared_inbox: Option<String>,
	pub payload_kind: String,
	pub payload_json: String,
}

#[derive(Debug, Clone, Deserialize, surrealdb_types::SurrealValue)]
struct CountRow {
	count: u64,
}

#[derive(Debug, Clone, Deserialize, surrealdb_types::SurrealValue)]
pub struct SharedInboxRow {
	pub id: Option<Value>,
	pub address: String,
	pub mailbox: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, surrealdb_types::SurrealValue)]
struct TlsRptCheckpointRow {
	domain: String,
}

#[derive(Debug, Clone, Deserialize, surrealdb_types::SurrealValue)]
struct CounterMaxRow {
	max: Option<u64>,
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
			enc_wrapped_dek_customer,
			outbound_dnssec_validate,
			quota_max_recipients_per_message,
			quota_hourly_send_limit,
			quota_daily_send_limit,
			quota_max_queued_jobs,
			plus_addressing_enabled,
			plus_delimiter
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
			outbound_dnssec_validate: row.outbound_dnssec_validate,
			quota: Some(TenantQuotaConfig {
				max_recipients_per_message: row
					.quota_max_recipients_per_message
					.and_then(|v| u32::try_from(v).ok()),
				hourly_send_limit: row.quota_hourly_send_limit.and_then(|v| u32::try_from(v).ok()),
				daily_send_limit: row.quota_daily_send_limit.and_then(|v| u32::try_from(v).ok()),
				max_queued_jobs: row.quota_max_queued_jobs.and_then(|v| u32::try_from(v).ok()),
			}),
			addressing: TenantAddressingConfig {
				plus_addressing_enabled: row.plus_addressing_enabled.unwrap_or(false),
				plus_delimiter: row
					.plus_delimiter
					.and_then(|v| v.chars().next())
					.filter(|c| *c == '+')
					.unwrap_or('+'),
			},
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
			org_id = $org_id,
			idempotency_key = $idempotency_key,
			actor_account = $actor_account,
			shared_inbox = $shared_inbox,
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
		.bind(("org_id", job.org_id.clone()))
		.bind(("idempotency_key", job.idempotency_key.clone()))
		.bind(("actor_account", job.actor_account.clone()))
		.bind(("shared_inbox", job.shared_inbox.clone()))
		.bind(("payload_kind", job.payload_kind.clone()))
		.bind(("payload_json", job.payload_json.clone()))
		.await
		.map_err(|e| format!("enqueue outbound job failed: {e}"))?;
	Ok(())
}

pub async fn find_active_outbound_job_by_idempotency_key(
	idempotency_key: &str,
) -> Result<Option<String>, String> {
	if !is_ready() {
		return Ok(None);
	}
	let sql = r#"
		SELECT job_id
		FROM outbound_queue
		WHERE idempotency_key = $idempotency_key
		  AND status != "dead"
		LIMIT 1;
	"#;
	let mut response = DB
		.query(sql)
		.bind(("idempotency_key", idempotency_key.to_string()))
		.await
		.map_err(|e| format!("idempotency lookup failed: {e}"))?;
	let rows: Vec<OutboundQueueIdRow> = response
		.take(0)
		.map_err(|e| format!("idempotency decode failed: {e}"))?;
	Ok(rows.into_iter().next().map(|r| r.job_id))
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
	org_id: Option<&str>,
	actor_account: Option<&str>,
	shared_inbox: Option<&str>,
	delivered_at_epoch_secs: u64,
) -> Result<(), String> {
	if !is_ready() {
		return Err("database not initialized".to_string());
	}
	let sql = r#"
		CREATE type::thing("outbound_delivery", $job_id) SET
			job_id = $job_id,
			org_id = $org_id,
			actor_account = $actor_account,
			shared_inbox = $shared_inbox,
			delivered_at_epoch_secs = $delivered_at_epoch_secs;
	"#;
	match DB
		.query(sql)
		.bind(("job_id", job_id.to_string()))
		.bind(("org_id", org_id.map(|v| v.to_string())))
		.bind(("actor_account", actor_account.map(|v| v.to_string())))
		.bind(("shared_inbox", shared_inbox.map(|v| v.to_string())))
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

pub async fn count_queued_outbound_jobs_for_org(org_id: &str) -> Result<u64, String> {
	if !is_ready() {
		return Ok(0);
	}
	let sql = r#"
		SELECT count() AS count
		FROM outbound_queue
		WHERE org_id = $org_id
		  AND status IN ["queued", "processing"];
	"#;
	let mut response = DB
		.query(sql)
		.bind(("org_id", org_id.to_string()))
		.await
		.map_err(|e| format!("count queued outbound jobs failed: {e}"))?;
	let rows: Vec<CountRow> = response
		.take(0)
		.map_err(|e| format!("decode queued outbound jobs count failed: {e}"))?;
	Ok(rows.into_iter().next().map(|r| r.count).unwrap_or(0))
}

pub async fn count_outbound_deliveries_since(org_id: &str, since_epoch_secs: u64) -> Result<u64, String> {
	if !is_ready() {
		return Ok(0);
	}
	let sql = r#"
		SELECT count() AS count
		FROM outbound_delivery
		WHERE org_id = $org_id
		  AND delivered_at_epoch_secs >= $since;
	"#;
	let mut response = DB
		.query(sql)
		.bind(("org_id", org_id.to_string()))
		.bind(("since", since_epoch_secs))
		.await
		.map_err(|e| format!("count outbound deliveries failed: {e}"))?;
	let rows: Vec<CountRow> = response
		.take(0)
		.map_err(|e| format!("decode outbound deliveries count failed: {e}"))?;
	Ok(rows.into_iter().next().map(|r| r.count).unwrap_or(0))
}

pub async fn find_shared_inbox_by_address(address: &str) -> Result<Option<SharedInboxRow>, String> {
	if !is_ready() {
		return Ok(None);
	}
	let normalized = address.trim().to_ascii_lowercase();
	let sql = r#"
		SELECT id, address, mailbox
		FROM shared_inbox
		WHERE address = $address
		  AND is_active = true
		LIMIT 1;
	"#;
	let mut response = DB
		.query(sql)
		.bind(("address", normalized))
		.await
		.map_err(|e| format!("shared inbox lookup failed: {e}"))?;
	response
		.take(0)
		.map_err(|e| format!("shared inbox decode failed: {e}"))
}

pub async fn can_send_as_shared_inbox(address: &str, actor_account: &str) -> Result<bool, String> {
	if !is_ready() {
		return Ok(false);
	}
	let Some(shared) = find_shared_inbox_by_address(address).await? else {
		return Ok(false);
	};
	let Some(shared_id) = shared.id.and_then(extract_record_id) else {
		return Ok(false);
	};
	let sql = r#"
		SELECT count() AS count
		FROM has_shared_inbox_member
		WHERE in = type::thing("shared_inbox", $shared_id)
		  AND out = type::thing("account", $actor_account)
		  AND is_active = true
		  AND can_send_as = true;
	"#;
	let mut response = DB
		.query(sql)
		.bind(("shared_id", shared_id))
		.bind(("actor_account", actor_account.to_string()))
		.await
		.map_err(|e| format!("shared inbox membership lookup failed: {e}"))?;
	let rows: Vec<CountRow> = response
		.take(0)
		.map_err(|e| format!("shared inbox membership decode failed: {e}"))?;
	Ok(rows.into_iter().next().map(|r| r.count).unwrap_or(0) > 0)
}

pub async fn record_shared_inbox_event(
	shared_inbox_id: &str,
	actor_account: &str,
	event_type: &str,
	email_delivery_id: Option<&str>,
) -> Result<(), String> {
	if !is_ready() {
		return Ok(());
	}
	let sql = r#"
		CREATE shared_inbox_event SET
			shared_inbox = type::thing("shared_inbox", $shared_inbox_id),
			actor = type::thing("account", $actor_account),
			event_type = $event_type,
			email_delivery = IF $email_delivery_id = NONE THEN NONE ELSE type::thing("has_email_delivery", $email_delivery_id) END,
			created_at = time::now();
	"#;
	DB.query(sql)
		.bind(("shared_inbox_id", shared_inbox_id.to_string()))
		.bind(("actor_account", actor_account.to_string()))
		.bind(("event_type", event_type.to_string()))
		.bind(("email_delivery_id", email_delivery_id.map(|v| v.to_string())))
		.await
		.map_err(|e| format!("record shared inbox event failed: {e}"))?;
	Ok(())
}

pub async fn persist_inbound_email_row(
	email_id: &str,
	message_id: &str,
	content_hash: &str,
	size_bytes: usize,
	blob_path: &str,
	internal_date_rfc3339: &str,
	subject: Option<&str>,
	ingest_status: &str,
	ingest_error: Option<&str>,
) -> Result<(), String> {
	if !is_ready() {
		return Ok(());
	}
	let subject = subject.unwrap_or("").trim().to_string();
	let sql = r#"
		UPSERT type::thing("email", $email_id) CONTENT {
			message_id: $message_id,
			content_hash: $content_hash,
			date: NONE,
			subject: $subject,
			subject_normalized: string::lowercase($subject),
			references: [],
			from: [],
			sender_address: NONE,
			reply_to: [],
			to: [],
			cc: [],
			bcc: [],
			depth: 0,
			mime_root_ct: "message/rfc822",
			size: $size,
			snippet: "",
			tags: [],
			spf: NONE,
			dkim: NONE,
			dmarc: NONE,
			blob_path: $blob_path,
			blob_sha: $content_hash,
			envelope_enc: NONE,
			kind: "inbound",
			recurrence: NONE,
			internal_date: <datetime>$internal_date,
			send_at: NONE,
			created_at: time::now(),
			ingest_status: $ingest_status,
			ingest_error: $ingest_error
		};
	"#;
	DB.query(sql)
		.bind(("email_id", email_id.to_string()))
		.bind(("message_id", message_id.to_string()))
		.bind(("content_hash", content_hash.to_string()))
		.bind(("subject", subject))
		.bind(("size", size_bytes as i64))
		.bind(("blob_path", blob_path.to_string()))
		.bind(("internal_date", internal_date_rfc3339.to_string()))
		.bind(("ingest_status", ingest_status.to_string()))
		.bind(("ingest_error", ingest_error.map(|v| v.to_string())))
		.await
		.map_err(|e| format!("persist inbound email failed: {e}"))?;
	Ok(())
}

pub async fn mark_inbound_email_ingest_failed(email_id: &str, error: &str) -> Result<(), String> {
	if !is_ready() {
		return Ok(());
	}
	let sql = r#"
		UPDATE type::thing("email", $email_id) SET
			ingest_status = "failed",
			ingest_error = $ingest_error;
	"#;
	DB.query(sql)
		.bind(("email_id", email_id.to_string()))
		.bind(("ingest_error", error.to_string()))
		.await
		.map_err(|e| format!("mark inbound ingest failed: {e}"))?;
	Ok(())
}

pub async fn persist_inbound_attachment_row(
	email_id: &str,
	part_id: &str,
	file_name: &str,
	content_type: &str,
	file_path: &str,
	size_bytes: usize,
	hash: &str,
) -> Result<(), String> {
	if !is_ready() {
		return Ok(());
	}
	let attachment_id = format!("{}:{}", email_id, part_id);
	let sql = r#"
		UPSERT type::thing("email_attachment", $attachment_id) CONTENT {
			email: type::thing("email", $email_id),
			part_id: $part_id,
			file_name: $file_name,
			content_type: $content_type,
			file_path: $file_path,
			size: $size,
			hash: $hash
		};
	"#;
	DB.query(sql)
		.bind(("attachment_id", attachment_id))
		.bind(("email_id", email_id.to_string()))
		.bind(("part_id", part_id.to_string()))
		.bind(("file_name", file_name.to_string()))
		.bind(("content_type", content_type.to_string()))
		.bind(("file_path", file_path.to_string()))
		.bind(("size", size_bytes as i64))
		.bind(("hash", hash.to_string()))
		.await
		.map_err(|e| format!("persist inbound attachment failed: {e}"))?;
	Ok(())
}

pub async fn next_mailbox_uid_modseq(mailbox_id: &str) -> Result<u64, String> {
	if !is_ready() {
		return Ok(1);
	}
	let sql = r#"
		SELECT math::max(uid) AS max
		FROM has_email_delivery
		WHERE out = type::thing("mailbox", $mailbox_id);
	"#;
	let mut response = DB
		.query(sql)
		.bind(("mailbox_id", mailbox_id.to_string()))
		.await
		.map_err(|e| format!("mailbox uid lookup failed: {e}"))?;
	let rows: Vec<CounterMaxRow> = response
		.take(0)
		.map_err(|e| format!("mailbox uid decode failed: {e}"))?;
	Ok(rows
		.into_iter()
		.next()
		.and_then(|r| r.max)
		.unwrap_or(0)
		.saturating_add(1))
}

pub async fn create_email_delivery(
	email_id: &str,
	mailbox_id: &str,
	uid: u64,
	modseq: u64,
	tags: &[String],
) -> Result<String, String> {
	if !is_ready() {
		return Ok(String::new());
	}
	let relation_id = format!("{email_id}:{mailbox_id}:{uid}");
	let sql = r#"
		RELATE type::thing("email", $email_id)->has_email_delivery->type::thing("mailbox", $mailbox_id)
		CONTENT {
			id: type::thing("has_email_delivery", $relation_id),
			uid: $uid,
			modseq: $modseq,
			flags: [],
			keywords: [],
			status: "open",
			assignee: NONE,
			tags: $tags,
			priority: 0,
			due_at: NONE,
			received_at: time::now()
		};
	"#;
	DB.query(sql)
		.bind(("email_id", email_id.to_string()))
		.bind(("mailbox_id", mailbox_id.to_string()))
		.bind(("relation_id", relation_id.clone()))
		.bind(("uid", uid as i64))
		.bind(("modseq", modseq as i64))
		.bind(("tags", tags.to_vec()))
		.await
		.map_err(|e| format!("create email delivery failed: {e}"))?;
	Ok(relation_id)
}

pub async fn tls_rpt_checkpoint_exists(domain: &str, report_date: &str) -> Result<bool, String> {
	if !is_ready() {
		return Ok(false);
	}
	let sql = r#"
		SELECT domain
		FROM tls_rpt_checkpoint
		WHERE domain = $domain
		  AND report_date = $report_date
		LIMIT 1;
	"#;
	let mut response = DB
		.query(sql)
		.bind(("domain", domain.to_ascii_lowercase()))
		.bind(("report_date", report_date.to_string()))
		.await
		.map_err(|e| format!("tls-rpt checkpoint lookup failed: {e}"))?;
	let rows: Vec<TlsRptCheckpointRow> = response
		.take(0)
		.map_err(|e| format!("tls-rpt checkpoint decode failed: {e}"))?;
	Ok(!rows.is_empty())
}

pub async fn record_tls_rpt_checkpoint(
	domain: &str,
	report_date: &str,
	sent_at_epoch_secs: u64,
	recipient_count: usize,
) -> Result<(), String> {
	if !is_ready() {
		return Ok(());
	}
	let id = format!("{}:{}", domain.to_ascii_lowercase(), report_date);
	let sql = r#"
		UPSERT type::thing("tls_rpt_checkpoint", $id) CONTENT {
			domain: $domain,
			report_date: $report_date,
			sent_at_epoch_secs: $sent_at_epoch_secs,
			recipient_count: $recipient_count
		};
	"#;
	DB.query(sql)
		.bind(("id", id))
		.bind(("domain", domain.to_ascii_lowercase()))
		.bind(("report_date", report_date.to_string()))
		.bind(("sent_at_epoch_secs", sent_at_epoch_secs))
		.bind(("recipient_count", recipient_count as i64))
		.await
		.map_err(|e| format!("record tls-rpt checkpoint failed: {e}"))?;
	Ok(())
}

pub async fn is_recipient_suppressed(address: &str) -> bool {
	if !is_ready() {
		return false;
	}
	let domain = address
		.rsplit_once('@')
		.map(|(_, d)| d.to_ascii_lowercase())
		.unwrap_or_default();
	let sql = r#"
		SELECT id
		FROM suppression
		WHERE is_active = true
		  AND (expires_at_epoch_secs = NONE OR expires_at_epoch_secs > $now)
		  AND (
				(scope = "address" AND target = $address)
				OR
				(scope = "domain" AND target = $domain)
		  )
		LIMIT 1;
	"#;
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs();
	let mut response = match DB
		.query(sql)
		.bind(("address", address.to_ascii_lowercase()))
		.bind(("domain", domain))
		.bind(("now", now))
		.await
	{
		Ok(r) => r,
		Err(_) => return false,
	};
	let rows: Vec<SuppressionRow> = match response.take(0) {
		Ok(rows) => rows,
		Err(_) => return false,
	};
	rows.iter().any(|r| r.id.is_some())
}

pub async fn upsert_suppression(scope: &str, target: &str, reason: &str) -> Result<(), String> {
	if !is_ready() {
		return Ok(());
	}

	let normalized_scope = scope.to_ascii_lowercase();
	let normalized_target = target.to_ascii_lowercase();

	let create_sql = r#"
		CREATE suppression SET
			scope = $scope,
			target = $target,
			reason = $reason,
			is_active = true,
			expires_at_epoch_secs = NONE;
	"#;

	match DB
		.query(create_sql)
		.bind(("scope", normalized_scope.clone()))
		.bind(("target", normalized_target.clone()))
		.bind(("reason", reason.to_string()))
		.await
	{
		Ok(_) => Ok(()),
		Err(create_err) => {
			let update_sql = r#"
				UPDATE suppression
				SET
					reason = $reason,
					is_active = true,
					expires_at_epoch_secs = NONE
				WHERE scope = $scope AND target = $target;
			"#;
			DB.query(update_sql)
				.bind(("scope", normalized_scope))
				.bind(("target", normalized_target))
				.bind(("reason", reason.to_string()))
				.await
				.map_err(|update_err| {
					format!(
						"upsert suppression failed (create: {create_err}; update: {update_err})"
					)
				})?;
			Ok(())
		}
	}
}

pub async fn consume_smtp_rate_limit(
	counter_key: &str,
	limit: u32,
	expires_at_epoch_secs: u64,
) -> Result<bool, String> {
	if !is_ready() {
		return Ok(true);
	}

	let create_sql = r#"
		CREATE type::thing("smtp_rate_limit", $counter_key) SET
			counter_key = $counter_key,
			count = 1,
			expires_at_epoch_secs = $expires_at_epoch_secs;
	"#;

	match DB
		.query(create_sql)
		.bind(("counter_key", counter_key.to_string()))
		.bind(("expires_at_epoch_secs", expires_at_epoch_secs))
		.await
	{
		Ok(_) => return Ok(true),
		Err(err) => {
			let msg = err.to_string().to_ascii_lowercase();
			let duplicate = msg.contains("already") || msg.contains("exist") || msg.contains("duplicate");
			if !duplicate {
				return Err(format!("create smtp rate-limit row failed: {err}"));
			}
		}
	}

	let increment_sql = r#"
		UPDATE type::thing("smtp_rate_limit", $counter_key) SET
			count += 1,
			expires_at_epoch_secs = $expires_at_epoch_secs
		WHERE count < $limit
		RETURN AFTER;
	"#;
	let mut response = DB
		.query(increment_sql)
		.bind(("counter_key", counter_key.to_string()))
		.bind(("limit", limit as u64))
		.bind(("expires_at_epoch_secs", expires_at_epoch_secs))
		.await
		.map_err(|e| format!("increment smtp rate-limit row failed: {e}"))?;
	let updated: Option<SmtpRateLimitCounterRow> = response
		.take(0)
		.map_err(|e| format!("decode smtp rate-limit increment failed: {e}"))?;
	if let Some(row) = updated {
		let _ = row.count;
		Ok(true)
	} else {
		Ok(false)
	}
}

pub async fn cleanup_expired_smtp_rate_limits(now_epoch_secs: u64) -> Result<(), String> {
	if !is_ready() {
		return Ok(());
	}
	let sql = r#"
		DELETE smtp_rate_limit
		WHERE expires_at_epoch_secs < $now;
	"#;
	DB.query(sql)
		.bind(("now", now_epoch_secs))
		.await
		.map_err(|e| format!("cleanup smtp rate-limits failed: {e}"))?;
	Ok(())
}

pub async fn cleanup_dead_outbound_jobs(now_epoch_secs: u64) -> Result<(), String> {
	if !is_ready() {
		return Ok(());
	}
	let sql = r#"
		DELETE outbound_queue
		WHERE status = "dead"
		  AND expires_at_epoch_secs < $now;
	"#;
	DB.query(sql)
		.bind(("now", now_epoch_secs))
		.await
		.map_err(|e| format!("cleanup dead outbound jobs failed: {e}"))?;
	Ok(())
}

pub async fn cleanup_outbound_deliveries_older_than(cutoff_epoch_secs: u64) -> Result<(), String> {
	if !is_ready() {
		return Ok(());
	}
	let sql = r#"
		DELETE outbound_delivery
		WHERE delivered_at_epoch_secs < $cutoff;
	"#;
	DB.query(sql)
		.bind(("cutoff", cutoff_epoch_secs))
		.await
		.map_err(|e| format!("cleanup outbound deliveries failed: {e}"))?;
	Ok(())
}

pub async fn cleanup_tls_rpt_checkpoints_older_than(cutoff_epoch_secs: u64) -> Result<(), String> {
	if !is_ready() {
		return Ok(());
	}
	let sql = r#"
		DELETE tls_rpt_checkpoint
		WHERE sent_at_epoch_secs < $cutoff;
	"#;
	DB.query(sql)
		.bind(("cutoff", cutoff_epoch_secs))
		.await
		.map_err(|e| format!("cleanup tls-rpt checkpoints failed: {e}"))?;
	Ok(())
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

pub fn extract_record_id(value: Value) -> Option<String> {
	if let Value::RecordId(record) = value {
		return Some(match record.key {
			RecordIdKey::String(key) => key,
			RecordIdKey::Number(key) => key.to_string(),
			RecordIdKey::Uuid(key) => key.to_string(),
			_ => return None,
		});
	}
	None
}
