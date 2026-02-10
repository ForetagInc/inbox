use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::db::OutboundQueueRow;

static JOB_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QueuePayload {
	OutgoingRequest {
		from: String,
		to: Vec<String>,
		subject: String,
		text_body: Option<String>,
		html_body: Option<String>,
		idempotency_key: Option<String>,
	},
	RelayTransaction {
		mail_from: String,
		rcpt_to: Vec<String>,
		data: Vec<u8>,
	},
}

#[derive(Debug, Clone)]
pub struct QueueJob {
	pub id: String,
	pub org_id: Option<String>,
	pub actor_account: Option<String>,
	pub shared_inbox: Option<String>,
	pub created_at_epoch_secs: u64,
	pub expires_at_epoch_secs: u64,
	pub attempts: u32,
	pub lease_owner: Option<String>,
	pub lease_until_epoch_secs: Option<u64>,
	pub last_error: Option<String>,
	pub payload: QueuePayload,
}

pub fn to_queue_job(row: OutboundQueueRow) -> Result<QueueJob, String> {
	let payload: QueuePayload = serde_json::from_str(&row.payload_json)
		.map_err(|e| format!("queue payload parse failed for {}: {e}", row.job_id))?;
	Ok(QueueJob {
		id: row.job_id,
		org_id: row.org_id,
		actor_account: row.actor_account,
		shared_inbox: row.shared_inbox,
		created_at_epoch_secs: row.created_at_epoch_secs,
		expires_at_epoch_secs: row.expires_at_epoch_secs,
		attempts: row.attempts,
		lease_owner: row.lease_owner,
		lease_until_epoch_secs: row.lease_until_epoch_secs,
		last_error: row.last_error,
		payload,
	})
}

pub fn payload_kind(payload: &QueuePayload) -> &'static str {
	match payload {
		QueuePayload::OutgoingRequest { .. } => "outgoing_request",
		QueuePayload::RelayTransaction { .. } => "relay_transaction",
	}
}

pub fn now_epoch_secs() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}

pub fn next_job_id(now_epoch_secs: u64) -> String {
	let n = JOB_COUNTER.fetch_add(1, Ordering::Relaxed);
	format!("q{now_epoch_secs}-{n}")
}
