mod dsn;
mod model;
mod worker;

use model::{QueuePayload, next_job_id, now_epoch_secs, payload_kind};
use worker::process_due_jobs;

use crate::{
	config::Config,
	db::{self, OutboundQueueInsert},
	protocols::smtp::{
		error::OutgoingError, handler::outgoing::OutgoingRequest, transaction::Transaction,
	},
};

pub use worker::run_worker;

pub async fn enqueue_outgoing_request(
	request: OutgoingRequest,
	config: &Config,
) -> Result<String, OutgoingError> {
	enqueue(
		QueuePayload::OutgoingRequest {
			from: request.from,
			to: request.to,
			subject: request.subject,
			text_body: request.text_body,
			html_body: request.html_body,
		},
		config,
	)
	.await
}

pub async fn enqueue_transaction(
	txn: &Transaction,
	config: &Config,
) -> Result<String, OutgoingError> {
	let mail_from = txn.mail_from.clone().ok_or(OutgoingError::InvalidSender)?;
	if txn.rcpt_to.is_empty() {
		return Err(OutgoingError::NoRecipients);
	}
	let data = txn
		.data
		.clone()
		.ok_or_else(|| OutgoingError::Build("empty DATA payload".into()))?;

	enqueue(
		QueuePayload::RelayTransaction {
			mail_from,
			rcpt_to: txn.rcpt_to.clone(),
			data,
		},
		config,
	)
	.await
}

pub async fn poll_once(config: &Config, worker_id: &str) -> Result<(), String> {
	process_due_jobs(config, worker_id).await
}

async fn enqueue(payload: QueuePayload, config: &Config) -> Result<String, OutgoingError> {
	let now = now_epoch_secs();
	let job_id = next_job_id(now);
	let payload_json = serde_json::to_string(&payload)
		.map_err(|e| OutgoingError::Relay(format!("queue payload serialization failed: {e}")))?;
	let row = OutboundQueueInsert {
		job_id: job_id.clone(),
		created_at_epoch_secs: now,
		expires_at_epoch_secs: now + config.smtp.outbound_queue.ttl_secs,
		next_attempt_at_epoch_secs: now,
		attempts: 0,
		status: "queued".to_string(),
		payload_kind: payload_kind(&payload).to_string(),
		payload_json,
	};
	db::enqueue_outbound_job(&row)
		.await
		.map_err(OutgoingError::Relay)?;
	Ok(job_id)
}
