mod bounce;
mod dsn;
mod model;
mod worker;

use sha2::{Digest, Sha256};
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
	if let Some(shared_address) = request.shared_inbox.as_deref() {
		let Some(actor) = request.actor_account.as_deref() else {
			return Err(OutgoingError::Build(
				"shared inbox send-as requires actor_account".to_string(),
			));
		};
		let allowed = db::can_send_as_shared_inbox(shared_address, actor)
			.await
			.map_err(OutgoingError::Relay)?;
		if !allowed {
			return Err(OutgoingError::Build(
				"shared inbox send-as denied: actor not allowed".to_string(),
			));
		}
	}

	enqueue(
		QueuePayload::OutgoingRequest {
			from: request.from,
			to: request.to,
			subject: request.subject,
			text_body: request.text_body,
			html_body: request.html_body,
			idempotency_key: request.idempotency_key,
		},
		request.actor_account,
		request.shared_inbox,
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
		None,
		None,
		config,
	)
	.await
}

pub async fn poll_once(config: &Config, worker_id: &str) -> Result<(), String> {
	process_due_jobs(config, worker_id).await
}

async fn enqueue(
	payload: QueuePayload,
	actor_account: Option<String>,
	shared_inbox: Option<String>,
	config: &Config,
) -> Result<String, OutgoingError> {
	let now = now_epoch_secs();
	let job_id = next_job_id(now);
	let sender_domain = payload_sender_domain(&payload)
		.ok_or_else(|| OutgoingError::Build("invalid sender address".into()))?;
	let domain_settings = db::domain_settings(&sender_domain).await;
	let org_id = domain_settings
		.as_ref()
		.and_then(|settings| settings.org_id.clone());
	enforce_tenant_quota(domain_settings.as_ref(), org_id.as_deref(), &payload, now).await?;

	let idempotency_key = payload_idempotency_key(&payload)?;
	if let Some(existing_id) = db::find_active_outbound_job_by_idempotency_key(&idempotency_key)
		.await
		.map_err(OutgoingError::Relay)?
	{
		return Ok(existing_id);
	}

	let payload_json = serde_json::to_string(&payload)
		.map_err(|e| OutgoingError::Relay(format!("queue payload serialization failed: {e}")))?;
	let row = OutboundQueueInsert {
		job_id: job_id.clone(),
		created_at_epoch_secs: now,
		expires_at_epoch_secs: now + config.smtp.outbound_queue.ttl_secs,
		next_attempt_at_epoch_secs: now,
		attempts: 0,
		status: "queued".to_string(),
		org_id,
		idempotency_key: Some(idempotency_key.clone()),
		actor_account,
		shared_inbox,
		payload_kind: payload_kind(&payload).to_string(),
		payload_json,
	};
	match db::enqueue_outbound_job(&row).await {
		Ok(()) => {}
		Err(err) => {
			let lower = err.to_ascii_lowercase();
			let duplicate = lower.contains("duplicate") || lower.contains("exist") || lower.contains("already");
			if duplicate
				&& let Some(existing_id) =
					db::find_active_outbound_job_by_idempotency_key(&idempotency_key)
						.await
						.map_err(OutgoingError::Relay)?
			{
				return Ok(existing_id);
			}
			return Err(OutgoingError::Relay(err));
		}
	}
	Ok(job_id)
}

fn payload_sender_domain(payload: &QueuePayload) -> Option<String> {
	let sender = match payload {
		QueuePayload::OutgoingRequest { from, .. } => from.as_str(),
		QueuePayload::RelayTransaction { mail_from, .. } => mail_from.as_str(),
	};
	sender.rsplit_once('@').map(|(_, domain)| domain.to_ascii_lowercase())
}

fn payload_recipients_len(payload: &QueuePayload) -> usize {
	match payload {
		QueuePayload::OutgoingRequest { to, .. } => to.len(),
		QueuePayload::RelayTransaction { rcpt_to, .. } => rcpt_to.len(),
	}
}

fn payload_idempotency_key(payload: &QueuePayload) -> Result<String, OutgoingError> {
	match payload {
		QueuePayload::OutgoingRequest {
			idempotency_key: Some(key),
			..
		} => Ok(format!("api:{}", key.trim().to_ascii_lowercase())),
		QueuePayload::OutgoingRequest { .. } => {
			let nonce = next_job_id(now_epoch_secs());
			Ok(format!("api-auto:{nonce}"))
		}
		QueuePayload::RelayTransaction { .. } => {
			let bytes = serde_json::to_vec(payload)
				.map_err(|e| OutgoingError::Build(format!("idempotency payload encode failed: {e}")))?;
			let digest = Sha256::digest(bytes);
			Ok(format!("smtp:{:x}", digest))
		}
	}
}

async fn enforce_tenant_quota(
	domain_settings: Option<&db::DomainSettings>,
	org_id: Option<&str>,
	payload: &QueuePayload,
	now_epoch_secs: u64,
) -> Result<(), OutgoingError> {
	let Some(settings) = domain_settings else {
		return Ok(());
	};
	let Some(quota) = settings.quota.as_ref() else {
		return Ok(());
	};

	let recipients_len = payload_recipients_len(payload) as u32;
	if let Some(max_recipients) = quota.max_recipients_per_message
		&& recipients_len > max_recipients
	{
		return Err(OutgoingError::QuotaExceeded(format!(
			"recipient count {recipients_len} exceeds max {max_recipients}"
		)));
	}

	let Some(org_id) = org_id else {
		return Ok(());
	};

	if let Some(max_queued) = quota.max_queued_jobs {
		let queued = db::count_queued_outbound_jobs_for_org(org_id)
			.await
			.map_err(OutgoingError::Relay)?;
		if queued >= max_queued as u64 {
			return Err(OutgoingError::QuotaExceeded(format!(
				"queued jobs {queued} exceed max {max_queued}"
			)));
		}
	}

	if let Some(hourly_limit) = quota.hourly_send_limit {
		let since = now_epoch_secs.saturating_sub(3600);
		let sent = db::count_outbound_deliveries_since(org_id, since)
			.await
			.map_err(OutgoingError::Relay)?;
		if sent >= hourly_limit as u64 {
			return Err(OutgoingError::QuotaExceeded(format!(
				"hourly send limit reached ({hourly_limit})"
			)));
		}
	}

	if let Some(daily_limit) = quota.daily_send_limit {
		let since = now_epoch_secs.saturating_sub(86_400);
		let sent = db::count_outbound_deliveries_since(org_id, since)
			.await
			.map_err(OutgoingError::Relay)?;
		if sent >= daily_limit as u64 {
			return Err(OutgoingError::QuotaExceeded(format!(
				"daily send limit reached ({daily_limit})"
			)));
		}
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::{QueuePayload, payload_idempotency_key};

	#[test]
	fn relay_payload_idempotency_is_deterministic() {
		let payload = QueuePayload::RelayTransaction {
			mail_from: "a@example.com".into(),
			rcpt_to: vec!["b@example.net".into()],
			data: b"hello".to_vec(),
		};
		let a = payload_idempotency_key(&payload).expect("idempotency key");
		let b = payload_idempotency_key(&payload).expect("idempotency key");
		assert_eq!(a, b);
	}

	#[test]
	fn api_idempotency_uses_client_key() {
		let payload = QueuePayload::OutgoingRequest {
			from: "a@example.com".into(),
			to: vec!["b@example.net".into()],
			subject: "s".into(),
			text_body: None,
			html_body: None,
			idempotency_key: Some("ABC-123".into()),
		};
		let key = payload_idempotency_key(&payload).expect("idempotency key");
		assert_eq!(key, "api:abc-123");
	}
}
