use tokio::time::Duration;
use tracing::{error, info, warn};

use super::{
	dsn,
	model::{QueueJob, QueuePayload, now_epoch_secs, to_queue_job},
};
use crate::{
	config::Config,
	db,
	protocols::smtp::{
		error::OutgoingError,
		handler::outgoing::{OutgoingRequest, relay_transaction, send_outgoing},
		transaction::Transaction,
	},
};

pub async fn run_worker(config: Config) {
	let worker_id = format!(
		"smtp-worker-{}-{}",
		config.server.hostname,
		std::process::id()
	);
	let interval = Duration::from_secs(config.smtp.outbound_queue.poll_interval_secs.max(1));
	info!(
		"Outbound queue worker started (id={}, poll={}s)",
		worker_id, config.smtp.outbound_queue.poll_interval_secs
	);

	loop {
		if let Err(err) = process_due_jobs(&config, &worker_id).await {
			error!("Outbound queue processing error: {err}");
		}
		tokio::time::sleep(interval).await;
	}
}

pub async fn process_due_jobs(config: &Config, worker_id: &str) -> Result<(), String> {
	let now = now_epoch_secs();
	let lease_until = now.saturating_add(config.smtp.outbound_queue.lease_secs.max(1));
	let due_ids = db::list_due_outbound_job_ids(now, config.smtp.outbound_queue.batch_size).await?;

	for job_id in due_ids {
		let Some(row) = db::claim_outbound_job(&job_id, worker_id, now, lease_until).await? else {
			continue;
		};
		let job = to_queue_job(row)?;
		process_claimed_job(job, config, now).await;
	}

	Ok(())
}

async fn process_claimed_job(job: QueueJob, config: &Config, now: u64) {
	if matches!(db::outbound_delivery_exists(&job.id).await, Ok(true)) {
		let _ = db::mark_outbound_job_done(&job.id).await;
		return;
	}

	if now >= job.expires_at_epoch_secs {
		warn!("Queue job {} expired", job.id);
		let _ = dsn::write_failure_dsn(&job, "message expired in outbound queue").await;
		let _ = db::dead_letter_outbound_job(&job.id, "expired").await;
		return;
	}

	match deliver_job(&job, config).await {
		Ok(()) => {
			let _ = db::record_outbound_delivery(&job.id, now).await;
			let _ = db::mark_outbound_job_done(&job.id).await;
		}
		Err(err)
			if is_retryable(&err) && job.attempts + 1 < config.smtp.outbound_queue.max_attempts =>
		{
			let attempts = job.attempts + 1;
			let next_attempt = now.saturating_add(retry_delay_secs(attempts, config));
			let _ = db::retry_outbound_job(&job.id, attempts, next_attempt, &err.to_string()).await;
		}
		Err(err) => {
			warn!(
				"Queue job {} failed permanently (lease_owner={:?}, lease_until={:?}, last_error={:?}): {}",
				job.id, job.lease_owner, job.lease_until_epoch_secs, job.last_error, err
			);
			let _ = dsn::write_failure_dsn(&job, &err.to_string()).await;
			let _ = db::dead_letter_outbound_job(&job.id, &err.to_string()).await;
		}
	}
}

async fn deliver_job(job: &QueueJob, config: &Config) -> Result<(), OutgoingError> {
	match &job.payload {
		QueuePayload::OutgoingRequest {
			from,
			to,
			subject,
			text_body,
			html_body,
		} => {
			send_outgoing(
				OutgoingRequest {
					from: from.clone(),
					to: to.clone(),
					subject: subject.clone(),
					text_body: text_body.clone(),
					html_body: html_body.clone(),
				},
				config,
			)
			.await
		}
		QueuePayload::RelayTransaction {
			mail_from,
			rcpt_to,
			data,
		} => {
			let txn = Transaction {
				mail_from: Some(mail_from.clone()),
				rcpt_to: rcpt_to.clone(),
				data: Some(data.clone()),
			};
			relay_transaction(&txn, config).await
		}
	}
}

fn is_retryable(err: &OutgoingError) -> bool {
	matches!(err, OutgoingError::Relay(_))
}

fn retry_delay_secs(attempt: u32, config: &Config) -> u64 {
	let base = config.smtp.outbound_queue.retry_base_delay_secs.max(1);
	let max = config.smtp.outbound_queue.retry_max_delay_secs.max(base);
	let growth = 1u64
		.checked_shl((attempt.min(20) - 1) as u32)
		.unwrap_or(u64::MAX);
	base.saturating_mul(growth).min(max)
}
