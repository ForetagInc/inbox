use tokio::time::Duration;
use tracing::{Level, error, event, instrument, warn};

use super::{
	bounce::{classify_bounce, suppression_scopes},
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
	let mut last_cleanup = 0u64;

	loop {
		let now = now_epoch_secs();
		if let Err(err) = process_due_jobs(&config, &worker_id).await {
			error!("Outbound queue processing error: {err}");
		}
		if now.saturating_sub(last_cleanup) >= config.smtp.outbound_queue.cleanup_interval_secs.max(1)
		{
			if let Err(err) = run_cleanup(&config, now).await {
				error!("Outbound queue cleanup error: {err}");
			}
			last_cleanup = now;
		}
		tokio::time::sleep(interval).await;
	}
}

#[instrument(skip_all, fields(worker_id = %worker_id))]
pub async fn process_due_jobs(config: &Config, worker_id: &str) -> Result<(), String> {
	let now = now_epoch_secs();
	let lease_until = now.saturating_add(config.smtp.outbound_queue.lease_secs.max(1));
	let due_ids = db::list_due_outbound_job_ids(now, config.smtp.outbound_queue.batch_size).await?;
	let mut metrics = PollMetrics::default();

	for job_id in due_ids {
		let Some(row) = db::claim_outbound_job(&job_id, worker_id, now, lease_until).await? else {
			continue;
		};
		metrics.claimed += 1;
		let job = to_queue_job(row)?;
		let result = process_claimed_job(job, config, now).await;
		metrics.absorb(result);
	}

	let _ = metrics;

	Ok(())
}

async fn process_claimed_job(job: QueueJob, config: &Config, now: u64) -> PollResult {
	if matches!(db::outbound_delivery_exists(&job.id).await, Ok(true)) {
		let _ = db::mark_outbound_job_done(&job.id).await;
		return PollResult::Duplicate;
	}

	if now >= job.expires_at_epoch_secs {
		warn!("Queue job {} expired", job.id);
		let _ = dsn::write_failure_dsn(&job, "message expired in outbound queue").await;
		let _ = db::dead_letter_outbound_job(&job.id, "expired").await;
		let suppressed = apply_bounce_suppressions(&job, "message expired in outbound queue").await;
		return PollResult::Expired { suppressed };
	}

	match deliver_job(&job, config).await {
		Ok(()) => {
			let _ = db::record_outbound_delivery(
				&job.id,
				job.org_id.as_deref(),
				job.actor_account.as_deref(),
				job.shared_inbox.as_deref(),
				now,
			)
			.await;
			if let (Some(shared_address), Some(actor)) =
				(job.shared_inbox.as_deref(), job.actor_account.as_deref())
				&& let Ok(Some(shared)) = db::find_shared_inbox_by_address(shared_address).await
				&& let Some(shared_id) = shared.id.and_then(db::extract_record_id)
			{
				let _ = db::record_shared_inbox_event(&shared_id, actor, "send_as", None).await;
				event!(
					target: "smtp.shared_inbox.send_as",
					Level::INFO,
					shared_address = shared_address,
					actor = actor
				);
			}
			let _ = db::mark_outbound_job_done(&job.id).await;
			event!(
				target: "smtp.egress.queue",
				Level::INFO,
				action = "deliver",
				outcome = "success",
				job_id = %job.id
			);
			PollResult::Delivered
		}
		Err(err)
			if is_retryable(&err) && job.attempts + 1 < config.smtp.outbound_queue.max_attempts =>
		{
			let attempts = job.attempts + 1;
			let next_attempt = now.saturating_add(retry_delay_secs(attempts, config));
			let _ = db::retry_outbound_job(&job.id, attempts, next_attempt, &err.to_string()).await;
			event!(
				target: "smtp.egress.queue",
				Level::WARN,
				action = "deliver",
				outcome = "retry",
				job_id = %job.id,
				attempts = attempts
			);
			PollResult::Retried
		}
		Err(err) => {
			warn!(
				"Queue job {} failed permanently (lease_owner={:?}, lease_until={:?}, last_error={:?}): {}",
				job.id, job.lease_owner, job.lease_until_epoch_secs, job.last_error, err
			);
			let _ = dsn::write_failure_dsn(&job, &err.to_string()).await;
			let _ = db::dead_letter_outbound_job(&job.id, &err.to_string()).await;
			let suppressed = apply_bounce_suppressions(&job, &err.to_string()).await;
			event!(
				target: "smtp.egress.queue",
				Level::ERROR,
				action = "deliver",
				outcome = "dead_letter",
				job_id = %job.id,
				suppressed = suppressed
			);
			PollResult::Dead { suppressed }
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
			idempotency_key,
		} => {
			send_outgoing(
				OutgoingRequest {
					from: from.clone(),
					to: to.clone(),
					subject: subject.clone(),
					text_body: text_body.clone(),
					html_body: html_body.clone(),
					idempotency_key: idempotency_key.clone(),
					actor_account: job.actor_account.clone(),
					shared_inbox: job.shared_inbox.clone(),
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

#[derive(Debug, Default)]
struct PollMetrics {
	claimed: usize,
	delivered: usize,
	retried: usize,
	dead: usize,
	expired: usize,
	duplicate: usize,
	suppressed: usize,
}

impl PollMetrics {
	fn absorb(&mut self, result: PollResult) {
		match result {
			PollResult::Delivered => self.delivered += 1,
			PollResult::Retried => self.retried += 1,
			PollResult::Dead { suppressed } => {
				self.dead += 1;
				self.suppressed += suppressed;
			}
			PollResult::Expired { suppressed } => {
				self.expired += 1;
				self.suppressed += suppressed;
			}
			PollResult::Duplicate => self.duplicate += 1,
		}
	}
}

#[derive(Debug, Clone, Copy)]
enum PollResult {
	Delivered,
	Retried,
	Dead { suppressed: usize },
	Expired { suppressed: usize },
	Duplicate,
}

async fn apply_bounce_suppressions(job: &QueueJob, reason: &str) -> usize {
	let mut applied = 0usize;
	let category = classify_bounce(reason);
	let (scope, include_domain) = suppression_scopes(category);
	if scope == "none" {
		return 0;
	}
	for rcpt in job_recipients(job) {
		if db::upsert_suppression(scope, &rcpt, reason).await.is_ok() {
			applied += 1;
		}
		if include_domain
			&& let Some((_, domain)) = rcpt.rsplit_once('@')
			&& db::upsert_suppression("domain", domain, reason).await.is_ok()
		{
			applied += 1;
		}
	}
	applied
}

fn job_recipients(job: &QueueJob) -> Vec<String> {
	match &job.payload {
		QueuePayload::OutgoingRequest { to, .. } => to.clone(),
		QueuePayload::RelayTransaction { rcpt_to, .. } => rcpt_to.clone(),
	}
}

async fn run_cleanup(config: &Config, now_epoch_secs: u64) -> Result<(), String> {
	db::cleanup_expired_smtp_rate_limits(now_epoch_secs).await?;
	let dead_cutoff = now_epoch_secs.saturating_sub(config.smtp.outbound_queue.dead_job_retention_secs);
	db::cleanup_dead_outbound_jobs(dead_cutoff).await?;
	let delivery_cutoff =
		now_epoch_secs.saturating_sub(config.smtp.outbound_queue.delivery_retention_secs);
	db::cleanup_outbound_deliveries_older_than(delivery_cutoff).await
}
