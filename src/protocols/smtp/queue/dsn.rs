use std::path::PathBuf;

use mail_builder::MessageBuilder;

use super::model::{QueueJob, QueuePayload};

pub async fn write_failure_dsn(job: &QueueJob, reason: &str) -> Result<(), String> {
	let (from, to) = dsn_participants(job);
	if to.is_empty() || from.is_empty() {
		return Ok(());
	}

	let body = format!(
		concat!(
			"Delivery has failed.\n",
			"Queue-ID: {}\n",
			"Reason: {}\n",
			"Attempts: {}\n",
			"Created-At: {}\n"
		),
		job.id, reason, job.attempts, job.created_at_epoch_secs
	);
	let dsn = MessageBuilder::new()
		.from(from)
		.to(to)
		.subject(format!("Undeliverable: {}", job.id))
		.text_body(body)
		.write_to_vec()
		.map_err(|e| format!("build dsn failed: {e}"))?;

	let dsn_dir = PathBuf::from("data/bounces");
	tokio::fs::create_dir_all(&dsn_dir)
		.await
		.map_err(|e| format!("create dsn dir failed: {e}"))?;
	let file = dsn_dir.join(format!("{}.eml", job.id));
	tokio::fs::write(file, dsn)
		.await
		.map_err(|e| format!("write dsn failed: {e}"))?;
	Ok(())
}

fn dsn_participants(job: &QueueJob) -> (String, String) {
	match &job.payload {
		QueuePayload::OutgoingRequest { from, .. } => (
			format!("MAILER-DAEMON@{}", extract_domain_or_default(from)),
			from.clone(),
		),
		QueuePayload::RelayTransaction { mail_from, .. } => (
			format!("MAILER-DAEMON@{}", extract_domain_or_default(mail_from)),
			mail_from.clone(),
		),
	}
}

fn extract_domain_or_default(address: &str) -> String {
	address
		.rsplit_once('@')
		.map(|(_, domain)| domain.to_string())
		.unwrap_or_else(|| "localhost".to_string())
}
