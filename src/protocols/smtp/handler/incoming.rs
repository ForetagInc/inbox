use std::net::IpAddr;

use chrono::Utc;
use mail_auth::{
	AuthenticatedMessage, DkimResult, DmarcResult, MessageAuthenticator, SpfResult,
	dmarc::verify::DmarcParameters, spf::verify::SpfParameters,
};
use mail_parser::MimeHeaders;
use sha2::{Digest, Sha256};
use tracing::{Level, event};

use crate::{
	config::Config,
	db::{self, TenantEncryptionMode},
	protocols::smtp::error::IncomingError,
	storage::{self, EncryptionMode, StoragePolicy},
};

#[derive(Debug, Clone)]
pub struct MailAuthVerdict {
	pub spf: SpfResult,
	pub dkim: DkimResult,
	pub dmarc: DmarcResult,
}

impl MailAuthVerdict {
	pub fn accepted(&self, policy: &crate::config::MailAuthConfig) -> bool {
		let spf_ok = !policy.require_spf_pass || self.spf == SpfResult::Pass;
		let dkim_ok = !policy.require_dkim_pass || self.dkim == DkimResult::Pass;
		let dmarc_ok = !policy.require_dmarc_pass || self.dmarc == DmarcResult::Pass;
		spf_ok && dkim_ok && dmarc_ok
	}
}

pub async fn verify_mail(
	ip: IpAddr,
	helo_domain: &str,
	host_domain: &str,
	sender: &str,
	message: &[u8],
	allow_header_override: bool,
) -> Result<MailAuthVerdict, IncomingError> {
	if allow_header_override && let Some(verdict) = parse_test_auth_header(message) {
		return Ok(verdict);
	}

	let authenticator = MessageAuthenticator::new_cloudflare_tls()
		.map_err(|e| IncomingError::Auth(format!("resolver init failed: {e}")))?;

	let authenticated_message = AuthenticatedMessage::parse(message).ok_or(IncomingError::Parse)?;

	let dkim_output = authenticator.verify_dkim(&authenticated_message).await;
	let spf_output = authenticator
		.verify_spf(SpfParameters::verify_mail_from(
			ip,
			helo_domain,
			host_domain,
			sender,
		))
		.await;

	let sender_domain = extract_header_from_domain(&authenticated_message)
		.or_else(|| extract_domain(sender).map(str::to_string))
		.ok_or_else(|| IncomingError::Auth("unable to determine sender domain".to_string()))?;

	let dmarc_output = authenticator
		.verify_dmarc(
			DmarcParameters::new(
				&authenticated_message,
				&dkim_output,
				&sender_domain,
				&spf_output,
			)
			.with_domain_suffix_fn(|domain| psl::domain_str(domain).unwrap_or(domain)),
		)
		.await;

	Ok(MailAuthVerdict {
		spf: spf_output.result(),
		dkim: dkim_result(&dkim_output),
		dmarc: dmarc_result(&dmarc_output),
	})
}

pub async fn persist_incoming_message(
	message: &[u8],
	parsed: &mail_parser::Message<'_>,
	recipients: &[String],
) -> Result<Vec<String>, IncomingError> {
	let content_hash = format!("{:x}", Sha256::digest(message));
	let message_id = storage::sanitize_path_component(
		parsed
			.message_id()
			.filter(|v| !v.trim().is_empty())
			.unwrap_or(content_hash.as_str()),
	);
	let email_id = message_id.clone();
	let internal_date = Utc::now().to_rfc3339();
	let _ = db::persist_inbound_email_row(
		&email_id,
		&message_id,
		&content_hash,
		message.len(),
		"",
		&internal_date,
		None,
		"pending",
		None,
	)
	.await;

	let mut stored = Vec::new();
	let mut canonical_blob_path: Option<String> = None;
	let mut attachment_meta: Vec<AttachmentMeta> = Vec::new();
	let mut delivery_intents: Vec<DeliveryIntent> = Vec::new();
	let mut attachment_meta_recorded = false;

	for recipient in recipients {
		let Some(route) = resolve_recipient_route(recipient).await else {
			continue;
		};

		let policy = storage_policy_for_recipient(
			route.storage_mailbox.as_str(),
			route.domain.as_str(),
			route.domain_settings.as_ref(),
		);

		let msg_key = match storage::put_raw_message(&policy, &message_id, message).await {
			Ok(k) => k,
			Err(err) => {
				let _ = db::mark_inbound_email_ingest_failed(&email_id, &err.to_string()).await;
				return Err(err);
			}
		};
		if canonical_blob_path.is_none() {
			canonical_blob_path = Some(msg_key.clone());
		}
		stored.push(msg_key);

		// E2EE tenants are metadata-only server-side: no parsed body indexing blobs.
		let mut delivery_tags = Vec::new();
		if let Some(tag) = route.plus_tag.clone() {
			delivery_tags.push(format!("plus:{tag}"));
		}
		delivery_intents.push(DeliveryIntent {
			mailbox_id: route.mailbox_id.clone(),
			tags: delivery_tags,
			plus_applied: route.plus_tag.is_some(),
			domain: route.domain.clone(),
			base_local: route.base_local.clone(),
		});

		if policy.mode != EncryptionMode::E2ee {
			for (idx, part) in parsed.attachments().enumerate() {
				let content_type = part.content_type().map(|ct| {
					format!(
						"{}/{}",
						ct.c_type,
						ct.c_subtype.as_deref().unwrap_or("octet-stream")
					)
				});
				let part_id = format!("p{idx}");
				let key = match storage::put_attachment(
					&policy,
					&message_id,
					&part_id,
					content_type.as_deref(),
					part.contents(),
				)
				.await
				{
					Ok(k) => k,
					Err(err) => {
						let _ = db::mark_inbound_email_ingest_failed(&email_id, &err.to_string()).await;
						return Err(err);
					}
				};
				if !attachment_meta_recorded {
					attachment_meta.push(AttachmentMeta {
						part_id: part_id.clone(),
						file_name: part.attachment_name().unwrap_or("attachment").to_string(),
						content_type: content_type
							.unwrap_or_else(|| "application/octet-stream".to_string()),
						file_path: key,
						size_bytes: part.contents().len(),
						hash: format!("{:x}", Sha256::digest(part.contents())),
					});
				}
			}
			attachment_meta_recorded = true;
		}

		if policy.mode != EncryptionMode::E2ee && storage::store_parsed_parts() {
			for (idx, part) in parsed.text_bodies().enumerate() {
				let mime_path = format!("text/{idx}");
				if let Err(err) = storage::put_part_blob(
					&policy,
					&message_id,
					&mime_path,
					Some("text/plain; charset=utf-8"),
					part.contents(),
				)
				.await
				{
					let _ = db::mark_inbound_email_ingest_failed(&email_id, &err.to_string()).await;
					return Err(err);
				}
			}

			for (idx, part) in parsed.html_bodies().enumerate() {
				let mime_path = format!("html/{idx}");
				if let Err(err) = storage::put_part_blob(
					&policy,
					&message_id,
					&mime_path,
					Some("text/html; charset=utf-8"),
					part.contents(),
				)
				.await
				{
					let _ = db::mark_inbound_email_ingest_failed(&email_id, &err.to_string()).await;
					return Err(err);
				}
			}
		}
	}

	if stored.is_empty() {
		let err = "no valid recipient mailbox/domain to store message".to_string();
		let _ = db::mark_inbound_email_ingest_failed(&email_id, &err).await;
		return Err(IncomingError::Storage(
			err,
		));
	}

	if let Err(err) = db::persist_inbound_email_row(
		&email_id,
		&message_id,
		&content_hash,
		message.len(),
		canonical_blob_path.as_deref().unwrap_or_default(),
		&internal_date,
		None,
		"committed",
		None,
	)
	.await
	{
		let _ = db::mark_inbound_email_ingest_failed(&email_id, &err).await;
		return Err(IncomingError::Storage(err));
	}
	for meta in attachment_meta {
		if let Err(err) = db::persist_inbound_attachment_row(
			&email_id,
			&meta.part_id,
			&meta.file_name,
			&meta.content_type,
			&meta.file_path,
			meta.size_bytes,
			&meta.hash,
		)
		.await
		{
			let _ = db::mark_inbound_email_ingest_failed(&email_id, &err).await;
			return Err(IncomingError::Storage(err));
		}
	}
	for intent in delivery_intents {
		let uid = match db::next_mailbox_uid_modseq(&intent.mailbox_id).await {
			Ok(uid) => uid,
			Err(err) => {
				let _ = db::mark_inbound_email_ingest_failed(&email_id, &err).await;
				return Err(IncomingError::Storage(err));
			}
		};
		if let Err(err) = db::create_email_delivery(&email_id, &intent.mailbox_id, uid, uid, &intent.tags).await {
			let _ = db::mark_inbound_email_ingest_failed(&email_id, &err).await;
			return Err(IncomingError::Storage(err));
		}
		if intent.plus_applied {
			event!(
				target: "smtp.plus_addressing.applied",
				Level::INFO,
				domain = %intent.domain,
				base_local = %intent.base_local,
				tag_present = true
			);
		}
	}

	Ok(stored)
}

#[derive(Debug, Clone)]
struct RecipientRoute {
	domain: String,
	base_local: String,
	mailbox_id: String,
	storage_mailbox: String,
	plus_tag: Option<String>,
	domain_settings: Option<db::DomainSettings>,
}

#[derive(Debug, Clone)]
struct AttachmentMeta {
	part_id: String,
	file_name: String,
	content_type: String,
	file_path: String,
	size_bytes: usize,
	hash: String,
}

#[derive(Debug, Clone)]
struct DeliveryIntent {
	mailbox_id: String,
	tags: Vec<String>,
	plus_applied: bool,
	domain: String,
	base_local: String,
}

fn extract_header_from_domain(message: &AuthenticatedMessage<'_>) -> Option<String> {
	message
		.from
		.first()
		.and_then(|address| extract_domain(address))
		.map(str::to_string)
}

fn extract_domain(address: &str) -> Option<&str> {
	let (_, domain) = address.trim().rsplit_once('@')?;
	if domain.is_empty() {
		return None;
	}
	Some(domain)
}

fn dkim_result(outputs: &[mail_auth::DkimOutput<'_>]) -> DkimResult {
	if outputs.iter().any(|o| o.result() == &DkimResult::Pass) {
		return DkimResult::Pass;
	}
	outputs
		.first()
		.map(|o| o.result().clone())
		.unwrap_or(DkimResult::None)
}

fn dmarc_result(output: &mail_auth::DmarcOutput) -> DmarcResult {
	match (output.spf_result(), output.dkim_result()) {
		(DmarcResult::Pass, _) | (_, DmarcResult::Pass) => DmarcResult::Pass,
		(DmarcResult::TempError(err), _) | (_, DmarcResult::TempError(err)) => {
			DmarcResult::TempError(err.clone())
		}
		(DmarcResult::PermError(err), _) | (_, DmarcResult::PermError(err)) => {
			DmarcResult::PermError(err.clone())
		}
		(DmarcResult::Fail(err), _) | (_, DmarcResult::Fail(err)) => DmarcResult::Fail(err.clone()),
		_ => DmarcResult::None,
	}
}

pub async fn accepted_for_recipients(
	config: &Config,
	recipients: &[String],
	verdict: &MailAuthVerdict,
) -> bool {
	let mut matched_domain = false;
	for recipient in recipients {
		let Some(domain) = extract_domain(recipient) else {
			continue;
		};
		let overrides = db::domain_settings(domain)
			.await
			.and_then(|settings| settings.auth);
		let policy = config.merged_auth_policy(overrides.as_ref());
		if !verdict.accepted(&policy) {
			return false;
		}
		matched_domain = true;
	}

	if !matched_domain {
		return verdict.accepted(&config.auth);
	}

	true
}

fn parse_test_auth_header(raw: &[u8]) -> Option<MailAuthVerdict> {
	let text = String::from_utf8_lossy(raw);
	let line = text
		.lines()
		.find(|l| l.to_ascii_lowercase().starts_with("x-inbox-test-auth:"))?;
	let value = line.split_once(':')?.1.trim().to_ascii_lowercase();

	let spf = if value.contains("spf=pass") {
		SpfResult::Pass
	} else {
		SpfResult::Fail
	};
	let dkim = if value.contains("dkim=pass") {
		DkimResult::Pass
	} else {
		DkimResult::Fail(mail_auth::Error::ParseError)
	};
	let dmarc = if value.contains("dmarc=pass") {
		DmarcResult::Pass
	} else {
		DmarcResult::Fail(mail_auth::Error::ParseError)
	};

	Some(MailAuthVerdict { spf, dkim, dmarc })
}

fn split_recipient(recipient: &str) -> Option<(&str, &str)> {
	let (mailbox, domain) = recipient.trim().rsplit_once('@')?;
	if mailbox.is_empty() || domain.is_empty() {
		return None;
	}
	Some((mailbox, domain))
}

async fn resolve_recipient_route(recipient: &str) -> Option<RecipientRoute> {
	let (local, domain) = split_recipient(recipient)?;
	let domain = domain.to_ascii_lowercase();
	let settings = db::domain_settings(&domain).await;
	let (base_local, plus_tag) = normalize_plus_local(local, settings.as_ref());
	let normalized_base_address = format!("{base_local}@{domain}");
	let mut mailbox_id = normalized_base_address.clone();
	let mut storage_mailbox = base_local.clone();
	if let Ok(Some(shared)) = db::find_shared_inbox_by_address(&normalized_base_address).await {
		if let Some(mailbox) = shared.mailbox.clone().and_then(db::extract_record_id) {
			mailbox_id = mailbox;
			storage_mailbox = shared.address.split('@').next().unwrap_or(&base_local).to_string();
		}
	}
	Some(RecipientRoute {
		domain,
		base_local,
		mailbox_id,
		storage_mailbox,
		plus_tag,
		domain_settings: settings,
	})
}

fn normalize_plus_local(local: &str, settings: Option<&db::DomainSettings>) -> (String, Option<String>) {
	let local = local.trim().to_ascii_lowercase();
	let Some(settings) = settings else {
		return (local, None);
	};
	if !settings.addressing.plus_addressing_enabled || settings.addressing.plus_delimiter != '+' {
		return (local, None);
	}
	if let Some((base, tag)) = local.split_once('+') {
		let base = base.trim().to_string();
		let tag = tag.trim().to_string();
		if !base.is_empty() {
			return (base, (!tag.is_empty()).then_some(tag));
		}
	}
	(local, None)
}

fn storage_policy_for_recipient(
	mailbox: &str,
	domain: &str,
	settings: Option<&db::DomainSettings>,
) -> StoragePolicy {
	let org = settings
		.and_then(|s| s.org_id.clone())
		.unwrap_or_else(|| domain.to_string());
	let enc = settings.and_then(|s| s.encryption.as_ref());
	let mode = match enc.map(|e| e.mode) {
		Some(TenantEncryptionMode::E2ee) => EncryptionMode::E2ee,
		_ => EncryptionMode::Standard,
	};

	StoragePolicy {
		org,
		mailbox: mailbox.to_string(),
		mode,
		sse_c_key_b64: enc.and_then(|e| e.sse_c_key_b64.clone()),
		wrapped_dek_customer: enc.and_then(|e| e.wrapped_dek_customer.clone()),
	}
}
