use std::{env, path::PathBuf, sync::LazyLock};

use aws_config::{BehaviorVersion, Region};
use aws_credential_types::Credentials;
use aws_sdk_s3::{Client, primitives::ByteStream};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use md5::{Digest, Md5};
use tokio::sync::OnceCell;

use crate::protocols::smtp::error::IncomingError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncryptionMode {
	Standard,
	E2ee,
}

#[derive(Clone, Debug)]
pub struct StoragePolicy {
	pub org: String,
	pub mailbox: String,
	pub mode: EncryptionMode,
	pub sse_c_key_b64: Option<String>,
	pub wrapped_dek_customer: Option<String>,
}

struct S3Config {
	endpoint: String,
	region: String,
	bucket: String,
	access_key_id: String,
	secret_access_key: String,
	force_path_style: bool,
}

enum StorageBackend {
	S3(S3Backend),
	Local(LocalBackend),
}

struct S3Backend {
	client: Client,
	bucket: String,
}

struct LocalBackend {
	base_dir: PathBuf,
}

static BACKEND: OnceCell<StorageBackend> = OnceCell::const_new();
static STORE_PARSED_PARTS: LazyLock<bool> =
	LazyLock::new(|| parse_env_bool("INBOX_STORE_PARSED_PARTS", false));

pub fn store_parsed_parts() -> bool {
	*STORE_PARSED_PARTS
}

pub async fn put_raw_message(
	policy: &StoragePolicy,
	message_id: &str,
	message: &[u8],
) -> Result<String, IncomingError> {
	let key = format!(
		"msg/{}/{}/{}.eml",
		sanitize_path_component(&policy.org),
		sanitize_path_component(&policy.mailbox),
		sanitize_path_component(message_id)
	);
	put_blob(policy, &key, message, Some("message/rfc822")).await?;
	Ok(key)
}

pub async fn put_attachment(
	policy: &StoragePolicy,
	message_id: &str,
	part_id: &str,
	content_type: Option<&str>,
	data: &[u8],
) -> Result<String, IncomingError> {
	let key = format!(
		"att/{}/{}/{}/{}",
		sanitize_path_component(&policy.org),
		sanitize_path_component(&policy.mailbox),
		sanitize_path_component(message_id),
		sanitize_path_component(part_id)
	);
	put_blob(policy, &key, data, content_type).await?;
	Ok(key)
}

pub async fn put_part_blob(
	policy: &StoragePolicy,
	message_id: &str,
	mime_path: &str,
	content_type: Option<&str>,
	data: &[u8],
) -> Result<String, IncomingError> {
	let key = format!(
		"part/{}/{}/{}/{}",
		sanitize_path_component(&policy.org),
		sanitize_path_component(&policy.mailbox),
		sanitize_path_component(message_id),
		sanitize_slash_path(mime_path)
	);
	put_blob(policy, &key, data, content_type).await?;
	Ok(key)
}

async fn put_blob(
	policy: &StoragePolicy,
	key: &str,
	data: &[u8],
	content_type: Option<&str>,
) -> Result<(), IncomingError> {
	match backend().await? {
		StorageBackend::S3(s3) => put_s3_blob(s3, policy, key, data, content_type).await,
		StorageBackend::Local(local) => put_local_blob(local, key, data).await,
	}
}

async fn backend() -> Result<&'static StorageBackend, IncomingError> {
	BACKEND
		.get_or_try_init(|| async {
			if let Some(config) = load_s3_config() {
				let creds = Credentials::new(
					config.access_key_id,
					config.secret_access_key,
					None,
					None,
					"inbox-env",
				);
				let shared_config = aws_config::defaults(BehaviorVersion::latest())
					.region(Region::new(config.region))
					.credentials_provider(creds)
					.endpoint_url(config.endpoint)
					.load()
					.await;
				let s3_config = aws_sdk_s3::config::Builder::from(&shared_config)
					.force_path_style(config.force_path_style)
					.build();
				let client = Client::from_conf(s3_config);
				return Ok(StorageBackend::S3(S3Backend {
					client,
					bucket: config.bucket,
				}));
			}

			let base_dir = env::var("INBOX_INCOMING_DIR")
				.map(PathBuf::from)
				.unwrap_or_else(|_| PathBuf::from("data/incoming"));
			Ok(StorageBackend::Local(LocalBackend { base_dir }))
		})
		.await
}

async fn put_s3_blob(
	s3: &S3Backend,
	policy: &StoragePolicy,
	key: &str,
	data: &[u8],
	content_type: Option<&str>,
) -> Result<(), IncomingError> {
	let mut req = s3
		.client
		.put_object()
		.bucket(&s3.bucket)
		.key(key)
		.body(ByteStream::from(data.to_vec()));

	if let Some(content_type) = content_type {
		req = req.content_type(content_type);
	}

	if policy.mode == EncryptionMode::Standard
		&& let Some(key_b64) = policy.sse_c_key_b64.as_ref()
	{
		let key_md5 = sse_customer_key_md5(key_b64)?;
		req = req
			.sse_customer_algorithm("AES256")
			.sse_customer_key(key_b64)
			.sse_customer_key_md5(key_md5);
	}

	if policy.mode == EncryptionMode::E2ee {
		req = req.metadata("enc-mode", "e2ee");
		if let Some(wrapped_dek) = policy.wrapped_dek_customer.as_ref() {
			req = req.metadata("enc-wrapped-dek-customer", wrapped_dek);
		}
	}

	req.send()
		.await
		.map_err(|e| IncomingError::Storage(format!("s3 put object failed for {key}: {e}")))?;

	Ok(())
}

async fn put_local_blob(local: &LocalBackend, key: &str, data: &[u8]) -> Result<(), IncomingError> {
	let path = local.base_dir.join(key);
	if let Some(parent) = path.parent() {
		tokio::fs::create_dir_all(parent)
			.await
			.map_err(|e| IncomingError::Storage(format!("create dir failed for {key}: {e}")))?;
	}
	tokio::fs::write(&path, data)
		.await
		.map_err(|e| IncomingError::Storage(format!("write failed for {key}: {e}")))?;
	Ok(())
}

fn load_s3_config() -> Option<S3Config> {
	let endpoint = env::var("S3_ENDPOINT")
		.ok()
		.filter(|v| !v.trim().is_empty())?;
	let bucket = env::var("S3_BUCKET")
		.ok()
		.filter(|v| !v.trim().is_empty())?;
	let access_key_id = env::var("S3_ACCESS_KEY_ID")
		.ok()
		.filter(|v| !v.trim().is_empty())?;
	let secret_access_key = env::var("S3_SECRET_ACCESS_KEY")
		.ok()
		.filter(|v| !v.trim().is_empty())?;

	Some(S3Config {
		endpoint,
		region: env::var("S3_REGION")
			.ok()
			.filter(|v| !v.trim().is_empty())
			.unwrap_or_else(|| "auto".to_string()),
		bucket,
		access_key_id,
		secret_access_key,
		force_path_style: parse_env_bool("S3_FORCE_PATH_STYLE", false),
	})
}

fn parse_env_bool(key: &str, fallback: bool) -> bool {
	env::var(key)
		.ok()
		.map(|v| {
			matches!(
				v.trim().to_ascii_lowercase().as_str(),
				"1" | "true" | "yes" | "on"
			)
		})
		.unwrap_or(fallback)
}

fn sse_customer_key_md5(key_b64: &str) -> Result<String, IncomingError> {
	let decoded = BASE64_STANDARD
		.decode(key_b64.as_bytes())
		.map_err(|e| IncomingError::Storage(format!("invalid SSE-C base64 key: {e}")))?;
	let digest = Md5::digest(decoded);
	Ok(BASE64_STANDARD.encode(digest))
}

pub fn sanitize_path_component(input: &str) -> String {
	let mut out = String::with_capacity(input.len());
	for c in input.chars() {
		if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
			out.push(c);
		} else {
			out.push('_');
		}
	}
	if out.is_empty() {
		"unknown".to_string()
	} else {
		out
	}
}

fn sanitize_slash_path(input: &str) -> String {
	let mut out = String::with_capacity(input.len());
	for c in input.chars() {
		if c == '/' {
			out.push('/');
		} else if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
			out.push(c);
		} else {
			out.push('_');
		}
	}
	if out.is_empty() {
		"part".to_string()
	} else {
		out
	}
}
