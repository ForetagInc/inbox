pub mod r2;

use serde::Deserialize;
use std::{env, time::Duration};

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
	pub server: ServerConfig,
	pub smtp: SmtpConfig,
	pub auth: MailAuthConfig,
	pub telemetry: TelemetryConfig,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ServerConfig {
	pub hostname: String,
	pub bind_addr: String,
	pub max_connections: usize,
}

#[derive(Deserialize, Clone, Debug)]
pub struct SmtpConfig {
	pub transfer_port: u16,
	pub submission_port: u16,
	pub inbound_max_rcpt_to: usize,
	pub max_message_bytes: usize,
	pub rate_limit: SmtpRateLimitConfig,
	pub outbound_queue: OutboundQueueConfig,
	pub outbound: OutboundConfig,
}

#[derive(Deserialize, Clone, Debug)]
pub struct SmtpRateLimitConfig {
	pub enabled: bool,
	pub window_secs: u64,
	pub transfer_connections_per_window: u32,
	pub submission_connections_per_window: u32,
	pub transfer_messages_per_window: u32,
	pub submission_messages_per_window: u32,
	pub fail_open_on_db_error: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct OutboundQueueConfig {
	pub enabled: bool,
	pub poll_interval_secs: u64,
	pub cleanup_interval_secs: u64,
	pub dead_job_retention_secs: u64,
	pub delivery_retention_secs: u64,
	pub batch_size: usize,
	pub lease_secs: u64,
	pub retry_base_delay_secs: u64,
	pub retry_max_delay_secs: u64,
	pub max_attempts: u32,
	pub ttl_secs: u64,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum OutboundTlsMode {
	#[serde(rename = "opportunistic")]
	Opportunistic,
	#[serde(rename = "required")]
	Required,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum OutboundDaneMode {
	#[serde(rename = "off")]
	Off,
	#[serde(rename = "prefer")]
	Prefer,
	#[serde(rename = "require")]
	Require,
}

#[derive(Deserialize, Clone, Debug)]
pub struct OutboundConfig {
	pub default_port: u16,
	pub require_starttls: bool,
	pub allow_invalid_certs: bool,
	pub allow_plaintext_fallback: bool,
	pub tls_mode: OutboundTlsMode,
	pub dane_mode: OutboundDaneMode,
	pub dnssec_validate: bool,
	pub mta_sts_enforce: bool,
	pub tls_rpt_enabled: bool,
	pub tls_rpt_send_hour_utc: u8,
	pub tls_rpt_max_recipients_per_domain: usize,
	pub tls_rpt_fallback_from: Option<String>,
	pub tls_report_dir: String,
	pub timeout: Duration,
	pub dkim: Option<DkimConfig>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct DkimConfig {
	pub domain: String,
	pub selector: String,
	pub private_key_b64_pkcs8: String,
	pub headers: Vec<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct MailAuthConfig {
	pub require_spf_pass: bool,
	pub require_dkim_pass: bool,
	pub require_dmarc_pass: bool,
	pub allow_header_override: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct TelemetryConfig {
	pub enabled: bool,
	pub otlp_endpoint: String,
	pub service_name: String,
	pub sample_ratio: f64,
	pub console_logs: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct TenantMailAuthConfig {
	pub require_spf_pass: Option<bool>,
	pub require_dkim_pass: Option<bool>,
	pub require_dmarc_pass: Option<bool>,
}

impl Config {
	pub fn from_env() -> Self {
		let server = ServerConfig {
			hostname: env_var("SERVER_HOSTNAME", "mail.localhost"),
			bind_addr: env_var("SERVER_BIND_ADDR", "0.0.0.0"),
			max_connections: env_parse("SERVER_MAX_CONNECTIONS", 256usize),
		};

		let outbound = OutboundConfig {
			default_port: env_parse("SMTP_OUTBOUND_PORT", 25u16),
			require_starttls: env_parse_bool("SMTP_OUTBOUND_REQUIRE_STARTTLS", false),
			allow_invalid_certs: env_parse_bool("SMTP_OUTBOUND_ALLOW_INVALID_CERTS", false),
				allow_plaintext_fallback: env_parse_bool(
					"SMTP_OUTBOUND_ALLOW_PLAINTEXT_FALLBACK",
					true,
				),
				tls_mode: env_parse_outbound_tls_mode("SMTP_OUTBOUND_TLS_MODE"),
				dane_mode: env_parse_outbound_dane_mode("SMTP_OUTBOUND_DANE_MODE"),
				dnssec_validate: env_parse_bool("SMTP_OUTBOUND_DNSSEC_VALIDATE", true),
				mta_sts_enforce: env_parse_bool("SMTP_OUTBOUND_MTA_STS_ENFORCE", true),
				tls_rpt_enabled: env_parse_bool("SMTP_TLS_RPT_ENABLED", true),
				tls_rpt_send_hour_utc: env_parse("SMTP_TLS_RPT_SEND_HOUR_UTC", 2u8),
				tls_rpt_max_recipients_per_domain: env_parse(
					"SMTP_TLS_RPT_MAX_RECIPIENTS_PER_DOMAIN",
					5usize,
				),
				tls_rpt_fallback_from: env::var("SMTP_TLS_RPT_FALLBACK_FROM")
					.ok()
					.and_then(|v| {
						let trimmed = v.trim();
						if trimmed.is_empty() {
							None
						} else {
							Some(trimmed.to_string())
						}
					}),
			tls_report_dir: env_var("SMTP_TLS_REPORT_DIR", "data/tlsrpt"),
			timeout: Duration::from_secs(env_parse("SMTP_OUTBOUND_TIMEOUT_SECS", 30u64)),
			dkim: load_dkim_from_env(),
		};

		let smtp = SmtpConfig {
			transfer_port: env_parse("SMTP_TRANSFER_PORT", 25u16),
			submission_port: env_parse("SMTP_SUBMISSION_PORT", 587u16),
			inbound_max_rcpt_to: env_parse("SMTP_INBOUND_MAX_RCPT_TO", 100usize),
			max_message_bytes: env_parse(
				"SMTP_MAX_MESSAGE_BYTES",
				25 * 1024 * 1024usize,
			),
			rate_limit: SmtpRateLimitConfig {
				enabled: env_parse_bool("SMTP_RATE_LIMIT_ENABLED", true),
				window_secs: env_parse("SMTP_RATE_LIMIT_WINDOW_SECS", 60u64),
				transfer_connections_per_window: env_parse(
					"SMTP_RATE_LIMIT_TRANSFER_CONNECTIONS_PER_WINDOW",
					240u32,
				),
				submission_connections_per_window: env_parse(
					"SMTP_RATE_LIMIT_SUBMISSION_CONNECTIONS_PER_WINDOW",
					120u32,
				),
				transfer_messages_per_window: env_parse(
					"SMTP_RATE_LIMIT_TRANSFER_MESSAGES_PER_WINDOW",
					240u32,
				),
					submission_messages_per_window: env_parse(
						"SMTP_RATE_LIMIT_SUBMISSION_MESSAGES_PER_WINDOW",
						120u32,
					),
					fail_open_on_db_error: env_parse_bool(
						"SMTP_RATE_LIMIT_FAIL_OPEN_ON_DB_ERROR",
						true,
					),
				},
			outbound_queue: OutboundQueueConfig {
				enabled: env_parse_bool("SMTP_OUTBOUND_QUEUE_ENABLED", true),
				poll_interval_secs: env_parse("SMTP_OUTBOUND_QUEUE_POLL_INTERVAL_SECS", 2u64),
				cleanup_interval_secs: env_parse(
					"SMTP_OUTBOUND_QUEUE_CLEANUP_INTERVAL_SECS",
					300u64,
				),
				dead_job_retention_secs: env_parse(
					"SMTP_OUTBOUND_DEAD_JOB_RETENTION_SECS",
					7 * 86_400u64,
				),
				delivery_retention_secs: env_parse(
					"SMTP_OUTBOUND_DELIVERY_RETENTION_SECS",
					30 * 86_400u64,
				),
				batch_size: env_parse("SMTP_OUTBOUND_QUEUE_BATCH_SIZE", 100usize),
				lease_secs: env_parse("SMTP_OUTBOUND_QUEUE_LEASE_SECS", 120u64),
				retry_base_delay_secs: env_parse("SMTP_OUTBOUND_RETRY_BASE_DELAY_SECS", 30u64),
				retry_max_delay_secs: env_parse("SMTP_OUTBOUND_RETRY_MAX_DELAY_SECS", 3600u64),
				max_attempts: env_parse("SMTP_OUTBOUND_MAX_ATTEMPTS", 10u32),
				ttl_secs: env_parse("SMTP_OUTBOUND_TTL_SECS", 86400u64),
			},
			outbound,
		};

		let auth = MailAuthConfig {
			require_spf_pass: env_parse_bool("SMTP_REQUIRE_SPF_PASS", true),
			require_dkim_pass: env_parse_bool("SMTP_REQUIRE_DKIM_PASS", false),
			require_dmarc_pass: env_parse_bool("SMTP_REQUIRE_DMARC_PASS", false),
			allow_header_override: env_parse_bool("SMTP_AUTH_ALLOW_HEADER_OVERRIDE", false),
		};

		let telemetry = TelemetryConfig {
			enabled: env_parse_bool("OTEL_ENABLED", false),
			otlp_endpoint: env_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318/v1/traces"),
			service_name: env_var("OTEL_SERVICE_NAME", "inbox"),
			sample_ratio: env_parse("OTEL_SAMPLE_RATIO", 1.0f64),
			console_logs: env_parse_bool("OTEL_CONSOLE_LOGS", true),
		};

		Self {
			server,
			smtp,
			auth,
			telemetry,
		}
	}

	pub fn merged_auth_policy(&self, overrides: Option<&TenantMailAuthConfig>) -> MailAuthConfig {
		let mut policy = self.auth.clone();
		if let Some(tenant_auth) = overrides {
			if let Some(v) = tenant_auth.require_spf_pass {
				policy.require_spf_pass = v;
			}
			if let Some(v) = tenant_auth.require_dkim_pass {
				policy.require_dkim_pass = v;
			}
			if let Some(v) = tenant_auth.require_dmarc_pass {
				policy.require_dmarc_pass = v;
			}
		}
		policy
	}
}

fn env_var(key: &str, fallback: &str) -> String {
	env::var(key).unwrap_or_else(|_| fallback.to_string())
}

fn env_parse<T: std::str::FromStr>(key: &str, fallback: T) -> T {
	env::var(key)
		.ok()
		.and_then(|v| v.parse::<T>().ok())
		.unwrap_or(fallback)
}

fn env_parse_bool(key: &str, fallback: bool) -> bool {
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

fn env_parse_outbound_tls_mode(key: &str) -> OutboundTlsMode {
	match env::var(key)
		.unwrap_or_else(|_| "required".to_string())
		.to_ascii_lowercase()
		.as_str()
	{
		"opportunistic" => OutboundTlsMode::Opportunistic,
		_ => OutboundTlsMode::Required,
	}
}

fn env_parse_outbound_dane_mode(key: &str) -> OutboundDaneMode {
	match env::var(key)
		.unwrap_or_else(|_| "prefer".to_string())
		.to_ascii_lowercase()
		.as_str()
	{
		"off" => OutboundDaneMode::Off,
		"require" => OutboundDaneMode::Require,
		_ => OutboundDaneMode::Prefer,
	}
}

fn load_dkim_from_env() -> Option<DkimConfig> {
	let domain = env::var("SMTP_DKIM_DOMAIN")
		.ok()
		.filter(|v| !v.is_empty())?;
	let selector = env::var("SMTP_DKIM_SELECTOR")
		.ok()
		.filter(|v| !v.is_empty())?;
	let private_key_b64_pkcs8 = env::var("SMTP_DKIM_PRIVATE_KEY_B64_PKCS8")
		.ok()
		.filter(|v| !v.is_empty())?;

	let headers = env::var("SMTP_DKIM_HEADERS")
		.ok()
		.map(|v| {
			v.split(',')
				.map(|h| h.trim())
				.filter(|h| !h.is_empty())
				.map(|h| h.to_string())
				.collect::<Vec<_>>()
		})
		.filter(|v| !v.is_empty())
		.unwrap_or_else(|| vec!["From".into(), "To".into(), "Subject".into(), "Date".into()]);

	Some(DkimConfig {
		domain,
		selector,
		private_key_b64_pkcs8,
		headers,
	})
}
