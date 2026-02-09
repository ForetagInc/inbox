use std::{
	env,
	sync::{LazyLock, atomic::{AtomicBool, Ordering}}
};

use serde::Deserialize;
use surrealdb_types::SurrealValue;
use surrealdb::{
	Surreal,
	engine::remote::http::{Client, Http},
	opt::auth::Database
};
use tracing::{info, warn};

use crate::config::{DkimConfig, TenantMailAuthConfig};

pub static DB: LazyLock<Surreal<Client>> = LazyLock::new(Surreal::init);
static DB_READY: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
pub struct DomainSettings {
	pub dkim: Option<DkimConfig>,
	pub auth: Option<TenantMailAuthConfig>,
}

#[derive(Debug, Deserialize, surrealdb_types::SurrealValue)]
struct HasDomainRow {
	dkim_selector: Option<String>,
	dkim_private_key_b64_pkcs8: Option<String>,
	dkim_headers: Option<Vec<String>>,
	require_spf_pass: Option<bool>,
	require_dkim_pass: Option<bool>,
	require_dmarc_pass: Option<bool>,
}

pub async fn init() -> Result<(), surrealdb::Error> {
	DB.connect::<Http>(env::var("DATABASE_HOSTNAME").unwrap_or(String::from("localhost:8000")))
		.await?;

	DB.signin(Database {
		namespace: env::var("DATABASE_NAMESPACE").unwrap_or_else(|_| "foretag".to_string()),
		database: env::var("DATABASE_DATABASE").unwrap_or_else(|_| "workshop".to_string()),
		username: env::var("DATABASE_USERNAME").unwrap_or_else(|_| "email".to_string()),
		password: env::var("DATABASE_PASSWORD").unwrap_or_else(|_| "email".to_string())
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
			dkim_selector,
			dkim_private_key_b64_pkcs8,
			dkim_headers,
			require_spf_pass,
			require_dkim_pass,
			require_dmarc_pass
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
		let dkim = row
			.dkim_selector
			.and_then(|selector| {
				row.dkim_private_key_b64_pkcs8.map(|private_key_b64_pkcs8| DkimConfig {
					domain: domain.to_string(),
					selector,
					private_key_b64_pkcs8,
					headers: row
						.dkim_headers
						.unwrap_or_else(|| vec!["From".into(), "To".into(), "Subject".into(), "Date".into()])
				})
			});

		let auth = if row.require_spf_pass.is_some()
			|| row.require_dkim_pass.is_some()
			|| row.require_dmarc_pass.is_some()
		{
			Some(TenantMailAuthConfig {
				require_spf_pass: row.require_spf_pass,
				require_dkim_pass: row.require_dkim_pass,
				require_dmarc_pass: row.require_dmarc_pass
			})
		} else {
			None
		};

		DomainSettings { dkim, auth }
	})
}
