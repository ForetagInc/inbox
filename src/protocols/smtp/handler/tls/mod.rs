pub(crate) mod dane;
mod mta_sts;
mod reporting;

use std::collections::HashSet;

use crate::{
	config::{Config, OutboundDaneMode, OutboundTlsMode},
	protocols::smtp::error::OutgoingError,
};

#[derive(Debug, Clone)]
pub struct DomainTlsPolicy {
	pub require_tls: bool,
	pub mta_sts_mode: Option<String>,
	pub mta_sts_allowed_mx: Option<Vec<String>>,
	pub dane_required_hosts: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct TlsFailureContext {
	pub source: &'static str,
	pub mta_sts_mode: Option<String>,
	pub dane_required: bool,
}

pub async fn evaluate_domain_tls_policy(
	domain: &str,
	targets: &[String],
	dnssec_validate: bool,
	config: &Config,
) -> Result<DomainTlsPolicy, OutgoingError> {
	let mut require_tls = config.smtp.outbound.tls_mode == OutboundTlsMode::Required
		|| config.smtp.outbound.require_starttls;
	let mut mta_sts_mode = None;
	let mut mta_sts_allowed_mx = None;

	if config.smtp.outbound.mta_sts_enforce
		&& let Some(policy) = mta_sts::resolve_policy(domain, config).await?
	{
		mta_sts_mode = Some(policy.mode.clone());
		if policy.mode.eq_ignore_ascii_case("enforce") {
			require_tls = true;
			mta_sts_allowed_mx = Some(policy.mx_patterns);
		}
	}

	let dane_required_hosts = match config.smtp.outbound.dane_mode {
		OutboundDaneMode::Off => HashSet::new(),
		OutboundDaneMode::Prefer | OutboundDaneMode::Require => {
			dane::discover_dane_hosts(targets, dnssec_validate).await?
		}
	};

	if config.smtp.outbound.dane_mode == OutboundDaneMode::Require && dane_required_hosts.is_empty() {
		return Err(OutgoingError::Relay(format!(
			"DANE required for domain {domain}, but no TLSA records found for MX targets"
		)));
	}

	if !dane_required_hosts.is_empty() {
		require_tls = true;
	}

	Ok(DomainTlsPolicy {
		require_tls,
		mta_sts_mode,
		mta_sts_allowed_mx,
		dane_required_hosts,
	})
}

pub fn host_allowed_by_policy(policy: &DomainTlsPolicy, host: &str) -> bool {
	let Some(patterns) = policy.mta_sts_allowed_mx.as_ref() else {
		return true;
	};
	patterns.iter().any(|pattern| host_matches(pattern, host))
}

pub fn prioritize_targets(policy: &DomainTlsPolicy, targets: Vec<String>) -> Vec<String> {
	if policy.dane_required_hosts.is_empty() {
		return targets;
	}
	let mut preferred = Vec::new();
	let mut others = Vec::new();
	for host in targets {
		if policy.dane_required_hosts.contains(&host.to_ascii_lowercase()) {
			preferred.push(host);
		} else {
			others.push(host);
		}
	}
	preferred.extend(others);
	preferred
}

pub async fn write_tls_failure_report(
	config: &Config,
	domain: &str,
	host: &str,
	reason: &str,
	context: &TlsFailureContext,
) {
	reporting::write_tls_failure_report(config, domain, host, reason, context).await;
}

fn host_matches(pattern: &str, host: &str) -> bool {
	let pattern = pattern.to_ascii_lowercase();
	let host = host.to_ascii_lowercase();
	if let Some(suffix) = pattern.strip_prefix("*.") {
		return host == suffix || host.ends_with(&format!(".{suffix}"));
	}
	pattern == host
}
