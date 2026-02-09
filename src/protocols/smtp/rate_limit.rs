use std::{net::IpAddr, time::{SystemTime, UNIX_EPOCH}};

use crate::config::Config;
use crate::db;
use crate::protocols::smtp::handler::DeliveryMode;

pub async fn allow_connection(ip: IpAddr, mode: DeliveryMode, config: &Config) -> bool {
	if !config.smtp.rate_limit.enabled {
		return true;
	}
	let limit = match mode {
		DeliveryMode::Transfer => config.smtp.rate_limit.transfer_connections_per_window,
		DeliveryMode::Submission => config.smtp.rate_limit.submission_connections_per_window,
	};
	allow_key(
		"conn",
		ip,
		mode,
		limit,
		config.smtp.rate_limit.window_secs,
		config.smtp.rate_limit.fail_open_on_db_error,
	)
	.await
}

pub async fn allow_message(ip: IpAddr, mode: DeliveryMode, config: &Config) -> bool {
	if !config.smtp.rate_limit.enabled {
		return true;
	}
	let limit = match mode {
		DeliveryMode::Transfer => config.smtp.rate_limit.transfer_messages_per_window,
		DeliveryMode::Submission => config.smtp.rate_limit.submission_messages_per_window,
	};
	allow_key(
		"msg",
		ip,
		mode,
		limit,
		config.smtp.rate_limit.window_secs,
		config.smtp.rate_limit.fail_open_on_db_error,
	)
	.await
}

async fn allow_key(
	kind: &str,
	ip: IpAddr,
	mode: DeliveryMode,
	limit: u32,
	window_secs: u64,
	fail_open_on_db_error: bool,
) -> bool {
	if limit == 0 {
		return false;
	}
	let now_epoch_secs = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs();
	let window_secs = window_secs.max(1);
	let bucket = now_epoch_secs / window_secs;
	let expires_at = now_epoch_secs.saturating_add(window_secs.saturating_mul(2));
	let mode_key = match mode {
		DeliveryMode::Transfer => "transfer",
		DeliveryMode::Submission => "submission",
	};
	let key = build_counter_key(kind, mode_key, ip, bucket);
	match db::consume_smtp_rate_limit(&key, limit, expires_at).await {
		Ok(allowed) => allowed,
		Err(_) => fail_open_on_db_error,
	}
}

fn build_counter_key(kind: &str, mode_key: &str, ip: IpAddr, bucket: u64) -> String {
	format!("{kind}:{mode_key}:{ip}:{bucket}")
}

#[cfg(test)]
mod tests {
	use std::net::IpAddr;
	use std::str::FromStr;

	use super::build_counter_key;

	#[test]
	fn key_is_stable_across_instances() {
		let ip = IpAddr::from_str("203.0.113.10").expect("valid ip");
		let a = build_counter_key("conn", "submission", ip, 1234);
		let b = build_counter_key("conn", "submission", ip, 1234);
		assert_eq!(a, b);
	}
}
