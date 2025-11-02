use std::net::IpAddr;
use mail_auth::{AuthenticatedMessage, DmarcResult, MessageAuthenticator, dmarc::verify::DmarcParameters, spf::verify::SpfParameters};

use crate::protocols::smtp::error::IncomingError;

pub async fn verify_mail(ip: IpAddr, helo_domain: &str, host_domain: &str, sender: &str, message: &[u8]) -> Result<bool, IncomingError> {
	let authenticator = MessageAuthenticator::new_cloudflare_tls().expect("Failed to create a Cloudflare TLS authenticator");
	let message = AuthenticatedMessage::parse(&message).expect("Failed to parse the raw mail body");

	// @todo
	let sender_domain = "asterisk.gg";

	let dkim = authenticator
		.verify_dkim(&message)
		.await;

	let spf = authenticator
		.verify_spf(SpfParameters::verify_mail_from(ip, helo_domain, host_domain, sender))
		.await;

	let dmarc = authenticator
		.verify_dmarc(
			DmarcParameters::new(
				&message,
				&dkim,
				sender_domain,
				&spf,
			)
			.with_domain_suffix_fn(| domain | psl::domain_str(domain).unwrap())
		)
		.await;

	let dkim_result = dmarc.dkim_result();
	let spf_result = dmarc.spf_result();

	if dkim_result == &DmarcResult::Pass && spf_result == &DmarcResult::Pass {
		return Ok(true)
	}

	Ok(false)
}
