#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BounceCategory {
	Temporary,
	MailboxPermanent,
	DomainPermanent,
	PolicyPermanent,
	UnknownPermanent,
}

pub fn classify_bounce(reason: &str) -> BounceCategory {
	let lower = reason.to_ascii_lowercase();
	if lower.contains("4.") || lower.contains("timeout") || lower.contains("temporar") {
		return BounceCategory::Temporary;
	}

	let code = extract_enhanced_status(&lower);
	match code.as_deref() {
		Some("5.1.1") => BounceCategory::MailboxPermanent,
		Some("5.1.2") => BounceCategory::DomainPermanent,
		Some("5.1.3") => BounceCategory::DomainPermanent,
		Some("5.2.1") => BounceCategory::MailboxPermanent,
		Some("5.7.1") => BounceCategory::PolicyPermanent,
		Some(c) if c.starts_with("5.1.") => BounceCategory::MailboxPermanent,
		Some(c) if c.starts_with("5.2.") => BounceCategory::MailboxPermanent,
		Some(c) if c.starts_with("5.7.") => BounceCategory::PolicyPermanent,
		Some(c) if c.starts_with("5.") => BounceCategory::UnknownPermanent,
		_ => classify_by_text(&lower),
	}
}

pub fn suppression_scopes(category: BounceCategory) -> (&'static str, bool) {
	match category {
		BounceCategory::MailboxPermanent => ("address", false),
		BounceCategory::DomainPermanent => ("address", true),
		BounceCategory::PolicyPermanent => ("address", false),
		BounceCategory::UnknownPermanent => ("address", false),
		BounceCategory::Temporary => ("none", false),
	}
}

fn classify_by_text(lower: &str) -> BounceCategory {
	if lower.contains("user unknown")
		|| lower.contains("no such user")
		|| lower.contains("mailbox unavailable")
	{
		return BounceCategory::MailboxPermanent;
	}
	if lower.contains("domain")
		|| lower.contains("nxdomain")
		|| lower.contains("no such host")
		|| lower.contains("host not found")
	{
		return BounceCategory::DomainPermanent;
	}
	if lower.contains("policy") || lower.contains("blocked") || lower.contains("rejected") {
		return BounceCategory::PolicyPermanent;
	}
	BounceCategory::UnknownPermanent
}

fn extract_enhanced_status(text: &str) -> Option<String> {
	for token in text.split_whitespace() {
		let token = token.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
		let mut parts = token.split('.');
		let (Some(a), Some(b), Some(c)) = (parts.next(), parts.next(), parts.next()) else {
			continue;
		};
		if parts.next().is_some() {
			continue;
		}
		if a.len() == 1
			&& b.len() == 1
			&& c.len() == 1
			&& a.chars().all(|ch| ch.is_ascii_digit())
			&& b.chars().all(|ch| ch.is_ascii_digit())
			&& c.chars().all(|ch| ch.is_ascii_digit())
		{
			return Some(format!("{a}.{b}.{c}"));
		}
	}
	None
}

#[cfg(test)]
mod tests {
	use super::{BounceCategory, classify_bounce, suppression_scopes};

	#[test]
	fn classify_enhanced_code() {
		assert_eq!(classify_bounce("550 5.1.1 user unknown"), BounceCategory::MailboxPermanent);
		assert_eq!(classify_bounce("550 5.1.2 bad domain"), BounceCategory::DomainPermanent);
		assert_eq!(classify_bounce("421 4.4.1 timeout"), BounceCategory::Temporary);
	}

	#[test]
	fn deterministic_suppression_mapping() {
		assert_eq!(suppression_scopes(BounceCategory::MailboxPermanent), ("address", false));
		assert_eq!(suppression_scopes(BounceCategory::DomainPermanent), ("address", true));
		assert_eq!(suppression_scopes(BounceCategory::Temporary), ("none", false));
	}
}
