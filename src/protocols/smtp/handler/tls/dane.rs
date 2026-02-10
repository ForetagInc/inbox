use std::collections::HashSet;

use mail_auth::hickory_resolver::{TokioResolver, name_server::TokioConnectionProvider};
use sha2::{Digest, Sha256, Sha512};
use rustls::pki_types::CertificateDer;

use crate::protocols::smtp::error::OutgoingError;

#[derive(Debug, Clone)]
pub struct TlsaRecord {
	pub cert_usage: u8,
	pub selector: u8,
	pub matching: u8,
	pub cert_data: Vec<u8>,
}

pub async fn discover_dane_hosts(
	targets: &[String],
	dnssec_validate: bool,
) -> Result<HashSet<String>, OutgoingError> {
	let mut hosts = HashSet::new();
	for host in targets {
		let records = resolve_tlsa_records(host, dnssec_validate).await?;
		if !records.is_empty() {
			hosts.insert(host.to_ascii_lowercase());
		}
	}
	Ok(hosts)
}

pub async fn verify_peer_chain_against_tlsa(
	host: &str,
	certs: &[CertificateDer<'_>],
	dnssec_validate: bool,
) -> Result<(), OutgoingError> {
	let records = resolve_tlsa_records(host, dnssec_validate).await?;
	if records.is_empty() {
		return Err(OutgoingError::Relay(format!(
			"DANE TLSA missing for host {host}"
		)));
	}

	if certs.is_empty() {
		return Err(OutgoingError::Relay(format!(
			"DANE validation failed for {host}: no peer certificates"
		)));
	}

	let end_entity = certs[0].as_ref();
	let chain: Vec<&[u8]> = certs.iter().map(|c| c.as_ref()).collect();

	let matched = records.iter().any(|record| match record.cert_usage {
		1 | 3 => record_matches_certificate(record, end_entity).unwrap_or(false),
		0 | 2 => chain
			.iter()
			.any(|cert| record_matches_certificate(record, cert).unwrap_or(false)),
		_ => false,
	});

	if matched {
		Ok(())
	} else {
		Err(OutgoingError::Relay(format!(
			"DANE validation failed for {host}: TLSA mismatch"
		)))
	}
}

async fn resolve_tlsa_records(host: &str, dnssec_validate: bool) -> Result<Vec<TlsaRecord>, OutgoingError> {
	let mut builder = TokioResolver::builder(TokioConnectionProvider::default())
		.map_err(|e| OutgoingError::Relay(format!("resolver init failed: {e}")))?;
	builder.options_mut().validate = dnssec_validate;
	builder.options_mut().try_tcp_on_error = true;
	let resolver = builder.build();
	let owner = format!("_25._tcp.{host}");
	let lookup = resolver
		.tlsa_lookup(owner)
		.await
		.map_err(|e| {
			OutgoingError::Relay(format!("DNSSEC-validated TLSA lookup failed for {host}: {e}"))
		})?;

	Ok(lookup
		.iter()
		.map(|tlsa| TlsaRecord {
			cert_usage: tlsa.cert_usage().into(),
			selector: tlsa.selector().into(),
			matching: tlsa.matching().into(),
			cert_data: tlsa.cert_data().to_vec(),
		})
		.collect())
}

fn record_matches_certificate(record: &TlsaRecord, cert_der: &[u8]) -> Result<bool, OutgoingError> {
	let selected = match record.selector {
		0 => cert_der.to_vec(),
		1 => extract_spki_der(cert_der)?,
		_ => return Ok(false),
	};
	let candidate = match record.matching {
		0 => selected,
		1 => Sha256::digest(&selected).to_vec(),
		2 => Sha512::digest(&selected).to_vec(),
		_ => return Ok(false),
	};
	Ok(candidate == record.cert_data)
}

fn extract_spki_der(cert_der: &[u8]) -> Result<Vec<u8>, OutgoingError> {
	let cert = read_der_element(cert_der, 0)?;
	if cert.tag != 0x30 || cert.end != cert_der.len() {
		return Err(OutgoingError::Relay(
			"invalid certificate DER for DANE selector SPKI".into(),
		));
	}

	let tbs = read_der_element(cert_der, cert.content_start)?;
	if tbs.tag != 0x30 {
		return Err(OutgoingError::Relay(
			"invalid tbsCertificate DER for DANE selector SPKI".into(),
		));
	}

	let tbs_bytes = &cert_der[tbs.content_start..tbs.content_end];
	let mut idx = 0usize;

	if tbs_bytes.first() == Some(&0xA0) {
		idx = read_der_element(tbs_bytes, idx)?.end;
	}

	// serialNumber, signature, issuer, validity, subject
	for _ in 0..5 {
		idx = read_der_element(tbs_bytes, idx)?.end;
	}

	let spki = read_der_element(tbs_bytes, idx)?;
	if spki.tag != 0x30 {
		return Err(OutgoingError::Relay(
			"missing SubjectPublicKeyInfo for DANE selector SPKI".into(),
		));
	}
	Ok(tbs_bytes[spki.start..spki.end].to_vec())
}

#[derive(Debug, Clone, Copy)]
struct DerElement {
	tag: u8,
	start: usize,
	content_start: usize,
	content_end: usize,
	end: usize,
}

fn read_der_element(bytes: &[u8], start: usize) -> Result<DerElement, OutgoingError> {
	if start >= bytes.len() {
		return Err(OutgoingError::Relay("unexpected end of DER input".into()));
	}
	let tag = bytes[start];
	let len_start = start + 1;
	let (len, len_octets) = read_der_length(bytes, len_start)?;
	let content_start = len_start + len_octets;
	let content_end = content_start.saturating_add(len);
	if content_end > bytes.len() {
		return Err(OutgoingError::Relay("invalid DER length overflow".into()));
	}
	Ok(DerElement {
		tag,
		start,
		content_start,
		content_end,
		end: content_end,
	})
}

fn read_der_length(bytes: &[u8], offset: usize) -> Result<(usize, usize), OutgoingError> {
	let Some(first) = bytes.get(offset).copied() else {
		return Err(OutgoingError::Relay("missing DER length".into()));
	};
	if first & 0x80 == 0 {
		return Ok((first as usize, 1));
	}
	let count = (first & 0x7F) as usize;
	if count == 0 || count > 8 {
		return Err(OutgoingError::Relay("unsupported DER length encoding".into()));
	}
	let mut len = 0usize;
	for i in 0..count {
		let Some(b) = bytes.get(offset + 1 + i).copied() else {
			return Err(OutgoingError::Relay("truncated DER length".into()));
		};
		len = (len << 8) | b as usize;
	}
	Ok((len, 1 + count))
}
