use thiserror::Error;

#[derive(Error, Debug)]
pub enum IncomingError {
	#[error("Invalid SPF IP Address")]
	SPFIPInvalid,

	#[error("Invalid DKIM signature")]
	DKIMInvalid,
}
