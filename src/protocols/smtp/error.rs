use thiserror::Error;

#[derive(Error, Debug)]
pub enum IncomingError {
	#[error("mail parse failure")]
	Parse,

	#[error("message authentication failed: {0}")]
	Auth(String),

	#[error("message rejected by authentication policy")]
	PolicyReject,

	#[error("failed to persist incoming message: {0}")]
	Storage(String),
}

#[derive(Error, Debug)]
pub enum OutgoingError {
	#[error("invalid sender address")]
	InvalidSender,

	#[error("no recipient addresses")]
	NoRecipients,

	#[error("message build failed: {0}")]
	Build(String),

	#[error("DKIM configuration invalid: {0}")]
	Dkim(String),

	#[error("SMTP delivery failed: {0}")]
	Relay(String),
}
