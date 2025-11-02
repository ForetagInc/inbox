use std::net::IpAddr;
use crate::protocols::smtp::transaction::Transaction;

#[derive(PartialEq)]
pub enum SessionState {
	Greeting,
	Ready,
	/// Meta data for the Email
	ReceivingMail,
	ReceivingRcpt,
	/// Body & attachments for the Email
	ReceivingData,
	SendingMail,
	Finished,
}

pub struct SmtpSession {
	pub peer_ip: Option<IpAddr>,
	pub helo_domain: Option<String>,
	pub state: SessionState,
	pub transaction: Option<Transaction>,
}

impl SmtpSession {
	pub fn new(peer_ip: IpAddr) -> Self {
		SmtpSession {
			peer_ip: Some(peer_ip),
			helo_domain: None,
			state: SessionState::Greeting,
			transaction: None
		}
	}

	pub fn ensure_txn(&mut self) {
		if self.transaction.is_none() {
			self.transaction = Some(Transaction::default());
		}
	}

	pub fn reset_txn(&mut self) {
		self.transaction = Some(Transaction::default());
	}
}
