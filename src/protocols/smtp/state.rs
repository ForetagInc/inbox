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
	pub state: SessionState,
	pub transaction: Option<Transaction>,
}

impl SmtpSession {
	pub fn new() -> Self {
		SmtpSession {
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
