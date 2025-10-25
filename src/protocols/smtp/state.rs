#[derive(PartialEq)]
pub enum SessionState {
	Greeting,
	Ready,
	/// Meta data for the Email
	ReceivingMail,
	/// Body & attachments for the Email
	ReceivingData,
	SendingMail,
	Finished,
}

pub struct SmtpSession {
	pub state: SessionState,
}

impl SmtpSession {
	pub fn new() -> Self {
		SmtpSession {
			state: SessionState::Greeting,
		}
	}
}
