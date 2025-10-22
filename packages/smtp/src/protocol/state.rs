pub enum SessionState {
	Greeting,
	Ready,
	ReceivingMail,
	ReceivingData,
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
