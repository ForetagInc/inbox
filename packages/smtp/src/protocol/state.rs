pub enum SessionState {
    Greeting,
    Ready,
    ReceivingMail,
    ReceivingData,
    Finished,
}

pub struct SmtpSession {
    state: SessionState,
}
impl SmtpSession {
    fn new() -> Self {
        SmtpSession {
            state: SessionState::Greeting,
        }
    }
}
