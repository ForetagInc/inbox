use tracing::info;

use crate::protocols::smtp::commands::Command;
use crate::protocols::smtp::state::{SessionState, SmtpSession};

pub fn handle_command(command: Command, session: &mut SmtpSession) -> String {
	match command {
		Command::Helo(domain) => {
			session.state = SessionState::Ready;
			format!("250 {}", domain)
		}
		Command::Ehlo(domain) => {
			session.state = SessionState::Ready;
			format!("250 {}", domain)
		}
		Command::Mail(from) => {
			session.state = SessionState::ReceivingMail;
			info!("Received MAIL FROM: {}", from);
			format!("250 Ok")
		}
		Command::Rcpt(to) => {
			format!("250 Ok")
		}
		Command::Data => {
			session.state = SessionState::ReceivingData;
			format!("354 End data with <CR><LF>.<CR><LF>")
		}
		Command::Quit => {
			session.state = SessionState::Finished;
			format!("221 Bye")
		}
		Command::Rset => {
			session.state = SessionState::Ready;
			format!("250 Ok")
		}
		Command::Noop => {
			format!("250 Ok")
		}
	}
}
