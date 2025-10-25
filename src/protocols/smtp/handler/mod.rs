use tracing::info;
use std::io::Result;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use mail_parser::MessageParser;

use crate::protocols::smtp::commands::Command;
use crate::protocols::smtp::state::{SessionState, SmtpSession};

pub async fn handle_command<R, W>(
	command: Command,
	session: &mut SmtpSession,
	reader: &mut R,
	writer: &mut W,
) -> Result<()>
where
	R: AsyncBufRead + Unpin,
	W: AsyncWrite + Unpin,
{
	match command {
		Command::Helo(domain) | Command::Ehlo(domain) => {
			session.state = SessionState::Ready;
			writer
				.write_all(format!("250 {}\r\n", domain).as_bytes())
				.await?;
		}

		Command::Mail(from) => {
			session.state = SessionState::ReceivingMail;
			info!("MAIL FROM: {}", from);
			writer.write_all(b"250 Ok\r\n").await?;
		}

		Command::Rcpt(to) => {
			info!("RCPT TO: {}", to);
			writer.write_all(b"250 Ok\r\n").await?;
		}

		Command::Data => {
			session.state = SessionState::ReceivingData;
			writer
				.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
				.await?;

			let raw = read_message_data(reader).await?;
			let parser = MessageParser::default();

			info!("DATA FOUND: {:?}", parser.parse(&raw));

			if let Some(message) = parser.parse(&raw) {
				let subject = message.subject().unwrap_or_default();
				// let from = message.from().map(|a| a.to_string()).unwrap_or_default();
				// let to = message.to().map(|a| a.to_string()).unwrap_or_default();

				info!("Parsed mail Subject={}", subject);

				// 📨 TODO: Save to storage or queue
				writer.write_all(b"250 2.0.0 OK: queued\r\n").await?;
			} else {
				writer
					.write_all(b"550 5.6.0 Message parse failure\r\n")
					.await?;
			}

			session.state = SessionState::Ready;
		}

		Command::Quit => {
			session.state = SessionState::Finished;
			writer.write_all(b"221 Bye\r\n").await?;
		}

		Command::Rset => {
			session.state = SessionState::Ready;
			writer.write_all(b"250 Ok\r\n").await?;
		}

		Command::Noop => {
			writer.write_all(b"250 Ok\r\n").await?;
		}
	}

	Ok(())
}

/// Reads the full SMTP DATA payload, handling dot-stuffing.
async fn read_message_data<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
	let mut raw = Vec::new();

	loop {
		let mut line = Vec::new();
		let n = reader.read_until(b'\n', &mut line).await?;
		if n == 0 {
			break;
		}

		if line == b".\r\n" {
			break;
		}

		if line.starts_with(b"..") {
			line.remove(0);
		}

		raw.extend_from_slice(&line);
	}

	Ok(raw)
}
