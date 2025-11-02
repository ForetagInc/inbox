pub mod attachment;
pub mod incoming;

use tracing::info;
use std::io::Result;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use mail_parser::MessageParser;

use crate::protocols::smtp::commands::Command;
use crate::protocols::smtp::handler::incoming::verify_mail;
use crate::protocols::smtp::state::{SessionState, SmtpSession};

async fn reply<W: AsyncWrite + Unpin>(w: &mut W, code: u16, msg: &str) -> Result<()> {
	w.write_all(format!("{code} {msg}\r\n").as_bytes()).await
}

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
			reply(writer, 250, &domain).await?;
		}

		Command::Mail(from) => {
			session.state = SessionState::ReceivingMail;
			session.reset_txn();
			let txn = session.transaction.as_mut().expect("Transaction Exists");
			txn.mail_from = Some(from.clone());
			info!("MAIL FROM: {}", from);
			reply(writer, 250, "Ok").await?;
		}

		Command::Rcpt(to) => {
			if !matches!(session.state, SessionState::ReceivingMail | SessionState::ReceivingRcpt) {
                reply(writer, 503, "5.5.1 Bad sequence of commands").await?;
                return Ok(());
            }
            session.state = SessionState::ReceivingRcpt;
            let txn = session.transaction.as_mut().expect("Transaction Exists");
            txn.rcpt_to.push(to.clone());
			info!("RCPT TO: {}", to);
			reply(writer, 250, "OK").await?;
		}

		Command::Data => {
			let Some(txn) = session.transaction.as_ref() else {
				reply(writer, 305, "5.5.1 Bad sequence of commands").await?;
				return Ok(());
			};

			if txn.mail_from.is_none() {
				reply(writer, 503, "5.5.1 Need MAIL FROM first").await?;
                return Ok(());
			}

			if txn.rcpt_to.is_empty() {
				reply(writer, 554, "5.5.1 No valid recipients").await?;
                return Ok(());
			}

			session.state = SessionState::ReceivingData;

			reply(writer, 354, "End data with <CR><LF>.<CR><LF>").await?;

			let raw = read_message_data(reader).await?;
			let parser = MessageParser::default();

			match parser.parse(&raw) {
				Some(message) => {
					info!("DATA BYTES: {:?}", message);

					let subject = message.subject().unwrap_or_default();
					let from = message.from().map(|addrs| {
						addrs
        					.iter()
        					.map(|a| {
             					let email = a.address().unwrap_or_default();
             					match a.name().filter(|n| !n.is_empty()) {
                 					Some(name) => format!("{} <{}>", name, email),
                 					None => email.to_string(),
                 				}
             				})
        					.collect::<Vec<_>>()
             				.join(", ")
					})
					.unwrap_or_default();

					let mut txn = session.transaction.take().unwrap();
					txn.data = Some(raw.clone());

					// let to = message.to().map(|a| a.to_string()).unwrap_or_default();

					info!("Parsed mail Subject={}, from={:?}", &subject, from);

					// let verify_mail = verify_mail(ip, helo_domain, host_domain, from, message.raw_message());

					// 📨 TODO: Save to storage or queue
					reply(writer, 250, "2.0.0 OK: queued").await?;
				}
				None => {
					reply(writer, 550, "5.6.0 Message parse failure").await?;
				}
			}

			session.state = SessionState::Ready;
			session.reset_txn();
		}

		Command::Quit => {
			session.state = SessionState::Finished;
			reply(writer, 221, "Bye").await?;
		}

		Command::Rset => {
			session.state = SessionState::Ready;
			session.reset_txn();
			reply(writer, 250, "OK").await?;
		}

		Command::Noop => {
			reply(writer, 250, "OK").await?;
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
