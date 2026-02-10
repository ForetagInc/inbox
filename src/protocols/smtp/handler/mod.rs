pub mod attachment;
pub mod incoming;
pub mod outgoing;
pub mod tls;

use mail_parser::MessageParser;
use std::io::{Error, ErrorKind, Result};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{Level, event, instrument};

use crate::config::Config;
use crate::protocols::smtp::commands::Command;
use crate::protocols::smtp::handler::{
	attachment::find_oversized_attachment,
	incoming::{accepted_for_recipients, persist_incoming_message, verify_mail},
	outgoing::{OUTBOUND_MAX_ATTACHMENT_BYTES, OUTBOUND_MAX_MESSAGE_BYTES, relay_transaction},
};
use crate::protocols::smtp::queue;
use crate::protocols::smtp::rate_limit;
use crate::protocols::smtp::state::{SessionState, SmtpSession};

async fn reply<W: AsyncWrite + Unpin>(w: &mut W, code: u16, msg: &str) -> Result<()> {
	w.write_all(format!("{code} {msg}\r\n").as_bytes()).await
}

#[derive(Clone, Copy, Debug)]
pub enum DeliveryMode {
	Transfer,
	Submission,
}

pub async fn handle_command<R, W>(
	command: Command,
	session: &mut SmtpSession,
	mode: DeliveryMode,
	config: &Config,
	reader: &mut R,
	writer: &mut W,
) -> Result<()>
where
	R: AsyncBufRead + Unpin,
	W: AsyncWrite + Unpin,
{
	handle_command_inner(command, session, mode, config, reader, writer).await
}

#[instrument(skip_all, fields(mode = ?mode, peer_ip = ?session.peer_ip))]
async fn handle_command_inner<R, W>(
	command: Command,
	session: &mut SmtpSession,
	mode: DeliveryMode,
	config: &Config,
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
			session.helo_domain = Some(domain.clone());
			reply(writer, 250, &domain).await?;
		}

		Command::Mail(from) => {
			if let Some(peer_ip) = session.peer_ip
				&& !rate_limit::allow_message(peer_ip, mode, config).await
			{
				event!(
					target: "smtp.ingress",
					Level::WARN,
					action = "reject",
					reason = "rate_limit_message",
					mode = ?mode,
					peer_ip = %peer_ip
				);
				reply(writer, 451, "4.7.1 Rate limit exceeded").await?;
				return Ok(());
			}
			session.state = SessionState::ReceivingMail;
			session.reset_txn();
			let txn = session.transaction.as_mut().expect("Transaction Exists");
			txn.mail_from = Some(from.clone());
			reply(writer, 250, "Ok").await?;
		}

		Command::Rcpt(to) => {
			if !matches!(
				session.state,
				SessionState::ReceivingMail | SessionState::ReceivingRcpt
			) {
				reply(writer, 503, "5.5.1 Bad sequence of commands").await?;
				return Ok(());
			}
			session.state = SessionState::ReceivingRcpt;
			let txn = session.transaction.as_mut().expect("Transaction Exists");
			if txn.rcpt_to.len() >= config.smtp.inbound_max_rcpt_to {
				reply(writer, 452, "4.5.3 Too many recipients").await?;
				return Ok(());
			}
			txn.rcpt_to.push(to.clone());
			reply(writer, 250, "OK").await?;
		}

		Command::Data => {
			let Some(txn) = session.transaction.as_ref() else {
				reply(writer, 503, "5.5.1 Bad sequence of commands").await?;
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

			let max_data_bytes = match mode {
				DeliveryMode::Transfer => config.smtp.max_message_bytes,
				DeliveryMode::Submission => OUTBOUND_MAX_MESSAGE_BYTES,
			};
			let raw = match read_message_data(reader, max_data_bytes).await {
				Ok(raw) => raw,
				Err(err) if err.kind() == ErrorKind::InvalidData => {
					reply(writer, 552, "5.3.4 Message size exceeds fixed maximum").await?;
					return Ok(());
				}
				Err(err) => return Err(err),
			};
			let parser = MessageParser::default();

			match parser.parse(&raw) {
				Some(message) => {
					if matches!(mode, DeliveryMode::Submission)
						&& let Some(actual) =
							find_oversized_attachment(&message, OUTBOUND_MAX_ATTACHMENT_BYTES)
					{
						event!(
							target: "smtp.policy.attachment_reject",
							Level::WARN,
							direction = "outbound",
							limit_bytes = OUTBOUND_MAX_ATTACHMENT_BYTES as i64,
							actual_bytes = actual as i64
						);
						reply(writer, 552, "5.3.4 Attachment exceeds fixed maximum").await?;
						session.state = SessionState::Ready;
						session.reset_txn();
						return Ok(());
					}

					let mut txn = session.transaction.take().unwrap();
					txn.data = Some(raw.clone());

					match mode {
						DeliveryMode::Transfer => {
							let Some(peer_ip) = session.peer_ip else {
								reply(writer, 451, "4.3.0 Missing peer address").await?;
								return Ok(());
							};
							let helo_domain = session.helo_domain.as_deref().unwrap_or("unknown");
							let mail_from = txn.mail_from.as_deref().unwrap_or("");
							let raw_message = message.raw_message();

							let verdict = verify_mail(
								peer_ip,
								helo_domain,
								&config.server.hostname,
								mail_from,
								raw_message,
								config.auth.allow_header_override,
							)
							.await;

							match verdict {
								Ok(v) => {
									if !accepted_for_recipients(config, &txn.rcpt_to, &v).await {
										reply(
											writer,
											550,
											"5.7.1 Message rejected by SPF/DKIM/DMARC policy",
										)
										.await?;
									} else {
										let stored = persist_incoming_message(
											raw_message,
											&message,
											&txn.rcpt_to,
										)
										.await;
										match stored {
											Ok(_) => {
												event!(
													target: "smtp.ingress",
													Level::INFO,
													action = "accept",
													mode = "transfer",
													outcome = "stored"
												);
												reply(writer, 250, "2.0.0 OK: received").await?;
											}
											Err(_) => {
												reply(
													writer,
													451,
													"4.3.0 Temporary local storage failure",
												)
												.await?;
											}
										}
									}
								}
								Err(_) => {
									reply(
										writer,
										451,
										"4.7.0 Authentication check temporary failure",
									)
									.await?;
								}
							}
						}
						DeliveryMode::Submission => {
							if config.smtp.outbound_queue.enabled {
								match queue::enqueue_transaction(&txn, config).await {
									Ok(_) => {
										event!(
											target: "smtp.egress",
											Level::INFO,
											action = "enqueue",
											mode = "submission"
										);
										reply(writer, 250, "2.0.0 OK: queued").await?;
									}
									Err(_) => {
										reply(writer, 451, "4.3.0 Queueing failure").await?;
									}
								}
							} else {
								match relay_transaction(&txn, config).await {
									Ok(()) => {
										event!(
											target: "smtp.egress",
											Level::INFO,
											action = "deliver",
											mode = "submission",
											outcome = "accepted"
										);
										reply(writer, 250, "2.0.0 OK: submitted").await?;
									}
									Err(_) => {
										reply(writer, 554, "5.7.1 Message delivery failed").await?;
									}
								}
							}
						}
					}
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
async fn read_message_data<R: AsyncBufRead + Unpin>(
	reader: &mut R,
	max_bytes: usize,
) -> Result<Vec<u8>> {
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
		if raw.len() > max_bytes {
			return Err(Error::new(
				ErrorKind::InvalidData,
				"message size exceeds configured maximum",
			));
		}
	}

	Ok(raw)
}
