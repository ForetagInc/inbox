use std::{io::Error, net::{IpAddr, Ipv4Addr}};
use tokio::{io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader}, net::{TcpListener, TcpStream}};
use tracing::{Level, error, event};

use crate::{config::Config, protocols::smtp::{commands::Command, handler, rate_limit, state::{SessionState, SmtpSession}}};

pub struct TransferServer<'a> {
	listener: TcpListener,
	config: &'a Config,
}

impl<'a> TransferServer<'a> {
	pub async fn from_config(config: &'a Config) -> Self {
		let addr = format!("{}:{}", config.server.bind_addr, config.smtp.transfer_port);
		let listener = TcpListener::bind(&addr).await.unwrap();

		Self {
			listener,
			config
		}
	}

	pub async fn run(self) -> io::Result<()> {
		loop {
			let (socket, addr) = match self.listener.accept().await {
				Ok(v) => v,
				Err(err) => {
					error!("Accept error: {err}");
					continue;
				}
			};

			let cfg = self.config.clone();

			tokio::spawn(async move {
				if let Err(err) = Self::handle_connection(socket, &cfg).await {
					error!("Error handling connection from {}: {}", addr, err);
				}
			});
		}
	}

	async fn handle_connection(mut socket: TcpStream, config: &Config) -> Result<(), Error> {
		let peer_ip = socket.peer_addr().ok().map(|addr| addr.ip()).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
		if !rate_limit::allow_connection(peer_ip, handler::DeliveryMode::Transfer, config).await {
			event!(
				target: "smtp.ingress",
				Level::WARN,
				action = "reject",
				reason = "rate_limit_connection",
				mode = "transfer",
				peer_ip = %peer_ip
			);
			let _ = socket.write_all(b"421 4.7.1 Rate limit exceeded\r\n").await;
			return Ok(());
		}
		let (reader, mut writer) = socket.split();
		let mut reader = BufReader::new(reader);
		let mut line = String::new();

		let mut session = SmtpSession::new(peer_ip);

		let greeting = format!("220 {} Inbox SMTP\r\n", config.server.hostname);
		writer.write_all(greeting.as_bytes()).await?;

		session.state = SessionState::Ready;

		loop {
			line.clear();
			let bytes_read = reader.read_line(&mut line).await?;

			if bytes_read == 0 {
				break;
			}

			let trimmed = line.trim_end_matches(['\r', '\n']);
			match Command::parse(trimmed) {
				Ok(command) => {
					handler::handle_command(
						command,
						&mut session,
						handler::DeliveryMode::Transfer,
						config,
						&mut reader,
						&mut writer
					)
					.await?;
					if session.state == SessionState::Finished {
						break;
					}
				}
				Err(e) => {
					writer
						.write_all(format!("500 {}\r\n", e).as_bytes())
						.await?;
				}
			}
		}

		Ok(())
	}
}
