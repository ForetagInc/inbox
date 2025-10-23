use tokio::{io::{AsyncBufReadExt, AsyncWriteExt, BufReader}, net::{TcpListener, TcpStream}};
use tracing::{error, info};

use crate::{config::Config, protocols::smtp::{commands::Command, handler, state::SmtpSession}};

pub struct SubmissionServer<'a> {
	listener: TcpListener,
	config: &'a Config,
}

impl<'a> SubmissionServer<'a> {
	pub async fn from_config(config: &'a Config) -> Self {
		let addr = format!("{}:{}", config.server.bind_addr, 587);
		let listener = TcpListener::bind(&addr).await.unwrap();

		info!("[SMTP - Submission] Server initialized on {}", addr);

		Self {
			listener,
			config
		}
	}

	pub async fn run(self) {
		info!("[SMTP - Submission] Server listening for requests");

		loop {
			let (socket, addr) = self.listener.accept().await.unwrap();
			let config = self.config.clone();

			tokio::spawn(async move {
				if let Err(e) = Self::handle_connection(socket, &config).await {
					error!("Error handling connection from {}: {}", addr, e)
				}
			});
		}
	}

	async fn handle_connection(mut socket: TcpStream, config: &Config) -> Result<(), String> {
		let (reader, mut writer) = socket.split();
		let mut reader = BufReader::new(reader);
		let mut line = String::new();

		let mut session = SmtpSession::new();

		let greeting = format!("220 {} Inbox SMTP server\r\n", config.server.bind_addr);
		writer.write_all(greeting.as_bytes()).await;

		session.state = crate::protocols::smtp::state::SessionState::Ready;

		loop {
			line.clear();

			let bytes_read = reader.read_line(&mut line).await.unwrap();

			if bytes_read == 0 {
				// Connection closed by client
				return Ok(());
			}

			let command = Command::parse(line.trim());

			match command {
				Ok(command) => {
					let response = handler::handle_command(command, &mut session);
					writer
						.write_all(format!("{}\r\n", response).as_bytes())
						.await;
				}
				Err(e) => {
					writer
						.write_all(format!("500 {}\r\n", e).as_bytes())
						.await;
				}
			}
		}
	}
}
