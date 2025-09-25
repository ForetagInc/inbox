use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tracing::{error, info};

use crate::config::Config;
use crate::protocol::state::SmtpSession;

pub struct TcpServer {
    listener: TcpListener,
    config: Arc<Config>,
    limit_connections: Arc<Semaphore>,
}

impl TcpServer {
    pub async fn from_config(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", config.server.bind_addr, config.server.bind_port);
        let listener = TcpListener::bind(&addr).await?;

        let limit_connections = Arc::new(Semaphore::new(config.server.max_connections));

        info!("TCP server listening on {}", addr);
        info!("  - Max connections: {}", config.server.max_connections);

        Ok(TcpServer {
            listener,
            config: Arc::new(config),
            limit_connections,
        })
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            let permit = self.limit_connections.clone().acquire_owned().await?;

            let (socket, addr) = self.listener.accept().await?;

            let config_clone = self.config.clone();

            tokio::spawn(async move {
                drop(permit);

                if let Err(e) = Self::handle_connection(socket, config_clone).await {
                    error!("Error handling connection from {}: {}", addr, e)
                }
            });
        }
    }

    async fn handle_connection(
        mut socket: TcpStream,
        config: Arc<Config>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (reader, mut writer) = socket.split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        let mut session = SmtpSession::new();

        let greeting = format!("220 {} ESMTP server\r\n", config.server.hostname);
        writer.write_all(greeting.as_bytes()).await?;

        session.state = crate::protocol::state::SessionState::Ready;

        loop {
            line.clear();

            let bytes_read = reader.read_line(&mut line).await?;

            if bytes_read == 0 {
                // Connection closed by client
                return Ok(());
            }

            let command = line.trim();

            match command {
                // TODO: Matchers for all commands
                "QUIT" => {
                    writer.write_all(b"221 Bye\r\n").await?;
                    break;
                }
                _ => {
                    writer.write_all(b"500 Unrecognized state\r\n").await?;
                }
            }
        }

        Ok(())
    }
}
