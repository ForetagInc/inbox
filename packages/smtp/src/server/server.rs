use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tracing::{debug, error, info};

use crate::config::Config;

pub struct TcpServer {
    listener: TcpListener,
    config: Config,
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
            config,
            limit_connections,
        })
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            let permit = self.limit_connections.clone().acquire_owned().await?;

            let (socket, addr) = self.listener.accept().await?;
            info!("New connection from: {}", addr);

            tokio::spawn(async move {
                drop(permit);

                if let Err(e) = Self::handle_connection(socket).await {
                    error!("Error handling connection from {}: {}", addr, e)
                }
            });
        }
    }

    async fn handle_connection(mut socket: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = [0; 1024];

        loop {
            let n = socket.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }

            let received = std::str::from_utf8(&buf[0..n])?;
            debug!("Received: {}", received.trim());
            socket.write_all(&buf[0..n]).await?;
        }
    }
}
