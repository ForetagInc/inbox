use crate::{
    config::{Config, ServerConfig},
    server::server::TcpServer,
};

pub mod config;
pub mod server;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let config = Config {
        server: ServerConfig {
            bind_addr: "127.0.0.1".to_string(),
            bind_port: 8080,
            hostname: "localhost".to_string(),
            max_connections: 5,
        },
    };

    let server = TcpServer::from_config(config).await?;
    server.run().await?;

    Ok(())
}
