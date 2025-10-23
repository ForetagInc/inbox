use crate::{
    config::{Config, ServerConfig},
    server::server::TcpServer,
};

pub mod config;
pub mod protocol;
pub mod protocols;
pub mod server;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let config = Config {
        server: ServerConfig {
            bind_addr: "0.0.0.0".to_string(),
            bind_port: 25,
            hostname: "localhost".to_string(),
            max_connections: 10,
        },
    };

    let server = TcpServer::from_config(config).await?;
    server.run().await?;

    Ok(())
}
