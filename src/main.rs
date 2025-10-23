use crate::{
	config::{Config, ServerConfig},
	server::{submission::SubmissionServer, transfer::TransferServer}
};

pub mod api;
pub mod config;
pub mod protocols;
pub mod server;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
	tracing_subscriber::fmt::init();

	let config = Config {
		server: ServerConfig {
			bind_addr: "0.0.0.0".to_string(),
			max_connections: 10,
		},
	};

    // let http_server = server::http::create_server().await;

	let transfer_server = TransferServer::from_config(&config).await.run();
	let submission_server = SubmissionServer::from_config(&config).await.run();

	tokio::try_join!(transfer_server, submission_server)?;

	Ok(())
}
