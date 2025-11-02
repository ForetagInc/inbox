extern crate dotenv;

use dotenv::dotenv;

use crate::{
	config::{Config, ServerConfig},
	server::{http::HTTPServer, submission::SubmissionServer, transfer::TransferServer}
};

pub mod api;
pub mod config;
pub mod db;
pub mod integrations;
pub mod protocols;
pub mod server;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
	dotenv().ok();
	tracing_subscriber::fmt::init();

	// db::init().await;

	let config = Config {
		server: ServerConfig {
			hostname: "mail.wrkshp.so".to_string(),
			bind_addr: "0.0.0.0".to_string(),
			max_connections: 10,
		},
	};

    let http_server = HTTPServer::serve().await;

	let transfer_server = TransferServer::from_config(&config).await.run();
	let submission_server = SubmissionServer::from_config(&config).await.run();

	tokio::try_join!(http_server, transfer_server, submission_server)?;

	Ok(())
}
