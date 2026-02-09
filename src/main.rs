extern crate dotenv;

use dotenv::dotenv;
use inbox::{
	db,
	config::Config,
	server::{http::HTTPServer, submission::SubmissionServer, transfer::TransferServer}
};
use tracing::warn;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
	dotenv().ok();
	tracing_subscriber::fmt::init();

	if let Err(err) = db::init().await {
		warn!("Database initialization failed: {err}. Domain tenant overrides will be disabled.");
	}

	let config = Config::from_env();

	let http_server = HTTPServer::serve(config.clone()).await;

	let transfer_server = TransferServer::from_config(&config).await.run();
	let submission_server = SubmissionServer::from_config(&config).await.run();

	tokio::try_join!(http_server, transfer_server, submission_server)?;

	Ok(())
}
