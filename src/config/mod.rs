pub mod r2;

use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
	pub server: ServerConfig,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ServerConfig {
	pub hostname: String,
	pub bind_addr: String,
	pub max_connections: usize,
}
