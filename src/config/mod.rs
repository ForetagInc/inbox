use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub server: ServerConfig,
}

#[derive(Deserialize, Debug)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub bind_port: u16,
    pub hostname: String,
    pub max_connections: usize,
}
