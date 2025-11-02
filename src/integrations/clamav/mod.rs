pub mod error;

use clamav_client::tokio::Tcp;

pub fn instance() -> Tcp<&'static str> {
	let client = Tcp { host_address: "localhost:3310" };
	client
}
