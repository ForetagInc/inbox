use tracing::error;

use crate::config::r2;
use crate::integrations::clamav;
use crate::integrations::clamav::error::ClamAVError;

#[derive(Debug)]
pub struct Attachment {
	pub name: String,
	pub data: Vec<u8>
}

impl Attachment {
	pub fn new(name: String, data: Vec<u8>) -> Self {
	 	Self {
			name,
			data
		}
	}

	pub async fn scan(&self) -> Result<bool, ClamAVError> {
		let clamav = clamav::instance();

		let clamd_available = match clamav_client::tokio::ping(clamav).await {
			Ok(response) => response == clamav_client::PONG,
			Err(_) => false
		};

		if !clamd_available {
			error!("ClamD is not available");
			return Err(ClamAVError::Unavailable);
		}

		let stream_result = clamav_client::tokio::scan_buffer(&self.data, clamav, None).await;

		match stream_result {
			Ok(result) => {
				let clean = clamav_client::clean(&result).unwrap();
				if clean {
					Ok(true)
				} else {
					Ok(false)
				}
			},
			Err(_) => Err(ClamAVError::ScanFailed),
		}
	}

	pub async fn upload(&self) {
		let scan = self.scan().await;
		let file = r2::instance().await;

		match scan {
			Ok(true) => {
				file.upload("", &self.data, None, None).await;
			},
			Ok(false) => error!("Attachment is infected"),
			Err(err) => error!("Failed to scan attachment: {}", err)
		}
	}
}

pub fn find_oversized_attachment(
	parsed: &mail_parser::Message<'_>,
	limit_bytes: usize,
) -> Option<usize> {
	parsed
		.attachments()
		.map(|part| part.contents().len())
		.find(|size| *size > limit_bytes)
}
