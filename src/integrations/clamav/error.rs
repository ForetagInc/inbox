use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClamAVError {
	#[error("ClamAV service is unavailable")]
	Unavailable,

	#[error("Scan failed")]
	ScanFailed,
}
