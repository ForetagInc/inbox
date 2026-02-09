use cloudflare_r2_rs::r2::R2Manager;

pub async fn instance() -> R2Manager {
	let bucket = std::env::var("S3_BUCKET").unwrap_or_else(|_| "bucket".to_string());
	let endpoint =
		std::env::var("S3_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".to_string());
	let key = std::env::var("S3_ACCESS_KEY_ID").unwrap_or_else(|_| "key".to_string());
	let secret = std::env::var("S3_SECRET_ACCESS_KEY").unwrap_or_else(|_| "secret".to_string());
	let region = std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());
	R2Manager::new_with_region(&bucket, &endpoint, &key, &secret, &region).await
}
