use cloudflare_r2_rs::r2::R2Manager;

pub async fn instance() -> R2Manager {
	R2Manager::new("bucket", "xd", "api-token-id", "api-token-secret").await
}
