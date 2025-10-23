use axum::{extract::Request, response::IntoResponse, Extension};
use dav_server::{fakels::FakeLs, DavHandler};

pub mod fs;
pub use fs::SurrealFS;

pub async fn instance() -> DavHandler<fs::Filter> {
	let fs = SurrealFS::new("/tmp");

	let handler = DavHandler::builder()
		.filesystem(Box::new(fs))
		.locksystem(FakeLs::new())
		.build_handler();

	handler
}

pub async fn dav_handler(Extension(dav): Extension<DavHandler<fs::Filter>>, request: Request) -> impl IntoResponse {
	let filter = fs::Filter::from_request(&request).await.unwrap();
	dav.handle_guarded(request, filter).await
}
