use axum::{Extension, Router, routing::{any, get}};
use tokio::net::TcpListener;
use async_graphql_axum::GraphQL;
use tracing::info;

use crate::api::{schema, graphiql};
use crate::protocols::dav::{instance, dav_handler};

pub async fn create_server() {
	// .route("/dav", any(dav_handler))
	// .route("/dav/", any(dav_handler))
	// .route("/dav/{*path}", any(dav_handler))
	// .layer(Extension(instance))
	let app = Router::new()
		.route("/graphql", get(graphiql).post_service(GraphQL::new(schema())));

	let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
	axum::serve(listener, app).await.unwrap();

	info!("Started HTTP Server on http://0.0.0.0:3000");
}
