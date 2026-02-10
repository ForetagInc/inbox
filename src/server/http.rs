use async_graphql_axum::GraphQL;
use axum::{Extension, Router, routing::get};
use std::{future::Future, io::Error};
use tokio::net::TcpListener;
use tracing::info;

use crate::api::{schema, graphiql};
use crate::config::Config;
use crate::protocols::dav::instance;

pub struct HTTPServer {
	pub router: Router
}

impl HTTPServer {
	pub async fn serve(config: Config) -> impl Future<Output = Result<(), Error>> {
		async move {
			let router = Router::new()
				// .route("/dav", any(dav_handler))
				// .route("/dav/", any(dav_handler))
				// .route("/dav/{*path}", any(dav_handler))
				.layer(Extension(instance))
				.route("/graphql", get(graphiql).post_service(GraphQL::new(schema(config))));

			let listener = TcpListener::bind("0.0.0.0:3000").await?;
			info!("[HTTP] Listening on http://0.0.0.0:3000");
			axum::serve(listener, router).await
		}
	}
}
