use axum::{Extension, Router, routing::{any, get}};
use tokio::{io, net::TcpListener};
use async_graphql_axum::GraphQL;
use tracing::info;
use std::{future::Future, io::Error};

use crate::api::{schema, graphiql};
use crate::protocols::dav::{instance, dav_handler};

pub struct HTTPServer {
	pub router: Router
}

impl HTTPServer {
	pub async fn serve() -> impl Future<Output = Result<(), Error>> {
		async move {
			let router = Router::new()
				// .route("/dav", any(dav_handler))
				// .route("/dav/", any(dav_handler))
				// .route("/dav/{*path}", any(dav_handler))
				// .layer(Extension(instance))
				.route("/graphql", get(graphiql).post_service(GraphQL::new(schema())));

			let listener = TcpListener::bind("0.0.0.0:3000").await?;
			info!("[HTTP] Listening on http://0.0.0.0:3000");
			axum::serve(listener, router).await
		}
	}
}
