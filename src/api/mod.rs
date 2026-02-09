use async_graphql::{Context, EmptySubscription, Error, Object, Schema, http::GraphiQLSource};
use axum::response::{self, IntoResponse};

use crate::{
	config::Config,
	protocols::smtp::{
		handler::outgoing::{OutgoingRequest, send_outgoing},
		queue,
	},
};

pub struct Query;

#[Object]
impl Query {
	async fn hello(&self) -> &'static str {
		"world"
	}
}

pub struct Mutation;

#[Object]
impl Mutation {
	async fn send_email(
		&self,
		ctx: &Context<'_>,
		from: String,
		to: Vec<String>,
		subject: String,
		text_body: Option<String>,
		html_body: Option<String>,
	) -> Result<bool, Error> {
		let config = ctx.data::<Config>()?;
		let request = OutgoingRequest {
			from,
			to,
			subject,
			text_body,
			html_body,
		};

		if config.smtp.outbound_queue.enabled {
			queue::enqueue_outgoing_request(request, config)
				.await
				.map(|_| true)
				.map_err(|e| Error::new(e.to_string()))
		} else {
			send_outgoing(request, config)
				.await
				.map(|_| true)
				.map_err(|e| Error::new(e.to_string()))
		}
	}
}

pub async fn graphiql() -> impl IntoResponse {
	response::Html(GraphiQLSource::build().endpoint("/graphql").finish())
}

pub fn schema(config: Config) -> Schema<Query, Mutation, EmptySubscription> {
	let schema = Schema::build(Query, Mutation, EmptySubscription)
		.data(config)
		.finish();

	schema
}
