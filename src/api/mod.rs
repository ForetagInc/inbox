use async_graphql::{http::GraphiQLSource, EmptySubscription, Object, Schema};
use axum::response::{self, IntoResponse};

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
	async fn send_email(&self) -> bool {
		true
	}
}

pub async fn graphiql() -> impl IntoResponse {
	response::Html(GraphiQLSource::build().endpoint("/").finish())
}

pub fn schema() -> Schema<Query, Mutation, EmptySubscription> {
	let schema = Schema::build(Query, Mutation, EmptySubscription)
    	.finish();

	schema
}
