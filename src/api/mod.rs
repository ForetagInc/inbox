use async_graphql::{Context, EmptySubscription, Error, Object, Schema, http::GraphiQLSource};
use axum::response::{self, IntoResponse};

use crate::{
	config::Config,
	db,
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
		idempotency_key: Option<String>,
		actor_account: Option<String>,
		shared_inbox: Option<String>,
	) -> Result<bool, Error> {
		let config = ctx.data::<Config>()?;
		let shared_inbox = shared_inbox.map(|v| v.trim().to_ascii_lowercase());
		let actor_account = actor_account.map(|v| v.trim().to_string());
		if let Some(shared_address) = shared_inbox.as_deref() {
			let actor = actor_account
				.as_deref()
				.ok_or_else(|| Error::new("shared inbox send-as requires actor_account"))?;
			let allowed = db::can_send_as_shared_inbox(shared_address, actor)
				.await
				.map_err(Error::new)?;
			if !allowed {
				return Err(Error::new(
					"shared inbox send-as denied: actor is not an active member with can_send_as",
				));
			}
		}
		let request = OutgoingRequest {
			from,
			to,
			subject,
			text_body,
			html_body,
			idempotency_key,
			actor_account: actor_account.clone(),
			shared_inbox: shared_inbox.clone(),
		};

		if config.smtp.outbound_queue.enabled {
			let enqueued = queue::enqueue_outgoing_request(request, config)
				.await
				.map_err(|e| Error::new(e.to_string()))?;
			if let (Some(shared), Some(actor)) = (shared_inbox.as_deref(), actor_account.as_deref())
				&& let Ok(Some(row)) = db::find_shared_inbox_by_address(shared).await
				&& let Some(shared_id) = row.id.and_then(db::extract_record_id)
			{
				let _ = db::record_shared_inbox_event(&shared_id, actor, "send_as", None).await;
			}
			let _ = enqueued;
			Ok(true)
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
