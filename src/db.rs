use std::{sync::LazyLock, env};
use surrealdb::{engine::remote::http::{Client, Http}, opt::auth::Database, Surreal};
use tracing::info;

pub static DB: LazyLock<Surreal<Client>> = LazyLock::new(Surreal::init);

pub async fn init() {
	DB.connect::<Http>(env::var("DATABASE_HOSTNAME").unwrap_or(String::from("localhost:8000"))).await.unwrap();

	DB.signin(Database {
		namespace: env::var("DATABASE_NAMESPACE").unwrap(),
		database: env::var("DATABASE_DATABASE").unwrap(),
		username: env::var("DATABASE_USERNAME").unwrap(),
		password: env::var("DATABASE_PASSNAME").unwrap()
	}).await.unwrap();

	info!("Database initialized successfully");
}
