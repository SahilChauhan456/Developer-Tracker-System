mod auth;
mod db;
mod handlers;
mod models;

use axum::{
    Router,
    http::{HeaderValue, Method, header},
    routing::{get, patch, post},
};
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    if let Err(e) = dotenvy::dotenv() {
        eprintln!("Warning: Could not load .env file: {}", e);
    }

    let pool = db::create_pool().await;

    let cors = CorsLayer::new()
        .allow_origin(vec![
            "http://localhost:3000".parse::<HeaderValue>().unwrap(),
            "http://127.0.0.1:3000".parse::<HeaderValue>().unwrap(),
        ])
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    let app = Router::new()
        .route("/api/auth/register", post(handlers::register))
        .route("/api/auth/login", post(handlers::login))
        .route("/api/profile", get(handlers::get_profile))
        .route(
            "/api/issues",
            get(handlers::get_issues).post(handlers::create_issue),
        )
        .route(
            "/api/issues/{id}",
            patch(handlers::update_issue_status).delete(handlers::delete_issue),
        )
        .layer(cors)
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4000")
        .await
        .unwrap();

    println!("Rust API running on http://127.0.0.1:4000");
    axum::serve(listener, app).await.unwrap();
}
