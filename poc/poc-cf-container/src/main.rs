//! Minimal Rust axum service for the CF Containers platform probe (P1).
//! Proves a Rust HTTP service builds + runs in a Cloudflare Container and is
//! reachable from the Worker/DO proxy. Listens on `$PORT` (default 8080), the
//! `defaultPort` the Container DO class declares.

use axum::{routing::get, Json, Router};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route(
            "/health",
            get(|| async {
                Json(serde_json::json!({
                    "status": "ok",
                    "service": "poc-cf-container",
                    "runtime": "native-rust-on-cf-container",
                }))
            }),
        )
        .route("/", get(|| async { "poc-cf-container alive" }));

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("bind");
    eprintln!("poc-cf-container listening on 0.0.0.0:{port}");
    axum::serve(listener, app).await.expect("serve");
}
