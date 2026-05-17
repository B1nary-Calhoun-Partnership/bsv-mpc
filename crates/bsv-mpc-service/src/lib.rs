//! Library interface for the standalone MPC Key Share Service.
//!
//! Exposes the service's handlers, storage, and router construction
//! so they can be used from integration tests and embedded deployments.

pub mod handlers;
pub mod messagebox;
pub mod storage;

pub use messagebox::{HandlerFuture, MessageBoxListener, OutgoingRoundMessage};

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use std::sync::RwLock;

pub use storage::SqliteShareStorage;

/// Shared application state, accessible from all request handlers.
pub struct AppState {
    /// Path to the data directory where the SQLite database lives.
    pub data_dir: String,
    /// In-memory (dev) or SQLite-backed share storage.
    pub storage: RwLock<SqliteShareStorage>,
    /// Server start time for uptime reporting.
    pub started_at: chrono::DateTime<chrono::Utc>,
}

/// Build the Axum router with all KSS endpoints.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        // DKG protocol
        .route("/dkg/init", post(handlers::handle_dkg_init))
        .route("/dkg/round", post(handlers::handle_dkg_round))
        // Signing protocol
        .route("/sign/init", post(handlers::handle_sign_init))
        .route("/sign/round", post(handlers::handle_sign_round))
        // Partial ECDH (for BRC-42 key derivation)
        .route("/ecdh", post(handlers::handle_ecdh))
        // Presigning protocol
        .route("/presign/init", post(handlers::handle_presign_init))
        .route("/presign/round", post(handlers::handle_presign_round))
        // Read-only
        .route("/health", get(handlers::handle_health))
        .route(
            "/shares/{agent_id}",
            get(handlers::handle_get_share_metadata),
        )
        // Authrite handshake
        .route("/.well-known/auth", post(handlers::handle_authrite))
        .with_state(state)
}
