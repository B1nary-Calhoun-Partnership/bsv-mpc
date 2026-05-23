//! Library interface for the standalone MPC Key Share Service.
//!
//! Exposes the service's handlers, storage, and router construction
//! so they can be used from integration tests and embedded deployments.

pub mod auth;
pub mod custody;
pub mod dkg_handler;
pub mod handlers;
pub mod messagebox;
pub mod presign_handler;
pub mod provision;
pub mod refresh_handler;
pub mod refresh_relay_handlers;
pub mod reshar_handler;
pub mod reshare_relay_handlers;
pub mod relay_handlers;
pub mod sign_relay_handler;
pub mod signing_handler;
pub mod storage;

pub use auth::AuthState;
pub use dkg_handler::DkgHandler;
pub use refresh_handler::RefreshHandler;
pub use reshar_handler::ResharHandler;
pub use messagebox::{HandlerFuture, MessageBoxListener, OutgoingRoundMessage};
pub use presign_handler::{
    BundleStore, FileBundleStore, InMemoryBundleStore, PresignHandler, PresignHandlerConfig,
    PresignOutcome,
};
pub use signing_handler::SigningHandler;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use std::sync::RwLock;

pub use storage::SqliteShareStorage;

/// Optional presignature-provisioning config (#4): when set, the service ships
/// each generated `Presignature_A` to the cosigner DO's pool over the authed
/// `/ceremony/ingest-presig` route, making the deployed cosigner self-stocking.
pub struct ProvisionConfig {
    /// Base URL of the cosigner DO worker (e.g. `https://…workers.dev`).
    pub worker_url: String,
    /// The service's BRC-31 session to the worker (lazy handshake, cached).
    pub auth: tokio::sync::Mutex<bsv_mpc_core::brc31_client::Brc31Client>,
    /// HTTP client for outbound provisioning requests.
    pub http: reqwest::Client,
}

/// Optional durable share custody (#9): when set, the cosigner persists its
/// KEK-wrapped `share_A` to the worker DO (`/custody/put-share`) at DKG-complete
/// and lazily reloads it (`/custody/get-share`) on a cache miss after a restart
/// — so an ephemeral-container restart can never permanently lock funds.
pub struct CustodyConfig {
    /// Base URL of the durable worker DO (e.g. `https://…workers.dev`).
    pub worker_url: String,
    /// The 32-byte KEK (derived from the cosigner's stable identity secret) that
    /// seals `share_A` before it leaves this process. The DO never sees it.
    pub kek: [u8; 32],
    /// Stable BRC-31 session to the worker (the custody-record owner identity).
    pub auth: tokio::sync::Mutex<bsv_mpc_core::brc31_client::Brc31Client>,
    /// HTTP client for outbound custody requests.
    pub http: reqwest::Client,
}

/// Shared application state, accessible from all request handlers.
pub struct AppState {
    /// Path to the data directory where the SQLite database lives.
    pub data_dir: String,
    /// In-memory (dev) or SQLite-backed share storage.
    pub storage: RwLock<SqliteShareStorage>,
    /// Server start time for uptime reporting.
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Presignature provisioning to the cosigner DO (`None` = disabled).
    pub provision: Option<ProvisionConfig>,
    /// BRC-31 server auth config + live session store (§07/§08.1). Built via
    /// [`AuthState::from_env`] in production (enforced when
    /// `MPC_SERVER_PRIVATE_KEY` is set), or [`AuthState::dev`] in dev/tests.
    pub auth: AuthState,
    /// Durable share custody to the worker DO (`None` = disabled / in-memory only).
    pub custody: Option<CustodyConfig>,
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
        // §06.17.1 container-as-cosigner over the relay (#30, CONTAINER target):
        // arm the presign-over-relay cosigner + co-sign from the coordinator-held
        // ciphertext. Additive — does NOT alter the §06.20 HTTP presign/sign path.
        .route(
            "/presign-relay/identity",
            get(relay_handlers::handle_presign_relay_identity),
        )
        .route(
            "/presign-relay/init",
            post(relay_handlers::handle_presign_relay_init),
        )
        .route("/sign-relay", post(relay_handlers::handle_sign_relay))
        // §18.2 container key-refresh over the relay (#10, CONTAINER target):
        // arm the container as a refresh peer + rotate-on-commit (purges presigs
        // per §18.9). Heavy MPC — container only, NOT the worker isolate.
        .route(
            "/refresh-relay/identity",
            get(refresh_relay_handlers::handle_refresh_relay_identity),
        )
        .route(
            "/refresh-relay/init",
            post(refresh_relay_handlers::handle_refresh_relay_init),
        )
        // §18.2 container cross-(t,n) reshare over the relay (#35c pt2, CONTAINER
        // target): arm the container as a reshare peer (phase A throwaway DKG +
        // phase B PSS), combine, then store the rotated new-(t,n) share + purge
        // presigs. Heavy MPC — container only, NOT the worker isolate.
        .route(
            "/reshare-relay/identity",
            get(reshare_relay_handlers::handle_reshare_relay_identity),
        )
        .route(
            "/reshare-relay/init",
            post(reshare_relay_handlers::handle_reshare_relay_init),
        )
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
