//! Axum HTTP server with BRC-100 endpoint routing.
//!
//! This module sets up the HTTP server that bsv-worm (and any other BRC-100
//! client) talks to. Every route matches the bsv-wallet-cli API surface —
//! same paths, same request/response shapes. The proxy is a transparent
//! drop-in replacement.
//!
//! ## Route organization
//!
//! Routes are grouped by the subsystem that handles them:
//!
//! - **Core signing** — `getPublicKey`, `createSignature`, `verifySignature`,
//!   `createAction`, `internalizeAction`. These go through the MPC bridge.
//! - **Encryption** — `encrypt`, `decrypt`, `createHmac`, `verifyHmac`.
//!   These use locally-derived keys; no MPC rounds needed.
//! - **UTXO management** — `listOutputs`, `listActions`, `relinquishOutput`.
//!   Query the local UTXO tracker.
//! - **Identity & auth** — `getNetwork`, `getVersion`, `isAuthenticated`.
//!   Static or trivial responses.
//! - **Certificates** — `listCertificates`, `proveCertificate`,
//!   `acquireCertificate`, `relinquishCertificate`. Local certificate store.
//! - **Discovery** — `discoverByIdentityKey`, `discoverByAttributes`.
//!   Forwarded to overlay network.
//! - **Key linkage** — `revealCounterpartyKeyLinkage`, `revealSpecificKeyLinkage`.
//!   BRC-42 key derivation revelations.
//! - **Health** — Liveness check for load balancers and monitoring.

use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::bridge::MpcBridge;
use crate::config::ProxyConfig;
use crate::fee_injector::FeeInjector;
use crate::presign_manager::{self, PresignManager};
use crate::utxo_tracker::UtxoTracker;
use crate::wallet_api;

/// Shared application state accessible from all route handlers.
///
/// Wrapped in `Arc` so it can be shared across the axum router, the
/// background presignature replenishment task, and any future background
/// workers.
pub struct AppState {
    /// Proxy configuration (immutable after startup).
    pub config: ProxyConfig,

    /// MPC bridge for threshold signing operations.
    ///
    /// The bridge holds this party's decrypted share, the joint public key,
    /// and an HTTP client for communicating with the KSS.
    pub bridge: MpcBridge,

    /// Pool of pre-computed presignatures for single-round online signing.
    ///
    /// Protected by `RwLock` because reads (checking pool size) are much more
    /// frequent than writes (adding/removing presignatures).
    pub presign_manager: Arc<RwLock<PresignManager>>,

    /// Fee injector for adding MPC signing fees to transactions.
    pub fee_injector: FeeInjector,

    /// Local UTXO tracker for outputs controlled by the proxy.
    ///
    /// Protected by `RwLock` — reads (listOutputs, balance checks) are
    /// frequent, writes (createAction spending, internalizeAction adding)
    /// are less frequent.
    pub utxo_tracker: Arc<RwLock<UtxoTracker>>,
}

/// Start the BRC-100 HTTP server.
///
/// This function:
/// 1. Loads and decrypts the key share
/// 2. Initializes the MPC bridge with the KSS
/// 3. Starts the background presignature replenishment task
/// 4. Binds to `0.0.0.0:{port}` and serves BRC-100 endpoints
///
/// # Errors
///
/// Returns an error if the share file cannot be loaded, the KSS is
/// unreachable during initialization, or the TCP listener fails to bind.
pub async fn run(config: ProxyConfig) -> anyhow::Result<()> {
    let bridge = MpcBridge::new(&config).await?;

    let fee_injector = FeeInjector::new(
        config.fee_per_signing,
        config.fee_addresses.clone(),
        config.fee_threshold.clone(),
    );

    let presign_manager = Arc::new(RwLock::new(PresignManager::new(
        config.max_presignatures,
    )));

    let utxo_tracker = Arc::new(RwLock::new(UtxoTracker::new()));

    let state = Arc::new(AppState {
        config: config.clone(),
        bridge,
        presign_manager: presign_manager.clone(),
        fee_injector,
        utxo_tracker,
    });

    // Background presignature replenishment — runs forever, generating
    // presignatures during idle time so online signing is single-round.
    let bg_state = state.clone();
    tokio::spawn(async move {
        presign_manager::background_replenish(bg_state).await;
    });

    let app = Router::new()
        // ── Core signing (MPC) ───────────────────────────────────────────
        //
        // These endpoints trigger actual 2PC threshold signing ceremonies
        // with the KSS. `createAction` is the main transaction-building
        // endpoint that bsv-worm calls for every on-chain operation.
        .route("/getPublicKey", post(wallet_api::get_public_key))
        .route("/createSignature", post(wallet_api::create_signature))
        .route("/verifySignature", post(wallet_api::verify_signature))
        .route("/createAction", post(wallet_api::create_action))
        .route("/internalizeAction", post(wallet_api::internalize_action))
        // ── Encryption (local) ───────────────────────────────────────────
        //
        // Encryption uses locally-derived symmetric keys (BRC-42 key
        // derivation from the MPC share). No network round-trips needed.
        .route("/encrypt", post(wallet_api::encrypt))
        .route("/decrypt", post(wallet_api::decrypt))
        .route("/createHmac", post(wallet_api::create_hmac))
        .route("/verifyHmac", post(wallet_api::verify_hmac))
        // ── UTXO management ──────────────────────────────────────────────
        //
        // The proxy maintains its own UTXO set, tracking outputs by basket
        // (BRC-46) and tags. This is the same data model as bsv-wallet-cli.
        .route("/listOutputs", post(wallet_api::list_outputs))
        .route("/listActions", post(wallet_api::list_actions))
        .route("/relinquishOutput", post(wallet_api::relinquish_output))
        // ── Identity & auth ──────────────────────────────────────────────
        //
        // Static or trivial endpoints. `getPublicKey` with `identityKey: true`
        // is the canonical way to get the agent's identity key.
        .route("/getNetwork", post(wallet_api::get_network))
        .route("/getVersion", post(wallet_api::get_version))
        .route("/isAuthenticated", post(wallet_api::is_authenticated))
        // ── Certificates ─────────────────────────────────────────────────
        //
        // BRC-52 certificate storage and proof. Certificates are stored
        // locally; signing uses the MPC bridge.
        .route("/listCertificates", post(wallet_api::list_certificates))
        .route("/proveCertificate", post(wallet_api::prove_certificate))
        .route(
            "/acquireCertificate",
            post(wallet_api::acquire_certificate),
        )
        .route(
            "/relinquishCertificate",
            post(wallet_api::relinquish_certificate),
        )
        // ── Discovery ────────────────────────────────────────────────────
        //
        // BRC-56 peer discovery. Forwarded to the overlay network.
        .route(
            "/discoverByIdentityKey",
            post(wallet_api::discover_by_identity_key),
        )
        .route(
            "/discoverByAttributes",
            post(wallet_api::discover_by_attributes),
        )
        // ── Key linkage ──────────────────────────────────────────────────
        //
        // BRC-42 key linkage revelation for third-party auditors.
        .route(
            "/revealCounterpartyKeyLinkage",
            post(wallet_api::reveal_counterparty_key_linkage),
        )
        .route(
            "/revealSpecificKeyLinkage",
            post(wallet_api::reveal_specific_key_linkage),
        )
        // ── Health ───────────────────────────────────────────────────────
        .route("/health", get(wallet_api::health))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", config.port);
    tracing::info!("MPC Signing Proxy listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
