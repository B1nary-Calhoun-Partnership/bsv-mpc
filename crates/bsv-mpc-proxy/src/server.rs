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
use crate::storage::{InMemoryBackend, StorageBackend};
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

    /// Storage backend for UTXO management.
    ///
    /// In standalone mode this is an [`InMemoryBackend`] wrapping the
    /// [`UtxoTracker`]. In hosted mode it delegates to wallet-infra's
    /// `StorageClient`. The backend handles its own locking internally.
    pub storage: Arc<dyn StorageBackend>,

    /// Shared HTTP client for broadcasting transactions and other outbound requests.
    pub http_client: reqwest::Client,
}

/// Builder for constructing an `AppState` with all required components.
///
/// This is the primary entry point for library consumers who want to
/// construct an MPC signing proxy programmatically (without the HTTP server).
///
/// # Example
///
/// ```rust,no_run
/// use bsv_mpc_proxy::{ProxyBuilder, ProxyConfig};
///
/// # async fn example() -> anyhow::Result<()> {
/// let config = ProxyConfig::from_env()?;
/// let state = ProxyBuilder::new(config).build().await?;
/// // Use state.bridge, state.fee_injector, etc. directly
/// # Ok(())
/// # }
/// ```
pub struct ProxyBuilder {
    config: ProxyConfig,
    bridge: Option<MpcBridge>,
    fee_injector: Option<FeeInjector>,
    presign_manager: Option<PresignManager>,
    storage: Option<Arc<dyn StorageBackend>>,
    http_client: Option<reqwest::Client>,
}

impl ProxyBuilder {
    /// Create a new builder from a proxy configuration.
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            bridge: None,
            fee_injector: None,
            presign_manager: None,
            storage: None,
            http_client: None,
        }
    }

    /// Override the MPC bridge (skips KSS connection during build).
    pub fn with_bridge(mut self, bridge: MpcBridge) -> Self {
        self.bridge = Some(bridge);
        self
    }

    /// Override the fee injector.
    pub fn with_fee_injector(mut self, injector: FeeInjector) -> Self {
        self.fee_injector = Some(injector);
        self
    }

    /// Override the presignature manager.
    pub fn with_presign_manager(mut self, manager: PresignManager) -> Self {
        self.presign_manager = Some(manager);
        self
    }

    /// Override the storage backend.
    ///
    /// Defaults to [`InMemoryBackend`] if not specified.
    pub fn with_storage(mut self, storage: impl StorageBackend + 'static) -> Self {
        self.storage = Some(Arc::new(storage));
        self
    }

    /// Override the HTTP client.
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Build the `AppState`.
    ///
    /// If no bridge was provided, connects to the KSS using the config.
    /// All other components use sensible defaults from the config if not overridden.
    pub async fn build(self) -> anyhow::Result<Arc<AppState>> {
        let bridge = match self.bridge {
            Some(b) => b,
            None => MpcBridge::new(&self.config).await?,
        };

        let fee_injector = self.fee_injector.unwrap_or_else(|| {
            FeeInjector::new(
                self.config.fee_per_signing,
                self.config.fee_addresses.clone(),
                self.config.fee_threshold.clone(),
            )
        });

        let presign_manager =
            Arc::new(RwLock::new(self.presign_manager.unwrap_or_else(|| {
                PresignManager::new(self.config.max_presignatures)
            })));

        let storage: Arc<dyn StorageBackend> = self
            .storage
            .unwrap_or_else(|| Arc::new(InMemoryBackend::new()));

        let http_client = match self.http_client {
            Some(c) => c,
            None => reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        };

        Ok(Arc::new(AppState {
            config: self.config,
            bridge,
            presign_manager,
            fee_injector,
            storage,
            http_client,
        }))
    }
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

    let presign_manager = Arc::new(RwLock::new(PresignManager::new(config.max_presignatures)));

    let storage: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let state = Arc::new(AppState {
        config: config.clone(),
        bridge,
        presign_manager: presign_manager.clone(),
        fee_injector,
        storage,
        http_client,
    });

    // Background presignature replenishment — runs forever, generating
    // presignatures during idle time so online signing is single-round.
    let bg_state = state.clone();
    tokio::spawn(async move {
        presign_manager::background_replenish(bg_state).await;
    });

    let app = build_router(state);

    let addr = format!("0.0.0.0:{}", config.port);
    tracing::info!("MPC Signing Proxy listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Build the BRC-100 router for a given [`AppState`].
///
/// Shared by [`run`] (the production server) and library consumers / tests that
/// want to serve a pre-assembled state (e.g., the real-sats createAction gate).
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
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
        .route("/acquireCertificate", post(wallet_api::acquire_certificate))
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
        // ── Chain info ────────────────────────────────────────────────────
        .route("/getHeight", post(wallet_api::get_height))
        .route(
            "/waitForAuthentication",
            post(wallet_api::wait_for_authentication),
        )
        // ── Health ───────────────────────────────────────────────────────
        .route("/health", get(wallet_api::health))
        // ── Discovery side-channel (Path A) ──────────────────────────────
        // Overlay discovery clients fetch MPC-specific node capabilities
        // here after validating this cosigner's SHIP token. See
        // bsv-mpc-overlay/src/chip.rs docs for architecture rationale.
        .route("/capabilities", get(wallet_api::capabilities))
        .with_state(state)
}
