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
use crate::presign_manager::{self, DevicePresigSetPool, PresignManager};
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

    /// **§1 device-holds-(t−1) presig SET pool (issue #38).** Present only when
    /// this proxy is a device holding `t−1` shares (`bridge.is_device_holds()`).
    /// `relay_sign` consumes one correlated set per signed input and drives
    /// `t−1` local parties + one external cosigner over the relay. `None` for the
    /// normal single-share deployment (which uses `presign_manager`).
    pub device_presig_pool: Option<Arc<RwLock<DevicePresigSetPool>>>,

    /// **§4 policy engine (issue #43).** When present, `createAction` runs the
    /// policy `check_signing` hook before signing; a `RequireApproval` verdict
    /// triggers an approval collection over the relay
    /// ([`crate::relay_approval`]) and the spend proceeds only on `Approved`.
    /// `None` = no policy gate (signing proceeds unconditionally — the prior
    /// behavior). `std::sync::Mutex` because `check_signing` is sync and the lock
    /// is never held across an `.await`.
    pub policy_engine: Option<Arc<std::sync::Mutex<bsv_mpc_core::policy::PolicyEngine>>>,

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
    device_presig_pool: Option<DevicePresigSetPool>,
    policy_engine: Option<bsv_mpc_core::policy::PolicyEngine>,
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
            device_presig_pool: None,
            policy_engine: None,
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

    /// **§1 device-holds-(t−1) (issue #38).** Provide the correlated device
    /// presig-set pool. Required when the bridge holds `t−1` shares — `relay_sign`
    /// consumes one set per signed input.
    pub fn with_device_presig_pool(mut self, pool: DevicePresigSetPool) -> Self {
        self.device_presig_pool = Some(pool);
        self
    }

    /// **§4 policy engine (issue #43).** Provide a `PolicyEngine`; `createAction`
    /// then gates each spend through `check_signing` (and an approval collection
    /// over the relay on `RequireApproval`) before signing.
    pub fn with_policy_engine(mut self, engine: bsv_mpc_core::policy::PolicyEngine) -> Self {
        self.policy_engine = Some(engine);
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

        let device_presig_pool = self.device_presig_pool.map(|p| Arc::new(RwLock::new(p)));

        let policy_engine = self
            .policy_engine
            .map(|e| Arc::new(std::sync::Mutex::new(e)));

        Ok(Arc::new(AppState {
            config: self.config,
            bridge,
            presign_manager,
            device_presig_pool,
            policy_engine,
            fee_injector,
            storage,
            http_client,
        }))
    }
}

/// Load a `PolicyEngine` for the env-driven binary entry point per audit #77.
///
/// Reads `MPC_POLICY_MANIFEST` (path to a CBOR-encoded
/// [`bsv_mpc_core::policy::PolicyManifest`]) off the config. On
/// `MPC_NETWORK=mainnet` this MUST be set, otherwise the binary fails fast:
/// the audit caught that the env-driven entry point at `server.rs:284`
/// hardcoded `policy_engine: None`, meaning every container/CF deployment of
/// the proxy historically ran without an enforced policy gate.
///
/// Returns:
/// - `Ok(Some(engine))` when the manifest path is set and loads cleanly.
/// - `Ok(None)` for testnet/dev when no manifest is configured (prior
///   behavior preserved for non-mainnet operators).
/// - `Err(_)` when `MPC_NETWORK=mainnet` AND no manifest is configured, or
///   when the manifest file cannot be read / parsed.
pub fn load_policy_engine_from_config(
    config: &ProxyConfig,
) -> anyhow::Result<Option<bsv_mpc_core::policy::PolicyEngine>> {
    let network_is_mainnet = config
        .network
        .as_deref()
        .map(|s| s.eq_ignore_ascii_case("mainnet"))
        .unwrap_or(false);

    let Some(path) = config.policy_manifest_path.as_deref() else {
        if network_is_mainnet {
            return Err(anyhow::anyhow!(
                "MPC_NETWORK=mainnet but MPC_POLICY_MANIFEST is unset — \
                 refusing to start a mainnet proxy without an enforced \
                 PolicyManifest (audit bsv-mpc#77). Provide a CBOR manifest \
                 path, or set MPC_NETWORK to a non-mainnet value for \
                 staging/dev runs."
            ));
        }
        return Ok(None);
    };

    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("read MPC_POLICY_MANIFEST {path:?}: {e}"))?;
    let manifest = bsv_mpc_core::policy::PolicyManifest::from_cbor(&bytes)
        .map_err(|e| anyhow::anyhow!("parse MPC_POLICY_MANIFEST {path:?}: {e}"))?;
    let engine = bsv_mpc_core::policy::PolicyEngine::new(manifest)
        .map_err(|e| anyhow::anyhow!("build PolicyEngine from {path:?}: {e}"))?;
    Ok(Some(engine))
}

/// Start the BRC-100 HTTP server.
///
/// This function:
/// 1. Loads and decrypts the key share
/// 2. Initializes the MPC bridge with the KSS
/// 3. Loads the env-supplied policy manifest (audit #77; fail-closed on mainnet)
/// 4. Starts the background presignature replenishment task
/// 5. Binds to `0.0.0.0:{port}` and serves BRC-100 endpoints
///
/// # Errors
///
/// Returns an error if the share file cannot be loaded, the KSS is
/// unreachable during initialization, the TCP listener fails to bind, or
/// — per audit #77 — `MPC_NETWORK=mainnet` without `MPC_POLICY_MANIFEST`.
pub async fn run(config: ProxyConfig) -> anyhow::Result<()> {
    // Load the policy engine BEFORE we touch the KSS / share / network so a
    // misconfigured mainnet deployment refuses to start with the clearest
    // possible error (audit bsv-mpc#77).
    let policy_engine =
        load_policy_engine_from_config(&config)?.map(|e| Arc::new(std::sync::Mutex::new(e)));

    let bridge = MpcBridge::new(&config).await?;

    let fee_injector = FeeInjector::new(
        config.fee_per_signing,
        config.fee_addresses.clone(),
        config.fee_threshold.clone(),
    );

    let presign_manager = Arc::new(RwLock::new(PresignManager::new(config.max_presignatures)));

    // §1 device-holds-(t−1) (issue #38): a device holding `t−1` shares consumes
    // correlated presig SETS (one per device share) rather than single presigs.
    // The set pool is provisioned out-of-band (the device's `t−1`-party + cosigner
    // presign ceremony); background single-presig replenishment does not stock it.
    let device_presig_pool = if bridge.is_device_holds() {
        Some(Arc::new(RwLock::new(DevicePresigSetPool::new(
            config.max_presignatures,
        ))))
    } else {
        None
    };

    let storage: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let state = Arc::new(AppState {
        config: config.clone(),
        bridge,
        presign_manager: presign_manager.clone(),
        device_presig_pool,
        // §4 policy + approval gate (audit bsv-mpc#77): the engine is loaded
        // from `MPC_POLICY_MANIFEST` above; `MPC_NETWORK=mainnet` without a
        // manifest already errored out before this point, so a `None` here
        // means the operator explicitly chose testnet/dev with no manifest.
        policy_engine,
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
