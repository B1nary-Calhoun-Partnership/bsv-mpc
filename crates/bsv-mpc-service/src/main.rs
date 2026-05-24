//! # bsv-mpc-service
//!
//! Standalone MPC Key Share Service binary for self-hosted deployments.
//!
//! This is the self-hosted alternative to the Cloudflare Worker version
//! (`bsv-mpc-worker`). It exposes the same API surface over HTTP, backed
//! by local SQLite instead of Durable Object SQLite. Suitable for:
//!
//! - **Mode A (Split Stack)**: VPS or bare-metal deployment where you control
//!   the hardware. The agent container runs the MPC Proxy (share_B), and this
//!   service runs on a separate machine holding share_A.
//!
//! - **Independent operator**: Run your own Key Share Service for third-party
//!   agents. Advertise via CHIP tokens on the BSV overlay network.
//!
//! - **Development/testing**: Local development without Cloudflare infrastructure.
//!
//! ## Usage
//!
//! ```bash
//! # Start with defaults (port 4322, data in ./shares)
//! bsv-mpc-service
//!
//! # Custom port and data directory
//! bsv-mpc-service --port 4322 --data-dir /var/lib/mpc-shares
//!
//! # Via environment variables
//! MPC_SERVICE_PORT=4322 MPC_DATA_DIR=/var/lib/mpc-shares bsv-mpc-service
//! ```
//!
//! ## API
//!
//! Identical to `bsv-mpc-worker`:
//!
//! | Method | Path              | Description                                  |
//! |--------|-------------------|----------------------------------------------|
//! | POST   | `/dkg/init`       | Start DKG ceremony, return round 1 message   |
//! | POST   | `/dkg/round`      | Process DKG round, return next or complete    |
//! | POST   | `/presign/init`   | Start presigning protocol                     |
//! | POST   | `/presign/round`  | Process presigning round                      |
//! | GET    | `/health`         | Liveness check + share count                  |
//! | GET    | `/shares/:agent`  | Share metadata (no secrets exposed)            |

use std::sync::Arc;
use std::sync::RwLock;

use bsv_mpc_service::{AppState, SqliteShareStorage};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bsv_mpc_service=info".into()),
        )
        .init();

    let port: u16 = std::env::var("MPC_SERVICE_PORT")
        .unwrap_or_else(|_| "4322".into())
        .parse()?;
    let data_dir = std::env::var("MPC_DATA_DIR").unwrap_or_else(|_| "./shares".into());

    // Ensure data directory exists.
    std::fs::create_dir_all(&data_dir)?;

    tracing::info!(port, data_dir, "Starting MPC Key Share Service");

    let storage = SqliteShareStorage::open(&data_dir)?;

    // #4 presignature provisioning: when MPC_WORKER_URL is set, ship each
    // generated Presignature_A to the cosigner DO pool over the authed
    // /ceremony/ingest-presig route (self-stocking cosigner). The BRC-31 auth
    // identity comes from MPC_SERVICE_AUTH_KEY if set, else an ephemeral key is
    // generated (the DO stores presigs under its OWN identity, so the caller's
    // identity need only be a valid session — no secret to commit).
    let provision = match std::env::var("MPC_WORKER_URL").ok() {
        Some(worker_url) => {
            let auth_key = match std::env::var("MPC_SERVICE_AUTH_KEY").ok() {
                Some(auth_hex) => {
                    let key_bytes = hex::decode(auth_hex.trim())
                        .map_err(|e| anyhow::anyhow!("MPC_SERVICE_AUTH_KEY invalid hex: {e}"))?;
                    bsv::primitives::ec::PrivateKey::from_bytes(&key_bytes)
                        .map_err(|e| anyhow::anyhow!("MPC_SERVICE_AUTH_KEY invalid key: {e:?}"))?
                }
                None => {
                    let mut b = [0u8; 32];
                    getrandom::getrandom(&mut b).map_err(|e| anyhow::anyhow!("entropy: {e}"))?;
                    b[0] |= 0x01;
                    bsv::primitives::ec::PrivateKey::from_bytes(&b)
                        .map_err(|e| anyhow::anyhow!("ephemeral auth key: {e:?}"))?
                }
            };
            tracing::info!(%worker_url, "presignature provisioning ENABLED");
            Some(bsv_mpc_service::ProvisionConfig {
                worker_url,
                auth: tokio::sync::Mutex::new(bsv_mpc_core::brc31_client::Brc31Client::new(
                    auth_key,
                )),
                http: reqwest::Client::new(),
            })
        }
        None => {
            tracing::info!("presignature provisioning disabled (set MPC_WORKER_URL to enable)");
            None
        }
    };

    // #9 durable share custody: when BOTH MPC_SERVER_PRIVATE_KEY (the stable
    // custody root → KEK + the custody-record owner identity) and MPC_WORKER_URL
    // (the durable DO) are set, persist the KEK-wrapped share_A to the DO at
    // DKG-complete and lazily reload it after a restart — closing the
    // ephemeral-container fund-lock. The KEK never leaves this process; the DO
    // holds only sealed bytes.
    let custody = match (
        std::env::var("MPC_SERVER_PRIVATE_KEY").ok(),
        std::env::var("MPC_WORKER_URL").ok(),
    ) {
        (Some(server_hex), Some(worker_url)) if !server_hex.trim().is_empty() => {
            let key_bytes: [u8; 32] = hex::decode(server_hex.trim())
                .map_err(|e| anyhow::anyhow!("MPC_SERVER_PRIVATE_KEY invalid hex: {e}"))?
                .try_into()
                .map_err(|_| anyhow::anyhow!("MPC_SERVER_PRIVATE_KEY must be 32 bytes"))?;
            let auth_key = bsv::primitives::ec::PrivateKey::from_bytes(&key_bytes)
                .map_err(|e| anyhow::anyhow!("MPC_SERVER_PRIVATE_KEY invalid key: {e:?}"))?;
            let kek = bsv_mpc_core::custody::derive_custody_kek(&key_bytes);
            tracing::info!(%worker_url, "durable share custody ENABLED (#9)");
            Some(bsv_mpc_service::CustodyConfig {
                worker_url,
                kek,
                auth: tokio::sync::Mutex::new(bsv_mpc_core::brc31_client::Brc31Client::new(
                    auth_key,
                )),
                http: reqwest::Client::new(),
            })
        }
        _ => {
            tracing::warn!(
                "durable share custody DISABLED — share_A is in-memory only and is LOST on \
                 restart (set MPC_SERVER_PRIVATE_KEY + MPC_WORKER_URL to enable; required \
                 before funded use)"
            );
            None
        }
    };

    let state = Arc::new(AppState {
        data_dir,
        storage: RwLock::new(storage),
        started_at: chrono::Utc::now(),
        provision,
        // §07.6: enforce BRC-31 owner-authz when MPC_SERVER_PRIVATE_KEY is set;
        // dev mode (allow-unauthenticated) otherwise.
        auth: bsv_mpc_service::AuthState::from_env(),
        custody,
    });

    let app = bsv_mpc_service::build_router(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    tracing::info!("Listening on 0.0.0.0:{port}");
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
