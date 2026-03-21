//! # bsv-mpc-proxy
//!
//! Binary entry point for the MPC signing proxy.
//!
//! This process listens on `localhost:3322` (or the configured port) and
//! presents the same BRC-100 HTTP API that bsv-wallet-cli exposes. Any
//! application that talks to the wallet — including bsv-worm — can point
//! at this proxy with **zero code changes**. Internally, every signing
//! request is translated into a 2-party CGGMP'24 threshold ECDSA ceremony
//! with a remote Key Share Service (KSS).
//!
//! ## Usage
//!
//! ```bash
//! # Minimal — uses defaults (port 3322, KSS at https://kss.lobsterfarm.com)
//! MPC_SHARE_PATH=./share.enc bsv-mpc-proxy
//!
//! # Explicit configuration
//! bsv-mpc-proxy --port 3322 \
//!               --kss-url https://kss.lobsterfarm.com \
//!               --share-path ./share.enc
//! ```

use bsv_mpc_proxy::{config::ProxyConfig, server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = ProxyConfig::from_env()?;
    tracing::info!(
        port = config.port,
        kss_url = %config.kss_url,
        share_path = %config.share_path,
        max_presignatures = config.max_presignatures,
        fee_per_signing = config.fee_per_signing,
        "Starting MPC Signing Proxy"
    );

    server::run(config).await
}
