//! # bsv-mpc-proxy
//!
//! A BRC-100 compatible signing proxy that translates standard wallet API calls
//! into MPC threshold signing operations using the CGGMP'24 protocol.
//!
//! ## Library usage
//!
//! This crate can be used as a library (without running the HTTP server).
//! Use [`ProxyBuilder`] to construct an [`AppState`], then call the `_impl`
//! handler functions directly with parsed JSON values:
//!
//! ```rust,no_run
//! use bsv_mpc_proxy::{ProxyBuilder, ProxyConfig, wallet_api};
//! use serde_json::json;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = ProxyConfig::from_env()?;
//! let state = ProxyBuilder::new(config).build().await?;
//!
//! // Call handlers directly — no HTTP needed
//! let result = wallet_api::get_network_impl(&state, json!({})).await;
//! assert_eq!(result["network"], "mainnet");
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────┐     BRC-100 HTTP      ┌─────────────────┐    2PC rounds    ┌─────────┐
//! │  bsv-worm    │ ──────────────────────►│  bsv-mpc-proxy  │ ◄──────────────► │   KSS   │
//! │  (or any     │   localhost:3322       │                 │   HTTPS/JSON     │ (remote │
//! │  BRC-100     │                        │  ┌───────────┐  │                  │  party) │
//! │  client)     │                        │  │ presign   │  │                  └─────────┘
//! └──────────────┘                        │  │ pool      │  │
//!                                         │  └───────────┘  │
//!                                         │  ┌───────────┐  │
//!                                         │  │ fee       │  │
//!                                         │  │ injector  │  │
//!                                         │  └───────────┘  │
//!                                         └─────────────────┘
//! ```
//!
//! The proxy maintains a pool of presignatures generated during idle time.
//! When a signing request arrives, it consumes a presignature for single-round
//! online signing (< 100ms latency). If the pool is empty, it falls back to
//! the full 4-round interactive protocol (~400ms).
//!
//! ## Modules
//!
//! - [`config`] — Proxy configuration from environment variables
//! - [`server`] — Axum router with BRC-100 endpoint routing, `AppState`, and `ProxyBuilder`
//! - [`wallet_api`] — Handler implementations for each BRC-100 endpoint (both Axum and library variants)
//! - [`bridge`] — Translates wallet calls to MPC protocol rounds
//! - [`fee_injector`] — Adds MPC signing fee outputs to transactions
//! - [`presign_manager`] — Background presignature pool management
//! - [`utxo_tracker`] — In-memory UTXO tracking
//! - [`storage`] — Storage backend abstraction (in-memory or wallet-infra)
//! - [`error`] — Proxy-specific error types

pub mod bridge;
pub mod config;
pub mod error;
pub mod fee_injector;
pub mod presign_manager;
pub mod relay_sign;
pub mod server;
pub mod storage;
pub mod utxo_tracker;
pub mod wallet_api;

// ─── Public re-exports for library consumers ────────────────────────────────
//
// These re-exports allow `use bsv_mpc_proxy::AppState` instead of
// `use bsv_mpc_proxy::server::AppState`.

pub use bridge::MpcBridge;
pub use config::ProxyConfig;
pub use error::{ProxyError, ProxyResult};
pub use fee_injector::{FeeInjectionInfo, FeeInjector};
pub use presign_manager::PresignManager;
pub use server::{AppState, ProxyBuilder};
pub use storage::{InMemoryBackend, StorageBackend, WalletInfraBackend};
pub use utxo_tracker::{TrackedOutput, UtxoTracker};
