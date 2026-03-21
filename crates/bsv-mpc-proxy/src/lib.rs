//! # bsv-mpc-proxy
//!
//! A BRC-100 compatible signing proxy that translates standard wallet API calls
//! into MPC threshold signing operations using the CGGMP'24 protocol.
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
//! - [`server`] — Axum router with BRC-100 endpoint routing
//! - [`wallet_api`] — Handler implementations for each BRC-100 endpoint
//! - [`bridge`] — Translates wallet calls to MPC protocol rounds
//! - [`fee_injector`] — Adds MPC signing fee outputs to transactions
//! - [`presign_manager`] — Background presignature pool management
//! - [`error`] — Proxy-specific error types

pub mod bridge;
pub mod config;
pub mod error;
pub mod fee_injector;
pub mod presign_manager;
pub mod server;
pub mod wallet_api;
