//! `bsv-mpc-client` — greenfield native (iOS/Android via UniFFI) + web
//! (wasm-bindgen) client wrapping `bsv-mpc-core` threshold signing.
//!
//! 100% Calhoun-solo, **zero `rust-mpc` / `100cash` dependency** (issue #41):
//! platform patterns (Secure-Enclave wrap-key, UniFFI shell) are reimplemented
//! fresh, never depended on. Build plan: `docs/41-CLIENT-PLAN.md`.
//!
//! ## Shape
//! One target-agnostic [`WalletClient`] core over three host-**injected** seams —
//! [`WalletStorage`], [`ChainServices`], [`KeyStore`] — so the host owns all I/O
//! and secrets stay [`zeroize::Zeroizing`] end-to-end. The UniFFI / wasm-bindgen
//! FFI skins (Phase 4) are thin wrappers over this core.
//!
//! Phase 1 (this) is the target-agnostic core: it compiles on both native and
//! `wasm32-unknown-unknown`.

mod chain;
mod client;
mod error;
mod keystore;
mod signer;
mod storage;
mod transport;
pub mod txbuild;

/// wasm-bindgen skin (web client). Only compiled on `wasm32`.
#[cfg(target_arch = "wasm32")]
pub mod wasm;

/// UniFFI skin (native shells). Only compiled under `--features native`.
#[cfg(feature = "native")]
pub mod ffi;

#[cfg(feature = "native")]
uniffi::setup_scaffolding!();

pub use chain::{BroadcastResult, ChainServices, Utxo};
pub use client::WalletClient;
pub use error::ClientError;
pub use keystore::{InMemoryKeyStore, KeyStore};
pub use signer::unseal_signing_scalar;
pub use storage::{StoredShare, WalletStorage};
pub use transport::RoundTransport;

// Re-export the signing result type so callers don't need a direct bsv-mpc-core dep.
pub use bsv_mpc_core::SigningResult;
