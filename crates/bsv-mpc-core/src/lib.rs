//! # bsv-mpc-core
//!
//! Core MPC threshold ECDSA signing protocol for BSV, wrapping the
//! [cggmp24](https://github.com/LFDT-Lockness/cggmp21) implementation of the
//! CGGMP'24 protocol for secp256k1.
//!
//! This crate provides the cryptographic protocol layer for threshold signing:
//!
//! - **Distributed Key Generation (DKG)**: Run a multi-party ceremony to produce
//!   a joint secp256k1 public key where no single party holds the full private key.
//!   The resulting public key is a standard BSV compressed public key that can
//!   receive funds at a P2PKH address.
//!
//! - **Threshold Signing**: Given a t-of-n threshold configuration, any `t` parties
//!   can cooperate to produce a valid ECDSA signature over a BSV sighash. The
//!   signature is indistinguishable from a single-signer ECDSA signature.
//!
//! - **Presignature Stockpiling**: Background generation of presignatures that
//!   reduce online signing to a single round (versus 4 rounds without). Critical
//!   for latency-sensitive BSV transaction signing.
//!
//! - **HD Key Derivation**: SLIP-10/BIP-32 compatible child key derivation from
//!   MPC shares, enabling standard BSV wallet derivation paths (m/44'/236'/...)
//!   without reconstructing the private key.
//!
//! - **Share Management**: AES-256-GCM encrypted storage of key shares with
//!   BRC-42 derived encryption keys. Shares never exist in plaintext at rest.
//!
//! - **Participation Proofs**: BRC-18 OP_RETURN proofs that record which nodes
//!   participated in a signing ceremony, enabling on-chain fee distribution.
//!
//! ## Protocol Overview
//!
//! The CGGMP'24 protocol (Canetti, Gennaro, Goldfeder, Makriyannis, Peled) is a
//! state-of-the-art threshold ECDSA scheme with:
//!
//! - **Identifiable abort**: If a party misbehaves, the protocol identifies them.
//! - **UC security**: Composable security proof in the Universal Composability framework.
//! - **Efficient presigning**: 3-round offline phase, 1-round online signing.
//! - **secp256k1 native**: Operates directly on Bitcoin's curve.
//!
//! ## Usage
//!
//! This crate is a building block. It handles the raw MPC protocol and share
//! management. The transport layer (how round messages are delivered between
//! parties) is handled by `bsv-mpc-worker` and `bsv-mpc-service`.

// Canonical BRC-31 client. NATIVE-ONLY: it depends on `bsv-middleware-rs`
// (canonical BRC-104 wire helpers), which is a non-wasm dependency. The worker
// (wasm32) is a BRC-31 *server* and never constructs this client, so gating the
// module off wasm keeps the worker's wasm graph unchanged.
pub mod approval;
pub mod aux_binding;
#[cfg(not(target_arch = "wasm32"))]
pub mod brc31_client;
pub mod canonical;
pub mod custody;
pub mod dkg;
pub mod ecdh;
pub mod envelope;
pub mod error;
pub mod hd;
pub mod paillier_pool;
pub mod policy;
pub mod presig_at_rest;
pub mod presig_encryption;
// Diagnostic stage timing for the device-side presig-over-relay ceremony (#96 →
// #98). Native-only: it uses `std::time::Instant` (unsupported on
// wasm32-unknown-unknown) and the presig coordinator path is itself native-only.
#[cfg(not(target_arch = "wasm32"))]
pub mod presig_timing;
pub mod presigning;
pub mod primes_at_rest;
pub mod proof;
pub mod recovery;
pub mod recovery_health;
pub mod refresh;
pub mod refresh_coordinator;
pub mod reshar_coordinator;
pub mod share;
pub mod signing;
pub mod types;

// Re-export key public types for ergonomic imports.
pub use error::{MpcError, Result};
pub use recovery_health::{
    authorize_recovery, min_survivors_to_recover, survivor_quorum_ok, RecoveryCooldown,
    RecoveryGuardError, RecoveryHealth, RecoveryStatus, TrusteesReachable,
};
pub use refresh::RefreshResult;
pub use refresh_coordinator::{RefreshCommit, RefreshCoordinator, RefreshRoundResult};
pub use reshar_coordinator::{
    combine_reshared_with_aux, ContributorInputs, ResharCommit, ResharConfig, ResharCoordinator,
    ResharRoundResult,
};
pub use types::{
    DkgResult, EncryptedShare, InvalidationTrigger, JointPublicKey, ParticipationProof, PolicyId,
    PresigBinding, PresigBundle, Presignature, RoundMessage, SessionId, ShareIndex, SigningResult,
    ThresholdConfig,
};
