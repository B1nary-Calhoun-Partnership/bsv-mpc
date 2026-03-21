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

pub mod dkg;
pub mod error;
pub mod hd;
pub mod presigning;
pub mod proof;
pub mod share;
pub mod signing;
pub mod types;

// Re-export key public types for ergonomic imports.
pub use error::{MpcError, Result};
pub use types::{
    DkgResult, EncryptedShare, JointPublicKey, ParticipationProof, Presignature, RoundMessage,
    SessionId, ShareIndex, SigningResult, ThresholdConfig,
};
