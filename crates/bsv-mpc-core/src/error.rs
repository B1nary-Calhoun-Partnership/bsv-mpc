//! Error types for the MPC core protocol.
//!
//! All fallible operations in this crate return [`Result<T>`], which is an alias
//! for `std::result::Result<T, MpcError>`. Error variants are organized by the
//! subsystem that produces them.

use thiserror::Error;

/// Errors that can occur during MPC protocol operations.
#[derive(Debug, Error)]
pub enum MpcError {
    /// Error during the Distributed Key Generation ceremony.
    ///
    /// This can occur when a party sends an invalid commitment, fails a
    /// zero-knowledge proof, or the Feldman VSS verification fails.
    #[error("DKG protocol error: {0}")]
    Dkg(String),

    /// Error during the threshold signing protocol.
    ///
    /// This can occur when a party provides an invalid partial signature,
    /// the presignature is malformed, or the final signature fails verification.
    #[error("Signing protocol error: {0}")]
    Signing(String),

    /// Error reading, writing, encrypting, or decrypting key shares.
    #[error("Share storage error: {0}")]
    ShareStorage(String),

    /// Invalid threshold configuration.
    ///
    /// The threshold `t` must satisfy `2 <= t <= n`. A 1-of-n scheme is just
    /// single-signer ECDSA and should not use MPC. A t > n scheme is impossible.
    #[error("Invalid threshold: t={t}, n={n} (require 2 <= t <= n)")]
    InvalidThreshold {
        /// Minimum signers required.
        t: u16,
        /// Total number of share-holders.
        n: u16,
    },

    /// A key share failed validation.
    ///
    /// This occurs when a deserialized share does not match the expected session,
    /// has an out-of-range index, or fails the Feldman commitment check.
    #[error("Invalid share: {0}")]
    InvalidShare(String),

    /// The presignature pool is empty and online signing requires a presignature.
    ///
    /// Callers should either wait for background presigning to replenish the pool,
    /// or fall back to the 4-round interactive signing protocol.
    #[error("Presignature pool exhausted — no presignatures available for 1-round signing")]
    PresigningExhausted,

    /// AES-256-GCM encryption or decryption error.
    ///
    /// This typically means the wrong encryption key was used to decrypt a share,
    /// or the ciphertext was tampered with (GCM authentication tag mismatch).
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Serialization or deserialization error (serde).
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Generic MPC protocol error for cases not covered by specific variants.
    #[error("MPC protocol error: {0}")]
    Protocol(String),
}

/// A specialized `Result` type for MPC operations.
pub type Result<T> = std::result::Result<T, MpcError>;

impl From<serde_json::Error> for MpcError {
    fn from(err: serde_json::Error) -> Self {
        MpcError::Serialization(err.to_string())
    }
}
