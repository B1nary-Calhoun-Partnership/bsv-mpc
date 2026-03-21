//! MPC bridge — translates BRC-100 wallet operations to CGGMP'24 protocol rounds.
//!
//! The bridge is the core translation layer between the BRC-100 wallet API
//! surface and the underlying MPC threshold signing protocol. It holds this
//! party's decrypted key share, maintains a session with the Key Share Service
//! (KSS), and orchestrates the multi-round signing ceremonies.
//!
//! ## Protocol rounds
//!
//! ### Presigning (offline, 3 rounds)
//!
//! ```text
//! Proxy                          KSS
//!   │── Round 1: commit ──────────►│
//!   │◄── Round 1: commit ──────────│
//!   │── Round 2: decommit ────────►│
//!   │◄── Round 2: decommit ────────│
//!   │── Round 3: proof ───────────►│
//!   │◄── Round 3: proof ───────────│
//!   │                               │
//!   │  Presignature stored locally  │
//! ```
//!
//! ### Online signing (1 round with presignature, 4 rounds without)
//!
//! ```text
//! # With presignature (fast path):
//! Proxy                          KSS
//!   │── sign(hash, presig) ───────►│
//!   │◄── partial_sig ──────────────│
//!   │  Combine → DER signature     │
//!
//! # Without presignature (full protocol):
//! Proxy                          KSS
//!   │── Round 1 ──────────────────►│
//!   │◄── Round 1 ──────────────────│
//!   │── Round 2 ──────────────────►│
//!   │◄── Round 2 ──────────────────│
//!   │── Round 3 ──────────────────►│
//!   │◄── Round 3 ──────────────────│
//!   │── Round 4 (sign) ──────────►│
//!   │◄── partial_sig ──────────────│
//!   │  Combine → DER signature     │
//! ```
//!
//! ## Security properties
//!
//! - The full private key **never exists** on either party. Each party holds
//!   only their share, which is useless without the other party's cooperation.
//! - Identifiable abort: if the KSS misbehaves (sends invalid data), the
//!   protocol identifies it and the proxy can report the violation.
//! - Presignatures are one-time-use. Each presignature is consumed during
//!   signing and cannot be reused.

use crate::config::ProxyConfig;
use bsv_mpc_core::types::*;

/// Bridges BRC-100 wallet calls to MPC threshold signing operations.
///
/// Created once at startup from the proxy configuration. Holds the decrypted
/// share in memory for the lifetime of the process.
pub struct MpcBridge {
    /// URL of the Key Share Service (the other MPC party).
    kss_url: String,

    /// This party's decrypted key share.
    ///
    /// Loaded from `config.share_path` and decrypted with `config.encryption_key`
    /// (or a DKG-derived key) during `new()`. The share is a secp256k1 scalar
    /// that, combined with the KSS's share, produces the joint signing key.
    #[allow(dead_code)]
    share: EncryptedShare,

    /// Joint public key computed during the DKG ceremony.
    ///
    /// This is the standard compressed secp256k1 public key that appears on-chain
    /// in P2PKH outputs. It can be computed from either party's share + the other
    /// party's public share component, or from the DKG transcript.
    joint_key: JointPublicKey,

    /// HTTP client for communicating with the KSS.
    ///
    /// Uses `reqwest` with TLS. The KSS authenticates requests using the
    /// session ID established during initialization.
    client: reqwest::Client,

    /// Session identifier linking this proxy to a specific KSS session.
    ///
    /// Established during `new()` when the proxy registers with the KSS.
    /// All subsequent signing requests include this session ID.
    session_id: SessionId,
}

impl MpcBridge {
    /// Initialize the MPC bridge.
    ///
    /// This performs the following steps:
    /// 1. Read the encrypted share file from `config.share_path`.
    /// 2. Decrypt the share using `config.encryption_key` (or DKG-derived key).
    /// 3. Validate the share (Feldman commitment check).
    /// 4. Extract the joint public key from the share metadata.
    /// 5. Establish a session with the KSS at `config.kss_url`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The share file does not exist or cannot be read.
    /// - Decryption fails (wrong key or corrupted file).
    /// - Share validation fails (tampering detected).
    /// - The KSS is unreachable or rejects the session.
    pub async fn new(config: &ProxyConfig) -> anyhow::Result<Self> {
        todo!(
            "1. Read encrypted share from config.share_path\n\
             2. Determine decryption key:\n\
                a. If config.encryption_key is Some, decode hex → 32-byte AES key\n\
                b. Otherwise, derive key from DKG session metadata in share header\n\
             3. Decrypt share using AES-256-GCM (bsv_mpc_core::share::decrypt)\n\
             4. Validate share against Feldman commitments\n\
             5. Extract JointPublicKey from share metadata\n\
             6. Create reqwest::Client with TLS\n\
             7. POST to {kss_url}/session/init with our share's public component\n\
             8. Receive SessionId from KSS\n\
             9. Return initialized MpcBridge"
        )
    }

    /// Sign a 32-byte message hash using 2-party threshold ECDSA.
    ///
    /// If a `presignature` is provided, this performs single-round online
    /// signing (~50-100ms). Without a presignature, it runs the full 4-round
    /// interactive protocol (~300-500ms).
    ///
    /// The returned `SigningResult` contains:
    /// - `signature`: DER-encoded ECDSA signature
    /// - `participation_proof`: BRC-18 data for on-chain fee distribution
    ///
    /// # Arguments
    ///
    /// - `message_hash` — The 32-byte SHA-256d sighash to sign.
    /// - `presignature` — Optional presignature for single-round signing.
    ///
    /// # Errors
    ///
    /// - `MpcError::Signing` — Protocol error (invalid partial sig, abort).
    /// - `ProxyError::KssError` — Network error communicating with KSS.
    pub async fn sign(
        &self,
        message_hash: &[u8; 32],
        presignature: Option<Presignature>,
    ) -> bsv_mpc_core::error::Result<SigningResult> {
        let _ = (message_hash, presignature);
        todo!(
            "If presignature is Some:\n\
               1. Compute local partial signature using presignature + message_hash\n\
               2. POST to {{kss_url}}/sign/online with:\n\
                  - session_id\n\
                  - presignature_id (from the presignature)\n\
                  - partial_sig (our partial signature)\n\
                  - message_hash\n\
               3. Receive KSS's partial signature\n\
               4. Combine partial signatures → full ECDSA signature\n\
               5. Verify signature against joint_key and message_hash\n\
               6. DER-encode and return SigningResult\n\
             \n\
             If presignature is None (full protocol):\n\
               1. Round 1: Generate and exchange commitments with KSS\n\
                  POST {{kss_url}}/sign/round/1 with commitment\n\
               2. Round 2: Exchange decommitments\n\
                  POST {{kss_url}}/sign/round/2 with decommitment\n\
               3. Round 3: Exchange ZK proofs\n\
                  POST {{kss_url}}/sign/round/3 with proof\n\
               4. Round 4: Exchange partial signatures\n\
                  POST {{kss_url}}/sign/round/4 with partial_sig + message_hash\n\
               5. Combine → verify → DER-encode → return SigningResult"
        )
    }

    /// Run the presigning protocol to generate a reusable presignature.
    ///
    /// Presignatures are generated during idle time by the background
    /// replenishment task. Each presignature enables single-round online
    /// signing for one future signature request.
    ///
    /// The presigning protocol is 3 rounds:
    /// 1. Commit — Exchange Paillier ciphertexts and commitments.
    /// 2. Decommit — Reveal and verify commitments.
    /// 3. Proof — Exchange ZK proofs of correctness.
    ///
    /// # Errors
    ///
    /// - `MpcError::Signing` — Protocol error during presigning.
    /// - `ProxyError::KssError` — Network error communicating with KSS.
    pub async fn presign(&self) -> bsv_mpc_core::error::Result<Presignature> {
        todo!(
            "1. Round 1 (commit):\n\
                a. Generate local presigning commitment\n\
                b. POST to {{kss_url}}/presign/round/1 with commitment\n\
                c. Receive KSS commitment\n\
             2. Round 2 (decommit):\n\
                a. Generate decommitment from Round 1 state\n\
                b. POST to {{kss_url}}/presign/round/2 with decommitment\n\
                c. Receive KSS decommitment, verify against Round 1 commitment\n\
             3. Round 3 (proof):\n\
                a. Generate ZK proof of correctness\n\
                b. POST to {{kss_url}}/presign/round/3 with proof\n\
                c. Receive KSS proof, verify\n\
             4. Combine into Presignature and return"
        )
    }

    /// Get the joint public key.
    ///
    /// This is the secp256k1 compressed public key that can receive BSV
    /// at a standard P2PKH address. It was computed during the DKG ceremony.
    pub fn joint_public_key(&self) -> &JointPublicKey {
        &self.joint_key
    }

    /// Get the current KSS session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Get the KSS URL.
    pub fn kss_url(&self) -> &str {
        &self.kss_url
    }
}
