//! UniFFI skin (native shells: iOS / Android) — compiled only under `--features native`.
//!
//! UniFFI 0.28 proc-macro mode (no `.udl`). Three surfaces:
//! - **sync tx helpers** + the host-driven [`FfiSigningSession`] state machine (the
//!   `sans-io` pattern: the shell owns I/O + the biometric and pumps round messages;
//!   kept as the lower-level primitive).
//! - **[`FfiDeployedSigner`]** (#63 / #41-4d) — the HIGH-LEVEL async `sign()` running
//!   the full §06.17.1 deployed-cosigner ceremony INTERNALLY (relay transport
//!   Rust-owned; the host injects ONLY the Secure Enclave via the [`FfiKeyStore`]
//!   callback interface). This is what `RealMpcCeremonyService` binds to.
//! - **[`WalletStorageConn`]** (#64) — the BRC-103/104 storage seam: `rpc(method,
//!   params) -> json` (Rust owns all the auth crypto). Bound by `RealWalletStorageService`.

use crate::txbuild;

/// FFI-friendly error.
///
/// The internal [`ClientError`](crate::ClientError) carries `&'static str` fields
/// (not FFI-representable), so the boundary uses this String-based error instead.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("{0}")]
    Client(String),
}

/// Swift/Kotlin-callable: txid (display hex) of a raw transaction hex.
#[uniffi::export]
pub fn ffi_tx_txid(raw_tx_hex: String) -> Result<String, FfiError> {
    let raw = hex::decode(&raw_tx_hex).map_err(|e| FfiError::Client(format!("bad hex: {e}")))?;
    Ok(txbuild::compute_txid(&raw))
}

/// Swift/Kotlin-callable: output satoshi values of a raw transaction hex, in order.
#[uniffi::export]
pub fn ffi_tx_output_sats(raw_tx_hex: String) -> Result<Vec<u64>, FfiError> {
    let raw = hex::decode(&raw_tx_hex).map_err(|e| FfiError::Client(format!("bad hex: {e}")))?;
    let outs = txbuild::parse_tx_outputs(&raw).map_err(FfiError::Client)?;
    Ok(outs.into_iter().map(|(sats, _script)| sats).collect())
}

// ── Host-driven signing session (the proven `sans-io` FFI pattern) ────────────
//
// The native shell (Swift/Kotlin) owns all I/O and the biometric unseal; it
// passes the *already-unsealed* cggmp24 key-share JSON in, then pumps round
// messages between this session and the cosigner over its own transport. Rust
// stays a pure, synchronous state machine — no async, no foreign callbacks.

use std::sync::{Arc, Mutex};

/// One step of the host-driven signing ceremony.
#[derive(uniffi::Enum)]
pub enum FfiSignStep {
    /// More rounds to go — send these messages to the cosigner, then call
    /// `process` again with the cosigner's reply.
    NextRound { messages: Vec<Vec<u8>> },
    /// Done — the combined signature.
    Complete {
        signature_der: Vec<u8>,
        r: Vec<u8>,
        s: Vec<u8>,
    },
}

/// A host-driven threshold-signing session over a single share.
#[derive(uniffi::Object)]
pub struct FfiSigningSession {
    inner: Mutex<bsv_mpc_core::signing::SigningCoordinator>,
}

fn msgs_to_bytes(msgs: Vec<bsv_mpc_core::RoundMessage>) -> Result<Vec<Vec<u8>>, FfiError> {
    msgs.iter()
        .map(|m| serde_json::to_vec(m).map_err(|e| FfiError::Client(format!("encode msg: {e}"))))
        .collect()
}

fn bytes_to_msgs(raw: Vec<Vec<u8>>) -> Result<Vec<bsv_mpc_core::RoundMessage>, FfiError> {
    raw.iter()
        .map(|b| {
            serde_json::from_slice(b).map_err(|e| FfiError::Client(format!("decode msg: {e}")))
        })
        .collect()
}

#[uniffi::export]
impl FfiSigningSession {
    /// Create a session from the host-unsealed cggmp24 key-share JSON + the
    /// signing metadata (everything `StoredShare` holds, plus the joint pubkey).
    #[uniffi::constructor]
    pub fn new(
        share_json: Vec<u8>,
        joint_pubkey_compressed: Vec<u8>,
        session_id: Vec<u8>,
        share_index: u16,
        threshold: u16,
        parties: u16,
    ) -> Result<Arc<Self>, FfiError> {
        use bsv_mpc_core::signing::SigningCoordinator;
        use bsv_mpc_core::{EncryptedShare, SessionId, ShareIndex, ThresholdConfig};

        let config = ThresholdConfig::new(threshold, parties)
            .map_err(|e| FfiError::Client(e.to_string()))?;
        let sid: [u8; 32] = session_id
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::Client("session_id must be 32 bytes".into()))?;
        let session = SessionId::from_bytes(sid);
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: share_json,
            session_id: session,
            share_index: ShareIndex(share_index),
            config,
            joint_pubkey_compressed,
        };
        let participants: Vec<u16> = (0..parties).collect();
        let coord = SigningCoordinator::new(session, share, config, participants);
        Ok(Arc::new(Self {
            inner: Mutex::new(coord),
        }))
    }

    /// Begin signing `sighash` (32 bytes). Returns this party's round-1 messages.
    pub fn init(
        &self,
        sighash: Vec<u8>,
        brc42_offset: Option<Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>, FfiError> {
        let hash: [u8; 32] = sighash
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::Client("sighash must be 32 bytes".into()))?;
        let offset: Option<[u8; 32]> = match brc42_offset {
            Some(o) => Some(
                o.as_slice()
                    .try_into()
                    .map_err(|_| FfiError::Client("brc42_offset must be 32 bytes".into()))?,
            ),
            None => None,
        };
        let mut coord = self.inner.lock().expect("session lock");
        let msgs = coord
            .init_round(&hash, offset)
            .map_err(|e| FfiError::Client(e.to_string()))?;
        msgs_to_bytes(msgs)
    }

    /// Feed the cosigner's messages for the current round; advance the ceremony.
    pub fn process(&self, incoming: Vec<Vec<u8>>) -> Result<FfiSignStep, FfiError> {
        use bsv_mpc_core::signing::SigningRoundResult;
        let msgs = bytes_to_msgs(incoming)?;
        let mut coord = self.inner.lock().expect("session lock");
        match coord
            .process_round(msgs)
            .map_err(|e| FfiError::Client(e.to_string()))?
        {
            SigningRoundResult::NextRound(next) => Ok(FfiSignStep::NextRound {
                messages: msgs_to_bytes(next)?,
            }),
            SigningRoundResult::Complete(res) => Ok(FfiSignStep::Complete {
                signature_der: res.signature,
                r: res.r,
                s: res.s,
            }),
        }
    }
}

// ── High-level deployed-cosigner SIGN seam over UniFFI (issue #63 / #41-4d) ───
//
// The locked design (handoff §4.5 Decision 1): a HIGH-LEVEL async `sign()` that
// runs the FULL §06.17.1 deployed-cosigner ceremony INTERNALLY in Rust (unseal →
// take a ready presig bundle → ONE relay round-trip → combine → fail-closed
// pre-flight). The host injects ONLY the Secure Enclave as a callback interface;
// the relay/HTTP transport is Rust-owned. NOT the sans-io `FfiSigningSession`
// (that stays as the lower-level primitive). Native-only.

/// Host-implemented Secure-Enclave callback — the ONLY crypto-adjacent host code
/// for the deployed sign seam. Swift/Kotlin implement biometric-gated unseal of
/// the device-sealed cggmp24 key-share. Async: the unseal awaits a biometric.
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait FfiKeyStore: Send + Sync {
    /// Unseal the device-sealed share JSON for `agent_id`, showing `reason` as the
    /// biometric prompt. Returns the plaintext cggmp24 KeyShare JSON bytes.
    async fn unseal_share(&self, agent_id: String, reason: String) -> Result<Vec<u8>, FfiError>;
}

/// Adapts the foreign [`FfiKeyStore`] to the internal `NativeKeyStore`.
#[cfg(not(target_arch = "wasm32"))]
struct FfiKeyStoreAdapter(std::sync::Arc<dyn FfiKeyStore>);

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl crate::native_io::keystore::NativeKeyStore for FfiKeyStoreAdapter {
    async fn unseal_share(
        &self,
        agent_id: &str,
        reason: &str,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, crate::error::ClientError> {
        let bytes = self
            .0
            .unseal_share(agent_id.to_string(), reason.to_string())
            .await
            .map_err(|e| crate::error::ClientError::Unseal(e.to_string()))?;
        Ok(zeroize::Zeroizing::new(bytes))
    }
}

/// FFI config for a provisioned wallet's deployed signer (all hex/primitive — no
/// FFI-opaque crypto types crossing the boundary).
#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Record)]
pub struct FfiSignerConfig {
    pub relay_url: String,
    pub container_url: String,
    /// §07.4 device identity private key (64-char hex). Distinct from the MPC share.
    pub identity_key_hex: String,
    /// Device secret rooting the at-rest seal of bundle presig bytes (64-char hex).
    pub at_rest_root_hex: String,
    /// Durable presig-pool directory (app storage path).
    pub bundle_dir: String,
    /// §09 policy hash (64-char hex; empty ⇒ all-zero).
    pub policy_id_hex: String,
    /// Joint pubkey hex (the wallet id + owner-authz key).
    pub agent_id: String,
    /// 33-byte compressed joint pubkey (66-char hex).
    pub joint_pubkey_hex: String,
    /// Base58Check P2PKH address of the joint key.
    pub joint_address: String,
    pub threshold: u16,
    pub parties: u16,
    pub participants: Vec<u16>,
    /// This device's signing index (the coordinator party).
    pub device_share_index: u16,
    /// The deployed cosigner's keygen index.
    pub cosigner_party: u16,
    /// Share-metadata session id (32-byte hex).
    pub dkg_session_id_hex: String,
}

/// A combined BSV-ready signature (DER + raw r/s), pre-flight-verified before return.
#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Record)]
pub struct FfiSignature {
    pub signature_der: Vec<u8>,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

#[cfg(not(target_arch = "wasm32"))]
fn hex32(s: &str, what: &str) -> Result<[u8; 32], FfiError> {
    let v = hex::decode(s).map_err(|e| FfiError::Client(format!("{what} hex: {e}")))?;
    v.as_slice()
        .try_into()
        .map_err(|_| FfiError::Client(format!("{what} must be 32 bytes")))
}

/// The high-level deployed signer. Construct with [`FfiDeployedSigner::connect`].
#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Object)]
pub struct FfiDeployedSigner {
    inner: crate::native_io::signer::DeployedSigner,
}

#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export(async_runtime = "tokio")]
impl FfiDeployedSigner {
    /// Connect to a provisioned wallet's deployed cosigner (BRC-31 handshake) +
    /// open the durable presig pool. `keystore` is the host's Secure Enclave.
    #[uniffi::constructor]
    pub async fn connect(
        config: FfiSignerConfig,
        keystore: std::sync::Arc<dyn FfiKeyStore>,
    ) -> Result<std::sync::Arc<Self>, FfiError> {
        use bsv::primitives::ec::PrivateKey;
        use bsv_mpc_core::types::{JointPublicKey, PolicyId, SessionId, ThresholdConfig};

        let identity = {
            let bytes = hex32(&config.identity_key_hex, "identity_key")?;
            PrivateKey::from_bytes(&bytes)
                .map_err(|e| FfiError::Client(format!("identity key: {e}")))?
        };
        let at_rest_root = hex32(&config.at_rest_root_hex, "at_rest_root")?;
        let policy_id = if config.policy_id_hex.is_empty() {
            PolicyId([0u8; 32])
        } else {
            PolicyId(hex32(&config.policy_id_hex, "policy_id")?)
        };
        let joint_compressed = hex::decode(&config.joint_pubkey_hex)
            .map_err(|e| FfiError::Client(format!("joint_pubkey hex: {e}")))?;
        let config_t = ThresholdConfig::new(config.threshold, config.parties)
            .map_err(|e| FfiError::Client(e.to_string()))?;
        let dkg_session_id =
            SessionId::from_bytes(hex32(&config.dkg_session_id_hex, "dkg_session_id")?);

        let signer_config = crate::native_io::signer::DeployedSignerConfig {
            relay_url: config.relay_url,
            container_url: config.container_url,
            identity,
            at_rest_root,
            bundle_dir: std::path::PathBuf::from(config.bundle_dir),
            policy_id,
            meta: crate::native_io::signer::WalletMeta {
                agent_id: config.agent_id,
                joint_key: JointPublicKey {
                    compressed: joint_compressed,
                    address: config.joint_address,
                },
                config: config_t,
                participants: config.participants,
                device_share_index: config.device_share_index,
                cosigner_party: config.cosigner_party,
                dkg_session_id,
            },
        };
        let keystore: std::sync::Arc<dyn crate::native_io::keystore::NativeKeyStore> =
            std::sync::Arc::new(FfiKeyStoreAdapter(keystore));
        let inner = crate::native_io::signer::DeployedSigner::connect(signer_config, keystore)
            .await
            .map_err(|e| FfiError::Client(e.to_string()))?;
        Ok(std::sync::Arc::new(Self { inner }))
    }

    /// Ready presig bundles in the pool.
    pub fn pool_len(&self) -> u32 {
        self.inner.pool_len() as u32
    }

    /// Opportunistic top-up: one biometric mints `n` durable presig bundles (heavy;
    /// off the tap path). Returns how many were minted.
    pub async fn top_up_presigs(
        &self,
        n: u32,
        reason: String,
        timeout_secs: u64,
    ) -> Result<u32, FfiError> {
        self.inner
            .top_up_presigs(
                n as usize,
                &reason,
                std::time::Duration::from_secs(timeout_secs),
            )
            .await
            .map(|m| m as u32)
            .map_err(|e| FfiError::Client(e.to_string()))
    }

    /// The high-level deployed sign: biometric-gated, fast (pool) online sign with a
    /// fail-closed pre-flight. `sighash` is 32 bytes; `brc42_offset` (32 bytes) is the
    /// optional BRC-42 derived-key shift.
    pub async fn sign(
        &self,
        sighash: Vec<u8>,
        reason: String,
        brc42_offset: Option<Vec<u8>>,
        recv_timeout_secs: u64,
        presign_timeout_secs: u64,
    ) -> Result<FfiSignature, FfiError> {
        let hash: [u8; 32] = sighash
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::Client("sighash must be 32 bytes".into()))?;
        let offset: Option<[u8; 32]> = match brc42_offset {
            Some(o) => Some(
                o.as_slice()
                    .try_into()
                    .map_err(|_| FfiError::Client("brc42_offset must be 32 bytes".into()))?,
            ),
            None => None,
        };
        let res = self
            .inner
            .sign(
                &hash,
                &reason,
                offset,
                std::time::Duration::from_secs(recv_timeout_secs),
                std::time::Duration::from_secs(presign_timeout_secs),
            )
            .await
            .map_err(|e| FfiError::Client(e.to_string()))?;
        Ok(FfiSignature {
            signature_der: res.signature,
            r: res.r,
            s: res.s,
        })
    }
}

// ── High-level BRC-103/104 storage seam over UniFFI (issue #64) ───────────────
//
// Rust owns ALL the BRC-31/103/104 crypto/auth; the native shell only supplies
// the device identity key (held device-sealed) + the JSON method/params, and
// receives parsed JSON back. Exposed as a `uniffi::Object` with **async**
// methods (UniFFI 0.28 runtime-agnostic async export) because the underlying
// transport is async `reqwest`. Native-only — never in the wasm build.

/// An open, authenticated (Phase-A handshake complete) storage connection.
#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Object)]
pub struct WalletStorageConn {
    inner: crate::native_io::storage::StorageClient,
}

#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export(async_runtime = "tokio")]
impl WalletStorageConn {
    /// Open a connection: runs the BRC-103/104 Phase-A handshake against
    /// `base_url` using the device identity private key (64-char hex).
    #[uniffi::constructor]
    pub async fn open(
        base_url: String,
        identity_key_hex: String,
    ) -> Result<std::sync::Arc<Self>, FfiError> {
        let inner = crate::native_io::storage::StorageClient::open(&base_url, &identity_key_hex)
            .await
            .map_err(|e| FfiError::Client(e.to_string()))?;
        Ok(std::sync::Arc::new(Self { inner }))
    }

    /// Run a signed (Phase-B) JSON-RPC call. `params_json` is a JSON array
    /// string of params; returns the JSON-encoded `result`. The server's
    /// response signature is verified (fail-closed) inside this call.
    pub async fn rpc(&self, method: String, params_json: String) -> Result<String, FfiError> {
        let params: Vec<serde_json::Value> = serde_json::from_str(&params_json)
            .map_err(|e| FfiError::Client(format!("params_json must be a JSON array: {e}")))?;
        let result = self
            .inner
            .rpc(&method, params)
            .await
            .map_err(|e| FfiError::Client(e.to_string()))?;
        serde_json::to_string(&result).map_err(|e| FfiError::Client(format!("encode result: {e}")))
    }
}
