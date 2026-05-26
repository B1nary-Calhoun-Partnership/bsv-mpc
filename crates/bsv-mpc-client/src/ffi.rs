//! UniFFI skin (native shells: iOS / Android) — compiled only under `--features native`.
//!
//! UniFFI 0.28 proc-macro mode (no `.udl`). Exposes **synchronous** surface — the
//! tx helpers plus a host-driven [`FfiSigningSession`] state machine (the proven
//! `sans-io` pattern: the Swift/Kotlin shell owns I/O + the biometric unseal and
//! pumps round messages; Rust stays a pure sync transform, no foreign callbacks).
//! Wiring the *async* `WalletClient` over UniFFI callback interfaces is the
//! deferred Phase 4c skin.

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
