//! UniFFI skin (native shells: iOS / Android) — compiled only under `--features native`.
//!
//! UniFFI 0.28 proc-macro mode (no `.udl`). For now it exposes the **pure,
//! synchronous** tx helpers (the same surface the wasm skin exposes), proving the
//! Swift/Kotlin binding gate. The async `WalletClient` over UniFFI
//! `callback_interface` traits lands in the Phase 4b skin.

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
