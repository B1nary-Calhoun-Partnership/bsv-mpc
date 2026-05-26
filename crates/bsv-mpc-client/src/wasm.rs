//! wasm-bindgen skin (web client) — the browser-facing surface.
//!
//! Compiled only on `wasm32` (the native build never pulls `wasm-bindgen`). For
//! now it exposes the **pure, synchronous** tx-construction helpers a browser
//! wallet needs to build/identify transactions client-side; the async
//! `WalletClient` (init/derive_address/sign over JS host callbacks) lands in the
//! Phase 4b skin. Run the JS-binding test with `wasm-pack test --node`.

use wasm_bindgen::prelude::*;

use crate::txbuild;

/// Set a readable panic hook for the browser console. Call once at startup.
#[wasm_bindgen(start)]
pub fn __start() {
    // No console_error_panic_hook dep yet (Phase 4b); keep startup a no-op so the
    // module initializes cleanly under wasm-pack/node.
}

/// Compute the txid (display hex) of a raw transaction given as hex.
///
/// Mirrors `txbuild::compute_txid`; exposed to JS so the web client can identify
/// a transaction it built without a round-trip to a server.
#[wasm_bindgen(js_name = txTxid)]
pub fn tx_txid(raw_tx_hex: &str) -> Result<String, JsError> {
    let raw = hex::decode(raw_tx_hex).map_err(|e| JsError::new(&format!("bad hex: {e}")))?;
    Ok(txbuild::compute_txid(&raw))
}

/// Parse a raw tx (hex) and return its output satoshi values, in order.
///
/// Mirrors `txbuild::parse_tx_outputs`; lets the web client read a tx it built.
#[wasm_bindgen(js_name = txOutputSats)]
pub fn tx_output_sats(raw_tx_hex: &str) -> Result<Vec<u64>, JsError> {
    let raw = hex::decode(raw_tx_hex).map_err(|e| JsError::new(&format!("bad hex: {e}")))?;
    let outs = txbuild::parse_tx_outputs(&raw).map_err(|e| JsError::new(&e))?;
    Ok(outs.into_iter().map(|(sats, _script)| sats).collect())
}
