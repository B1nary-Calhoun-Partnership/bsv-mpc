//! Host-injected chain-access seam (UTXO lookup + broadcast).
//!
//! Native impls use reqwest → WhatsOnChain / ARC (Phase 4 `native-io`); wasm +
//! UniFFI impls delegate to host callbacks. The round-message relay transport for
//! the cosigner also rides this host seam, so the native-only `bsv-mpc-messagebox`
//! crate is never pulled into the wasm graph.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::ClientError;

/// An unspent output spendable by this wallet.
#[derive(Clone, Serialize, Deserialize)]
pub struct Utxo {
    /// Big-endian (display) txid hex.
    pub txid: String,
    pub vout: u32,
    pub satoshis: u64,
    /// Locking script hex.
    pub script_hex: String,
}

/// Outcome of a broadcast attempt.
#[derive(Clone, Serialize, Deserialize)]
pub struct BroadcastResult {
    pub txid: String,
    pub accepted: bool,
    pub detail: Option<String>,
}

/// Chain access seam.
///
/// `?Send`: host/UniFFI/wasm implementations are single-threaded.
#[async_trait(?Send)]
pub trait ChainServices {
    /// UTXOs locking to `address` (P2PKH).
    async fn list_utxos(&self, address: &str) -> Result<Vec<Utxo>, ClientError>;
    /// Broadcast a raw tx (or BEEF) hex; returns the network's verdict.
    async fn broadcast(&self, raw_tx_hex: &str) -> Result<BroadcastResult, ClientError>;
}
