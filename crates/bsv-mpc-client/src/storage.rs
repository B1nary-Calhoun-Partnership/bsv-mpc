//! Host-injected wallet storage seam.
//!
//! Native impls use sqlx (Phase 4 `native-io`); wasm + UniFFI impls delegate to
//! host callbacks (browser storage / app Keychain).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::ClientError;

/// Per-agent share **metadata**. The secret share material itself lives
/// device-sealed in the [`KeyStore`](crate::KeyStore); this record holds only
/// what's needed to reconstruct the signing context around it.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredShare {
    pub agent_id: String,
    /// This party's share index in `[0, parties)`.
    pub share_index: u16,
    /// Group threshold config.
    pub threshold: u16,
    pub parties: u16,
    /// 32-byte MPC session id (the cggmp24 ExecutionId seed); both parties agree.
    pub session_id: Vec<u8>,
    /// Serialized `bsv_mpc_core::JointPublicKey` (group pubkey) — used by
    /// `derive_address` and as the signing pubkey.
    pub joint_pubkey: Vec<u8>,
}

/// Persistence seam.
///
/// `?Send`: host/UniFFI/wasm implementations are single-threaded.
#[async_trait(?Send)]
pub trait WalletStorage {
    async fn put_share(&self, share: StoredShare) -> Result<(), ClientError>;
    async fn get_share(&self, agent_id: &str) -> Result<Option<StoredShare>, ClientError>;
    async fn list_agents(&self) -> Result<Vec<String>, ClientError>;
}
