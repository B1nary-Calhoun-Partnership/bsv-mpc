//! Host-injected wallet storage seam.
//!
//! Native impls use sqlx (Phase 4 `native-io`); wasm + UniFFI impls delegate to
//! host callbacks (browser storage / app Keychain).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::ClientError;

/// A persisted, device-sealed share record.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredShare {
    pub agent_id: String,
    /// Serialized `bsv_mpc_core::EncryptedShare` (core AES-256-GCM sealed). The
    /// [`KeyStore`](crate::KeyStore) adds the device biometric seal on top.
    pub encrypted_share: Vec<u8>,
    /// Serialized `bsv_mpc_core::JointPublicKey` (33-byte compressed pubkey + config).
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
