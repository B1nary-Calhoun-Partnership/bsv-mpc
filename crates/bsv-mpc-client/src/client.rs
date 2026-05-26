//! The target-agnostic client core.
//!
//! All orchestration lives here; the UniFFI (native) and wasm-bindgen (web) skins
//! (Phase 4) are thin type-translating wrappers over this struct. `Rc<dyn _>` (not
//! `Arc`) because the `?Send` seams are single-threaded on both the wasm (one JS
//! thread) and the UniFFI callback boundary.

use std::rc::Rc;

use crate::chain::{ChainServices, Utxo};
use crate::error::ClientError;
use crate::keystore::KeyStore;
use crate::storage::{StoredShare, WalletStorage};

/// A threshold wallet for one agent, composed over three host-injected seams.
pub struct WalletClient {
    agent_id: String,
    storage: Rc<dyn WalletStorage>,
    chain: Rc<dyn ChainServices>,
    keystore: Rc<dyn KeyStore>,
}

impl WalletClient {
    /// Wire the three seams for `agent_id`.
    pub fn new(
        agent_id: String,
        storage: Rc<dyn WalletStorage>,
        chain: Rc<dyn ChainServices>,
        keystore: Rc<dyn KeyStore>,
    ) -> Self {
        Self {
            agent_id,
            storage,
            chain,
            keystore,
        }
    }

    /// This client's agent id.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Provision a share: device-seal the (already core-encrypted) blob via the
    /// keystore, then persist the record. Exercises keystore + storage.
    pub async fn provision_share(
        &self,
        record: StoredShare,
        sealed_blob: &[u8],
    ) -> Result<(), ClientError> {
        self.keystore
            .seal_share(&self.agent_id, sealed_blob)
            .await?;
        self.storage.put_share(record).await?;
        Ok(())
    }

    /// List provisioned agent ids (storage passthrough).
    pub async fn list_agents(&self) -> Result<Vec<String>, ClientError> {
        self.storage.list_agents().await
    }

    /// Spendable UTXOs for `address` (chain passthrough).
    pub async fn list_utxos(&self, address: &str) -> Result<Vec<Utxo>, ClientError> {
        self.chain.list_utxos(address).await
    }

    /// BRC-42 child address derivation (local, no MPC round). **Staged — Phase 2**
    /// (lifts the proxy tx helpers + wires `bsv_mpc_core::hd`).
    pub async fn derive_address(
        &self,
        _protocol_id: &str,
        _key_id: &str,
    ) -> Result<String, ClientError> {
        Err(ClientError::NotImplemented("derive_address (Phase 2)"))
    }

    /// Biometric-gated threshold signature over a sighash. **Staged — Phase 3**
    /// (unseal → `bsv_mpc_core::signing`, `Zeroizing` end-to-end).
    pub async fn sign(
        &self,
        _sighash_hex: &str,
        _brc42_offset_hex: Option<&str>,
        _reason: &str,
    ) -> Result<String, ClientError> {
        Err(ClientError::NotImplemented("sign (Phase 3)"))
    }
}
