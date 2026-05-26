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

    /// BRC-42 "anyone" child address derivation — **local, no MPC round**.
    ///
    /// Loads the agent's stored [`JointPublicKey`](bsv_mpc_core::JointPublicKey),
    /// derives the BRC-42 child key for `(protocol_id, key_id)` at security level
    /// 2 (the standard named-protocol level), and returns its P2PKH address.
    pub async fn derive_address(
        &self,
        protocol_id: &str,
        key_id: &str,
    ) -> Result<String, ClientError> {
        let stored = self
            .storage
            .get_share(&self.agent_id)
            .await?
            .ok_or_else(|| ClientError::Host {
                seam: "storage",
                reason: format!("no share provisioned for agent '{}'", self.agent_id),
            })?;
        let joint: bsv_mpc_core::JointPublicKey = serde_json::from_slice(&stored.joint_pubkey)?;
        let child = bsv_mpc_core::hd::derive_anyone_joint_key(&joint, protocol_id, key_id, 2)?;
        Ok(child.address)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{BroadcastResult, Utxo};
    use crate::keystore::InMemoryKeyStore;
    use async_trait::async_trait;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemStorage {
        shares: RefCell<HashMap<String, StoredShare>>,
    }
    #[async_trait(?Send)]
    impl WalletStorage for MemStorage {
        async fn put_share(&self, share: StoredShare) -> Result<(), ClientError> {
            self.shares
                .borrow_mut()
                .insert(share.agent_id.clone(), share);
            Ok(())
        }
        async fn get_share(&self, agent_id: &str) -> Result<Option<StoredShare>, ClientError> {
            Ok(self.shares.borrow().get(agent_id).cloned())
        }
        async fn list_agents(&self) -> Result<Vec<String>, ClientError> {
            Ok(self.shares.borrow().keys().cloned().collect())
        }
    }

    struct NoChain;
    #[async_trait(?Send)]
    impl ChainServices for NoChain {
        async fn list_utxos(&self, _address: &str) -> Result<Vec<Utxo>, ClientError> {
            Ok(vec![])
        }
        async fn broadcast(&self, _raw_tx_hex: &str) -> Result<BroadcastResult, ClientError> {
            Err(ClientError::NotImplemented("broadcast (test)"))
        }
    }

    // Compressed secp256k1 generator point G — a valid public key to derive from.
    const G_COMPRESSED_HEX: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn client_with_joint_key() -> WalletClient {
        let storage = Rc::new(MemStorage::default());
        let joint = bsv_mpc_core::JointPublicKey {
            compressed: hex::decode(G_COMPRESSED_HEX).unwrap(),
            address: String::new(), // unused by derive_anyone_joint_key (it reads .compressed)
        };
        storage.shares.borrow_mut().insert(
            "agent-1".into(),
            StoredShare {
                agent_id: "agent-1".into(),
                encrypted_share: vec![],
                joint_pubkey: serde_json::to_vec(&joint).unwrap(),
            },
        );
        WalletClient::new(
            "agent-1".into(),
            storage,
            Rc::new(NoChain),
            Rc::new(InMemoryKeyStore::new()),
        )
    }

    #[tokio::test]
    async fn derive_address_is_deterministic_and_key_id_sensitive() {
        let client = client_with_joint_key();
        // BRC-42 protocol names must be >= 5 chars (enforced by bsv_mpc_core::hd).
        let a1 = client.derive_address("payments", "1").await.unwrap();
        let a2 = client.derive_address("payments", "1").await.unwrap();
        assert!(!a1.is_empty(), "address must be non-empty");
        assert_eq!(a1, a2, "BRC-42 derivation must be deterministic");
        let a3 = client.derive_address("payments", "2").await.unwrap();
        assert_ne!(a1, a3, "different key_id must derive a different address");

        // Validate-don't-skip: an invalid (too-short) protocol name is rejected
        // by core for the right reason, surfaced as ClientError::Core.
        let err = client.derive_address("p2p", "1").await.unwrap_err();
        assert!(
            matches!(err, ClientError::Core(_)),
            "expected Core error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn derive_address_without_share_rejects_for_the_right_reason() {
        let client = WalletClient::new(
            "ghost".into(),
            Rc::new(MemStorage::default()),
            Rc::new(NoChain),
            Rc::new(InMemoryKeyStore::new()),
        );
        let err = client.derive_address("p2p", "1").await.unwrap_err();
        assert!(
            matches!(
                err,
                ClientError::Host {
                    seam: "storage",
                    ..
                }
            ),
            "expected storage Host error, got {err:?}"
        );
    }
}
