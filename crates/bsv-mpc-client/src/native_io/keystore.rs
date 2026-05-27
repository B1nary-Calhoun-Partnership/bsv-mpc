//! `NativeKeyStore` — the `Send + Sync` async Secure-Enclave seam for the native
//! deployed-cosigner ceremony (#63).
//!
//! The generic [`KeyStore`](crate::keystore::KeyStore) is `?Send` (single-threaded
//! wasm / sans-io UniFFI). The high-level async `sign()` runs the deployed ceremony
//! on a real tokio runtime against `Send` relay functions, and the host injects the
//! Secure Enclave as a UniFFI **callback interface** (which is `Send + Sync`). So
//! the deployed path uses this parallel `Send + Sync` trait. The host implements
//! ONE method: biometric-gated unseal of the device-sealed cggmp24 key-share.

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::error::ClientError;

/// Biometric-gated unseal of the device-sealed share (the ONLY host crypto-adjacent
/// callback for the deployed sign seam — Secure Enclave on iOS, StrongBox on
/// Android, in-memory in CI). `Send + Sync`: the deployed ceremony runs on a real
/// runtime and the UniFFI callback interface is thread-safe.
#[async_trait]
pub trait NativeKeyStore: Send + Sync {
    /// Device-seal the freshly-provisioned cggmp24 key-share JSON for `agent_id`
    /// (the Secure Enclave wrap, write side). Called once at provisioning
    /// ([`create_wallet`](super::provision::provision_wallet)); the plaintext is
    /// consumed (not retained) here.
    async fn seal_share(&self, agent_id: &str, share_plaintext: &[u8]) -> Result<(), ClientError>;

    /// Unseal the device-sealed cggmp24 key-share JSON for `agent_id`, presenting
    /// `reason` to the user as the biometric prompt. The plaintext is returned as
    /// `Zeroizing` (wiped on drop); every fund-bearing sign re-prompts (the locked
    /// biometric-per-spend policy) so the in-memory window is per-op.
    async fn unseal_share(
        &self,
        agent_id: &str,
        reason: &str,
    ) -> Result<Zeroizing<Vec<u8>>, ClientError>;
}

/// In-memory `NativeKeyStore` for CI / local verification — the audited Secure
/// Enclave stand-in (no biometric, no hardware). Stores the share plaintext keyed
/// by `agent_id`. NEVER ships to production (the real impl is the host's Enclave
/// callback).
#[derive(Default)]
pub struct MemNativeKeyStore {
    shares: std::sync::Mutex<std::collections::HashMap<String, Zeroizing<Vec<u8>>>>,
}

impl MemNativeKeyStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seal (store) a share plaintext for `agent_id` (test provisioning).
    pub fn put(&self, agent_id: &str, share_plaintext: Vec<u8>) {
        self.shares
            .lock()
            .expect("mem keystore mutex")
            .insert(agent_id.to_string(), Zeroizing::new(share_plaintext));
    }
}

#[async_trait]
impl NativeKeyStore for MemNativeKeyStore {
    async fn seal_share(&self, agent_id: &str, share_plaintext: &[u8]) -> Result<(), ClientError> {
        self.shares
            .lock()
            .map_err(|_| ClientError::Host {
                seam: "keystore",
                reason: "mem keystore mutex poisoned".into(),
            })?
            .insert(
                agent_id.to_string(),
                Zeroizing::new(share_plaintext.to_vec()),
            );
        Ok(())
    }

    async fn unseal_share(
        &self,
        agent_id: &str,
        _reason: &str,
    ) -> Result<Zeroizing<Vec<u8>>, ClientError> {
        self.shares
            .lock()
            .map_err(|_| ClientError::Host {
                seam: "keystore",
                reason: "mem keystore mutex poisoned".into(),
            })?
            .get(agent_id)
            .cloned()
            .ok_or_else(|| ClientError::Host {
                seam: "keystore",
                reason: format!("no sealed share for agent '{agent_id}'"),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unseal_round_trips_and_missing_share_rejects_for_the_right_reason() {
        let ks = MemNativeKeyStore::new();
        // Exercise the real trait seal/unseal seam (the #65 provisioning write side).
        ks.seal_share("agent-1", b"cggmp24-keyshare-json")
            .await
            .unwrap();
        let got = ks.unseal_share("agent-1", "Approve spend").await.unwrap();
        assert_eq!(&got[..], b"cggmp24-keyshare-json");

        // Validate-don't-skip: an absent agent rejects as a keystore Host error.
        let err = ks.unseal_share("ghost", "Approve spend").await.unwrap_err();
        assert!(
            matches!(
                err,
                ClientError::Host {
                    seam: "keystore",
                    ..
                }
            ),
            "expected keystore Host error, got {err:?}"
        );
    }
}
