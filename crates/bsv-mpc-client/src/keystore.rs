//! The enclave seam: a biometric-gated wrap-key store.
//!
//! On device, a Swift `SecureEnclaveKeyStore` — reimplemented fresh from the
//! studied 100cash pattern (Secure Enclave P-256 + ECIES + `.biometryCurrentSet`,
//! a fresh `LAContext` per unseal) — implements [`KeyStore`] via a UniFFI callback
//! interface (Phase 4). The unsealed share is returned ONLY as
//! [`Zeroizing`]`<Vec<u8>>` so it is wiped on drop and flows straight into
//! `bsv-mpc-core` signing, never persisted in plaintext.

use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::error::ClientError;

/// Biometric-gated seal/unseal of a device-protected share blob.
///
/// `?Send`: device/host implementations (UniFFI foreign trait, wasm JS closures)
/// are single-threaded and not `Send`.
#[async_trait(?Send)]
pub trait KeyStore {
    /// Device-encrypt (biometric-bound) and persist `sealed_input` (already
    /// core-encrypted) under `agent_id`. Mirrors Swift `sealShare(_:)`.
    async fn seal_share(&self, agent_id: &str, sealed_input: &[u8]) -> Result<(), ClientError>;

    /// Unseal under a FRESH biometric prompt (user-present for every signature).
    /// `reason` is the prompt string. Returns the plaintext wrapped in
    /// [`Zeroizing`] (wiped on drop). Mirrors Swift `unsealShare(reason:)`.
    async fn unseal_share(
        &self,
        agent_id: &str,
        reason: &str,
    ) -> Result<Zeroizing<Vec<u8>>, ClientError>;
}

/// Simulator / CI / wasm-test keystore — NO Secure Enclave, NO biometrics. Holds
/// the blob in memory (wrapped in `Zeroizing`). The studied `MockKeyStore`
/// equivalent, reimplemented fresh.
#[derive(Default)]
pub struct InMemoryKeyStore {
    shares: RwLock<HashMap<String, Zeroizing<Vec<u8>>>>,
}

impl InMemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait(?Send)]
impl KeyStore for InMemoryKeyStore {
    async fn seal_share(&self, agent_id: &str, sealed_input: &[u8]) -> Result<(), ClientError> {
        let mut g = self.shares.write().map_err(|_| ClientError::Host {
            seam: "keystore",
            reason: "lock poisoned".into(),
        })?;
        g.insert(agent_id.to_string(), Zeroizing::new(sealed_input.to_vec()));
        Ok(())
    }

    async fn unseal_share(
        &self,
        agent_id: &str,
        _reason: &str,
    ) -> Result<Zeroizing<Vec<u8>>, ClientError> {
        let g = self.shares.read().map_err(|_| ClientError::Host {
            seam: "keystore",
            reason: "lock poisoned".into(),
        })?;
        g.get(agent_id)
            .cloned()
            .ok_or_else(|| ClientError::Unseal(format!("no sealed share for agent '{agent_id}'")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn seal_unseal_roundtrip_returns_zeroizing_and_rejects_unknown_agent() {
        let ks = InMemoryKeyStore::new();
        let secret = b"device-sealed core-encrypted share blob";

        ks.seal_share("agent-1", secret).await.unwrap();

        // Round-trips; the return is `Zeroizing<Vec<u8>>` (derefs to the bytes).
        let got: Zeroizing<Vec<u8>> = ks.unseal_share("agent-1", "Sign tx").await.unwrap();
        assert_eq!(&got[..], secret);

        // Validate-don't-skip: unknown agent rejects FOR THE RIGHT REASON.
        let err = ks.unseal_share("ghost", "Sign tx").await.unwrap_err();
        assert!(
            matches!(err, ClientError::Unseal(_)),
            "expected Unseal error, got {err:?}"
        );
    }
}
