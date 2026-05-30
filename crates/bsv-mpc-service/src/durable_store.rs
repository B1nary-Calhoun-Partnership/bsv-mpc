//! **#102 — the durable share-custody seam.** The deployed CF Container cosigner
//! keeps shares in an in-memory cache (ephemeral: wiped on every redeploy/restart),
//! with #9 KEK-sealed durable custody on the Worker DO as the survival anchor. This
//! makes durability **structural** instead of bolted-on per-call-site: a fundable
//! share becomes durable through ONE method ([`DurableShares::persist_durable`],
//! custody-PUT FIRST + fail-closed), and recovery ([`DurableShares::load_or_recover`])
//! transparently re-hydrates it from custody after a restart.
//!
//! It is a thin **borrowing facade** over the `AppState` cache + custody fields (got
//! via [`AppState::shares`](crate::AppState::shares)) — so it adds the durable API
//! with ZERO change to `AppState`'s shape, every sync read site, or the cggmp24
//! state-machine's hot-cache write (the mainnet-proven paths stay byte-identical).
//!
//! Keys are opaque strings — bare `agent_id` (2-party) or composite `{agent_id}#{index}`
//! (n-party device-holds). The Worker-DO custody store and the in-memory cache use the
//! SAME key (`SqliteShareStorage::composite_key`), so cache + custody never drift.
//!
//! ## Invariant (the fund-safety property #102 closes)
//! A wallet is reported **provisioned/fundable ONLY after `persist_durable` returns
//! `Ok`** — i.e. only after its share is durably custodied — so an ephemeral-container
//! restart can never strand a funded wallet's cosigner share.

use std::sync::{Arc, RwLock};

use bsv_mpc_core::types::EncryptedShare;

use crate::storage::SqliteShareStorage;
use crate::CustodyConfig;

/// Borrowing durable-custody facade over the in-memory cache + the optional #9
/// custody backend. Construct via [`AppState::shares`](crate::AppState::shares).
pub struct DurableShares<'a> {
    cache: &'a Arc<RwLock<SqliteShareStorage>>,
    custody: Option<&'a CustodyConfig>,
}

impl<'a> DurableShares<'a> {
    pub(crate) fn new(
        cache: &'a Arc<RwLock<SqliteShareStorage>>,
        custody: Option<&'a CustodyConfig>,
    ) -> Self {
        Self { cache, custody }
    }

    /// Whether durable custody is configured (vs in-memory-only dev mode).
    pub fn has_custody(&self) -> bool {
        self.custody.is_some()
    }

    /// **THE durable persist (fail-closed).** Custody-PUT FIRST (when custody is
    /// configured) so a returned `Ok` GUARANTEES the share survives a restart, THEN
    /// the in-memory cache — exactly the mainnet-proven `/dkg/round` ordering,
    /// generalized to every path + key (bare or composite). Callers MUST gate
    /// "provisioned/fundable" on this returning `Ok`.
    pub async fn persist_durable(
        &self,
        key: &str,
        share: &EncryptedShare,
        owner: &str,
    ) -> anyhow::Result<()> {
        // 1. Durable first — if this fails, the share is NOT persisted (the caller
        //    must not signal fundable), so there is no funded-but-stranded window.
        if let Some(custody) = self.custody {
            custody
                .put_share(key, share, owner)
                .await
                .map_err(|e| anyhow::anyhow!("durable custody put for '{key}': {e}"))?;
        }
        // 2. Hot cache (so an immediate sign-after-provision hits memory, not custody).
        self.cache
            .write()
            .map_err(|_| anyhow::anyhow!("share cache RwLock poisoned"))?
            .store_share_with_owner(key, share, owner)
    }

    /// [`persist_durable`](Self::persist_durable) for a composite held index
    /// `{agent_id}#{index}` (n-party device-holds).
    pub async fn persist_durable_at_index(
        &self,
        agent_id: &str,
        index: u16,
        share: &EncryptedShare,
        owner: &str,
    ) -> anyhow::Result<()> {
        self.persist_durable(
            &SqliteShareStorage::composite_key(agent_id, index),
            share,
            owner,
        )
        .await
    }

    /// Load a share by its raw key: in-memory cache hit (hot), else recover from
    /// durable custody (re-binding the owner into the cache), else `Ok(None)`. Works
    /// for bare `agent_id` AND composite `{agent_id}#{index}` keys.
    pub async fn load_or_recover(&self, key: &str) -> anyhow::Result<Option<EncryptedShare>> {
        // Hot path: in-memory cache.
        {
            let cache = self
                .cache
                .read()
                .map_err(|_| anyhow::anyhow!("share cache RwLock poisoned"))?;
            if let Some(share) = cache.get_share(key)? {
                return Ok(Some(share));
            }
        }
        // Cold path (post-restart): recover from durable custody, re-binding owner.
        if let Some(custody) = self.custody {
            if let Some((share, owner)) = custody
                .get_share(key)
                .await
                .map_err(|e| anyhow::anyhow!("durable custody recover for '{key}': {e}"))?
            {
                self.cache
                    .write()
                    .map_err(|_| anyhow::anyhow!("share cache RwLock poisoned"))?
                    .store_share_with_owner(key, &share, &owner)?;
                return Ok(Some(share));
            }
        }
        Ok(None)
    }

    /// [`load_or_recover`](Self::load_or_recover) for a composite held index
    /// `{agent_id}#{index}` — the composite custody recovery missing before #102.
    pub async fn load_or_recover_at_index(
        &self,
        agent_id: &str,
        index: u16,
    ) -> anyhow::Result<Option<EncryptedShare>> {
        self.load_or_recover(&SqliteShareStorage::composite_key(agent_id, index))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_mpc_core::types::{SessionId, ShareIndex, ThresholdConfig};

    fn cache() -> Arc<RwLock<SqliteShareStorage>> {
        let dir = std::env::temp_dir().join(format!("durable_store_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(RwLock::new(
            SqliteShareStorage::open(dir.to_str().unwrap()).unwrap(),
        ))
    }

    fn share(tag: u8) -> EncryptedShare {
        EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![tag; 16],
            session_id: SessionId::from_bytes([tag; 32]),
            share_index: ShareIndex(tag as u16),
            config: ThresholdConfig::new(2, 2).unwrap(),
            joint_pubkey_compressed: vec![],
        }
    }

    // custody=None ⇒ persist/load exercise the cache + the composite-key seam logic
    // (the real custody durability is proven by the deployed post-redeploy E2E + the
    // key-agnostic #9 custody round-trip the seam reuses unchanged).

    #[tokio::test]
    async fn bare_persist_then_load_round_trips() {
        let c = cache();
        let shares = DurableShares::new(&c, None);
        shares
            .persist_durable("agentA", &share(1), "owner1")
            .await
            .unwrap();
        let got = shares.load_or_recover("agentA").await.unwrap().unwrap();
        assert_eq!(got.ciphertext, share(1).ciphertext);
        assert!(shares.load_or_recover("missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn composite_persist_then_load_round_trips_and_is_key_isolated() {
        let c = cache();
        let shares = DurableShares::new(&c, None);
        // Two held indices of ONE agent — must NOT collide (the last-write-wins bug).
        shares
            .persist_durable_at_index("agentB", 3, &share(3), "ownerB")
            .await
            .unwrap();
        shares
            .persist_durable_at_index("agentB", 4, &share(4), "ownerB")
            .await
            .unwrap();

        assert_eq!(
            shares
                .load_or_recover_at_index("agentB", 3)
                .await
                .unwrap()
                .unwrap()
                .ciphertext,
            share(3).ciphertext
        );
        assert_eq!(
            shares
                .load_or_recover_at_index("agentB", 4)
                .await
                .unwrap()
                .unwrap()
                .ciphertext,
            share(4).ciphertext
        );
        // Composite namespace is disjoint from the bare key + from other indices.
        assert!(shares.load_or_recover("agentB").await.unwrap().is_none());
        assert!(shares
            .load_or_recover_at_index("agentB", 5)
            .await
            .unwrap()
            .is_none());
        // The composite key matches the storage layer's own format (no drift).
        assert_eq!(SqliteShareStorage::composite_key("agentB", 3), "agentB#3");
    }
}
