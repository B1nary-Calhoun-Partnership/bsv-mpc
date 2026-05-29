//! In-memory storage for encrypted MPC key shares (development/testing).
//!
//! Mirrors the storage pattern from `bsv-mpc-worker::storage` but for the
//! standalone service. Production will use local SQLite (rusqlite).
//!
//! ## Schema (planned SQLite, currently in-memory HashMap)
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS shares (
//!     agent_id        TEXT PRIMARY KEY,
//!     session_id      TEXT NOT NULL,
//!     share_index     INTEGER NOT NULL,
//!     encrypted_share BLOB NOT NULL,
//!     config_json     TEXT NOT NULL,
//!     created_at      TEXT NOT NULL DEFAULT (datetime('now')),
//!     updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
//! );
//!
//! CREATE TABLE IF NOT EXISTS presigning_state (
//!     id         TEXT PRIMARY KEY,
//!     agent_id   TEXT NOT NULL,
//!     session_id TEXT NOT NULL,
//!     round      INTEGER NOT NULL,
//!     state      BLOB NOT NULL,
//!     created_at TEXT NOT NULL DEFAULT (datetime('now')),
//!     FOREIGN KEY (agent_id) REFERENCES shares(agent_id)
//! );
//!
//! CREATE TABLE IF NOT EXISTS presignatures (
//!     id         TEXT PRIMARY KEY,
//!     agent_id   TEXT NOT NULL,
//!     session_id TEXT NOT NULL,
//!     data       BLOB NOT NULL,
//!     created_at TEXT NOT NULL DEFAULT (datetime('now')),
//!     consumed   INTEGER NOT NULL DEFAULT 0,
//!     FOREIGN KEY (agent_id) REFERENCES shares(agent_id)
//! );
//!
//! CREATE TABLE IF NOT EXISTS dkg_state (
//!     session_id TEXT PRIMARY KEY,
//!     agent_id   TEXT NOT NULL,
//!     round      INTEGER NOT NULL,
//!     state      BLOB NOT NULL,
//!     created_at TEXT NOT NULL DEFAULT (datetime('now')),
//!     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
//! );
//!
//! CREATE TABLE IF NOT EXISTS signing_state (
//!     session_id TEXT PRIMARY KEY,
//!     agent_id   TEXT NOT NULL,
//!     round      INTEGER NOT NULL,
//!     state      BLOB NOT NULL,
//!     sighash    BLOB NOT NULL,
//!     created_at TEXT NOT NULL DEFAULT (datetime('now')),
//!     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
//! );
//! ```
//!
//! ## Thread Safety
//!
//! Storage is wrapped in `tokio::sync::RwLock` in the `AppState`.
//! For the in-memory implementation, all state is inside the struct itself.

use std::collections::{HashMap, VecDeque};

use bsv_mpc_core::types::EncryptedShare;
use serde::{Deserialize, Serialize};

/// In-memory share storage for the self-hosted Key Share Service.
///
/// Production will use `rusqlite::Connection` for persistent SQLite storage.
/// This in-memory implementation matches the `bsv-mpc-worker::storage::ShareStorage`
/// pattern but is instance-based (held in `AppState`) rather than global-static.
pub struct SqliteShareStorage {
    /// Path to the SQLite database file (for display/logging only; not yet used).
    pub db_path: String,
    /// Encrypted shares keyed by agent_id.
    shares: HashMap<String, StoredShare>,
    /// Protocol state keyed by session_id.
    protocol_state: HashMap<String, Vec<u8>>,
    /// Available presignatures keyed by agent_id (FIFO queue per agent).
    presignatures: HashMap<String, VecDeque<StoredPresignature>>,
}

/// A stored encrypted share with metadata.
struct StoredShare {
    share: EncryptedShare,
    /// The authorized owner's BRC-31 identity (§08.1 — the DKG-time identity
    /// key). Empty string when DKG ran unauthenticated (dev mode); a non-empty
    /// value gates `/sign`, `/presign`, `/ecdh` to that identity alone.
    owner_identity: String,
    created_at: String,
    updated_at: String,
}

/// A stored presignature.
#[allow(dead_code)] // fields used for audit/debugging in production SQLite
struct StoredPresignature {
    id: String,
    session_id: String,
    data: Vec<u8>,
    created_at: String,
}

/// Metadata about a stored share (safe to return over the wire).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareMetadata {
    /// The agent this share belongs to (BRC-31 identity key, hex).
    pub agent_id: String,
    /// The MPC session ID (SHA-256 hash of DKG transcript).
    pub session_id: String,
    /// This party's index in the threshold group.
    pub share_index: u16,
    /// Threshold configuration: minimum signers required.
    pub threshold: u16,
    /// Total parties in the group.
    pub parties: u16,
    /// When the share was created (UTC ISO-8601).
    pub created_at: String,
    /// When the share was last updated (UTC ISO-8601).
    pub updated_at: String,
    /// Number of available (unconsumed) presignatures.
    pub presignature_count: u64,
}

/// Intermediate DKG coordinator state, persisted between rounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgSessionState {
    /// The temporary DKG session ID.
    pub session_id: String,
    /// The agent initiating this DKG.
    pub agent_id: String,
    /// Current round number (0-indexed).
    pub round: u8,
    /// Serialized coordinator state (opaque bytes from bsv-mpc-core).
    pub state: Vec<u8>,
}

/// Intermediate signing coordinator state, persisted between rounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningSessionState {
    /// The ephemeral signing session ID.
    pub session_id: String,
    /// The agent requesting signing.
    pub agent_id: String,
    /// Current round number.
    pub round: u8,
    /// Serialized signing coordinator state.
    pub state: Vec<u8>,
    /// The sighash being signed (32 bytes).
    pub sighash: Vec<u8>,
}

#[allow(dead_code)] // methods form the public storage API
impl SqliteShareStorage {
    /// Open (or create) in-memory storage in the given data directory.
    ///
    /// Production will open a SQLite database at `{data_dir}/mpc-shares.db`
    /// with WAL journal mode and foreign keys enabled.
    pub fn open(data_dir: &str) -> anyhow::Result<Self> {
        let db_path = format!("{data_dir}/mpc-shares.db");
        Ok(SqliteShareStorage {
            db_path,
            shares: HashMap::new(),
            protocol_state: HashMap::new(),
            presignatures: HashMap::new(),
        })
    }

    // ── Share CRUD ────────────────────────────────────────────────────

    /// Store an encrypted key share for an agent (upsert), without binding an
    /// owner. Equivalent to `store_share_with_owner(agent_id, share, "")`.
    pub fn store_share(&mut self, agent_id: &str, share: &EncryptedShare) -> anyhow::Result<()> {
        self.store_share_with_owner(agent_id, share, "")
    }

    /// Store an encrypted key share recording its authorized `owner_identity`
    /// (§08.1 — the DKG-time BRC-31 identity). Mirrors the worker DO's
    /// `store_share_with_owner`: on upsert, an empty `owner_identity` PRESERVES
    /// the existing owner (so a key-refresh that doesn't re-authenticate the
    /// owner won't silently drop it); a non-empty value replaces it.
    pub fn store_share_with_owner(
        &mut self,
        agent_id: &str,
        share: &EncryptedShare,
        owner_identity: &str,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        match self.shares.get_mut(agent_id) {
            Some(existing) => {
                existing.share = share.clone();
                existing.updated_at = now;
                if !owner_identity.is_empty() {
                    existing.owner_identity = owner_identity.to_string();
                }
            }
            None => {
                self.shares.insert(
                    agent_id.to_string(),
                    StoredShare {
                        share: share.clone(),
                        owner_identity: owner_identity.to_string(),
                        created_at: now.clone(),
                        updated_at: now,
                    },
                );
            }
        }
        Ok(())
    }

    /// Read the share's authorized owner identity (hex), if recorded + non-empty.
    /// `None` means "no owner bound" (dev/legacy share) — the §07 entrypoint
    /// auth gate still applies, but no per-identity owner check is enforced.
    pub fn get_share_owner(&self, agent_id: &str) -> anyhow::Result<Option<String>> {
        Ok(self
            .shares
            .get(agent_id)
            .map(|s| s.owner_identity.clone())
            .filter(|o| !o.is_empty()))
    }

    /// Retrieve an encrypted key share for an agent.
    pub fn get_share(&self, agent_id: &str) -> anyhow::Result<Option<EncryptedShare>> {
        Ok(self.shares.get(agent_id).map(|s| s.share.clone()))
    }

    // ── Composite (agent_id, share_index) keying — ADR-0052 device-holds-(t−1) ──
    //
    // A cosigner or device holding `w > 1` indices of ONE ceremony has the SAME
    // joint pubkey (hence the same `agent_id`) for every held share; keying by
    // `agent_id` alone would overwrite all but the last (last-write-wins — the
    // PR-2 storage blocker). These store/load each held share under the separate
    // composite key `"{agent_id}#{index}"`. An `agent_id` is a 33-byte compressed
    // pubkey hex (no `#`), so a composite key can never collide with a bare
    // `agent_id` (legacy single-share) key — the two namespaces are disjoint and
    // the existing 2-of-2 / reshare / refresh path is byte-for-byte unchanged.

    /// Composite storage key for one held index of an agent's ceremony.
    fn composite_key(agent_id: &str, index: u16) -> String {
        format!("{agent_id}#{index}")
    }

    /// Store one held share at `(agent_id, index)`, recording its `owner_identity`
    /// (§08.1). Owner-preservation semantics match [`store_share_with_owner`].
    pub fn store_share_at_index(
        &mut self,
        agent_id: &str,
        index: u16,
        share: &EncryptedShare,
        owner_identity: &str,
    ) -> anyhow::Result<()> {
        self.store_share_with_owner(&Self::composite_key(agent_id, index), share, owner_identity)
    }

    /// Retrieve the held share at `(agent_id, index)`, if present.
    pub fn get_share_at_index(
        &self,
        agent_id: &str,
        index: u16,
    ) -> anyhow::Result<Option<EncryptedShare>> {
        self.get_share(&Self::composite_key(agent_id, index))
    }

    /// Read the recorded owner identity (hex) for the held share at
    /// `(agent_id, index)`, if recorded + non-empty.
    pub fn get_share_owner_at_index(
        &self,
        agent_id: &str,
        index: u16,
    ) -> anyhow::Result<Option<String>> {
        self.get_share_owner(&Self::composite_key(agent_id, index))
    }

    /// Every composite-keyed index persisted for `agent_id`, ascending. Empty for
    /// a legacy bare-`agent_id` share (those carry no composite key). Used by the
    /// post-DKG persistence-before-funding verification (all `w` held shares MUST
    /// be durably present before a fundable address is returned) and by
    /// signing-time held-index lookup.
    pub fn held_indices(&self, agent_id: &str) -> anyhow::Result<Vec<u16>> {
        let prefix = format!("{agent_id}#");
        let mut out: Vec<u16> = self
            .shares
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix).and_then(|s| s.parse::<u16>().ok()))
            .collect();
        out.sort_unstable();
        Ok(out)
    }

    /// Delete an agent's share and all associated state.
    pub fn delete_share(&mut self, agent_id: &str) -> anyhow::Result<()> {
        self.shares.remove(agent_id);
        self.presignatures.remove(agent_id);
        // In production: also delete from dkg_state, signing_state, presigning_state
        Ok(())
    }

    /// List all agent IDs with stored shares.
    pub fn list_agents(&self) -> anyhow::Result<Vec<String>> {
        let mut agents: Vec<String> = self.shares.keys().cloned().collect();
        agents.sort();
        Ok(agents)
    }

    /// Count total shares.
    pub fn share_count(&self) -> anyhow::Result<usize> {
        Ok(self.shares.len())
    }

    /// Get share metadata without exposing secrets.
    pub fn get_share_metadata(&self, agent_id: &str) -> anyhow::Result<Option<ShareMetadata>> {
        Ok(self.shares.get(agent_id).map(|stored| {
            let presig_count = self
                .presignatures
                .get(agent_id)
                .map(|q| q.len() as u64)
                .unwrap_or(0);
            ShareMetadata {
                agent_id: agent_id.to_string(),
                session_id: stored.share.session_id.hex(),
                share_index: stored.share.share_index.0,
                threshold: stored.share.config.threshold,
                parties: stored.share.config.parties,
                created_at: stored.created_at.clone(),
                updated_at: stored.updated_at.clone(),
                presignature_count: presig_count,
            }
        }))
    }

    // ── DKG State ─────────────────────────────────────────────────────

    /// Store intermediate DKG coordinator state between rounds.
    pub fn store_dkg_state(&mut self, state: &DkgSessionState) -> anyhow::Result<()> {
        self.protocol_state
            .insert(format!("dkg:{}", state.session_id), state.state.clone());
        Ok(())
    }

    /// Load DKG coordinator state for a session.
    pub fn get_dkg_state(&self, session_id: &str) -> anyhow::Result<Option<DkgSessionState>> {
        Ok(self
            .protocol_state
            .get(&format!("dkg:{session_id}"))
            .map(|state| DkgSessionState {
                session_id: session_id.to_string(),
                agent_id: String::new(), // TODO: store agent_id in protocol_state
                round: 0,
                state: state.clone(),
            }))
    }

    /// Delete DKG state after ceremony completes (or on error).
    pub fn delete_dkg_state(&mut self, session_id: &str) -> anyhow::Result<()> {
        self.protocol_state.remove(&format!("dkg:{session_id}"));
        Ok(())
    }

    // ── Signing State ─────────────────────────────────────────────────

    /// Store intermediate signing coordinator state between rounds.
    pub fn store_signing_state(&mut self, state: &SigningSessionState) -> anyhow::Result<()> {
        self.protocol_state
            .insert(format!("sign:{}", state.session_id), state.state.clone());
        Ok(())
    }

    /// Load signing coordinator state for a session.
    pub fn get_signing_state(
        &self,
        session_id: &str,
    ) -> anyhow::Result<Option<SigningSessionState>> {
        Ok(self
            .protocol_state
            .get(&format!("sign:{session_id}"))
            .map(|state| SigningSessionState {
                session_id: session_id.to_string(),
                agent_id: String::new(),
                round: 0,
                state: state.clone(),
                sighash: Vec::new(),
            }))
    }

    /// Delete signing state after signing completes.
    pub fn delete_signing_state(&mut self, session_id: &str) -> anyhow::Result<()> {
        self.protocol_state.remove(&format!("sign:{session_id}"));
        Ok(())
    }

    // ── Presigning ────────────────────────────────────────────────────

    /// Store intermediate presigning state for a round.
    pub fn store_presigning_state(
        &mut self,
        agent_id: &str,
        session_id: &str,
        round: u8,
        state: &[u8],
    ) -> anyhow::Result<()> {
        let key = format!("presign:{agent_id}:{session_id}:{round}");
        self.protocol_state.insert(key, state.to_vec());
        Ok(())
    }

    /// Retrieve presigning state for a specific round.
    pub fn get_presigning_state(
        &self,
        agent_id: &str,
        round: u8,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        // Find matching key by prefix (since session_id is embedded)
        let prefix = format!("presign:{agent_id}:");
        for (key, val) in &self.protocol_state {
            if key.starts_with(&prefix) && key.ends_with(&format!(":{round}")) {
                return Ok(Some(val.clone()));
            }
        }
        Ok(None)
    }

    /// Store a completed presignature.
    pub fn store_presignature(
        &mut self,
        agent_id: &str,
        session_id: &str,
        presig_id: &str,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let queue = self.presignatures.entry(agent_id.to_string()).or_default();
        queue.push_back(StoredPresignature {
            id: presig_id.to_string(),
            session_id: session_id.to_string(),
            data: data.to_vec(),
            created_at: chrono::Utc::now().to_rfc3339(),
        });
        Ok(())
    }

    /// Consume a presignature for online signing (FIFO, atomic).
    pub fn consume_presignature(&mut self, agent_id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self
            .presignatures
            .get_mut(agent_id)
            .and_then(|q| q.pop_front())
            .map(|p| p.data))
    }

    /// Count available (unconsumed) presignatures for an agent.
    pub fn presignature_count(&self, agent_id: &str) -> anyhow::Result<u64> {
        Ok(self
            .presignatures
            .get(agent_id)
            .map(|q| q.len() as u64)
            .unwrap_or(0))
    }

    /// Atomically delete ALL presignatures for an agent (§18.9 invalidation).
    /// MUST be called on a share-refresh commit (the new share invalidates every
    /// presig generated against the old one — they MUST NOT be consumable across
    /// the refresh boundary). Returns the number purged.
    pub fn delete_presignatures_for_agent(&mut self, agent_id: &str) -> anyhow::Result<u64> {
        Ok(self
            .presignatures
            .remove(agent_id)
            .map(|q| q.len() as u64)
            .unwrap_or(0))
    }

    /// Clean up consumed presignatures older than the given duration.
    /// No-op for in-memory storage (consumed presignatures are already removed).
    pub fn prune_consumed_presignatures(
        &self,
        _older_than: chrono::Duration,
    ) -> anyhow::Result<u64> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_mpc_core::types::{SessionId, ShareIndex, ThresholdConfig};

    fn dummy_share() -> EncryptedShare {
        EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![1u8; 32],
            session_id: SessionId::from_str_hash("test-session"),
            share_index: ShareIndex(0),
            config: ThresholdConfig::new(2, 2).unwrap(),
            joint_pubkey_compressed: vec![],
        }
    }

    #[test]
    fn owner_binding_round_trips_and_empty_preserves() {
        let mut s = SqliteShareStorage::open("/tmp/test-owner-store").unwrap();
        let share = dummy_share();

        // No owner bound by default (store_share ⇒ empty owner).
        s.store_share("agentA", &share).unwrap();
        assert_eq!(s.get_share_owner("agentA").unwrap(), None);

        // Binding an owner records it.
        s.store_share_with_owner("agentA", &share, "02owner")
            .unwrap();
        assert_eq!(
            s.get_share_owner("agentA").unwrap().as_deref(),
            Some("02owner")
        );

        // A later upsert with an EMPTY owner must PRESERVE the existing owner
        // (mirrors the worker DO — a key-refresh that doesn't re-auth the owner
        // must not silently drop ownership).
        s.store_share_with_owner("agentA", &share, "").unwrap();
        assert_eq!(
            s.get_share_owner("agentA").unwrap().as_deref(),
            Some("02owner"),
            "empty owner on upsert must preserve the bound owner"
        );

        // A non-empty owner replaces it.
        s.store_share_with_owner("agentA", &share, "02newowner")
            .unwrap();
        assert_eq!(
            s.get_share_owner("agentA").unwrap().as_deref(),
            Some("02newowner")
        );

        // Unknown agent ⇒ None.
        assert_eq!(s.get_share_owner("ghost").unwrap(), None);
    }

    #[test]
    fn refresh_rotation_overwrites_share_and_purges_presigs() {
        // §18.9: a share-refresh commit rotates the share AND invalidates every
        // presig generated against the old share (must not be consumable across
        // the refresh boundary).
        let mut s = SqliteShareStorage::open("/tmp/test-refresh-rotate").unwrap();
        let old = dummy_share();
        s.store_share_with_owner("agentR", &old, "02owner").unwrap();
        s.store_presignature("agentR", "sess", "p1", b"presig-1")
            .unwrap();
        s.store_presignature("agentR", "sess", "p2", b"presig-2")
            .unwrap();
        assert_eq!(s.presignature_count("agentR").unwrap(), 2);

        // Refresh commit: overwrite the share (new key material, same agent_id)
        // and purge the now-invalid presigs.
        let mut refreshed = dummy_share();
        refreshed.ciphertext = b"refreshed-cggmp24-share".to_vec();
        s.store_share_with_owner("agentR", &refreshed, "").unwrap(); // empty owner preserves
        let purged = s.delete_presignatures_for_agent("agentR").unwrap();

        assert_eq!(purged, 2, "both stale presigs purged");
        assert_eq!(
            s.presignature_count("agentR").unwrap(),
            0,
            "no presig consumable across the refresh boundary (§18.9)"
        );
        assert!(
            s.consume_presignature("agentR").unwrap().is_none(),
            "consume after purge yields nothing"
        );
        // The rotated share is in place; the owner binding survived the rotation.
        assert_eq!(
            s.get_share("agentR").unwrap().unwrap().ciphertext,
            b"refreshed-cggmp24-share"
        );
        assert_eq!(
            s.get_share_owner("agentR").unwrap().as_deref(),
            Some("02owner")
        );
    }
}
