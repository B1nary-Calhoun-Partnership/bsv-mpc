//! In-memory storage for MPC key shares (development/testing).
//!
//! Replaces Durable Object SQLite for local development and native testing.
//! Production CF Worker deployment will use DO SQLite for persistent storage
//! across Worker restarts.
//!
//! ## Storage Model
//!
//! Three logical stores backed by `HashMap` / `VecDeque`:
//!
//! - **Shares**: Encrypted key shares keyed by `agent_id` (one share per agent).
//! - **Protocol state**: Serialized coordinator state keyed by `session_id`
//!   (persisted between HTTP round-trip requests during DKG/signing/presigning).
//! - **Presignatures**: Completed presignatures per agent (FIFO consumption).
//!
//! All data lives in a global `Mutex<InnerStorage>` and is lost on Worker restart.
//! This is acceptable for development; production uses DO SQLite which survives restarts.

use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex};

use bsv_mpc_core::types::EncryptedShare;
use serde::{Deserialize, Serialize};

/// Global in-memory storage instance.
///
/// In production, this will be replaced by Durable Object SQLite.
/// Using a global static allows the storage to persist across
/// HTTP requests within the same Worker invocation.
static STORAGE: LazyLock<Mutex<InnerStorage>> =
    LazyLock::new(|| Mutex::new(InnerStorage::default()));

/// Internal storage state behind the mutex.
#[derive(Default)]
#[allow(dead_code)] // protocol_state is used by handlers via store/get/delete_protocol_state
struct InnerStorage {
    /// Encrypted shares keyed by agent_id.
    shares: HashMap<String, StoredShare>,
    /// Protocol state (coordinator serialized bytes) keyed by session_id.
    protocol_state: HashMap<String, Vec<u8>>,
    /// Available presignatures keyed by agent_id (FIFO queue per agent).
    presignatures: HashMap<String, VecDeque<StoredPresignature>>,
}

/// A stored encrypted share with metadata.
struct StoredShare {
    share: EncryptedShare,
    created_at: String,
    updated_at: String,
    /// BRC-31 identity key (hex) of the party that ran DKG for this share —
    /// the only principal authorized to sign/ECDH with it (§08.1: the
    /// long-lived identity key, NOT the joint pubkey). Empty for shares stored
    /// without an owner (dev / unauthenticated mode).
    owner_identity: String,
}

/// A stored presignature.
#[allow(dead_code)] // fields used for audit/debugging in production DO SQLite
struct StoredPresignature {
    id: String,
    session_id: String,
    data: Vec<u8>,
    created_at: String,
}

/// Metadata about a stored share (safe to return over the wire — no secret data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareMetadata {
    /// The agent this share belongs to (BRC-31 identity key, hex).
    pub agent_id: String,
    /// The MPC session ID (SHA-256 hash of DKG transcript).
    pub session_id: String,
    /// This party's index in the threshold group.
    pub share_index: u16,
    /// Threshold configuration (t-of-n).
    pub threshold: u16,
    /// Total parties in the group.
    pub parties: u16,
    /// When the share was created.
    pub created_at: String,
    /// When the share was last updated (e.g., after key refresh).
    pub updated_at: String,
    /// Number of available (unconsumed) presignatures for this agent.
    pub presignature_count: u64,
}

/// Storage backend the KSS handlers depend on, abstracted so the handlers run
/// over either the in-memory [`ShareStorage`] (native unit tests) or the
/// DO-SQLite [`crate::do_storage::DoSqlStorage`] (the deployed worker). Methods
/// return `Result<_, String>` — the common denominator between the in-memory
/// (`String`) and worker (`worker::Error`) error types.
pub trait MpcStore {
    /// Store a share recording its `owner_identity` (the DKG-time BRC-31
    /// identity authorized to sign with it — §08.1). Used at DKG completion.
    /// (The owner-less `store_share` lives as an inherent method on each
    /// backend for tests / refresh; the trait surface is owner-aware.)
    fn store_share_with_owner(
        &self,
        agent_id: &str,
        share: &EncryptedShare,
        owner_identity: &str,
    ) -> Result<(), String>;
    fn get_share(&self, agent_id: &str) -> Result<Option<EncryptedShare>, String>;
    /// Read the share's authorized owner identity (hex pubkey), if recorded.
    /// `None` (or empty) means no owner is bound (dev / legacy share).
    fn get_share_owner(&self, agent_id: &str) -> Result<Option<String>, String>;
    fn get_share_metadata(&self, agent_id: &str) -> Result<Option<ShareMetadata>, String>;
    fn share_count(&self) -> Result<usize, String>;
    fn total_presignature_count(&self) -> Result<u64, String>;
}

/// In-memory share storage wrapper.
///
/// All methods access the global `STORAGE` static. The struct itself is a
/// zero-sized marker that provides typed method access. Used by native unit
/// tests; the deployed worker uses [`crate::do_storage::DoSqlStorage`].
pub struct ShareStorage;

impl MpcStore for ShareStorage {
    fn store_share_with_owner(
        &self,
        agent_id: &str,
        share: &EncryptedShare,
        owner_identity: &str,
    ) -> Result<(), String> {
        ShareStorage::store_share_with_owner(self, agent_id, share, owner_identity)
    }
    fn get_share(&self, agent_id: &str) -> Result<Option<EncryptedShare>, String> {
        ShareStorage::get_share(self, agent_id)
    }
    fn get_share_owner(&self, agent_id: &str) -> Result<Option<String>, String> {
        ShareStorage::get_share_owner(self, agent_id)
    }
    fn get_share_metadata(&self, agent_id: &str) -> Result<Option<ShareMetadata>, String> {
        ShareStorage::get_share_metadata(self, agent_id)
    }
    fn share_count(&self) -> Result<usize, String> {
        ShareStorage::share_count(self)
    }
    fn total_presignature_count(&self) -> Result<u64, String> {
        ShareStorage::total_presignature_count(self)
    }
}

#[allow(dead_code)] // methods form the public storage API, called by handlers and tests
impl ShareStorage {
    /// Create a new ShareStorage instance.
    ///
    /// For the in-memory implementation, this is a no-op.
    /// In production, this will initialize the DO SQLite schema.
    pub fn new() -> Self {
        ShareStorage
    }

    // ── Share CRUD ────────────────────────────────────────────────────

    /// Store an encrypted key share for an agent (upsert).
    ///
    /// If the agent already has a share, this replaces it (used during key refresh).
    pub fn store_share(&self, agent_id: &str, share: &EncryptedShare) -> Result<(), String> {
        self.store_share_with_owner(agent_id, share, "")
    }

    /// Store an encrypted key share recording its authorized `owner_identity`
    /// (§08.1). Preserves a prior owner on upsert when `owner_identity` is empty
    /// (e.g. key refresh that doesn't re-authenticate the owner).
    pub fn store_share_with_owner(
        &self,
        agent_id: &str,
        share: &EncryptedShare,
        owner_identity: &str,
    ) -> Result<(), String> {
        let mut storage = STORAGE.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        let now = chrono::Utc::now().to_rfc3339();
        let owner = if owner_identity.is_empty() {
            storage
                .shares
                .get(agent_id)
                .map(|s| s.owner_identity.clone())
                .unwrap_or_default()
        } else {
            owner_identity.to_string()
        };
        let created_at = storage
            .shares
            .get(agent_id)
            .map(|s| s.created_at.clone())
            .unwrap_or_else(|| now.clone());
        storage.shares.insert(
            agent_id.to_string(),
            StoredShare {
                share: share.clone(),
                created_at,
                updated_at: now,
                owner_identity: owner,
            },
        );
        Ok(())
    }

    /// Retrieve an encrypted key share for an agent.
    ///
    /// Returns `None` if the agent has no share stored (DKG not yet run).
    pub fn get_share(&self, agent_id: &str) -> Result<Option<EncryptedShare>, String> {
        let storage = STORAGE.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        Ok(storage.shares.get(agent_id).map(|s| s.share.clone()))
    }

    /// Retrieve the share's authorized owner identity (hex), if recorded.
    pub fn get_share_owner(&self, agent_id: &str) -> Result<Option<String>, String> {
        let storage = STORAGE.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        Ok(storage
            .shares
            .get(agent_id)
            .map(|s| s.owner_identity.clone())
            .filter(|o| !o.is_empty()))
    }

    /// Delete an agent's key share and all associated data (cascading).
    pub fn delete_share(&self, agent_id: &str) -> Result<bool, String> {
        let mut storage = STORAGE.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        let existed = storage.shares.remove(agent_id).is_some();
        storage.presignatures.remove(agent_id);
        Ok(existed)
    }

    /// List all agent IDs that have shares stored.
    pub fn list_agents(&self) -> Result<Vec<String>, String> {
        let storage = STORAGE.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        let mut agents: Vec<String> = storage.shares.keys().cloned().collect();
        agents.sort();
        Ok(agents)
    }

    /// Count the total number of shares stored.
    pub fn share_count(&self) -> Result<usize, String> {
        let storage = STORAGE.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        Ok(storage.shares.len())
    }

    /// Get metadata about a share without exposing any secret data.
    pub fn get_share_metadata(&self, agent_id: &str) -> Result<Option<ShareMetadata>, String> {
        let storage = STORAGE.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        Ok(storage.shares.get(agent_id).map(|stored| {
            let presig_count = storage
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

    // ── Protocol State ────────────────────────────────────────────────

    /// Store intermediate protocol state (DKG or signing coordinator).
    ///
    /// Keyed by session_id. Used to persist coordinator state between
    /// HTTP round-trip requests during multi-round protocols.
    pub fn store_protocol_state(&self, session_id: &str, state: Vec<u8>) -> Result<(), String> {
        let mut storage = STORAGE.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        storage.protocol_state.insert(session_id.to_string(), state);
        Ok(())
    }

    /// Retrieve stored protocol state.
    pub fn get_protocol_state(&self, session_id: &str) -> Result<Option<Vec<u8>>, String> {
        let storage = STORAGE.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        Ok(storage.protocol_state.get(session_id).cloned())
    }

    /// Delete protocol state after ceremony completion or on error.
    pub fn delete_protocol_state(&self, session_id: &str) -> Result<(), String> {
        let mut storage = STORAGE.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        storage.protocol_state.remove(session_id);
        Ok(())
    }

    // ── Presignatures ─────────────────────────────────────────────────

    /// Store a completed presignature for an agent.
    pub fn store_presignature(
        &self,
        agent_id: &str,
        session_id: &str,
        presig_id: &str,
        data: Vec<u8>,
    ) -> Result<(), String> {
        let mut storage = STORAGE.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        let queue = storage
            .presignatures
            .entry(agent_id.to_string())
            .or_default();
        queue.push_back(StoredPresignature {
            id: presig_id.to_string(),
            session_id: session_id.to_string(),
            data,
            created_at: chrono::Utc::now().to_rfc3339(),
        });
        Ok(())
    }

    /// Consume the oldest presignature for an agent (FIFO).
    ///
    /// Atomically removes and returns the oldest unconsumed presignature.
    /// Returns `None` if no presignatures are available.
    pub fn consume_presignature(&self, agent_id: &str) -> Result<Option<Vec<u8>>, String> {
        let mut storage = STORAGE.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        Ok(storage
            .presignatures
            .get_mut(agent_id)
            .and_then(|q| q.pop_front())
            .map(|p| p.data))
    }

    /// Count available presignatures for an agent.
    pub fn presignature_count(&self, agent_id: &str) -> Result<u64, String> {
        let storage = STORAGE.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        Ok(storage
            .presignatures
            .get(agent_id)
            .map(|q| q.len() as u64)
            .unwrap_or(0))
    }

    /// Count total presignatures across all agents.
    pub fn total_presignature_count(&self) -> Result<u64, String> {
        let storage = STORAGE.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        Ok(storage.presignatures.values().map(|q| q.len() as u64).sum())
    }

    /// Reset all storage (for tests).
    #[cfg(test)]
    pub fn reset(&self) {
        if let Ok(mut storage) = STORAGE.lock() {
            storage.shares.clear();
            storage.protocol_state.clear();
            storage.presignatures.clear();
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_mpc_core::types::{SessionId, ShareIndex, ThresholdConfig};

    /// Serializes storage tests so they don't race the global `STORAGE`
    /// static via `reset()`. Each test acquires this lock for its full
    /// body. Std-only so we don't pull `serial_test` into the dep tree.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Acquire the test lock — poisoning is recovered (a failing test
    /// poisons the mutex; subsequent tests still need to run).
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn make_test_share(agent_id: &str) -> EncryptedShare {
        EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![1, 2, 3, 4],
            session_id: SessionId::from_str_hash(&format!("session-{agent_id}")),
            share_index: ShareIndex(0),
            config: ThresholdConfig {
                threshold: 2,
                parties: 2,
            },
            joint_pubkey_compressed: Vec::new(),
        }
    }

    #[test]
    fn store_and_get_share() {
        let _guard = test_lock();
        let storage = ShareStorage::new();
        storage.reset();

        let share = make_test_share("agent-1");
        storage.store_share("agent-1", &share).unwrap();

        let retrieved = storage.get_share("agent-1").unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(
            retrieved.session_id,
            SessionId::from_str_hash("session-agent-1")
        );
        assert_eq!(retrieved.share_index.0, 0);
    }

    #[test]
    fn get_nonexistent_share() {
        let _guard = test_lock();
        let storage = ShareStorage::new();
        storage.reset();

        let result = storage.get_share("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn delete_share_cascading() {
        let _guard = test_lock();
        let storage = ShareStorage::new();
        storage.reset();

        let share = make_test_share("agent-del");
        storage.store_share("agent-del", &share).unwrap();
        storage
            .store_presignature("agent-del", "sess", "presig-1", vec![10, 20])
            .unwrap();

        assert_eq!(storage.presignature_count("agent-del").unwrap(), 1);

        let deleted = storage.delete_share("agent-del").unwrap();
        assert!(deleted);
        assert!(storage.get_share("agent-del").unwrap().is_none());
        assert_eq!(storage.presignature_count("agent-del").unwrap(), 0);
    }

    #[test]
    fn delete_nonexistent_share() {
        let _guard = test_lock();
        let storage = ShareStorage::new();
        storage.reset();

        let deleted = storage.delete_share("nonexistent").unwrap();
        assert!(!deleted);
    }

    #[test]
    fn list_agents_and_count() {
        let _guard = test_lock();
        let storage = ShareStorage::new();
        storage.reset();

        assert_eq!(storage.share_count().unwrap(), 0);
        assert!(storage.list_agents().unwrap().is_empty());

        storage.store_share("bob", &make_test_share("bob")).unwrap();
        storage
            .store_share("alice", &make_test_share("alice"))
            .unwrap();

        assert_eq!(storage.share_count().unwrap(), 2);
        let agents = storage.list_agents().unwrap();
        assert_eq!(agents, vec!["alice", "bob"]); // sorted
    }

    #[test]
    fn share_metadata() {
        let _guard = test_lock();
        let storage = ShareStorage::new();
        storage.reset();

        assert!(storage.get_share_metadata("agent-m").unwrap().is_none());

        storage
            .store_share("agent-m", &make_test_share("agent-m"))
            .unwrap();
        storage
            .store_presignature("agent-m", "sess", "p1", vec![1])
            .unwrap();
        storage
            .store_presignature("agent-m", "sess", "p2", vec![2])
            .unwrap();

        let meta = storage.get_share_metadata("agent-m").unwrap().unwrap();
        assert_eq!(meta.agent_id, "agent-m");
        assert_eq!(
            meta.session_id,
            SessionId::from_str_hash("session-agent-m").hex()
        );
        assert_eq!(meta.share_index, 0);
        assert_eq!(meta.threshold, 2);
        assert_eq!(meta.parties, 2);
        assert_eq!(meta.presignature_count, 2);
    }

    #[test]
    fn protocol_state_round_trip() {
        let _guard = test_lock();
        let storage = ShareStorage::new();
        storage.reset();

        let state_bytes = vec![42u8; 100];
        storage
            .store_protocol_state("dkg-session-1", state_bytes.clone())
            .unwrap();

        let loaded = storage
            .get_protocol_state("dkg-session-1")
            .unwrap()
            .unwrap();
        assert_eq!(loaded, state_bytes);

        storage.delete_protocol_state("dkg-session-1").unwrap();
        assert!(storage
            .get_protocol_state("dkg-session-1")
            .unwrap()
            .is_none());
    }

    #[test]
    fn presignature_fifo_consumption() {
        let _guard = test_lock();
        let storage = ShareStorage::new();
        storage.reset();

        storage
            .store_presignature("agent-fifo", "s1", "p1", vec![1])
            .unwrap();
        storage
            .store_presignature("agent-fifo", "s1", "p2", vec![2])
            .unwrap();
        storage
            .store_presignature("agent-fifo", "s1", "p3", vec![3])
            .unwrap();

        assert_eq!(storage.presignature_count("agent-fifo").unwrap(), 3);

        // FIFO: oldest first
        assert_eq!(
            storage.consume_presignature("agent-fifo").unwrap(),
            Some(vec![1])
        );
        assert_eq!(
            storage.consume_presignature("agent-fifo").unwrap(),
            Some(vec![2])
        );
        assert_eq!(storage.presignature_count("agent-fifo").unwrap(), 1);

        assert_eq!(
            storage.consume_presignature("agent-fifo").unwrap(),
            Some(vec![3])
        );
        assert_eq!(storage.presignature_count("agent-fifo").unwrap(), 0);

        // Empty: returns None
        assert!(storage
            .consume_presignature("agent-fifo")
            .unwrap()
            .is_none());
    }

    #[test]
    fn total_presignature_count() {
        let _guard = test_lock();
        let storage = ShareStorage::new();
        storage.reset();

        storage
            .store_presignature("a1", "s", "p1", vec![1])
            .unwrap();
        storage
            .store_presignature("a1", "s", "p2", vec![2])
            .unwrap();
        storage
            .store_presignature("a2", "s", "p3", vec![3])
            .unwrap();

        assert_eq!(storage.total_presignature_count().unwrap(), 3);
    }

    #[test]
    fn store_share_upsert() {
        let _guard = test_lock();
        let storage = ShareStorage::new();
        storage.reset();

        let share1 = make_test_share("agent-up");
        storage.store_share("agent-up", &share1).unwrap();

        // Upsert with different data
        let mut share2 = make_test_share("agent-up");
        share2.ciphertext = vec![99, 98, 97];
        storage.store_share("agent-up", &share2).unwrap();

        let retrieved = storage.get_share("agent-up").unwrap().unwrap();
        assert_eq!(retrieved.ciphertext, vec![99, 98, 97]);
        assert_eq!(storage.share_count().unwrap(), 1);
    }

    #[test]
    fn owner_identity_round_trip_and_preserve() {
        // §08.1 / #5: store records the owner; get_share_owner returns it.
        let _guard = test_lock();
        let storage = ShareStorage::new();
        storage.reset();

        let share = make_test_share("agent-own");
        // No owner recorded by the owner-less path.
        storage.store_share("agent-own", &share).unwrap();
        assert_eq!(storage.get_share_owner("agent-own").unwrap(), None);

        // Recording an owner sticks.
        storage
            .store_share_with_owner("agent-own", &share, "02ownerkey")
            .unwrap();
        assert_eq!(
            storage.get_share_owner("agent-own").unwrap().as_deref(),
            Some("02ownerkey")
        );

        // An owner-less upsert (e.g. refresh) preserves the existing owner.
        let mut share2 = make_test_share("agent-own");
        share2.ciphertext = vec![1, 2, 3];
        storage.store_share("agent-own", &share2).unwrap();
        assert_eq!(
            storage.get_share_owner("agent-own").unwrap().as_deref(),
            Some("02ownerkey"),
            "owner-less upsert must not drop the bound owner"
        );
    }
}
