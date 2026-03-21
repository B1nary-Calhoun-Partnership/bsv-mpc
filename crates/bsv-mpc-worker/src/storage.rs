//! Durable Object SQLite storage for encrypted MPC key shares.
//!
//! Each agent's key share is stored encrypted in a Durable Object that provides
//! per-agent isolation. The Durable Object uses SQLite (CF D1-compatible API)
//! for structured storage of shares, presigning state, and session metadata.
//!
//! ## Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS shares (
//!     agent_id       TEXT PRIMARY KEY,
//!     session_id     TEXT NOT NULL,
//!     share_index    INTEGER NOT NULL,
//!     encrypted_share BLOB NOT NULL,
//!     config_json    TEXT NOT NULL,
//!     created_at     TEXT NOT NULL,
//!     updated_at     TEXT NOT NULL
//! );
//!
//! CREATE TABLE IF NOT EXISTS presigning_state (
//!     id         TEXT PRIMARY KEY,
//!     agent_id   TEXT NOT NULL,
//!     session_id TEXT NOT NULL,
//!     round      INTEGER NOT NULL,
//!     state      BLOB NOT NULL,
//!     created_at TEXT NOT NULL,
//!     FOREIGN KEY (agent_id) REFERENCES shares(agent_id)
//! );
//!
//! CREATE TABLE IF NOT EXISTS presignatures (
//!     id         TEXT PRIMARY KEY,
//!     agent_id   TEXT NOT NULL,
//!     session_id TEXT NOT NULL,
//!     data       BLOB NOT NULL,
//!     created_at TEXT NOT NULL,
//!     consumed   INTEGER NOT NULL DEFAULT 0,
//!     FOREIGN KEY (agent_id) REFERENCES shares(agent_id)
//! );
//! ```
//!
//! ## Security
//!
//! - Shares are stored encrypted (AES-256-GCM with BRC-42 derived keys).
//! - The encryption key never touches this Worker — shares arrive pre-encrypted
//!   from the DKG protocol and are returned encrypted for the signing protocol.
//! - Presigning state is also stored encrypted.
//! - The `config_json` field stores the threshold configuration as plaintext
//!   (it contains no secret data — just t, n values).

use bsv_mpc_core::types::EncryptedShare;
use worker::*;

/// Wrapper around Durable Object storage providing typed access to MPC share data.
///
/// All methods operate on the Durable Object's SQLite backend, which provides
/// single-writer consistency and survives Worker restarts.
pub struct ShareStorage {
    /// Reference to the Durable Object's transactional storage API.
    ///
    /// In production this wraps `worker::durable_object::State::storage()`.
    /// The storage handle provides both key-value and SQL interfaces;
    /// we use the SQL interface for structured queries.
    _marker: std::marker::PhantomData<()>,
}

/// Metadata about a stored share (safe to return over the wire — no secret data).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

impl ShareStorage {
    /// Create a new ShareStorage wrapping the Durable Object's storage context.
    ///
    /// Initializes the SQLite schema if the tables do not already exist.
    /// Uses IF NOT EXISTS so this is safe to call on every request.
    pub async fn new(_ctx: &RouteContext<()>) -> Result<Self> {
        todo!(
            "1. Get storage handle from Durable Object state\n\
             2. Execute CREATE TABLE IF NOT EXISTS for shares, presigning_state, presignatures\n\
             3. Return ShareStorage instance wrapping the storage handle"
        )
    }

    /// Store an encrypted key share for an agent.
    ///
    /// If the agent already has a share, this replaces it (used during key refresh).
    /// The share is stored encrypted — this method does not perform any
    /// encryption/decryption; it trusts that the caller (DKG protocol) has
    /// already encrypted the share with the appropriate BRC-42 derived key.
    pub async fn store_share(
        &self,
        agent_id: &str,
        share: &EncryptedShare,
    ) -> Result<()> {
        todo!(
            "INSERT OR REPLACE INTO shares (agent_id, session_id, share_index, \
             encrypted_share, config_json, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))\n\
             \n\
             config_json = serde_json::to_string(&share.config)"
        )
    }

    /// Retrieve an encrypted key share for an agent.
    ///
    /// Returns `None` if the agent has no share stored (e.g., DKG has not been
    /// run yet). The returned share is encrypted — the caller must decrypt it
    /// with the appropriate BRC-42 derived key.
    pub async fn get_share(
        &self,
        agent_id: &str,
    ) -> Result<Option<EncryptedShare>> {
        todo!(
            "SELECT session_id, share_index, encrypted_share, config_json \
             FROM shares WHERE agent_id = ?\n\
             \n\
             Parse config_json back to ThresholdConfig\n\
             Reconstruct EncryptedShare from columns"
        )
    }

    /// Delete an agent's key share.
    ///
    /// Used when an agent is decommissioned or when performing a full key rotation.
    /// Also deletes all presigning state and presignatures for the agent.
    pub async fn delete_share(&self, agent_id: &str) -> Result<()> {
        todo!(
            "BEGIN TRANSACTION;\n\
             DELETE FROM presignatures WHERE agent_id = ?;\n\
             DELETE FROM presigning_state WHERE agent_id = ?;\n\
             DELETE FROM shares WHERE agent_id = ?;\n\
             COMMIT;"
        )
    }

    /// List all agent IDs that have shares stored in this Durable Object.
    ///
    /// Returns just the identity keys, not the share data itself.
    /// Used by the `/health` endpoint and for inventory management.
    pub async fn list_agents(&self) -> Result<Vec<String>> {
        todo!("SELECT agent_id FROM shares ORDER BY created_at")
    }

    /// Count the total number of shares stored.
    ///
    /// Lightweight query for the health endpoint.
    pub async fn share_count(&self) -> Result<usize> {
        todo!("SELECT COUNT(*) FROM shares")
    }

    /// Get metadata about a share without exposing any secret data.
    ///
    /// Returns the agent ID, session ID, share index, threshold config,
    /// timestamps, and presignature count. Safe to return over the wire.
    pub async fn get_share_metadata(
        &self,
        agent_id: &str,
    ) -> Result<Option<ShareMetadata>> {
        todo!(
            "SELECT s.agent_id, s.session_id, s.share_index, s.config_json, \
             s.created_at, s.updated_at, \
             (SELECT COUNT(*) FROM presignatures p WHERE p.agent_id = s.agent_id AND p.consumed = 0) \
             AS presig_count \
             FROM shares s WHERE s.agent_id = ?"
        )
    }

    /// Store intermediate presigning state for a round.
    ///
    /// During the 3-round presigning protocol, each round's output must be
    /// persisted so that the next round can pick up where it left off.
    /// This is necessary because the CF Worker may restart between rounds.
    pub async fn store_presigning_state(
        &self,
        agent_id: &str,
        session_id: &str,
        round: u8,
        state: &[u8],
    ) -> Result<()> {
        todo!(
            "INSERT OR REPLACE INTO presigning_state (id, agent_id, session_id, round, state, created_at) \
             VALUES (agent_id || ':' || round, ?, ?, ?, ?, datetime('now'))"
        )
    }

    /// Retrieve presigning state for a specific round.
    pub async fn get_presigning_state(
        &self,
        agent_id: &str,
        round: u8,
    ) -> Result<Option<Vec<u8>>> {
        todo!(
            "SELECT state FROM presigning_state \
             WHERE agent_id = ? AND round = ?"
        )
    }

    /// Store a completed presignature.
    ///
    /// Presignatures are generated in the offline phase and consumed one-at-a-time
    /// during online signing. Each presignature can be used exactly once.
    pub async fn store_presignature(
        &self,
        agent_id: &str,
        session_id: &str,
        presig_id: &str,
        data: &[u8],
    ) -> Result<()> {
        todo!(
            "INSERT INTO presignatures (id, agent_id, session_id, data, created_at, consumed) \
             VALUES (?, ?, ?, ?, datetime('now'), 0)"
        )
    }

    /// Consume a presignature for online signing.
    ///
    /// Atomically marks the presignature as consumed and returns its data.
    /// Returns `None` if no unconsumed presignatures are available.
    /// The oldest presignature is consumed first (FIFO).
    pub async fn consume_presignature(
        &self,
        agent_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        todo!(
            "BEGIN TRANSACTION;\n\
             SELECT id, data FROM presignatures \
             WHERE agent_id = ? AND consumed = 0 \
             ORDER BY created_at ASC LIMIT 1;\n\
             UPDATE presignatures SET consumed = 1 WHERE id = ?;\n\
             COMMIT;\n\
             Return the data"
        )
    }

    /// Count available (unconsumed) presignatures for an agent.
    pub async fn presignature_count(&self, agent_id: &str) -> Result<u64> {
        todo!(
            "SELECT COUNT(*) FROM presignatures \
             WHERE agent_id = ? AND consumed = 0"
        )
    }
}
