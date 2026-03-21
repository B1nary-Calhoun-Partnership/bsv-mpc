//! Local SQLite storage for encrypted MPC key shares.
//!
//! This is the self-hosted equivalent of the Durable Object SQLite storage in
//! `bsv-mpc-worker`. Uses a local SQLite database file for share persistence.
//!
//! ## Database Location
//!
//! The database is stored at `{data_dir}/mpc-shares.db`. The data directory
//! is specified via the `--data-dir` CLI flag or `MPC_DATA_DIR` environment
//! variable (default: `./shares`).
//!
//! ## Schema
//!
//! Identical to the Worker version:
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
//! `SqliteShareStorage` is protected by `tokio::sync::RwLock` in the `AppState`.
//! Read operations (get, list, count) acquire a read lock; write operations
//! (store, delete, consume) acquire a write lock. This is safe for the expected
//! concurrency level (one agent per share, low QPS).

use bsv_mpc_core::types::{EncryptedShare, ThresholdConfig};
use serde::{Deserialize, Serialize};

/// SQLite-backed share storage for the self-hosted Key Share Service.
pub struct SqliteShareStorage {
    /// Path to the SQLite database file.
    pub db_path: String,
    // In production: rusqlite::Connection or similar
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

impl SqliteShareStorage {
    /// Open (or create) the SQLite database in the given data directory.
    ///
    /// Creates all tables if they don't exist. Uses WAL journal mode for
    /// better concurrent read performance.
    pub fn open(data_dir: &str) -> anyhow::Result<Self> {
        let db_path = format!("{data_dir}/mpc-shares.db");
        todo!(
            "1. Open SQLite connection at db_path\n\
             2. PRAGMA journal_mode=WAL\n\
             3. PRAGMA foreign_keys=ON\n\
             4. CREATE TABLE IF NOT EXISTS for all 5 tables\n\
             5. Return SqliteShareStorage {{ db_path }}"
        )
    }

    // ── Share CRUD ────────────────────────────────────────────────────

    /// Store an encrypted key share for an agent (upsert).
    pub fn store_share(&self, agent_id: &str, share: &EncryptedShare) -> anyhow::Result<()> {
        todo!(
            "INSERT OR REPLACE INTO shares \
             (agent_id, session_id, share_index, encrypted_share, config_json, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))"
        )
    }

    /// Retrieve an encrypted key share for an agent.
    pub fn get_share(&self, agent_id: &str) -> anyhow::Result<Option<EncryptedShare>> {
        todo!(
            "SELECT session_id, share_index, encrypted_share, config_json \
             FROM shares WHERE agent_id = ?"
        )
    }

    /// Delete an agent's share and all associated state.
    pub fn delete_share(&self, agent_id: &str) -> anyhow::Result<()> {
        todo!(
            "BEGIN;\n\
             DELETE FROM presignatures WHERE agent_id = ?;\n\
             DELETE FROM presigning_state WHERE agent_id = ?;\n\
             DELETE FROM signing_state WHERE agent_id = ?;\n\
             DELETE FROM dkg_state WHERE agent_id = ?;\n\
             DELETE FROM shares WHERE agent_id = ?;\n\
             COMMIT;"
        )
    }

    /// List all agent IDs with stored shares.
    pub fn list_agents(&self) -> anyhow::Result<Vec<String>> {
        todo!("SELECT agent_id FROM shares ORDER BY created_at")
    }

    /// Count total shares.
    pub fn share_count(&self) -> anyhow::Result<usize> {
        todo!("SELECT COUNT(*) FROM shares")
    }

    /// Get share metadata without exposing secrets.
    pub fn get_share_metadata(&self, agent_id: &str) -> anyhow::Result<Option<ShareMetadata>> {
        todo!(
            "SELECT s.*, \
             (SELECT COUNT(*) FROM presignatures p WHERE p.agent_id = s.agent_id AND p.consumed = 0) \
             FROM shares s WHERE s.agent_id = ?"
        )
    }

    // ── DKG State ─────────────────────────────────────────────────────

    /// Store intermediate DKG coordinator state between rounds.
    pub fn store_dkg_state(&self, state: &DkgSessionState) -> anyhow::Result<()> {
        todo!(
            "INSERT OR REPLACE INTO dkg_state \
             (session_id, agent_id, round, state, created_at, updated_at) \
             VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))"
        )
    }

    /// Load DKG coordinator state for a session.
    pub fn get_dkg_state(&self, session_id: &str) -> anyhow::Result<Option<DkgSessionState>> {
        todo!("SELECT * FROM dkg_state WHERE session_id = ?")
    }

    /// Delete DKG state after ceremony completes (or on error).
    pub fn delete_dkg_state(&self, session_id: &str) -> anyhow::Result<()> {
        todo!("DELETE FROM dkg_state WHERE session_id = ?")
    }

    // ── Signing State ─────────────────────────────────────────────────

    /// Store intermediate signing coordinator state between rounds.
    pub fn store_signing_state(&self, state: &SigningSessionState) -> anyhow::Result<()> {
        todo!(
            "INSERT OR REPLACE INTO signing_state \
             (session_id, agent_id, round, state, sighash, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))"
        )
    }

    /// Load signing coordinator state for a session.
    pub fn get_signing_state(
        &self,
        session_id: &str,
    ) -> anyhow::Result<Option<SigningSessionState>> {
        todo!("SELECT * FROM signing_state WHERE session_id = ?")
    }

    /// Delete signing state after signing completes.
    pub fn delete_signing_state(&self, session_id: &str) -> anyhow::Result<()> {
        todo!("DELETE FROM signing_state WHERE session_id = ?")
    }

    // ── Presigning ────────────────────────────────────────────────────

    /// Store intermediate presigning state for a round.
    pub fn store_presigning_state(
        &self,
        agent_id: &str,
        session_id: &str,
        round: u8,
        state: &[u8],
    ) -> anyhow::Result<()> {
        todo!(
            "INSERT OR REPLACE INTO presigning_state \
             (id, agent_id, session_id, round, state, created_at) \
             VALUES (agent_id || ':' || round, ?, ?, ?, ?, datetime('now'))"
        )
    }

    /// Retrieve presigning state for a specific round.
    pub fn get_presigning_state(
        &self,
        agent_id: &str,
        round: u8,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        todo!(
            "SELECT state FROM presigning_state \
             WHERE agent_id = ? AND round = ?"
        )
    }

    /// Store a completed presignature.
    pub fn store_presignature(
        &self,
        agent_id: &str,
        session_id: &str,
        presig_id: &str,
        data: &[u8],
    ) -> anyhow::Result<()> {
        todo!(
            "INSERT INTO presignatures (id, agent_id, session_id, data, created_at, consumed) \
             VALUES (?, ?, ?, ?, datetime('now'), 0)"
        )
    }

    /// Consume a presignature for online signing (FIFO, atomic).
    pub fn consume_presignature(&self, agent_id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        todo!(
            "BEGIN;\n\
             SELECT id, data FROM presignatures \
             WHERE agent_id = ? AND consumed = 0 \
             ORDER BY created_at ASC LIMIT 1;\n\
             UPDATE presignatures SET consumed = 1 WHERE id = ?;\n\
             COMMIT;\n\
             Return data"
        )
    }

    /// Count available (unconsumed) presignatures for an agent.
    pub fn presignature_count(&self, agent_id: &str) -> anyhow::Result<u64> {
        todo!(
            "SELECT COUNT(*) FROM presignatures \
             WHERE agent_id = ? AND consumed = 0"
        )
    }

    /// Clean up consumed presignatures older than the given duration.
    ///
    /// Consumed presignatures are kept for audit purposes but can be pruned
    /// after the retention period (default: 30 days).
    pub fn prune_consumed_presignatures(
        &self,
        older_than: chrono::Duration,
    ) -> anyhow::Result<u64> {
        todo!(
            "DELETE FROM presignatures \
             WHERE consumed = 1 AND created_at < datetime('now', '-N days')\n\
             Return number of rows deleted"
        )
    }
}
