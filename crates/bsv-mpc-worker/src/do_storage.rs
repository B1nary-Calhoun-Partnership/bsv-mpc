//! Phase I Step 4 (I-4a) — Durable-Object-SQLite-backed MPC storage.
//!
//! The **fund-safety** store: replaces the process-global in-memory
//! [`crate::storage`] `static STORAGE` with a per-DO co-located SQLite
//! database (`state.storage().sql()`), so an (encrypted) `share_A` survives
//! isolate hibernation / eviction. An in-memory share is lost on eviction →
//! the 2-of-2 joint key can never sign again → funds permanently locked. DO
//! SQLite is strongly consistent, single-writer, co-located (zero-latency on
//! the signing hot path), and per-agent isolated.
//!
//! Mirrors the [`crate::storage::ShareStorage`] method surface so the KSS
//! handlers (I-4a.2) can swap the backend with no logic change.
//!
//! ## Schema (3 tables)
//!
//! - `mpc_shares(agent_id PK, share_json, created_at, updated_at)` — the whole
//!   [`EncryptedShare`] is stored as **JSON TEXT** (not per-column). TEXT (not
//!   BLOB) is deliberate: a BLOB column comes back from the DO SQLite cursor as
//!   a JS byte-array that serde won't map into `Vec<u8>` without `serde_bytes`;
//!   TEXT deserializes cleanly into `String` (the I-3b POC lesson). The share
//!   is already AES-256-GCM ciphertext, so the JSON holds ciphertext only.
//! - `mpc_protocol_state(session_id PK, state_hex, updated_at)` — multi-round
//!   coordinator transcript bytes as hex TEXT (belt-and-suspenders persistence;
//!   the live coordinator is pinned in the DO isolate for the short ceremony).
//! - `mpc_presignatures(id PK, agent_id, session_id, data_hex, created_at)` — FIFO
//!   per agent, ordered by `created_at` (ms) then `id`.

use bsv_mpc_core::types::EncryptedShare;
use serde::Deserialize;
use worker::{Date, Error, Result, SqlStorage, State};

use crate::storage::{MpcStore, ShareMetadata};

/// DO-SQLite-backed storage, scoped to one Durable Object's co-located SQLite.
/// Cheap to construct (borrows `&State`); each method opens a fresh
/// `sql()` handle, matching the I-3b POC pattern.
pub struct DoSqlStorage<'a> {
    state: &'a State,
}

/// `SELECT share_json` row.
#[derive(Deserialize)]
struct ShareJsonRow {
    share_json: String,
}

/// `SELECT share_json, created_at, updated_at` row (for metadata).
#[derive(Deserialize)]
struct ShareMetaRow {
    share_json: String,
    created_at: String,
    updated_at: String,
}

/// `SELECT state_hex` row.
#[derive(Deserialize)]
struct StateRow {
    state_hex: String,
}

/// `SELECT id, data_hex` row (oldest presignature).
#[derive(Deserialize)]
struct PresigRow {
    id: String,
    data_hex: String,
}

/// `SELECT COUNT(*) as n` row.
#[derive(Deserialize)]
struct CountRow {
    n: i64,
}

#[allow(dead_code)] // full storage surface; some methods land consumers in I-4a.2
impl<'a> DoSqlStorage<'a> {
    /// Wrap a Durable Object's `State`. Call [`ensure_schema`] once per
    /// request before other operations (idempotent).
    pub fn new(state: &'a State) -> Self {
        Self { state }
    }

    fn sql(&self) -> SqlStorage {
        self.state.storage().sql()
    }

    fn now_ms() -> i64 {
        Date::now().as_millis() as i64
    }

    /// Create all three tables if absent (idempotent).
    pub fn ensure_schema(&self) -> Result<()> {
        let sql = self.sql();
        sql.exec(
            "CREATE TABLE IF NOT EXISTS mpc_shares (\
               agent_id TEXT PRIMARY KEY, \
               share_json TEXT NOT NULL, \
               created_at TEXT NOT NULL, \
               updated_at TEXT NOT NULL, \
               owner_identity TEXT NOT NULL DEFAULT ''\
             )",
            None,
        )?;
        // Migration for DOs whose `mpc_shares` predates `owner_identity` (#5):
        // ADD COLUMN is idempotent-by-intent — swallow the "duplicate column"
        // error so re-running ensure_schema on an already-migrated DO is a no-op.
        let _ = sql.exec(
            "ALTER TABLE mpc_shares ADD COLUMN owner_identity TEXT NOT NULL DEFAULT ''",
            None,
        );
        sql.exec(
            "CREATE TABLE IF NOT EXISTS mpc_protocol_state (\
               session_id TEXT PRIMARY KEY, \
               state_hex TEXT NOT NULL, \
               updated_at TEXT NOT NULL\
             )",
            None,
        )?;
        sql.exec(
            "CREATE TABLE IF NOT EXISTS mpc_presignatures (\
               id TEXT PRIMARY KEY, \
               agent_id TEXT NOT NULL, \
               session_id TEXT NOT NULL, \
               data_hex TEXT NOT NULL, \
               created_at INTEGER NOT NULL\
             )",
            None,
        )?;
        sql.exec(
            "CREATE TABLE IF NOT EXISTS mpc_primes (\
               session_id TEXT PRIMARY KEY, \
               primes_json TEXT NOT NULL, \
               created_at INTEGER NOT NULL\
             )",
            None,
        )?;
        // Durable BRC-31 auth sessions (#5 step 3 / §07.7). Co-located in the
        // per-identity DO's SQLite so the handshake-write + request-read survive
        // CF isolate churn (the auth-session-isolate fix).
        sql.exec(
            "CREATE TABLE IF NOT EXISTS mpc_auth_sessions (\
               server_nonce TEXT PRIMARY KEY, \
               peer_identity_key TEXT NOT NULL, \
               peer_nonce TEXT NOT NULL, \
               created_at INTEGER NOT NULL\
             )",
            None,
        )?;
        Ok(())
    }

    // ── BRC-31 auth sessions (#5 step 3 / §07.7) ─────────────────────────

    /// Persist (upsert) a BRC-31 auth session, keyed by `server_nonce`.
    pub fn put_auth_session(
        &self,
        server_nonce: &str,
        peer_identity_key: &str,
        peer_nonce: &str,
        created_at: u64,
    ) -> Result<()> {
        self.sql().exec(
            "INSERT INTO mpc_auth_sessions \
               (server_nonce, peer_identity_key, peer_nonce, created_at) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(server_nonce) DO UPDATE SET \
               peer_identity_key = excluded.peer_identity_key, \
               peer_nonce = excluded.peer_nonce, created_at = excluded.created_at",
            vec![
                server_nonce.into(),
                peer_identity_key.into(),
                peer_nonce.into(),
                (created_at as i64).into(),
            ],
        )?;
        Ok(())
    }

    /// Look up a BRC-31 auth session by `server_nonce`.
    pub fn get_auth_session(&self, server_nonce: &str) -> Result<Option<(String, String, u64)>> {
        #[derive(Deserialize)]
        struct SessionRow {
            peer_identity_key: String,
            peer_nonce: String,
            created_at: i64,
        }
        let rows: Vec<SessionRow> = self
            .sql()
            .exec(
                "SELECT peer_identity_key, peer_nonce, created_at \
                 FROM mpc_auth_sessions WHERE server_nonce = ?",
                vec![server_nonce.into()],
            )?
            .to_array()?;
        Ok(rows
            .into_iter()
            .next()
            .map(|r| (r.peer_identity_key, r.peer_nonce, r.created_at as u64)))
    }

    // ── Pregenerated Paillier primes (I-4b: seeded off-worker) ───────────
    //
    // CGGMP'24 auxinfo safe-prime generation is too CPU-heavy for the wasm32
    // CF isolate, so primes are generated natively off-worker, POSTed to
    // `/ceremony/seed-primes`, and stashed here (opaque serde JSON of
    // `PregeneratedPrimes<SecurityLevel128>`) until the DKG loop consumes them
    // at coordinator init. Persisted so a seed call + a later ceremony-start
    // call survive an eviction in between. (Validated by deserialization at
    // consumption time, in the I-4b.2 cosigner loop.)

    /// Store (upsert) the serialized pregenerated primes for a DKG session.
    pub fn store_primes(&self, session_id: &str, primes_json: &str) -> Result<()> {
        self.sql().exec(
            "INSERT INTO mpc_primes (session_id, primes_json, created_at) \
             VALUES (?, ?, ?) \
             ON CONFLICT(session_id) DO UPDATE SET \
               primes_json = excluded.primes_json, created_at = excluded.created_at",
            vec![session_id.into(), primes_json.into(), Self::now_ms().into()],
        )?;
        Ok(())
    }

    /// Read the serialized primes for a session, if seeded.
    pub fn get_primes(&self, session_id: &str) -> Result<Option<String>> {
        #[derive(Deserialize)]
        struct PrimesRow {
            primes_json: String,
        }
        let rows: Vec<PrimesRow> = self
            .sql()
            .exec(
                "SELECT primes_json FROM mpc_primes WHERE session_id = ?",
                vec![session_id.into()],
            )?
            .to_array()?;
        Ok(rows.into_iter().next().map(|r| r.primes_json))
    }

    /// Delete the primes for a session (consume-once after the ceremony).
    pub fn delete_primes(&self, session_id: &str) -> Result<()> {
        self.sql().exec(
            "DELETE FROM mpc_primes WHERE session_id = ?",
            vec![session_id.into()],
        )?;
        Ok(())
    }

    // ── Share CRUD ──────────────────────────────────────────────────────

    /// Store (upsert) an encrypted key share for an agent. Used on DKG
    /// completion and key refresh. Owner is left unchanged (see
    /// [`store_share_with_owner`]).
    pub fn store_share(&self, agent_id: &str, share: &EncryptedShare) -> Result<()> {
        self.store_share_with_owner(agent_id, share, "")
    }

    /// Store an encrypted key share recording its authorized `owner_identity`
    /// (§08.1 — the DKG-time BRC-31 identity). On upsert, an empty
    /// `owner_identity` preserves the existing owner (the `excluded` value is
    /// only applied when non-empty), so a key-refresh that doesn't
    /// re-authenticate the owner won't silently drop it.
    pub fn store_share_with_owner(
        &self,
        agent_id: &str,
        share: &EncryptedShare,
        owner_identity: &str,
    ) -> Result<()> {
        let json = serde_json::to_string(share)
            .map_err(|e| Error::RustError(format!("serialize EncryptedShare: {e}")))?;
        let now = Self::now_ms().to_string();
        self.sql().exec(
            "INSERT INTO mpc_shares (agent_id, share_json, created_at, updated_at, owner_identity) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(agent_id) DO UPDATE SET \
               share_json = excluded.share_json, updated_at = excluded.updated_at, \
               owner_identity = CASE WHEN excluded.owner_identity = '' \
                 THEN mpc_shares.owner_identity ELSE excluded.owner_identity END",
            vec![
                agent_id.into(),
                json.into(),
                now.clone().into(),
                now.into(),
                owner_identity.into(),
            ],
        )?;
        Ok(())
    }

    /// Read the share's authorized owner identity (hex), if recorded + non-empty.
    pub fn get_share_owner(&self, agent_id: &str) -> Result<Option<String>> {
        #[derive(Deserialize)]
        struct OwnerRow {
            owner_identity: String,
        }
        let rows: Vec<OwnerRow> = self
            .sql()
            .exec(
                "SELECT owner_identity FROM mpc_shares WHERE agent_id = ?",
                vec![agent_id.into()],
            )?
            .to_array()?;
        Ok(rows
            .into_iter()
            .next()
            .map(|r| r.owner_identity)
            .filter(|o| !o.is_empty()))
    }

    /// Retrieve an encrypted key share. `None` if DKG has not run for `agent_id`.
    pub fn get_share(&self, agent_id: &str) -> Result<Option<EncryptedShare>> {
        let rows: Vec<ShareJsonRow> = self
            .sql()
            .exec(
                "SELECT share_json FROM mpc_shares WHERE agent_id = ?",
                vec![agent_id.into()],
            )?
            .to_array()?;
        match rows.into_iter().next() {
            Some(r) => {
                let share: EncryptedShare = serde_json::from_str(&r.share_json)
                    .map_err(|e| Error::RustError(format!("deserialize EncryptedShare: {e}")))?;
                Ok(Some(share))
            }
            None => Ok(None),
        }
    }

    /// Delete an agent's share + cascade its mpc_presignatures. Returns whether a
    /// share row existed.
    pub fn delete_share(&self, agent_id: &str) -> Result<bool> {
        let existed = self.get_share(agent_id)?.is_some();
        self.sql().exec(
            "DELETE FROM mpc_shares WHERE agent_id = ?",
            vec![agent_id.into()],
        )?;
        self.sql().exec(
            "DELETE FROM mpc_presignatures WHERE agent_id = ?",
            vec![agent_id.into()],
        )?;
        Ok(existed)
    }

    /// List all agent IDs with a stored share, sorted.
    pub fn list_agents(&self) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct AgentRow {
            agent_id: String,
        }
        let rows: Vec<AgentRow> = self
            .sql()
            .exec(
                "SELECT agent_id FROM mpc_shares ORDER BY agent_id ASC",
                None,
            )?
            .to_array()?;
        Ok(rows.into_iter().map(|r| r.agent_id).collect())
    }

    /// Count stored mpc_shares.
    pub fn share_count(&self) -> Result<usize> {
        let rows: Vec<CountRow> = self
            .sql()
            .exec("SELECT COUNT(*) AS n FROM mpc_shares", None)?
            .to_array()?;
        Ok(rows.first().map(|r| r.n as usize).unwrap_or(0))
    }

    /// Share metadata (no secret data). Presignature count is included.
    pub fn get_share_metadata(&self, agent_id: &str) -> Result<Option<ShareMetadata>> {
        let rows: Vec<ShareMetaRow> = self
            .sql()
            .exec(
                "SELECT share_json, created_at, updated_at FROM mpc_shares WHERE agent_id = ?",
                vec![agent_id.into()],
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let share: EncryptedShare = serde_json::from_str(&row.share_json)
            .map_err(|e| Error::RustError(format!("deserialize EncryptedShare: {e}")))?;
        let presignature_count = self.presignature_count(agent_id)?;
        Ok(Some(ShareMetadata {
            agent_id: agent_id.to_string(),
            session_id: share.session_id.hex(),
            share_index: share.share_index.0,
            threshold: share.config.threshold,
            parties: share.config.parties,
            created_at: row.created_at,
            updated_at: row.updated_at,
            presignature_count,
        }))
    }

    // ── Protocol state ──────────────────────────────────────────────────

    /// Persist intermediate coordinator transcript bytes, keyed by session.
    pub fn store_protocol_state(&self, session_id: &str, state: &[u8]) -> Result<()> {
        let hex = hex::encode(state);
        let now = Self::now_ms().to_string();
        self.sql().exec(
            "INSERT INTO mpc_protocol_state (session_id, state_hex, updated_at) \
             VALUES (?, ?, ?) \
             ON CONFLICT(session_id) DO UPDATE SET \
               state_hex = excluded.state_hex, updated_at = excluded.updated_at",
            vec![session_id.into(), hex.into(), now.into()],
        )?;
        Ok(())
    }

    /// Retrieve protocol state bytes.
    pub fn get_protocol_state(&self, session_id: &str) -> Result<Option<Vec<u8>>> {
        let rows: Vec<StateRow> = self
            .sql()
            .exec(
                "SELECT state_hex FROM mpc_protocol_state WHERE session_id = ?",
                vec![session_id.into()],
            )?
            .to_array()?;
        match rows.into_iter().next() {
            Some(r) => {
                let bytes = hex::decode(&r.state_hex)
                    .map_err(|e| Error::RustError(format!("decode mpc_protocol_state hex: {e}")))?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    /// Delete protocol state after completion or error.
    pub fn delete_protocol_state(&self, session_id: &str) -> Result<()> {
        self.sql().exec(
            "DELETE FROM mpc_protocol_state WHERE session_id = ?",
            vec![session_id.into()],
        )?;
        Ok(())
    }

    // ── Presignatures (FIFO per agent) ──────────────────────────────────

    /// Store a completed presignature.
    pub fn store_presignature(
        &self,
        agent_id: &str,
        session_id: &str,
        presig_id: &str,
        data: &[u8],
    ) -> Result<()> {
        let hex = hex::encode(data);
        // The PK `id` is SERVER-generated (caller `presig_id` + a monotonic
        // sequence) so a caller reusing a `presig_id` can never collide on the
        // primary key (which previously 500'd the INSERT). `presig_id` stays in
        // the row id for traceability; uniqueness comes from the sequence.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = Self::now_ms();
        let row_id = format!("{presig_id}:{now}:{seq}");
        self.sql().exec(
            "INSERT INTO mpc_presignatures (id, agent_id, session_id, data_hex, created_at) \
             VALUES (?, ?, ?, ?, ?)",
            vec![
                row_id.into(),
                agent_id.into(),
                session_id.into(),
                hex.into(),
                now.into(),
            ],
        )?;
        Ok(())
    }

    /// Consume (remove + return) the oldest presignature for an agent.
    pub fn consume_presignature(&self, agent_id: &str) -> Result<Option<Vec<u8>>> {
        let rows: Vec<PresigRow> = self
            .sql()
            .exec(
                "SELECT id, data_hex FROM mpc_presignatures WHERE agent_id = ? \
                 ORDER BY created_at ASC, id ASC LIMIT 1",
                vec![agent_id.into()],
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        self.sql().exec(
            "DELETE FROM mpc_presignatures WHERE id = ?",
            vec![row.id.into()],
        )?;
        let bytes = hex::decode(&row.data_hex)
            .map_err(|e| Error::RustError(format!("decode presignature hex: {e}")))?;
        Ok(Some(bytes))
    }

    /// Count available mpc_presignatures for an agent.
    pub fn presignature_count(&self, agent_id: &str) -> Result<u64> {
        let rows: Vec<CountRow> = self
            .sql()
            .exec(
                "SELECT COUNT(*) AS n FROM mpc_presignatures WHERE agent_id = ?",
                vec![agent_id.into()],
            )?
            .to_array()?;
        Ok(rows.first().map(|r| r.n as u64).unwrap_or(0))
    }

    /// Count mpc_presignatures across all agents.
    pub fn total_presignature_count(&self) -> Result<u64> {
        let rows: Vec<CountRow> = self
            .sql()
            .exec("SELECT COUNT(*) AS n FROM mpc_presignatures", None)?
            .to_array()?;
        Ok(rows.first().map(|r| r.n as u64).unwrap_or(0))
    }
}

/// Bridge the inherent `worker::Result` API to the handler-facing
/// `Result<_, String>` [`MpcStore`] trait (the deployed worker's backend).
impl MpcStore for DoSqlStorage<'_> {
    fn store_share_with_owner(
        &self,
        agent_id: &str,
        share: &EncryptedShare,
        owner_identity: &str,
    ) -> std::result::Result<(), String> {
        DoSqlStorage::store_share_with_owner(self, agent_id, share, owner_identity)
            .map_err(|e| e.to_string())
    }
    fn get_share(&self, agent_id: &str) -> std::result::Result<Option<EncryptedShare>, String> {
        DoSqlStorage::get_share(self, agent_id).map_err(|e| e.to_string())
    }
    fn get_share_owner(&self, agent_id: &str) -> std::result::Result<Option<String>, String> {
        DoSqlStorage::get_share_owner(self, agent_id).map_err(|e| e.to_string())
    }
    fn get_share_metadata(
        &self,
        agent_id: &str,
    ) -> std::result::Result<Option<ShareMetadata>, String> {
        DoSqlStorage::get_share_metadata(self, agent_id).map_err(|e| e.to_string())
    }
    fn share_count(&self) -> std::result::Result<usize, String> {
        DoSqlStorage::share_count(self).map_err(|e| e.to_string())
    }
    fn total_presignature_count(&self) -> std::result::Result<u64, String> {
        DoSqlStorage::total_presignature_count(self).map_err(|e| e.to_string())
    }
}

/// Durable BRC-31 session store (§07.7) backed by this DO's SQLite.
impl crate::auth::AuthSessionStore for DoSqlStorage<'_> {
    fn put_session(&self, session: crate::auth::AuthSession) -> std::result::Result<(), String> {
        self.put_auth_session(
            &session.server_nonce,
            &session.peer_identity_key,
            &session.peer_nonce,
            session.created_at,
        )
        .map_err(|e| e.to_string())
    }
    fn get_session(
        &self,
        server_nonce: &str,
    ) -> std::result::Result<Option<crate::auth::AuthSession>, String> {
        Ok(self
            .get_auth_session(server_nonce)
            .map_err(|e| e.to_string())?
            .map(
                |(peer_identity_key, peer_nonce, created_at)| crate::auth::AuthSession {
                    server_nonce: server_nonce.to_string(),
                    peer_identity_key,
                    peer_nonce,
                    created_at,
                },
            ))
    }
}
