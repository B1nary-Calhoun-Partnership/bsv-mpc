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

use bsv_mpc_core::types::{EncryptedShare, PresigBundle};
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

/// `SELECT row_id, bundle_cbor_hex` row (oldest PresigBundle).
#[derive(Deserialize)]
struct BundleRow {
    row_id: String,
    bundle_cbor_hex: String,
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
        // Canonical BRC-31 sessions (#8 leg 2): full `StoredSession` as JSON.
        // Separate from the legacy `mpc_auth_sessions` (3-tuple) table so the new
        // canonical-wire path and the `/poc/auth-session-roundtrip` legacy route
        // never collide. Co-located in this DO's SQLite (isolate-stable).
        sql.exec(
            "CREATE TABLE IF NOT EXISTS mpc_canonical_sessions (\
               session_nonce TEXT PRIMARY KEY, \
               identity_key TEXT NOT NULL, \
               last_update INTEGER NOT NULL, \
               session_json TEXT NOT NULL\
             )",
            None,
        )?;
        // §07.1 replay defense (#8 leg 2): per-session consumed request-nonces.
        // The canonical `process_auth_with_storage` verifies the signature but
        // does NOT track per-request nonce reuse; this table is the consumed set
        // checked AFTER signature verification (so a forged nonce can't poison
        // it). Bounded by a TTL sweep on insert (mirrors the service's approach).
        // PK is the (session_nonce, request_nonce) pair so the same fresh nonce
        // is rejected on its second use within one session.
        sql.exec(
            "CREATE TABLE IF NOT EXISTS mpc_consumed_nonces (\
               session_nonce TEXT NOT NULL, \
               request_nonce TEXT NOT NULL, \
               seen_at INTEGER NOT NULL, \
               PRIMARY KEY (session_nonce, request_nonce)\
             )",
            None,
        )?;
        // PresigBundle pool (MPC-Spec §06.17.1 / ADR-0030): the coordinator's
        // stored unit per presign session. `bundle_cbor_hex` is the full
        // CBOR-encoded PresigBundle (its `presig_bytes` field is sealed at rest
        // via `bsv_mpc_core::presig_at_rest`; `cosigner_encrypted_shares` are
        // opaque BRC-2 ciphertext) — the DO never holds the at-rest key. The
        // binding-triple columns (`policy_id`, `joint_pubkey`,
        // `parties_at_keygen`) are denormalized out of the bundle so §06.18
        // invalidation can DELETE by binding without decoding every row.
        // `agent_id` = joint_pubkey hex = the pool key (§06.19 per-pubkey pool).
        sql.exec(
            "CREATE TABLE IF NOT EXISTS mpc_presig_bundles (\
               row_id TEXT PRIMARY KEY, \
               presig_id TEXT NOT NULL, \
               agent_id TEXT NOT NULL, \
               policy_id TEXT NOT NULL, \
               joint_pubkey TEXT NOT NULL, \
               parties_at_keygen TEXT NOT NULL, \
               bundle_cbor_hex TEXT NOT NULL, \
               created_at INTEGER NOT NULL\
             )",
            None,
        )?;
        // Durable custody of a cosigner's KEK-WRAPPED share (#9): a separate
        // table from `mpc_shares` (which holds THIS DO's own DKG shares) so the
        // two never collide. `share_json` here is the SEALED EncryptedShare
        // (AES-256-GCM under the container's KEK) — the DO never sees plaintext.
        sql.exec(
            "CREATE TABLE IF NOT EXISTS mpc_custody (\
               agent_id TEXT PRIMARY KEY, \
               share_json TEXT NOT NULL, \
               owner_identity TEXT NOT NULL DEFAULT '', \
               created_at TEXT NOT NULL, \
               updated_at TEXT NOT NULL\
             )",
            None,
        )?;
        Ok(())
    }

    // ── Durable share custody (#9 — KEK-wrapped share_A) ─────────────────

    /// Store a KEK-wrapped custody blob for `agent_id`, recording its authorized
    /// `owner_identity` (the cosigner's stable BRC-31 identity). On upsert an
    /// empty `owner_identity` preserves the bound owner (same semantics as
    /// `store_share_with_owner`). The blob is an already-sealed `EncryptedShare`.
    pub fn put_custody(
        &self,
        agent_id: &str,
        sealed: &EncryptedShare,
        owner_identity: &str,
    ) -> Result<()> {
        let json = serde_json::to_string(sealed)
            .map_err(|e| Error::RustError(format!("serialize custody blob: {e}")))?;
        let now = Self::now_ms().to_string();
        self.sql().exec(
            "INSERT INTO mpc_custody (agent_id, share_json, owner_identity, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(agent_id) DO UPDATE SET \
               share_json = excluded.share_json, updated_at = excluded.updated_at, \
               owner_identity = CASE WHEN excluded.owner_identity = '' \
                 THEN mpc_custody.owner_identity ELSE excluded.owner_identity END",
            vec![
                agent_id.into(),
                json.into(),
                owner_identity.into(),
                now.clone().into(),
                now.into(),
            ],
        )?;
        Ok(())
    }

    /// Read the custody blob's authorized owner identity, if recorded + non-empty.
    pub fn get_custody_owner(&self, agent_id: &str) -> Result<Option<String>> {
        #[derive(Deserialize)]
        struct OwnerRow {
            owner_identity: String,
        }
        let rows: Vec<OwnerRow> = self
            .sql()
            .exec(
                "SELECT owner_identity FROM mpc_custody WHERE agent_id = ?",
                vec![agent_id.into()],
            )?
            .to_array()?;
        Ok(rows
            .into_iter()
            .next()
            .map(|r| r.owner_identity)
            .filter(|o| !o.is_empty()))
    }

    /// Retrieve the sealed custody blob for `agent_id`. `None` if never stored.
    pub fn get_custody(&self, agent_id: &str) -> Result<Option<EncryptedShare>> {
        let rows: Vec<ShareJsonRow> = self
            .sql()
            .exec(
                "SELECT share_json FROM mpc_custody WHERE agent_id = ?",
                vec![agent_id.into()],
            )?
            .to_array()?;
        match rows.into_iter().next() {
            Some(r) => {
                let sealed: EncryptedShare = serde_json::from_str(&r.share_json)
                    .map_err(|e| Error::RustError(format!("deserialize custody blob: {e}")))?;
                Ok(Some(sealed))
            }
            None => Ok(None),
        }
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

    // ── Canonical BRC-31 session storage (#8 leg 2) ─────────────────────
    //
    // The middleware's `SessionStorage` trait persists the full canonical
    // `StoredSession` (it carries flags the legacy 3-tuple doesn't:
    // is_authenticated, certificates_*, created_at, last_update). It's stored as
    // JSON TEXT in its own table so the canonical handshake-write and the
    // canonical request-read hit the SAME co-located DO SQLite (the
    // auth-session-isolate fix) — and never collide with the legacy
    // `mpc_auth_sessions` table that the `/poc/auth-session-roundtrip` route
    // exercises. Keyed by `session_nonce`; a secondary lookup by identity scans
    // for the most recently updated row (the trait's `get_session_by_identity`).

    /// Upsert a canonical [`StoredSession`] (JSON), keyed by its server nonce.
    pub fn put_canonical_session(
        &self,
        session_nonce: &str,
        identity_key: &str,
        last_update: u64,
        session_json: &str,
    ) -> Result<()> {
        self.sql().exec(
            "INSERT INTO mpc_canonical_sessions \
               (session_nonce, identity_key, last_update, session_json) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(session_nonce) DO UPDATE SET \
               identity_key = excluded.identity_key, \
               last_update = excluded.last_update, \
               session_json = excluded.session_json",
            vec![
                session_nonce.into(),
                identity_key.into(),
                (last_update as i64).into(),
                session_json.into(),
            ],
        )?;
        Ok(())
    }

    /// Read a canonical session JSON by its server nonce.
    pub fn get_canonical_session(&self, session_nonce: &str) -> Result<Option<String>> {
        #[derive(Deserialize)]
        struct Row {
            session_json: String,
        }
        let rows: Vec<Row> = self
            .sql()
            .exec(
                "SELECT session_json FROM mpc_canonical_sessions WHERE session_nonce = ?",
                vec![session_nonce.into()],
            )?
            .to_array()?;
        Ok(rows.into_iter().next().map(|r| r.session_json))
    }

    /// Read the most-recently-updated canonical session JSON for an identity key.
    pub fn get_canonical_session_by_identity(&self, identity_key: &str) -> Result<Option<String>> {
        #[derive(Deserialize)]
        struct Row {
            session_json: String,
        }
        let rows: Vec<Row> = self
            .sql()
            .exec(
                "SELECT session_json FROM mpc_canonical_sessions \
                 WHERE identity_key = ? ORDER BY last_update DESC LIMIT 1",
                vec![identity_key.into()],
            )?
            .to_array()?;
        Ok(rows.into_iter().next().map(|r| r.session_json))
    }

    // ── §07.1 replay defense (#8 leg 2) ──────────────────────────────────

    /// Atomically record that `request_nonce` was consumed on the session keyed
    /// by `session_nonce`. Returns `true` if it was fresh (accept), `false` if
    /// already seen (replay → reject). Sweeps entries older than `ttl_ms` first
    /// so the consumed set stays bounded under the session TTL window. The DO is
    /// a single writer per request turn, so the SELECT-then-INSERT is atomic.
    pub fn consume_request_nonce(
        &self,
        session_nonce: &str,
        request_nonce: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<bool> {
        let sql = self.sql();
        // TTL sweep (bound the set).
        let cutoff = (now_ms.saturating_sub(ttl_ms)) as i64;
        sql.exec(
            "DELETE FROM mpc_consumed_nonces WHERE seen_at < ?",
            vec![cutoff.into()],
        )?;
        // Already consumed on this session?
        #[derive(Deserialize)]
        struct CntRow {
            n: i64,
        }
        let rows: Vec<CntRow> = sql
            .exec(
                "SELECT COUNT(*) AS n FROM mpc_consumed_nonces \
                 WHERE session_nonce = ? AND request_nonce = ?",
                vec![session_nonce.into(), request_nonce.into()],
            )?
            .to_array()?;
        if rows.first().map(|r| r.n).unwrap_or(0) > 0 {
            return Ok(false); // replay
        }
        sql.exec(
            "INSERT INTO mpc_consumed_nonces (session_nonce, request_nonce, seen_at) \
             VALUES (?, ?, ?)",
            vec![
                session_nonce.into(),
                request_nonce.into(),
                (now_ms as i64).into(),
            ],
        )?;
        Ok(true)
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

    /// Atomically delete ALL pooled presignatures for an agent (§18.9
    /// invalidation). On a share-refresh commit the cosigner MUST purge the pool
    /// so no presig generated against the OLD share is consumable against the
    /// new one. Single SQL DELETE → atomic within this DO. Returns the count
    /// purged (the COUNT + DELETE run in the same DO call, so no consume can
    /// interleave).
    pub fn delete_presignatures_for_agent(&self, agent_id: &str) -> Result<u64> {
        let n = self.presignature_count(agent_id)?;
        self.sql().exec(
            "DELETE FROM mpc_presignatures WHERE agent_id = ?",
            vec![agent_id.into()],
        )?;
        Ok(n)
    }

    // ── PresigBundle pool (§06.17.1 / ADR-0030) ─────────────────────────

    /// Persist a [`PresigBundle`] (§06.17.1). The binding triple is denormalized
    /// into indexed columns; the body is the CBOR encoding (with `presig_bytes`
    /// already sealed at rest by the caller via `presig_at_rest`). `row_id` is
    /// server-generated (`presig_id` + monotonic seq) so a reused `presig_id`
    /// can't collide on the PK.
    pub fn store_presig_bundle(&self, bundle: &PresigBundle) -> Result<()> {
        let (policy_id, joint_pubkey, parties_at_keygen) = bundle.storage_columns();
        let cbor = bundle
            .to_cbor()
            .map_err(|e| Error::RustError(format!("encode PresigBundle: {e}")))?;
        let cbor_hex = hex::encode(&cbor);
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = Self::now_ms();
        let row_id = format!("{}:{now}:{seq}", bundle.presig_id);
        self.sql().exec(
            "INSERT INTO mpc_presig_bundles \
               (row_id, presig_id, agent_id, policy_id, joint_pubkey, parties_at_keygen, bundle_cbor_hex, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                row_id.into(),
                bundle.presig_id.clone().into(),
                joint_pubkey.clone().into(),
                policy_id.into(),
                joint_pubkey.into(),
                parties_at_keygen.into(),
                cbor_hex.into(),
                now.into(),
            ],
        )?;
        Ok(())
    }

    /// Consume (FIFO, oldest-first) a [`PresigBundle`] for `agent_id`
    /// (= joint_pubkey hex). Single-use (§06.17.3): the row is overwritten in
    /// place (best-effort zeroize, §06.18) and then deleted, atomically within
    /// this DO, before the decoded bundle is returned. A consumed bundle can
    /// never be replayed.
    pub fn consume_presig_bundle(&self, agent_id: &str) -> Result<Option<PresigBundle>> {
        let rows: Vec<BundleRow> = self
            .sql()
            .exec(
                "SELECT row_id, bundle_cbor_hex FROM mpc_presig_bundles WHERE agent_id = ? \
                 ORDER BY created_at ASC, row_id ASC LIMIT 1",
                vec![agent_id.into()],
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        // Best-effort zeroize then delete (§06.18: overwrite, not logical-only).
        self.zeroize_and_delete("row_id", &row.row_id)?;
        let cbor = hex::decode(&row.bundle_cbor_hex)
            .map_err(|e| Error::RustError(format!("decode bundle hex: {e}")))?;
        let bundle = PresigBundle::from_cbor(&cbor)
            .map_err(|e| Error::RustError(format!("decode PresigBundle: {e}")))?;
        Ok(Some(bundle))
    }

    /// Count pooled bundles for `agent_id` (= joint_pubkey hex). §06.19 metric.
    pub fn presig_bundle_count(&self, agent_id: &str) -> Result<u64> {
        let rows: Vec<CountRow> = self
            .sql()
            .exec(
                "SELECT COUNT(*) AS n FROM mpc_presig_bundles WHERE agent_id = ?",
                vec![agent_id.into()],
            )?
            .to_array()?;
        Ok(rows.first().map(|r| r.n as u64).unwrap_or(0))
    }

    /// §06.18 invalidation — delete all bundles for a joint_pubkey (share-refresh
    /// commit / joint-pubkey change). Overwrite-then-delete (zeroize). Returns
    /// the count purged. Atomic within this DO.
    pub fn invalidate_bundles_for_joint_pubkey(&self, joint_pubkey_hex: &str) -> Result<u64> {
        self.invalidate_bundles_where("joint_pubkey", joint_pubkey_hex)
    }

    /// §06.18 invalidation — delete all bundles bound to a prior cosigner subset
    /// (operator replacement, §13.7). `parties_csv` is the canonical
    /// ascending-ordered CSV (matches [`PresigBundle::storage_columns`]).
    pub fn invalidate_bundles_for_subset(&self, parties_csv: &str) -> Result<u64> {
        self.invalidate_bundles_where("parties_at_keygen", parties_csv)
    }

    /// §06.18 invalidation — delete all bundles whose `policy_id` no longer
    /// matches the current manifest (policy update). Deletes every bundle bound
    /// to a DIFFERENT policy than `current_policy_hex`.
    pub fn invalidate_bundles_with_stale_policy(&self, current_policy_hex: &str) -> Result<u64> {
        let n: u64 = {
            let rows: Vec<CountRow> = self
                .sql()
                .exec(
                    "SELECT COUNT(*) AS n FROM mpc_presig_bundles WHERE policy_id != ?",
                    vec![current_policy_hex.into()],
                )?
                .to_array()?;
            rows.first().map(|r| r.n as u64).unwrap_or(0)
        };
        self.sql().exec(
            "UPDATE mpc_presig_bundles SET bundle_cbor_hex = hex(zeroblob(length(bundle_cbor_hex)/2)) \
             WHERE policy_id != ?",
            vec![current_policy_hex.into()],
        )?;
        self.sql().exec(
            "DELETE FROM mpc_presig_bundles WHERE policy_id != ?",
            vec![current_policy_hex.into()],
        )?;
        Ok(n)
    }

    /// Shared helper: count → overwrite (zeroize) → delete, for an equality
    /// predicate on one column. Returns the count purged.
    fn invalidate_bundles_where(&self, column: &str, value: &str) -> Result<u64> {
        let count_sql = format!("SELECT COUNT(*) AS n FROM mpc_presig_bundles WHERE {column} = ?");
        let rows: Vec<CountRow> = self.sql().exec(&count_sql, vec![value.into()])?.to_array()?;
        let n = rows.first().map(|r| r.n as u64).unwrap_or(0);
        let overwrite_sql = format!(
            "UPDATE mpc_presig_bundles SET bundle_cbor_hex = hex(zeroblob(length(bundle_cbor_hex)/2)) WHERE {column} = ?"
        );
        self.sql().exec(&overwrite_sql, vec![value.into()])?;
        let delete_sql = format!("DELETE FROM mpc_presig_bundles WHERE {column} = ?");
        self.sql().exec(&delete_sql, vec![value.into()])?;
        Ok(n)
    }

    /// Overwrite the sealed body of a single row (best-effort zeroize) then
    /// delete it. Used by single-use consume.
    fn zeroize_and_delete(&self, column: &str, value: &str) -> Result<()> {
        let overwrite_sql = format!(
            "UPDATE mpc_presig_bundles SET bundle_cbor_hex = hex(zeroblob(length(bundle_cbor_hex)/2)) WHERE {column} = ?"
        );
        self.sql().exec(&overwrite_sql, vec![value.into()])?;
        let delete_sql = format!("DELETE FROM mpc_presig_bundles WHERE {column} = ?");
        self.sql().exec(&delete_sql, vec![value.into()])?;
        Ok(())
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

/// Canonical BRC-31 session store (#8 leg 2): backs the
/// `bsv_middleware_cloudflare::SessionStorage` trait with THIS DO's co-located
/// SQLite. The middleware's `process_auth_with_storage` reads/writes the full
/// canonical [`StoredSession`] here, so the handshake-write and the per-request
/// read survive CF isolate churn — the auth-session-isolate fix, now on the
/// canonical wire. Sessions live in DO-SQLite (NOT KV) by design.
#[async_trait::async_trait(?Send)]
impl bsv_middleware_cloudflare::SessionStorage for DoSqlStorage<'_> {
    async fn get_session(
        &self,
        session_nonce: &str,
    ) -> bsv_middleware_cloudflare::Result<Option<bsv_middleware_cloudflare::types::StoredSession>>
    {
        let json = self
            .get_canonical_session(session_nonce)
            .map_err(|e| middleware_storage_err(&e))?;
        decode_stored_session(json)
    }

    async fn get_session_by_identity(
        &self,
        identity_key_hex: &str,
    ) -> bsv_middleware_cloudflare::Result<Option<bsv_middleware_cloudflare::types::StoredSession>>
    {
        let json = self
            .get_canonical_session_by_identity(identity_key_hex)
            .map_err(|e| middleware_storage_err(&e))?;
        decode_stored_session(json)
    }

    async fn save_session(
        &self,
        session: &bsv_middleware_cloudflare::types::StoredSession,
    ) -> bsv_middleware_cloudflare::Result<()> {
        self.upsert_canonical(session)
    }

    async fn update_session(
        &self,
        session: &bsv_middleware_cloudflare::types::StoredSession,
    ) -> bsv_middleware_cloudflare::Result<()> {
        self.upsert_canonical(session)
    }
}

impl DoSqlStorage<'_> {
    /// Shared upsert for `save_session`/`update_session` (same durable row).
    fn upsert_canonical(
        &self,
        session: &bsv_middleware_cloudflare::types::StoredSession,
    ) -> bsv_middleware_cloudflare::Result<()> {
        let json = serde_json::to_string(session).map_err(|e| {
            bsv_middleware_cloudflare::AuthCloudflareError::SerializationError(e.to_string())
        })?;
        self.put_canonical_session(
            &session.session_nonce,
            &session.peer_identity_key,
            session.last_update,
            &json,
        )
        .map_err(|e| middleware_storage_err(&e))
    }
}

/// Map a `worker::Error` from the DO-SQLite layer into the middleware's error.
fn middleware_storage_err(e: &Error) -> bsv_middleware_cloudflare::AuthCloudflareError {
    bsv_middleware_cloudflare::AuthCloudflareError::KvError(e.to_string())
}

/// Deserialize a stored canonical session JSON (if present).
fn decode_stored_session(
    json: Option<String>,
) -> bsv_middleware_cloudflare::Result<Option<bsv_middleware_cloudflare::types::StoredSession>> {
    match json {
        Some(s) => {
            let session = serde_json::from_str(&s).map_err(|e| {
                bsv_middleware_cloudflare::AuthCloudflareError::SerializationError(e.to_string())
            })?;
            Ok(Some(session))
        }
        None => Ok(None),
    }
}
