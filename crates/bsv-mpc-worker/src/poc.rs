//! Phase I Step 3 (I-3b) — DO SQLite persistence + hibernation POC.
//!
//! Proves the **fund-safety primitive** for the deployed cosigner: a
//! per-identity Durable Object that persists an (encrypted) key-share blob
//! to its **own co-located SQLite** (`state.storage().sql()`), so the share
//! survives DO hibernation / isolate eviction — unlike the current
//! in-memory `static` store, where an evicted Worker loses `share_A` and
//! the joint key can never sign again (lost funds).
//!
//! This is intentionally substrate-only (no relay): it isolates the DO
//! SQLite + hibernation story, which is novel in this codebase (poc17 only
//! persisted ~200-byte telemetry via the transactional KV; the worker has
//! never used DO SQLite). The relay-handshake-from-DO half of the POC
//! (lifting poc17's proven outbound-WS + BRC-103 onto this crate's
//! `transport_wasm`) lands in a follow-up I-3b commit; both are proven at
//! runtime by the I-3c deploy + forced-hibernation harness.
//!
//! ## Routes (forwarded from the Worker entrypoint to the per-identity DO)
//!
//! - `GET /poc/identity` — identity (from the `SERVER_PRIVATE_KEY` secret,
//!   reloaded every wake) + `instance_constructed_at_ms` (advances on
//!   eviction) + whether a share row is persisted. Two curls across a
//!   ~90s idle gap prove eviction (RAM telemetry advances) while identity
//!   + persisted share stay byte-stable — the hibernation gate.
//! - `POST /poc/persist` — idempotently persist a deterministic test
//!   share blob to DO SQLite, then read it back; returns the stored vs
//!   reloaded hex (must match). After an eviction the row is still there
//!   → the durability gate.
//!
//! Identity is loaded from the `SERVER_PRIVATE_KEY` secret on EVERY call
//! (never held in memory only) — the load-bearing piece that makes the
//! cosigner identity stable across hibernation (poc17 lesson).

use bsv::primitives::ec::PrivateKey;
use sha2::{Digest, Sha256};
use worker::*;

/// DO name for the POC cosigner (per-identity topology; one DO instance).
pub const POC_DO_NAME: &str = "cosigner-poc-1";

/// Per-identity cosigner Durable Object. Holds its key-share in DO SQLite
/// (durable across hibernation); `instance_constructed_at_ms` is in-memory
/// telemetry that advances whenever the isolate is evicted + reconstructed.
#[durable_object]
pub struct CosignerSessionDo {
    state: State,
    #[allow(dead_code)]
    env: Env,
    /// Wall-clock (ms) when THIS isolate instance was constructed. Resets
    /// on every eviction → the hibernation tell.
    instance_constructed_at_ms: u64,
}

impl DurableObject for CosignerSessionDo {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            instance_constructed_at_ms: Date::now().as_millis(),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let path = req.path();
        match path.as_str() {
            "/poc/identity" => self.handle_identity().await,
            "/poc/persist" => self.handle_persist().await,
            other => Response::error(format!("unknown POC route: {other}"), 404),
        }
    }
}

impl CosignerSessionDo {
    /// Load the cosigner identity from the `SERVER_PRIVATE_KEY` secret
    /// (every call — never cached in memory) and return its pubkey hex.
    fn identity_hex(&self) -> Result<String> {
        let priv_hex = self.env.secret("SERVER_PRIVATE_KEY")?.to_string();
        let key = PrivateKey::from_hex(&priv_hex)
            .map_err(|e| Error::RustError(format!("SERVER_PRIVATE_KEY parse: {e:?}")))?;
        Ok(key.public_key().to_hex())
    }

    /// Ensure the `shares` table exists (idempotent).
    fn ensure_schema(&self) -> Result<()> {
        self.state
            .storage()
            .sql()
            .exec(
                "CREATE TABLE IF NOT EXISTS shares (\
                   agent_id TEXT PRIMARY KEY, \
                   ciphertext BLOB NOT NULL, \
                   created_at INTEGER NOT NULL\
                 )",
                None,
            )
            .map(|_| ())
    }

    /// Read the persisted ciphertext blob for `agent_id`, if any.
    fn read_share(&self, agent_id: &str) -> Result<Option<Vec<u8>>> {
        let cursor = self.state.storage().sql().exec(
            "SELECT ciphertext FROM shares WHERE agent_id = ?",
            vec![agent_id.into()],
        )?;
        let rows: Vec<ShareRow> = cursor.to_array()?;
        Ok(rows.into_iter().next().map(|r| r.ciphertext))
    }

    /// `GET /poc/identity` — identity + hibernation telemetry + share presence.
    async fn handle_identity(&self) -> Result<Response> {
        let identity = self.identity_hex()?;
        self.ensure_schema()?;
        let share = self.read_share(&identity)?;
        Response::from_json(&serde_json::json!({
            "route": "poc/identity",
            "client_identity": identity,
            "instance_constructed_at_ms": self.instance_constructed_at_ms,
            "share_present": share.is_some(),
            "share_sha256": share.as_ref().map(|b| hex::encode(Sha256::digest(b))),
            "do_name": POC_DO_NAME,
        }))
    }

    /// `POST /poc/persist` — idempotently persist a deterministic test
    /// share blob to DO SQLite, then read it back; assert round-trip.
    async fn handle_persist(&self) -> Result<Response> {
        let identity = self.identity_hex()?;
        self.ensure_schema()?;

        // Deterministic stand-in for an encrypted share: sha256(identity ||
        // "poc-share") — stable across evictions so a reload after
        // hibernation returns byte-identical data (the durability proof).
        // (Real shares are AES-256-GCM ciphertext via bsv-mpc-core::share;
        // the POC proves the PERSISTENCE layer, orthogonal to encryption.)
        let mut h = Sha256::new();
        h.update(identity.as_bytes());
        h.update(b"poc-share");
        let want: Vec<u8> = h.finalize().to_vec();

        let existed = self.read_share(&identity)?.is_some();
        if !existed {
            self.state.storage().sql().exec(
                "INSERT INTO shares (agent_id, ciphertext, created_at) VALUES (?, ?, ?)",
                vec![
                    identity.clone().into(),
                    want.clone().into(),
                    (Date::now().as_millis() as i64).into(),
                ],
            )?;
        }

        let reloaded = self
            .read_share(&identity)?
            .ok_or_else(|| Error::RustError("share not found after persist".into()))?;
        let matches = reloaded == want;

        Response::from_json(&serde_json::json!({
            "route": "poc/persist",
            "client_identity": identity,
            "already_existed": existed,
            "stored_sha256": hex::encode(&want),
            "reloaded_sha256": hex::encode(&reloaded),
            "reload_matches": matches,
            "instance_constructed_at_ms": self.instance_constructed_at_ms,
        }))
    }
}

/// Row shape for `SELECT ciphertext`.
#[derive(serde::Deserialize)]
struct ShareRow {
    ciphertext: Vec<u8>,
}

/// Forward a `/poc/*` request from the Worker entrypoint to the singleton
/// per-identity [`CosignerSessionDo`] (keyed by [`POC_DO_NAME`]).
pub async fn forward_to_cosigner_do(req: Request, env: &Env) -> Result<Response> {
    let ns = env.durable_object("COSIGNER_DO")?;
    let id = ns.id_from_name(POC_DO_NAME)?;
    let stub = id.get_stub()?;
    stub.fetch_with_request(req).await
}
