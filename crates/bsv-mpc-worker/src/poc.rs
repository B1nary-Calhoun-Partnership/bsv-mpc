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
pub const POC_DO_NAME: &str = "cosigner-poc-2";

/// Live Calhoun MessageBox relay (the spec-normative §06 Socket.IO + BRC-103
/// channel). Overridable via the `RELAY_URL` Worker var. Only referenced by
/// the wasm32 `handle_handshake` path.
#[cfg(target_arch = "wasm32")]
pub const DEFAULT_RELAY_URL: &str = "https://rust-message-box.dev-a3e.workers.dev";

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
            // ── POC routes (substrate proofs) ──────────────────────────
            "/poc/identity" => self.handle_identity().await,
            "/poc/persist" => self.handle_persist().await,
            "/poc/share-roundtrip" => self.handle_share_roundtrip().await,
            "/poc/dkg-bench" => self.handle_dkg_bench(req).await,
            "/poc/issue-partial" => self.handle_issue_partial(req).await,
            "/poc/presig-pool" => self.handle_presig_pool(req).await,
            "/poc/sign-relay" => self.handle_sign_relay(req).await,
            "/poc/handshake" => self.handle_handshake().await,
            // ── KSS routes (I-4a.2: storage-backed by this DO's SQLite) ──
            // Auth is enforced at the Worker entrypoint before forwarding.
            // The live coordinators live in this DO isolate's statics (per-
            // session pinning); durable shares live in DO SQLite.
            "/dkg/init" => crate::api::handle_dkg_init(req).await,
            "/dkg/round" => {
                let store = self.kss_store()?;
                crate::api::handle_dkg_round(req, &store).await
            }
            "/sign/init" => {
                let store = self.kss_store()?;
                crate::api::handle_sign_init(req, &store).await
            }
            "/sign/round" => crate::api::handle_sign_round(req).await,
            "/ceremony/seed-primes" => self.handle_seed_primes(req).await,
            "/ceremony/ingest-presig" => self.handle_ingest_presig(req).await,
            "/presign/init" => {
                let store = self.kss_store()?;
                crate::api::handle_presign_init(req, &store).await
            }
            "/presign/round" => crate::api::handle_presign_round(req).await,
            "/ecdh" => {
                let store = self.kss_store()?;
                crate::api::handle_ecdh(req, &store).await
            }
            "/health" => {
                let store = self.kss_store()?;
                crate::api::handle_health(&store).await
            }
            p if p.starts_with("/shares/") => {
                let agent_id = p.trim_start_matches("/shares/").to_string();
                let store = self.kss_store()?;
                crate::api::handle_get_share_metadata(&agent_id, &store).await
            }
            other => Response::error(format!("unknown route: {other}"), 404),
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

    /// Build the DO-SQLite-backed KSS store (schema ensured) for the KSS
    /// handlers. The store's tables are co-located in this DO's SQLite, so a
    /// DKG-completed share persists durably (survives eviction).
    fn kss_store(&self) -> Result<crate::do_storage::DoSqlStorage<'_>> {
        let store = crate::do_storage::DoSqlStorage::new(&self.state);
        store.ensure_schema()?;
        Ok(store)
    }

    /// Ensure the `shares` table exists (idempotent). `ciphertext` is the
    /// hex of the (encrypted) share — stored as TEXT so the DO SQLite
    /// cursor deserializes cleanly into a `String` (a BLOB column comes
    /// back as a JS byte-array that serde won't map to `Vec<u8>` without
    /// `serde_bytes`; hex TEXT sidesteps that and is still ciphertext).
    fn ensure_schema(&self) -> Result<()> {
        self.state
            .storage()
            .sql()
            .exec(
                "CREATE TABLE IF NOT EXISTS shares (\
                   agent_id TEXT PRIMARY KEY, \
                   ciphertext TEXT NOT NULL, \
                   created_at INTEGER NOT NULL\
                 )",
                None,
            )
            .map(|_| ())
    }

    /// Read the persisted ciphertext (hex) for `agent_id`, if any.
    fn read_share(&self, agent_id: &str) -> Result<Option<String>> {
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
            "share_hex": share,
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
        let want: String = hex::encode(h.finalize());

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
            "stored_hex": want,
            "reloaded_hex": reloaded,
            "reload_matches": matches,
            "instance_constructed_at_ms": self.instance_constructed_at_ms,
        }))
    }
}

/// Row shape for `SELECT ciphertext` (hex TEXT).
#[derive(serde::Deserialize)]
struct ShareRow {
    ciphertext: String,
}

impl CosignerSessionDo {
    /// `GET /poc/share-roundtrip` — I-4a fund-safety proof for REAL shares.
    /// Stores a deterministic [`EncryptedShare`] via [`DoSqlStorage`] (the
    /// production storage layer), reads it back, and asserts byte-identical
    /// round-trip. Across a forced eviction the row persists while
    /// `instance_constructed_at_ms` advances — proving a real encrypted share
    /// survives hibernation on the deployed worker (not just the I-3b stub blob).
    async fn handle_share_roundtrip(&self) -> Result<Response> {
        use bsv_mpc_core::types::{EncryptedShare, SessionId, ShareIndex, ThresholdConfig};

        let identity = self.identity_hex()?;
        let store = crate::do_storage::DoSqlStorage::new(&self.state);
        store.ensure_schema()?;

        // Deterministic stand-in for a DKG-produced encrypted share: fixed
        // bytes so a post-eviction reload is byte-identical (the durability
        // proof). Real shares are AES-256-GCM ciphertext from bsv-mpc-core.
        let share = EncryptedShare {
            nonce: vec![0xAB; 12],
            ciphertext: vec![0xCD; 48],
            session_id: SessionId::from_str_hash(&format!("i4a-{identity}")),
            share_index: ShareIndex(0),
            config: ThresholdConfig {
                threshold: 2,
                parties: 2,
            },
            joint_pubkey_compressed: vec![0x02; 33],
        };

        let already_existed = store.get_share(&identity)?.is_some();
        if !already_existed {
            store.store_share(&identity, &share)?;
        }

        let reloaded = store
            .get_share(&identity)?
            .ok_or_else(|| Error::RustError("share missing after store".into()))?;
        let want = serde_json::to_string(&share)
            .map_err(|e| Error::RustError(format!("serialize want: {e}")))?;
        let got = serde_json::to_string(&reloaded)
            .map_err(|e| Error::RustError(format!("serialize got: {e}")))?;
        let reload_matches = want == got;
        let meta = store.get_share_metadata(&identity)?;

        Response::from_json(&serde_json::json!({
            "route": "poc/share-roundtrip",
            "client_identity": identity,
            "already_existed": already_existed,
            "reload_matches": reload_matches,
            "share_index": reloaded.share_index.0,
            "session_id": reloaded.session_id.hex(),
            "threshold": reloaded.config.threshold,
            "parties": reloaded.config.parties,
            "metadata_present": meta.is_some(),
            "share_count": store.share_count()?,
            "instance_constructed_at_ms": self.instance_constructed_at_ms,
            "do_name": POC_DO_NAME,
        }))
    }

    /// `GET /poc/dkg-bench` — I-4b feasibility probe. Runs a FULL 2-of-2
    /// CGGMP'24 DKG with BOTH parties inside this single wasm isolate (a
    /// conservative ~2× upper bound on real per-party cost) using fast Blum
    /// seeded primes, and reports wall-clock. Decides whether DKG-over-relay
    /// fits the CF Worker CPU budget on wasm32 (vs pivoting to sign-first). If
    /// the request dies without responding, that itself answers "doesn't fit".
    async fn handle_dkg_bench(&self, req: Request) -> Result<Response> {
        use bsv_mpc_core::dkg::{generate_test_primes, DkgCoordinator, DkgRoundResult};
        use bsv_mpc_core::types::{RoundMessage, SessionId, ShareIndex, ThresholdConfig};

        // `?stop=primes` returns after prime gen only — disambiguates whether
        // the CF budget is blown by Blum prime gen vs the DKG protocol math.
        // `?parties=1` runs ONE party's init only (keygen round-1 local cost).
        let q = req.url().ok();
        let stop = q
            .as_ref()
            .and_then(|u| {
                u.query_pairs()
                    .find(|(k, _)| k == "stop")
                    .map(|(_, v)| v.to_string())
            })
            .unwrap_or_default();

        let t0 = Date::now().as_millis();
        let p0 = generate_test_primes(&mut rand::rngs::OsRng);
        let p1 = generate_test_primes(&mut rand::rngs::OsRng);
        let primes_gen_ms = Date::now().as_millis() - t0;
        if stop == "primes" {
            return Response::from_json(&serde_json::json!({
                "route": "poc/dkg-bench", "checkpoint": "primes",
                "primes_gen_ms": primes_gen_ms, "note": "2 Blum PregeneratedPrimes sets",
            }));
        }

        let config =
            ThresholdConfig::new(2, 2).map_err(|e| Error::RustError(format!("config: {e}")))?;
        let session = SessionId::from_str_hash("dkg-bench");
        let mut c0 = DkgCoordinator::new(session, config, ShareIndex(0));
        let mut c1 = DkgCoordinator::new(session, config, ShareIndex(1));
        c0.set_pregenerated_primes(p0);
        c1.set_pregenerated_primes(p1);

        let t_dkg = Date::now().as_millis();
        // party1's init msgs → party0's inbox; party0's → party1's inbox.
        let mut to0: Vec<RoundMessage> = c1
            .init()
            .map_err(|e| Error::RustError(format!("c1.init: {e}")))?;
        let mut to1: Vec<RoundMessage> = c0
            .init()
            .map_err(|e| Error::RustError(format!("c0.init: {e}")))?;
        if stop == "init" {
            return Response::from_json(&serde_json::json!({
                "route": "poc/dkg-bench", "checkpoint": "init",
                "primes_gen_ms": primes_gen_ms,
                "init_ms": Date::now().as_millis() - t_dkg,
                "note": "both parties keygen round-1 init (local compute)",
            }));
        }
        let mut done0 = None;
        let mut done1 = None;
        let mut rounds = 0u32;
        while (done0.is_none() || done1.is_none()) && rounds < 40 {
            rounds += 1;
            let in1 = std::mem::take(&mut to1);
            let in0 = std::mem::take(&mut to0);
            if done1.is_none() {
                match c1
                    .process_round(in1)
                    .map_err(|e| Error::RustError(format!("c1 round {rounds}: {e}")))?
                {
                    DkgRoundResult::NextRound(m) => to0 = m,
                    DkgRoundResult::Complete(d) => done1 = Some(d),
                }
            }
            if done0.is_none() {
                match c0
                    .process_round(in0)
                    .map_err(|e| Error::RustError(format!("c0 round {rounds}: {e}")))?
                {
                    DkgRoundResult::NextRound(m) => to1 = m,
                    DkgRoundResult::Complete(d) => done0 = Some(d),
                }
            }
        }
        let dkg_ms = Date::now().as_millis() - t_dkg;
        let joint_match = match (&done0, &done1) {
            (Some(a), Some(b)) => a.joint_key.compressed == b.joint_key.compressed,
            _ => false,
        };

        Response::from_json(&serde_json::json!({
            "route": "poc/dkg-bench",
            "completed": done0.is_some() && done1.is_some(),
            "joint_match": joint_match,
            "rounds": rounds,
            "primes_gen_ms": primes_gen_ms,
            "dkg_ms": dkg_ms,
            "total_ms": Date::now().as_millis() - t0,
            "joint_pubkey": done0.as_ref().map(|d| hex::encode(&d.joint_key.compressed)),
            "note": "2-party DKG in ONE wasm isolate (~2x per-party); Blum seeded primes",
        }))
    }

    /// `POST /poc/issue-partial {presignature_hex, sighash_hex}` — proves the
    /// ADR-018 wasm DO light-sign op on the **deployed** worker: deserialize a
    /// cggmp24 `Presignature` (hex of its serde JSON), issue this party's
    /// partial signature, return it (hex of serde JSON). Pure field math — the
    /// hot path that must fit the CF Worker budget. (POC: the presignature is
    /// posted; production reads it from the DO `mpc_presignatures` pool.)
    async fn handle_issue_partial(&self, mut req: Request) -> Result<Response> {
        #[derive(serde::Deserialize)]
        struct IssuePartialRequest {
            presignature_hex: String,
            sighash_hex: String,
        }
        let body: IssuePartialRequest = req.json().await?;

        let presig_json = hex::decode(&body.presignature_hex)
            .map_err(|e| Error::RustError(format!("presignature_hex: {e}")))?;
        let sighash_bytes = hex::decode(&body.sighash_hex)
            .map_err(|e| Error::RustError(format!("sighash_hex: {e}")))?;
        if sighash_bytes.len() != 32 {
            return Response::error("sighash must be 32 bytes", 400);
        }
        let mut sighash = [0u8; 32];
        sighash.copy_from_slice(&sighash_bytes);

        let partial_json =
            bsv_mpc_core::signing::issue_partial_signature_json(&presig_json, &sighash)
                .map_err(|e| Error::RustError(format!("issue_partial: {e}")))?;

        Response::from_json(&serde_json::json!({
            "route": "poc/issue-partial",
            "ok": true,
            "partial_hex": hex::encode(&partial_json),
            "instance_constructed_at_ms": self.instance_constructed_at_ms,
        }))
    }

    /// `POST /ceremony/seed-primes {session_id, primes_json}` — I-4b.1.
    /// Persist off-worker-generated Paillier `PregeneratedPrimes` (serde JSON)
    /// to DO SQLite so the DKG loop can consume them at coordinator init
    /// without the (CF-CPU-prohibitive) in-wasm safe-prime generation. Auth is
    /// enforced at the Worker entrypoint before this is forwarded. Idempotent:
    /// re-seeding the same session reports `already_existed` (the eviction-
    /// survival proof) and confirms the stored blob is byte-identical.
    async fn handle_seed_primes(&self, mut req: Request) -> Result<Response> {
        #[derive(serde::Deserialize)]
        struct SeedPrimesRequest {
            session_id: String,
            primes_json: String,
        }
        let body: SeedPrimesRequest = req.json().await?;
        if body.session_id.is_empty() || body.primes_json.is_empty() {
            return Response::error("session_id and primes_json are required", 400);
        }

        let store = self.kss_store()?;
        let already_existed = store.get_primes(&body.session_id)?.is_some();
        if !already_existed {
            store.store_primes(&body.session_id, &body.primes_json)?;
        }
        let reloaded = store.get_primes(&body.session_id)?;
        let reload_matches = reloaded.as_deref() == Some(body.primes_json.as_str());

        Response::from_json(&serde_json::json!({
            "route": "ceremony/seed-primes",
            "session_id": body.session_id,
            "already_existed": already_existed,
            "stored": reloaded.is_some(),
            "reload_matches": reload_matches,
            "primes_len": body.primes_json.len(),
            "instance_constructed_at_ms": self.instance_constructed_at_ms,
        }))
    }

    /// `POST /ceremony/ingest-presig {session_id, presig_id, presignature_hex}`
    /// — #14 presig provisioning. The native CF Container generates a 2-party
    /// presignature with the proxy and ships **this party's** serialized
    /// `Presignature` (hex of its serde JSON) here; we stock it in the DO's
    /// `mpc_presignatures` FIFO pool (`store_presignature`) so the light
    /// online-sign loop can consume one per signature. `PresignaturePublicData`
    /// is NOT shipped — only the combiner (native proxy) needs it (ADR-018).
    ///
    /// Auth is enforced at the Worker entrypoint before forwarding. The presig
    /// is stored under **this DO's own cosigner identity** (derived from
    /// `SERVER_PRIVATE_KEY`), never a client-supplied agent_id — the requester
    /// cannot stock another agent's pool (handler-level authz, #5). The blob is
    /// stored opaque (validated at consumption time by `issue_partial_signature_json`,
    /// mirroring the seed-primes precedent).
    async fn handle_ingest_presig(&self, mut req: Request) -> Result<Response> {
        #[derive(serde::Deserialize)]
        struct IngestPresigRequest {
            session_id: String,
            presig_id: String,
            presignature_hex: String,
        }
        let body: IngestPresigRequest = req.json().await?;
        if body.session_id.is_empty() || body.presig_id.is_empty() {
            return Response::error("session_id and presig_id are required", 400);
        }
        let presig_bytes = hex::decode(&body.presignature_hex)
            .map_err(|e| Error::RustError(format!("presignature_hex: {e}")))?;
        if presig_bytes.is_empty() {
            return Response::error("presignature_hex is empty", 400);
        }

        let agent_id = self.identity_hex()?;
        let store = self.kss_store()?;
        store.store_presignature(&agent_id, &body.session_id, &body.presig_id, &presig_bytes)?;
        let pool_count = store.presignature_count(&agent_id)?;

        Response::from_json(&serde_json::json!({
            "route": "ceremony/ingest-presig",
            "agent_id": agent_id,
            "session_id": body.session_id,
            "presig_id": body.presig_id,
            "presig_len": presig_bytes.len(),
            "pool_count": pool_count,
            "instance_constructed_at_ms": self.instance_constructed_at_ms,
        }))
    }

    /// `POST /poc/presig-pool {presignature_hex, sighash_hex}` — #14 deployed
    /// runtime proof of the full provisioning → consumption → light-sign path
    /// on the wasm DO. Drains the pool, stocks the posted presignature, consumes
    /// the oldest (asserting the bytes survive the SQLite hex round-trip
    /// byte-identical), then issues this party's partial from the *consumed*
    /// presig. Because `issue_partial_signature` is deterministic, `partial_hex`
    /// must equal the native `EXPECTED_PARTIAL_HEX` fixture — a 110% byte-
    /// identical gate that the pool path does not corrupt the presignature.
    async fn handle_presig_pool(&self, mut req: Request) -> Result<Response> {
        #[derive(serde::Deserialize)]
        struct PresigPoolRequest {
            presignature_hex: String,
            sighash_hex: String,
        }
        let body: PresigPoolRequest = req.json().await?;

        let presig_bytes = hex::decode(&body.presignature_hex)
            .map_err(|e| Error::RustError(format!("presignature_hex: {e}")))?;
        let sighash_bytes = hex::decode(&body.sighash_hex)
            .map_err(|e| Error::RustError(format!("sighash_hex: {e}")))?;
        if sighash_bytes.len() != 32 {
            return Response::error("sighash must be 32 bytes", 400);
        }
        let mut sighash = [0u8; 32];
        sighash.copy_from_slice(&sighash_bytes);

        let agent_id = self.identity_hex()?;
        let store = self.kss_store()?;

        // Drain any leftovers so the proof is deterministic regardless of prior
        // runs (this is the POC DO; no funded pool to protect).
        let mut drained = 0u32;
        while store.consume_presignature(&agent_id)?.is_some() && drained < 1000 {
            drained += 1;
        }

        let presig_id = format!("poc-presig-{}", Date::now().as_millis());
        store.store_presignature(&agent_id, "poc-presig-pool", &presig_id, &presig_bytes)?;
        let count_after_store = store.presignature_count(&agent_id)?;

        let consumed = store
            .consume_presignature(&agent_id)?
            .ok_or_else(|| Error::RustError("pool empty after store".into()))?;
        let count_after_consume = store.presignature_count(&agent_id)?;
        let round_trip_matches = consumed == presig_bytes;

        let partial_json = bsv_mpc_core::signing::issue_partial_signature_json(&consumed, &sighash)
            .map_err(|e| Error::RustError(format!("issue_partial from consumed presig: {e}")))?;

        Response::from_json(&serde_json::json!({
            "route": "poc/presig-pool",
            "agent_id": agent_id,
            "drained_leftovers": drained,
            "count_after_store": count_after_store,
            "count_after_consume": count_after_consume,
            "round_trip_matches": round_trip_matches,
            "partial_hex": hex::encode(&partial_json),
            "instance_constructed_at_ms": self.instance_constructed_at_ms,
        }))
    }
}

// ============================================================================
// I-3b2 — relay-handshake-from-DO (the transport half of the cosigner POC)
// ============================================================================
//
// Drives the FULL Engine.IO 4 + Socket.IO 5 + BRC-103 handshake against the
// live MessageBox relay from inside the deployed DO, lifting poc17's proven
// outbound-WS flow onto this crate's wasm32 `transport_wasm` substrate. The
// DO's stable identity (`SERVER_PRIVATE_KEY`, reloaded every wake) is the
// `Peer` wallet. This is the wasm32 mirror of the proven native flow in
// `crates/bsv-mpc-messagebox/tests/transport_native_handshake.rs` — the only
// substantive difference is `spawn_local` (NOT `tokio::spawn`) for dispatch.

#[cfg(target_arch = "wasm32")]
impl CosignerSessionDo {
    /// `GET /poc/handshake` — dial the relay, complete BRC-103, and prove the
    /// channel: learn the relay's server identity from the first inbound
    /// General, then a best-effort `sendMessage` envelope round-trip. Returns
    /// the learned `server_identity` (the deterministic runtime gate).
    async fn handle_handshake(&self) -> Result<Response> {
        use bsv::auth::transports::socketio::build_envelope_payload;
        use bsv::auth::transports::socketio::codec::{EngineIoPacket, SocketIoPacket};
        use bsv::auth::{
            install_app_event_listener, run_dispatch, Peer, PeerOptions, SocketIoFrameSource,
            SocketIoSink, SocketIoTransport,
        };
        use bsv::wallet::ProtoWallet;
        use bsv_mpc_messagebox::transport_wasm::{polling_handshake, WsHandle};
        use futures::future::{select, Either};
        use futures::StreamExt;
        use serde_json::json;
        use std::time::Duration;
        use wasm_bindgen_futures::spawn_local;

        let t0 = Date::now().as_millis();

        // Stable cosigner identity from the secret (reloaded every wake).
        let priv_hex = self.env.secret("SERVER_PRIVATE_KEY")?.to_string();
        let client_priv = PrivateKey::from_hex(&priv_hex)
            .map_err(|e| Error::RustError(format!("SERVER_PRIVATE_KEY parse: {e:?}")))?;
        let client_pub_hex = client_priv.public_key().to_hex();

        let relay = self
            .env
            .var("RELAY_URL")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string());

        // 1. Engine.IO 4 polling handshake → sid.
        let handshake = polling_handshake(&relay).await?;
        // 2. WS upgrade (2probe → 3probe → 5).
        let mut ws = WsHandle::open_and_upgrade(&relay, &handshake.sid)
            .await
            .map_err(Error::RustError)?;
        let probe_round_trip_ms = ws.probe_round_trip_ms();
        let sink = ws.sender();

        // 3. Socket.IO 5 CONNECT to the default namespace `/`.
        sink.send_socketio(&SocketIoPacket::Connect {
            nsp: "/".to_string(),
            data: None,
        })
        .map_err(Error::RustError)?;
        loop {
            match ws.recv_engineio().await.map_err(Error::RustError)? {
                EngineIoPacket::Ping(payload) => {
                    let _ = sink.send_engineio(&EngineIoPacket::Pong(payload));
                }
                EngineIoPacket::Message(payload) => {
                    if let Ok(SocketIoPacket::Connect { .. }) = SocketIoPacket::decode(&payload) {
                        break; // CONNECT-ack — Socket.IO ready.
                    }
                }
                _ => {}
            }
        }

        // 4. Wire `Peer` over the upstream `SocketIoTransport<WsSender>`; spawn
        //    the dispatch loop with `spawn_local` (wasm32 is single-threaded —
        //    NOT `tokio::spawn`).
        let transport = SocketIoTransport::new(sink.clone());
        let callback = transport.callback_handle();
        let dispatch_sink = sink.clone();
        let wallet = ProtoWallet::new(Some(client_priv));
        let peer = Peer::new(PeerOptions {
            wallet,
            transport,
            certificates_to_request: None,
            session_manager: None,
            auto_persist_last_session: true,
            originator: Some("i-3b2-wasm".to_string()),
        });
        peer.start();
        let (mut events, _cb_id) = install_app_event_listener(&peer).await;
        spawn_local(run_dispatch(ws, dispatch_sink, callback));

        // 5. joinRoom. `to_peer(_, None, _)` auto-initiates the BRC-103
        //    handshake (InitialRequest → InitialResponse via the dispatch loop)
        //    and signs+sends the first General internally. Ok proves the full
        //    wasm32 canonical path end-to-end. (Requires bsv-rs >= 0.3.11,
        //    whose `wasm` feature enables `futures-timer/wasm-bindgen`; older
        //    versions panic on the handshake-timeout poll in the CF isolate.)
        let now_ms = Date::now().as_millis();
        let message_box = format!("i3b2-{now_ms}");
        let room_id = format!("{client_pub_hex}-{message_box}");
        peer.to_peer(
            &build_envelope_payload("joinRoom", &json!(room_id)),
            None,
            Some(20_000),
        )
        .await
        .map_err(|e| Error::RustError(format!("to_peer(joinRoom): {e:?}")))?;
        let handshake_rtt_ms = Date::now().as_millis() - t0;

        // 6. Server identity = sender of the first inbound General (the relay's
        //    `authenticated` event). Race a Delay so a silent relay can't hang.
        let server_identity =
            match select(events.next(), worker::Delay::from(Duration::from_secs(8))).await {
                Either::Left((Some(ev), _)) => Some(ev.sender.to_hex()),
                _ => None,
            };

        // 7. Best-effort envelope round-trip: send a self-addressed message and
        //    await the relay's `sendMessage-{room}`/`sendMessageAck-{room}` echo.
        let mut envelope_round_trip = false;
        if let Some(server_id) = server_identity.as_deref() {
            let send_payload = build_envelope_payload(
                "sendMessage",
                &json!({
                    "messageBox": message_box,
                    "message": {
                        "messageId": format!("i3b2-{now_ms}"),
                        "recipient": client_pub_hex,
                        "body": json!({"poc": "i-3b2", "ts": now_ms}),
                    }
                }),
            );
            if peer
                .to_peer(&send_payload, Some(server_id), Some(20_000))
                .await
                .is_ok()
            {
                let send_evt = format!("sendMessage-{room_id}");
                let ack_evt = format!("sendMessageAck-{room_id}");
                let deadline = Date::now().as_millis() + 8_000;
                while Date::now().as_millis() < deadline {
                    match select(events.next(), worker::Delay::from(Duration::from_secs(8))).await {
                        Either::Left((Some(ev), _)) => {
                            if ev.event_name == send_evt || ev.event_name == ack_evt {
                                envelope_round_trip = true;
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            }
        }

        Response::from_json(&serde_json::json!({
            "route": "poc/handshake",
            "client_identity": client_pub_hex,
            "server_identity": server_identity,
            "envelope_round_trip": envelope_round_trip,
            "room_id": room_id,
            "engineio_sid": handshake.sid,
            "probe_round_trip_ms": probe_round_trip_ms,
            "handshake_rtt_ms": handshake_rtt_ms,
            "relay": relay,
            "do_name": POC_DO_NAME,
            "instance_constructed_at_ms": self.instance_constructed_at_ms,
        }))
    }

    /// `POST /poc/sign-relay` — #15 (I-4b.2) the wasm DO's relay sign loop.
    /// Consumes a presignature from the pool, issues this party's partial
    /// (`issue_partial_signature_json`), wraps it as a canonical §05
    /// `MessageEnvelope` (BRC-78 ECIES to the recipient + BRC-31 outer sig),
    /// dials the live MessageBox relay (the I-3b2-proven path), and sends the
    /// wrapped partial to `recipient` on box `mpc-sign`.
    ///
    /// Request body:
    /// - `presignature_hex`, `sighash_hex` — as `/poc/presig-pool` (#14).
    /// - `recipient_pub_hex` (optional) — the combiner identity. **Defaults to
    ///   this DO's own identity**, in which case the DO joins its own
    ///   `{id}-mpc-sign` room, receives the wrapped partial back over the relay,
    ///   unwraps it (BRC-78 decrypt + BRC-31 verify), and asserts the recovered
    ///   partial is byte-identical to the issued one — a deterministic, curl-
    ///   only proof of the full wrap → relay → unwrap path on deployed wasm.
    /// - `from_index`/`to_index` (optional, default 0/1) — signing-time indices;
    ///   the combiner keys the partial by `from_index`.
    /// - `joint_pubkey_hex` (optional, 33-byte) — envelope field 3.
    /// - `session_id_hex` (optional, 32-byte).
    ///
    /// For an external combiner (`recipient_pub_hex` ≠ self) the DO only sends;
    /// the combiner's receive+combine is proven by the native harness (Part B).
    async fn handle_sign_relay(&self, mut req: Request) -> Result<Response> {
        use bsv::auth::transports::socketio::build_envelope_payload;
        use bsv::auth::transports::socketio::codec::{EngineIoPacket, SocketIoPacket};
        use bsv::auth::{
            install_app_event_listener, run_dispatch, Peer, PeerOptions, SocketIoFrameSource,
            SocketIoSink, SocketIoTransport,
        };
        use bsv::primitives::ec::PublicKey;
        use bsv::wallet::ProtoWallet;
        use bsv_mpc_core::envelope::{
            unwrap_envelope_to_round_message, wrap_round_message, WrapParams,
        };
        use bsv_mpc_core::types::{RoundMessage, SessionId, ShareIndex};
        use bsv_mpc_messagebox::transport_wasm::{polling_handshake, WsHandle};
        use bsv_mpc_messagebox::types::BOX_SIGN;
        use bsv_mpc_messagebox::wire::{unwrap_body_to_envelope, wrap_envelope_to_body};
        use futures::future::{select, Either};
        use futures::StreamExt;
        use serde_json::json;
        use std::time::Duration;
        use wasm_bindgen_futures::spawn_local;

        #[derive(serde::Deserialize)]
        struct SignRelayRequest {
            presignature_hex: String,
            sighash_hex: String,
            #[serde(default)]
            recipient_pub_hex: Option<String>,
            #[serde(default)]
            from_index: Option<u16>,
            #[serde(default)]
            to_index: Option<u16>,
            #[serde(default)]
            joint_pubkey_hex: Option<String>,
            #[serde(default)]
            session_id_hex: Option<String>,
        }
        let body: SignRelayRequest = req.json().await?;

        // ── 1. Decode inputs ────────────────────────────────────────────
        let presig_bytes = hex::decode(&body.presignature_hex)
            .map_err(|e| Error::RustError(format!("presignature_hex: {e}")))?;
        let sighash_bytes = hex::decode(&body.sighash_hex)
            .map_err(|e| Error::RustError(format!("sighash_hex: {e}")))?;
        if sighash_bytes.len() != 32 {
            return Response::error("sighash must be 32 bytes", 400);
        }
        let mut sighash = [0u8; 32];
        sighash.copy_from_slice(&sighash_bytes);

        let from_index = body.from_index.unwrap_or(0);
        let to_index = body.to_index.unwrap_or(1);

        let joint_pubkey = match &body.joint_pubkey_hex {
            Some(h) => {
                let b = hex::decode(h)
                    .map_err(|e| Error::RustError(format!("joint_pubkey_hex: {e}")))?;
                if b.len() != 33 {
                    return Response::error("joint_pubkey_hex must be 33 bytes", 400);
                }
                let mut a = [0u8; 33];
                a.copy_from_slice(&b);
                a
            }
            None => [0u8; 33],
        };

        let session_id = match &body.session_id_hex {
            Some(h) => {
                let b =
                    hex::decode(h).map_err(|e| Error::RustError(format!("session_id_hex: {e}")))?;
                if b.len() != 32 {
                    return Response::error("session_id_hex must be 32 bytes", 400);
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                SessionId(a)
            }
            None => SessionId::from_str_hash("poc-sign-relay"),
        };

        // ── 2. Identity (reloaded every wake) ───────────────────────────
        let priv_hex = self.env.secret("SERVER_PRIVATE_KEY")?.to_string();
        let client_priv = PrivateKey::from_hex(&priv_hex)
            .map_err(|e| Error::RustError(format!("SERVER_PRIVATE_KEY parse: {e:?}")))?;
        let client_pub_hex = client_priv.public_key().to_hex();
        let recipient_pub_hex = body
            .recipient_pub_hex
            .clone()
            .unwrap_or_else(|| client_pub_hex.clone());
        let is_self = recipient_pub_hex == client_pub_hex;
        let recipient_pub = PublicKey::from_hex(&recipient_pub_hex)
            .map_err(|e| Error::RustError(format!("recipient_pub_hex: {e:?}")))?;

        // ── 3. Pool: stock + consume, then issue this party's partial ────
        let agent_id = client_pub_hex.clone();
        let store = self.kss_store()?;
        let presig_id = format!("poc-sign-relay-{}", Date::now().as_millis());
        store.store_presignature(&agent_id, "poc-sign-relay", &presig_id, &presig_bytes)?;
        let consumed = store
            .consume_presignature(&agent_id)?
            .ok_or_else(|| Error::RustError("pool empty after store".into()))?;
        let round_trip_matches = consumed == presig_bytes;
        let partial_json = bsv_mpc_core::signing::issue_partial_signature_json(&consumed, &sighash)
            .map_err(|e| Error::RustError(format!("issue_partial: {e}")))?;

        // ── 4. Wrap the partial as a canonical §05 MessageEnvelope ───────
        let round_msg = RoundMessage {
            session_id,
            round: 1,
            from: ShareIndex(from_index),
            to: Some(ShareIndex(to_index)),
            payload: partial_json.clone(),
        };
        let params = WrapParams {
            to_party: to_index,
            joint_pubkey,
            phase: "sign".to_string(),
            execution_id_prefix: [0u8; 8],
            correlation_id: Some(session_id.hex()),
            traceparent: None,
        };
        let envelope = wrap_round_message(&round_msg, params, &recipient_pub, &client_priv)
            .map_err(|e| Error::RustError(format!("wrap_round_message: {e}")))?;
        let envelope_body = wrap_envelope_to_body(&envelope);

        // ── 5. Dial the relay (I-3b2-proven Socket.IO + BRC-103 path) ────
        let t0 = Date::now().as_millis();
        let relay = self
            .env
            .var("RELAY_URL")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string());

        let handshake = polling_handshake(&relay).await?;
        let mut ws = WsHandle::open_and_upgrade(&relay, &handshake.sid)
            .await
            .map_err(Error::RustError)?;
        let sink = ws.sender();

        sink.send_socketio(&SocketIoPacket::Connect {
            nsp: "/".to_string(),
            data: None,
        })
        .map_err(Error::RustError)?;
        loop {
            match ws.recv_engineio().await.map_err(Error::RustError)? {
                EngineIoPacket::Ping(payload) => {
                    let _ = sink.send_engineio(&EngineIoPacket::Pong(payload));
                }
                EngineIoPacket::Message(payload) => {
                    if let Ok(SocketIoPacket::Connect { .. }) = SocketIoPacket::decode(&payload) {
                        break;
                    }
                }
                _ => {}
            }
        }

        let transport = SocketIoTransport::new(sink.clone());
        let callback = transport.callback_handle();
        let dispatch_sink = sink.clone();
        let wallet = ProtoWallet::new(Some(client_priv));
        let peer = Peer::new(PeerOptions {
            wallet,
            transport,
            certificates_to_request: None,
            session_manager: None,
            auto_persist_last_session: true,
            originator: Some("i-4b2-sign-relay".to_string()),
        });
        peer.start();
        let (mut events, _cb_id) = install_app_event_listener(&peer).await;
        spawn_local(run_dispatch(ws, dispatch_sink, callback));

        // Join our own {id}-mpc-sign room (drives the BRC-103 handshake; for a
        // self-addressed send it is also the room the echo arrives on).
        let own_room = format!("{client_pub_hex}-{BOX_SIGN}");
        peer.to_peer(
            &build_envelope_payload("joinRoom", &json!(own_room)),
            None,
            Some(20_000),
        )
        .await
        .map_err(|e| Error::RustError(format!("to_peer(joinRoom): {e:?}")))?;
        let handshake_rtt_ms = Date::now().as_millis() - t0;

        // Server identity = sender of the first inbound General.
        let server_identity =
            match select(events.next(), worker::Delay::from(Duration::from_secs(8))).await {
                Either::Left((Some(ev), _)) => Some(ev.sender.to_hex()),
                _ => None,
            };

        // ── 6. Send the wrapped partial to `recipient` on box mpc-sign ───
        let now_ms = Date::now().as_millis();
        let message_id = format!("i4b2-{now_ms}");
        let mut sent = false;
        if let Some(server_id) = server_identity.as_deref() {
            let send_payload = build_envelope_payload(
                "sendMessage",
                &json!({
                    "messageBox": BOX_SIGN,
                    "message": {
                        "messageId": message_id,
                        "recipient": recipient_pub_hex,
                        "body": envelope_body,
                    }
                }),
            );
            sent = peer
                .to_peer(&send_payload, Some(server_id), Some(20_000))
                .await
                .is_ok();
        }

        // ── 7. Self-addressed: receive it back, unwrap, byte-compare ─────
        let recipient_room = format!("{recipient_pub_hex}-{BOX_SIGN}");
        let mut partial_roundtrip_matches = false;
        let mut received_back = false;
        if sent && is_self {
            let send_evt = format!("sendMessage-{recipient_room}");
            let deadline = Date::now().as_millis() + 8_000;
            while Date::now().as_millis() < deadline {
                match select(events.next(), worker::Delay::from(Duration::from_secs(8))).await {
                    Either::Left((Some(ev), _)) => {
                        if ev.event_name == send_evt {
                            received_back = true;
                            // The live General's `data.body` is the raw wrapped
                            // body value we sent. Unwrap → RoundMessage and
                            // compare the recovered partial byte-for-byte.
                            if let Some(raw_body) = ev.data.get("body") {
                                if let Ok(env) = unwrap_body_to_envelope(raw_body) {
                                    if let Ok(rm) = unwrap_envelope_to_round_message(
                                        &env,
                                        &PrivateKey::from_hex(&priv_hex).map_err(|e| {
                                            Error::RustError(format!("priv reparse: {e:?}"))
                                        })?,
                                        None,
                                    ) {
                                        partial_roundtrip_matches = rm.payload == partial_json;
                                    }
                                }
                            }
                            break;
                        }
                    }
                    _ => break,
                }
            }
        }

        Response::from_json(&serde_json::json!({
            "route": "poc/sign-relay",
            "client_identity": client_pub_hex,
            "recipient": recipient_pub_hex,
            "is_self": is_self,
            "server_identity": server_identity,
            "pool_round_trip_matches": round_trip_matches,
            "partial_hex": hex::encode(&partial_json),
            "envelope_len": envelope.encode_canonical().len(),
            "message_box": BOX_SIGN,
            "recipient_room": recipient_room,
            "message_id": message_id,
            "sent": sent,
            "received_back": received_back,
            "partial_roundtrip_matches": partial_roundtrip_matches,
            "handshake_rtt_ms": handshake_rtt_ms,
            "relay": relay,
            "do_name": POC_DO_NAME,
            "instance_constructed_at_ms": self.instance_constructed_at_ms,
        }))
    }
}

/// Native stub — the relay-handshake POC is wasm32-only (the Socket.IO +
/// BRC-103 transport uses `web_sys::WebSocket`). Keeps the `fetch` match arm
/// total when the worker is compiled for the host by `clippy --all-targets`.
#[cfg(not(target_arch = "wasm32"))]
impl CosignerSessionDo {
    async fn handle_handshake(&self) -> Result<Response> {
        Response::error("/poc/handshake is wasm32-only (deployed CF Worker)", 501)
    }

    async fn handle_sign_relay(&self, _req: Request) -> Result<Response> {
        Response::error("/poc/sign-relay is wasm32-only (deployed CF Worker)", 501)
    }
}

/// Forward a `/poc/*` request from the Worker entrypoint to the singleton
/// per-identity [`CosignerSessionDo`] (keyed by [`POC_DO_NAME`]).
pub async fn forward_to_cosigner_do(req: Request, env: &Env) -> Result<Response> {
    let ns = env.durable_object("COSIGNER_DO")?;
    let id = ns.id_from_name(POC_DO_NAME)?;
    let stub = id.get_stub()?;
    stub.fetch_with_request(req).await
}
