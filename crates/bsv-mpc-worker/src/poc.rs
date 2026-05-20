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
}

/// Native stub — the relay-handshake POC is wasm32-only (the Socket.IO +
/// BRC-103 transport uses `web_sys::WebSocket`). Keeps the `fetch` match arm
/// total when the worker is compiled for the host by `clippy --all-targets`.
#[cfg(not(target_arch = "wasm32"))]
impl CosignerSessionDo {
    async fn handle_handshake(&self) -> Result<Response> {
        Response::error("/poc/handshake is wasm32-only (deployed CF Worker)", 501)
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
