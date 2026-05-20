//! Durable Object that owns one cosigner's BRC-103 session against the
//! MessageBox relay. Replaces the H-3.1 stub.
//!
//! # H-3.5a scope
//!
//! Minimum-viable scaffold: the DO loads its identity priv from the
//! `SERVER_PRIVATE_KEY` secret on every fetch, derives the cosigner's
//! public-key hex, and surfaces it via `/identity`. The DO is bound as
//! `ENGINEIO_SESSION_DO` per `wrangler.toml`; the worker entry point
//! reaches it via
//! `env.durable_object("ENGINEIO_SESSION_DO")?.id_from_name("cosigner-test-1")?.get_stub()?.fetch_with_request(req)`.
//!
//! # Locked design decisions (from `docs/H-3-5-PLAN.md`)
//!
//! - **Identity from `SERVER_PRIVATE_KEY` secret**, not random per-DO.
//!   Matches every production Calhoun worker
//!   (`~/bsv/agents/test-agent/src/lib.rs:86`).
//! - **Per-identity DO** (audit §11.1 lock): one DO per cosigner.
//! - **Strategy 1 — re-handshake on every wake** (H-3.5 plan §"Reconnect strategy"):
//!   the outbound WS is NOT hibernation-eligible (no `state.accept_web_socket()`
//!   contract for client sockets); the relay's per-sid `SessionState` resets
//!   on a fresh Engine.IO sid anyway, so caching the BRC-103 session state
//!   wouldn't help. H-3.5a doesn't yet exercise the handshake — that's H-3.5b.
//! - **Empirical harness: deploy + curl** only (`wrangler dev` does not
//!   hibernate DOs). Truth lives in the deployed worker.
//!
//! # H-3.5b+ extensions (later sub-gates)
//!
//! - **H-3.5b**: in-DO BRC-103 handshake. Moves the H-3.3b /brc103-handshake
//!   flow into `fetch_handshake()`.
//! - **H-3.5c**: `/echo` POST handler — emits a signed General + awaits
//!   sendMessageAck through the DO-owned Peer.
//! - **H-3.5d**: persist `PersistedBrc103Session` (last_known_peer_identity_hex,
//!   persisted_at_ms, relay_url) to `state.storage()`.
//! - **H-3.5e**: forced-hibernation merge gate — pre.json + idle ≥70s + post.json
//!   with identical client_identity AND server_identity.

use worker::*;

/// The Durable Object class. One instance per cosigner identity (per
/// audit §11.1). Currently holds only the runtime handles; future
/// sub-gates add `inner: RefCell<Option<SessionPeer>>` for the live
/// `Peer` + `WsSender` between fetches.
#[durable_object]
pub struct EngineIoSessionDo {
    state: State,
    env: Env,
}

impl DurableObject for EngineIoSessionDo {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path();

        // The DO receives requests forwarded by the worker entry point's
        // `/relay-via-do/*` routes. The path is the full original URL
        // path, so we match on the full string (mirrors the canonical
        // pattern in `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/session.rs`).
        match path {
            "/relay-via-do/identity" => self.handle_identity().await,
            other => Response::error(format!("EngineIoSessionDo: unknown path {other}"), 404),
        }
    }
}

impl EngineIoSessionDo {
    /// `GET /relay-via-do/identity` — returns this DO's stable
    /// `client_identity` pubkey hex derived from the `SERVER_PRIVATE_KEY`
    /// secret. Two consecutive curls MUST return the same hex (H-3.5a
    /// empirical bar).
    async fn handle_identity(&self) -> Result<Response> {
        let priv_hex = self
            .env
            .secret("SERVER_PRIVATE_KEY")
            .map_err(|_| {
                Error::RustError(
                    "Missing SERVER_PRIVATE_KEY secret; set via \
                     `wrangler secret put SERVER_PRIVATE_KEY`"
                        .into(),
                )
            })?
            .to_string();

        let client_priv = bsv::primitives::PrivateKey::from_hex(&priv_hex).map_err(|e| {
            Error::RustError(format!(
                "invalid SERVER_PRIVATE_KEY (expected 32-byte hex): {e:?}"
            ))
        })?;
        let client_pub_hex = client_priv.public_key().to_hex();

        Response::from_json(&serde_json::json!({
            "socketio_status": "do_identity",
            "do_id": self.state.id().to_string(),
            "do_name": "cosigner-test-1",
            "client_identity": client_pub_hex,
            "gate": "H-3.5a",
        }))
    }
}
