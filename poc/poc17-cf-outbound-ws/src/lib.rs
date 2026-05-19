//! # POC 17 — Phase H Step 3: pure-Rust Engine.IO + Socket.IO client + BRC-103 transport
//!
//! Cloudflare Worker (DO scaffolding lands in H-3.5) that proves the
//! **pure Rust+WASM** substrate for the Phase H wasm32 MessageBox client
//! (audit `docs/PHASE-H-AUDIT.md` §2.5b + §11 + §11.2 revised).
//!
//! ## The five gates (audit §6.2 as rewritten in §2.5b)
//!
//! | Gate | What it proves | Status |
//! |---|---|---|
//! | H-3.1 | `cargo build --target wasm32-unknown-unknown -p poc17-cf-outbound-ws` clean | ✓ `cb923fc` |
//! | H-3.2a | Engine.IO polling handshake against live relay via `worker::Fetch`; vendored codec decodes Open packet; sid extracted | this commit |
//! | H-3.2b | WS upgrade via `web_sys::WebSocket`; Engine.IO probe/pong/upgrade dance | next commit |
//! | H-3.3 | BRC-103 mutual auth completes over the `authMessage` event channel | subsequent |
//! | H-3.4 | Canonical CBOR envelope round-trips byte-exact through the live Calhoun relay | subsequent |
//! | H-3.5 | Forced-hibernation reconnect via the DO; backfill via `/listMessages` | subsequent |

pub mod engineio_codec;
pub mod socketio_client;
pub mod transport;
pub mod transport_wasm;
pub mod worker_do;

use worker::*;

/// Default relay URL — overridable via `RELAY_URL` env var declared in
/// `wrangler.example.toml` so the operator can point the POC at a
/// staging relay for testing.
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";

/// CF Worker fetch event handler. H-3.2a routes `GET /open` to the
/// Engine.IO polling handshake; future gates add more endpoints.
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        // Liveness / sanity — also useful for verifying wrangler dev works
        // before exercising any outbound network.
        .get("/health", |_req, _ctx| {
            Response::ok("poc17-cf-outbound-ws — Phase H POC. See README.md for gates.\n")
        })
        // H-3.2 gate: drive the full Engine.IO 4 client handshake
        // against the live relay — polling phase (H-3.2a) followed by
        // the WS upgrade dance (H-3.2b). Returns parsed Open payload +
        // upgrade-result JSON.
        .get_async("/open", |_req, ctx| async move {
            let relay = ctx
                .env
                .var("RELAY_URL")
                .map(|v| v.to_string())
                .unwrap_or_else(|_| DEFAULT_RELAY.to_string());

            // H-3.2a: polling handshake.
            let handshake = match transport_wasm::polling_handshake(&relay).await {
                Ok(h) => h,
                Err(e) => return Response::error(format!("polling handshake failed: {e}"), 502),
            };

            // H-3.2b: WS upgrade via web_sys::WebSocket. Returns once
            // the `5` Upgrade packet has been sent after a successful
            // probe/pong exchange.
            let upgrade = match transport_wasm::upgrade_to_websocket(&relay, &handshake.sid).await {
                Ok(u) => u,
                Err(e) => {
                    return Response::error(
                        format!("ws upgrade failed (sid={}): {e}", handshake.sid),
                        502,
                    )
                }
            };

            Response::from_json(&serde_json::json!({
                "socketio_status": "ws_upgraded",
                "relay": relay,
                "sid": handshake.sid,
                "upgrades": handshake.upgrades,
                "pingInterval": handshake.ping_interval,
                "pingTimeout": handshake.ping_timeout,
                "maxPayload": handshake.max_payload,
                "ws_url": upgrade.ws_url,
                "probe_round_trip_ms": upgrade.probe_round_trip_ms,
                "gate": "H-3.2 (H-3.2a polling + H-3.2b ws-upgrade)",
            }))
        })
        .run(req, env)
        .await
}
