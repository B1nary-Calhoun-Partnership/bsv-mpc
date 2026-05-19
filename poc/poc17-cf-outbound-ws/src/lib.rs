//! # POC 17 — Phase H Step 3: pure-Rust Engine.IO + Socket.IO client + BRC-103 transport
//!
//! Cloudflare Worker + Durable Object that proves the **pure Rust+WASM**
//! substrate for the Phase H wasm32 MessageBox client (audit
//! `docs/PHASE-H-AUDIT.md` §2.5b + §11 + §11.2 revised).
//!
//! ## The five gates (audit §6.2 as rewritten in §2.5b)
//!
//! | Gate | What it proves |
//! |---|---|
//! | H-3.1 | `cargo build --target wasm32-unknown-unknown -p poc17-cf-outbound-ws` clean |
//! | H-3.2 | Socket.IO handshake from CF DO via pure-Rust client (vendored codec + `worker::Fetch` + `web_sys::WebSocket`) |
//! | H-3.3 | BRC-103 mutual auth completes over the `authMessage` event channel |
//! | H-3.4 | Canonical CBOR envelope round-trips byte-exact through the live Calhoun relay |
//! | H-3.5 | Forced-hibernation reconnect: evict DO → wake → re-handshake → `/listMessages` backfill → message recovered |
//!
//! ## Module layout
//!
//! - [`engineio_codec`] — vendored Engine.IO v4 + Socket.IO v5 packet codec
//!   (MIT, © Calhooon Contributors, from `bsv-messagebox-cloudflare-public`).
//! - [`socketio_client`] — minimal Rust Engine.IO + Socket.IO client state
//!   machine + event emit/on layer, built on the vendored codec.
//! - [`transport_wasm`] — wasm32 transport substrate (`worker::Fetch` for
//!   Engine.IO polling + `web_sys::WebSocket` for the WS upgrade).
//! - [`transport`] — `SocketIoTransport`: impl of `bsv_rs::auth::Transport`
//!   over `socketio_client`'s emit/on, dispatching BRC-103 `AuthMessage`
//!   frames on the `authMessage` event channel.
//! - [`worker_do`] — Durable Object holding the `Peer` + reconstructing
//!   the Socket.IO client on each wake (audit §3.1 — JS handles do not
//!   survive hibernation; pure-Rust state is rebuilt from
//!   `serialize_attachment`).

pub mod engineio_codec;
pub mod socketio_client;
pub mod transport;
pub mod transport_wasm;
pub mod worker_do;

use worker::*;

/// CF Worker fetch event handler. **H-3.1 scope: stub only.** Real
/// routing (gates H-3.2 through H-3.5) lands in subsequent commits.
#[event(fetch)]
async fn fetch(_req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    Response::ok(
        "poc17-cf-outbound-ws — Phase H POC stub.\n\
         See TESTING.md for the five hard gates per audit §6.2.\n\
         H-3.1 gate (wasm32 build clean) is the only gate exercised by this stub.\n",
    )
}
