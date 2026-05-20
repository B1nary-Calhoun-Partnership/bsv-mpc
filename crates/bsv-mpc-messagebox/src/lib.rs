//! # bsv-mpc-messagebox
//!
//! MessageBox transport client for the bsv-mpc stack — implements the spec-
//! normative cross-cosigner wire per MPC-Spec §06.
//!
//! ## What this crate is
//!
//! Per MPC-Spec §06.5, every inter-cosigner MPC message is delivered over the
//! BSV `message-box-server` protocol with the canonical CBOR `MessageEnvelope`
//! (§05) carried as the MessagePayload body. Per §06.4, receivers MUST
//! support WebSocket (canonical for v1), HTTP `/listMessages` polling, and
//! FCM push (mobile profile).
//!
//! This crate provides the [`MessageBoxClient`] that:
//!
//! - **Send-side** ([`http::send_message`]): wraps an [`envelope::MessageEnvelope`]
//!   in a MessageBox JSON body, posts to `POST /sendMessage` with BRC-31
//!   mutual auth headers.
//! - **Receive-side** ([`ws::subscribe`]): connects to `/ws` (raw WebSocket
//!   on the Calhoun relay; Socket.IO/EngineIO on Binary's relay — both
//!   surface the same `{event, data}` JSON event envelope), subscribes to
//!   the caller's identity inbox, yields decoded envelopes as a `Stream`.
//! - **Fallback** ([`http::list_messages`]): HTTP polling of `/listMessages`
//!   for environments without WS or for backfill after WS reconnect (§06.12).
//!
//! ## What this crate is NOT
//!
//! - **Not the proxy↔KSS direct HTTP path** in `bsv-mpc-proxy/src/bridge.rs`
//!   — that's an internal within-stack optimization and is NOT spec-normative
//!   (§06.14). A future task may bring that path into spec-conformance, but
//!   it's distinct from this crate.
//! - **Not the MessageBox SERVER** — that's `bsv-messagebox-cloudflare-public`
//!   (Calhoun's CF Worker) and Binary's Railway server. This crate is the
//!   CLIENT that talks to either.
//!
//! ## Discovery
//!
//! Per §06.7, each cosigner publishes its `transport.inbox_url` + zero-or-more
//! fallbacks in its CHIP token (§12). The MessageBox client takes one
//! `relay_url` at construction time; long-term cosigner discovery via
//! SHIP/SLAP overlay on topic `tm_mpc_signing` lives in `bsv-mpc-overlay`
//! and is consumed by the caller, not by this crate.

// Target-agnostic modules — compile on BOTH native and wasm32.
pub mod error;
pub mod types;
pub mod wire;

// WS transport substrate (Phase H Step 4 — Socket.IO + BRC-103). The
// protocol logic (codec, `SocketIoTransport`, `run_dispatch`, app-event
// envelope helpers) lives upstream in bsv-rs 0.3.10's `socketio`
// feature; these modules supply only the per-target WS plumbing that
// implements the upstream `SocketIoSink` / `SocketIoFrameSource` traits
// — `transport_wasm` (`web_sys::WebSocket` + `worker::Fetch`) on wasm32,
// `transport_native` (`tokio-tungstenite` + `reqwest`) on native.
#[cfg(not(target_arch = "wasm32"))]
pub mod transport_native;
#[cfg(target_arch = "wasm32")]
pub mod transport_wasm;

// Native-only modules — the raw-WS + BRC-104 SimplifiedFetchTransport
// path. These pull `tokio` / `reqwest` / `tokio-tungstenite`, none of
// which compile to `wasm32-unknown-unknown`. H-4.4b replaces `ws.rs`
// with a `subscribe.rs` driving the upstream Socket.IO + BRC-103
// transport over `transport_native`.
#[cfg(not(target_arch = "wasm32"))]
pub mod auth;
#[cfg(not(target_arch = "wasm32"))]
pub mod client;
#[cfg(not(target_arch = "wasm32"))]
pub mod http;
#[cfg(not(target_arch = "wasm32"))]
pub mod ws;

#[cfg(not(target_arch = "wasm32"))]
pub use client::{
    DecodedEnvelope, DecodedRoundMessage, EnvelopeSubscription, MessageBoxClient,
    RoundMessageSubscription,
};
pub use error::{MessageBoxError, Result};
#[cfg(not(target_arch = "wasm32"))]
pub use ws::{subscribe, InboundEnvelopeEvent, InboundVia, WsSubscription};
