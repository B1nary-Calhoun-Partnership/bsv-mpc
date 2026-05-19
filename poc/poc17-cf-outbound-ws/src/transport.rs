//! `SocketIoTransport` — Rust impl of `bsv_rs::auth::Transport` over
//! the [`crate::socketio_client::SocketIoClient`]'s `authMessage`
//! event channel.
//!
//! Rust analog of TS `~/bsv/authsocket-client/src/SocketClientTransport.ts`.
//! Lands upstream in `~/bsv/bsv-rs/src/auth/transports/` alongside the
//! existing `SimplifiedFetchTransport` + `WebSocketTransport`.
//!
//! # H-3.1 scope
//!
//! Stub only — types declared, trait not yet wired. Full impl in H-3.3
//! (BRC-103 handshake gate).

use crate::socketio_client::SocketIoClient;
use std::sync::Arc;

/// Wraps a `SocketIoClient` and dispatches BRC-103 `AuthMessage`
/// frames over its `authMessage` event channel.
pub struct SocketIoTransport {
    /// The underlying Socket.IO client. Held by `Arc` so the DO can
    /// share the same client across multiple `fetch()` calls.
    pub client: Arc<SocketIoClient>,
}

impl SocketIoTransport {
    pub fn new(client: Arc<SocketIoClient>) -> Self {
        Self { client }
    }
}
