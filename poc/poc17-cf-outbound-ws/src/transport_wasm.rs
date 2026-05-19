//! wasm32 transport substrate — `worker::Fetch` (Engine.IO polling
//! handshake) + `web_sys::WebSocket` (WS upgrade phase).
//!
//! Both phases of the Engine.IO 4 client lifecycle live here.
//! `socketio_client.rs` is transport-agnostic and consumes this
//! substrate via the (forthcoming) `SocketIo` trait abstraction.
//!
//! # H-3.1 scope
//!
//! Stub only — declares the wasm32-specific entry points. The
//! `web_sys::WebSocket` open call + Engine.IO polling fetch are H-3.2
//! work.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen::prelude::*;
use web_sys::WebSocket;

/// Returns a placeholder string to verify `web_sys::WebSocket` is
/// linkable on wasm32. **Replace with actual WS open in H-3.2.**
pub fn _h3_1_websys_link_check() -> &'static str {
    // We deliberately reference the `WebSocket` constructor type to
    // force linker resolution; the call itself does nothing.
    let _ctor: fn(&str) -> std::result::Result<WebSocket, JsValue> = WebSocket::new;
    "web_sys::WebSocket linkable on wasm32"
}
