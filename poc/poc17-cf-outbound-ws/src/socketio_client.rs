//! Minimal Rust Engine.IO + Socket.IO CLIENT built on top of the
//! vendored [`crate::engineio_codec`].
//!
//! # H-3.1 scope
//!
//! Stub only. The full state machine + event dispatch lands in H-3.2
//! through H-3.4. This file declares the public types the rest of the
//! POC scaffolding wires against, so the wasm32 build (H-3.1) can
//! confirm the crate compiles end-to-end.
//!
//! # Design (per audit §11.2 revised — Plan A1)
//!
//! - State machine: CONNECTING → CONNECTED → UPGRADING → UPGRADED → CLOSED.
//! - Engine.IO polling phase (initial handshake) via `worker::Fetch`
//!   on wasm32 / `reqwest` on native — both targets parse the same
//!   `engineio_codec::EngineIoPacket::Open` packet.
//! - WS upgrade phase via `web_sys::WebSocket` on wasm32 /
//!   `tokio-tungstenite` on native.
//! - Socket.IO `EVENT` packet shape inside Engine.IO `Message(4)` frames.
//! - `emit(event, json)` + `on(event, callback)` API surfaces.

use crate::engineio_codec::{EngineIoPacket, SocketIoPacket};

/// Engine.IO client state machine — transitions per Engine.IO 4 spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketIoState {
    /// Initial state — about to send the polling handshake GET.
    Connecting,
    /// Engine.IO Open packet received; session id + upgrades parsed.
    /// Socket.IO CONNECT exchanged.
    Connected,
    /// Probe sent on the upgraded WS transport; awaiting Pong reply.
    Upgrading,
    /// Upgrade committed (Engine.IO `5` Upgrade packet sent); WS is
    /// now the active transport.
    Upgraded,
    /// Transport closed — either by remote or by local disconnect.
    Closed,
}

/// Public client handle — what consumers see. **Stub for H-3.1.**
/// Full state + transport substrate wiring lands in H-3.2-H-3.4.
pub struct SocketIoClient {
    /// Session id assigned by the server (`sid` in the Open packet).
    /// `None` while in [`SocketIoState::Connecting`].
    pub sid: Option<String>,
    /// Current state.
    pub state: SocketIoState,
}

impl SocketIoClient {
    /// Construct a fresh client in the [`SocketIoState::Connecting`]
    /// state. The actual connect logic lives in H-3.2 work (this is a
    /// build-only stub today).
    pub fn new() -> Self {
        Self {
            sid: None,
            state: SocketIoState::Connecting,
        }
    }

    /// Force-touch the vendored codec types so the dead-code lint
    /// doesn't fire on `engineio_codec`'s public surface during the
    /// H-3.1 build. Removed in H-3.2 when actual codec wiring lands.
    pub fn _h3_1_codec_touch() -> bool {
        let pkt = EngineIoPacket::Noop;
        let enc = pkt.encode();
        let decoded = EngineIoPacket::decode(&enc).is_ok();
        let sio = SocketIoPacket::Connect {
            nsp: "/".to_string(),
            data: None,
        };
        let _ = sio.nsp();
        decoded
    }
}

impl Default for SocketIoClient {
    fn default() -> Self {
        Self::new()
    }
}
