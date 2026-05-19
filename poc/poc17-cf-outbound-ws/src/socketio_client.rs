//! Minimal Rust Engine.IO + Socket.IO CLIENT built on top of the
//! vendored [`crate::engineio_codec`].
//!
//! # H-3.2a scope
//!
//! Public type declarations only. The Engine.IO polling handshake
//! (proven in H-3.2a) is implemented in [`crate::transport_wasm`]
//! since it's wasm32-specific (CF Worker's `worker::Fetch`). The state
//! machine + event dispatch + the cross-target `SocketIo` trait
//! land in H-3.2b through H-3.4 as the upgrade dance + Socket.IO
//! `emit`/`on` + BRC-103 `authMessage` wiring lands.

/// Engine.IO client state machine — transitions per Engine.IO 4 spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketIoState {
    /// Initial state — about to send the polling handshake GET.
    Connecting,
    /// Engine.IO Open packet received; session id + upgrades parsed.
    /// (Status returned by H-3.2a's `/open` route.)
    Connected,
    /// Probe sent on the upgraded WS transport; awaiting Pong reply.
    Upgrading,
    /// Upgrade committed (Engine.IO `5` Upgrade packet sent); WS is
    /// now the active transport.
    Upgraded,
    /// Transport closed — either by remote or by local disconnect.
    Closed,
}

/// Public client handle — what consumers see. **Stub for H-3.2a.**
/// Full state + transport substrate wiring lands in H-3.2b-H-3.4.
pub struct SocketIoClient {
    /// Session id assigned by the server (`sid` in the Open packet).
    /// `None` while in [`SocketIoState::Connecting`].
    pub sid: Option<String>,
    /// Current state.
    pub state: SocketIoState,
}

impl SocketIoClient {
    pub fn new() -> Self {
        Self {
            sid: None,
            state: SocketIoState::Connecting,
        }
    }
}

impl Default for SocketIoClient {
    fn default() -> Self {
        Self::new()
    }
}
