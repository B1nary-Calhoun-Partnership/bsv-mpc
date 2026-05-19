//! Durable Object holding the `Peer` + `SocketIoClient` for one
//! cosigner identity. **Stub only for H-3.1.**
//!
//! # Design (per audit §3.1)
//!
//! - The Socket.IO client is **NOT** serializable across hibernation;
//!   the DO reconstructs it lazily on each `fetch()` call after a wake
//!   event.
//! - The `serialize_attachment` slot stores only the subscription
//!   state (subscribed boxes, last-seen sequence per box) + the
//!   `auth_identity_key` needed to re-instantiate `MessageBoxAuth`
//!   after wake.
//! - MPC ceremony state (KeyShare bytes, in-flight presigs) lives in
//!   `state.storage` (D1 / SQLite) — NOT in the WS attachment — to
//!   avoid the ~2KB attachment cap.
//!
//! # H-3.1 scope
//!
//! Just enough type declarations to confirm the wasm32 build is
//! green. Real `DurableObject` impl + `fetch()` routing land in
//! H-3.2 + H-3.5.

/// Subscription state that survives hibernation, persisted via
/// `serialize_attachment`. Sized ~500 bytes for ≤20 boxes, well under
/// the ~2KB cap per audit §3.1.
#[derive(serde::Serialize, serde::Deserialize, Default, Debug, Clone)]
pub struct WsAttachment {
    pub subscribed_boxes: Vec<String>,
    pub last_seen_message_id: std::collections::HashMap<String, String>,
    pub auth_identity_key: String,
    pub relay_url: String,
}
