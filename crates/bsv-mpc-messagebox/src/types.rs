//! Wire types matching the BSV `message-box-server` API.
//!
//! Field shapes mirror the TS / Go / Rust server implementations and are
//! kept byte-compatible (camelCase, ISO 8601 timestamps). See
//! `bsv-messagebox-cloudflare-public/src/types.rs` for the canonical Rust
//! definitions on the server side.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// POST /sendMessage
// ---------------------------------------------------------------------------

/// `POST /sendMessage` request body.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageRequest {
    pub message: MessagePayload,
    /// Payment is REQUIRED only when the recipient's box charges; for the
    /// `mpc-*` boxes we use, fee is configured to 0 and `payment` is omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePayload {
    /// Single recipient identity-key hex. Use `recipients` for multi-cast.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// Multi-cast recipients; mutually exclusive with `recipient`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipients: Option<Vec<String>>,
    /// Box name (per-recipient mailbox). MPC ceremonies use stable per-phase
    /// boxes like `mpc-dkg-inbox`, `mpc-sign-inbox`, etc.
    pub message_box: String,
    /// Optional dedup id (UUID RECOMMENDED). The server treats duplicate
    /// `(recipient, message_box, message_id)` tuples as no-ops.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    /// The wrapped canonical CBOR envelope. Encoded as a JSON string
    /// containing lowercase hex of the §05 `MessageEnvelope::encode_canonical`
    /// bytes — see `wire::wrap_envelope_to_body`.
    pub body: serde_json::Value,
}

/// `POST /sendMessage` response. The relay's success body is
/// `{ status: "success", message: "...", results: [{recipient, messageId}, ...] }`
/// per `bsv-messagebox-cloudflare-public/src/routes/send_message.rs::
/// outcome_to_http`. We expose the per-recipient acknowledgements under
/// the more conventional name `messages` via serde alias.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageResponse {
    pub status: String,
    /// Server-side human-readable summary. Optional — kept for parity.
    #[serde(default)]
    pub message: Option<String>,
    /// Per-recipient delivery results. Aliased so callers can use
    /// `.messages` while the wire field name stays `results`.
    #[serde(alias = "results", default)]
    pub messages: Vec<SendResultEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendResultEntry {
    pub recipient: String,
    pub message_id: String,
}

// ---------------------------------------------------------------------------
// POST /listMessages
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListMessagesRequest {
    pub message_box: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListMessagesResponse {
    pub status: String,
    #[serde(default)]
    pub messages: Vec<InboundMessage>,
}

/// One inbound message as returned by `/listMessages` or pushed over WS.
/// Matches the server's `MessageRow` schema byte-for-byte (per
/// `bsv-messagebox-cloudflare-public/src/lib.rs:list_messages` + OpenAPI).
///
/// Notably:
/// - `messageBox` is NOT included — the caller already knows which box
///   they queried.
/// - `body` is a **JSON STRING**, not a JSON object. The server stores
///   the original sender's `MessagePayload.body` inside a wrapper:
///   `{"message": <body>}` (per `routes/send_message.rs:202`). Use
///   [`crate::wire::unwrap_inbound_body`] to peel the wrap and decode the
///   canonical CBOR envelope in one call.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundMessage {
    pub message_id: String,
    /// Sender's BRC-31 identity-key hex (verified by the server).
    pub sender: String,
    /// JSON-stringified server-wrap. Pass to
    /// [`crate::wire::unwrap_inbound_body`].
    pub body: String,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// POST /acknowledgeMessage
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcknowledgeRequest {
    pub message_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcknowledgeResponse {
    pub status: String,
}

// ---------------------------------------------------------------------------
// Standardized MPC box names (per ceremony kind)
// ---------------------------------------------------------------------------
//
// Boxes are server-side mailbox names; the recipient subscribes to them.
// We use one box per ceremony kind so receivers can route incoming
// envelopes to the right coordinator without parsing the envelope first.

/// Box name for DKG ceremony envelopes.
pub const BOX_DKG: &str = "mpc-dkg";
/// Box name for Sign ceremony envelopes.
pub const BOX_SIGN: &str = "mpc-sign";
/// Box name for Presign ceremony envelopes.
pub const BOX_PRESIGN: &str = "mpc-presign";
/// Box name for ECDH ceremony envelopes (BRC-42 partial ECDH).
pub const BOX_ECDH: &str = "mpc-ecdh";
/// Box name for Refresh ceremony envelopes.
pub const BOX_REFRESH: &str = "mpc-refresh";

// ---------------------------------------------------------------------------
// Per-session presign mailboxes (MPC-Spec §06.17.2)
// ---------------------------------------------------------------------------
//
// Mailboxes are IMPLICIT on a `message-box-server` relay: they're created on
// the first `sendMessage` to a name and there's no create/delete API
// ("allocate" = use the name; "delete after ack" = best-effort relay GC plus
// `acknowledge`). Per §06.17.2 a presign session uses two transient mailboxes,
// each scoped by the canonical SessionId hex (§04):
//
//   - `mpc_{session_id}`          — round-trip channel for the 3-round cggmp24
//                                    protocol traffic.
//   - `presig_return_{session_id}` — one-way return channel for the cosigner-
//                                    encrypted presig-share ciphertexts.

/// Round-trip mailbox name for a presign session's 3-round protocol traffic
/// (§06.17.2): `mpc_{session_id_hex}`. `session_id_hex` is the 64-char
/// lowercase-hex canonical SessionId (§04). Pure + deterministic.
pub fn presign_protocol_box(session_id_hex: &str) -> String {
    format!("mpc_{session_id_hex}")
}

/// One-way return mailbox name for a presign session's cosigner-encrypted
/// share ciphertexts (§06.17.2): `presig_return_{session_id_hex}`. Pure +
/// deterministic.
pub fn presig_return_box(session_id_hex: &str) -> String {
    format!("presig_return_{session_id_hex}")
}

#[cfg(test)]
mod box_name_tests {
    use super::*;

    #[test]
    fn presign_mailbox_names_are_session_scoped_and_deterministic() {
        let sid = "f25e7c5e560e01926dfbfd70f3940352c1349e1e69a2f17c1668bda988014e0b";
        // Exact §06.17.2 spelling.
        assert_eq!(
            presign_protocol_box(sid),
            "mpc_f25e7c5e560e01926dfbfd70f3940352c1349e1e69a2f17c1668bda988014e0b"
        );
        assert_eq!(
            presig_return_box(sid),
            "presig_return_f25e7c5e560e01926dfbfd70f3940352c1349e1e69a2f17c1668bda988014e0b"
        );
        // Deterministic: same input → same name.
        assert_eq!(presign_protocol_box(sid), presign_protocol_box(sid));
        assert_eq!(presig_return_box(sid), presig_return_box(sid));
        // Distinct sessions → distinct mailboxes (no cross-session collision).
        let other = "00".repeat(32);
        assert_ne!(presign_protocol_box(sid), presign_protocol_box(&other));
        assert_ne!(presig_return_box(sid), presig_return_box(&other));
        // The two channels for one session never collide.
        assert_ne!(presign_protocol_box(sid), presig_return_box(sid));
    }
}
