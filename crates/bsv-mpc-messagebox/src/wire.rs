//! Wrap / unwrap helpers between the canonical CBOR `MessageEnvelope`
//! (MPC-Spec §05) and the MessageBox `MessagePayload.body` JSON field
//! (MPC-Spec §06.5 + `bsv-messagebox-cloudflare-public/src/types.rs`).
//!
//! ## Encoding
//!
//! The canonical CBOR envelope bytes are encoded as a **lowercase hex string**
//! and placed in `MessagePayload.body` as a JSON string value:
//!
//! ```json
//! { "body": "ac01010258200fc...db30" }
//! ```
//!
//! ### Why hex and not base64 or binary
//!
//! - MessageBox's `body` is `serde_json::Value` — JSON-native — so raw bytes
//!   don't fit.
//! - Hex is lowercase-canonical (no padding ambiguity, no `_` vs `/` URL-safe
//!   variant); base64 has multiple "correct" forms.
//! - Hex preserves grep-ability for debugging mainnet ceremony logs.
//! - The 2× wire overhead vs base64 is irrelevant at the §05 envelope size
//!   (~361 B for the test vector; tens of KB worst case for DKG auxinfo).
//!
//! Per §06.5 the body field IS the canonical envelope; the hex encoding is the
//! JSON-transport adapter, not a spec-modifying re-shape.

use bsv_mpc_core::envelope::MessageEnvelope;
use serde_json::Value;

use crate::error::{MessageBoxError, Result};

/// Encode a canonical MessageEnvelope as the JSON value that goes in
/// `MessagePayload.body`. The output is `Value::String(<lowercase hex>)`.
pub fn wrap_envelope_to_body(env: &MessageEnvelope) -> Value {
    let bytes = env.encode_canonical();
    Value::String(hex::encode(bytes))
}

/// Decode the server's `InboundMessage.body` (a JSON-stringified wrap of
/// the form `{"message": "<lowercase hex>"}`) back into a canonical
/// MessageEnvelope.
///
/// The server-imposed `{"message": ...}` wrap is per
/// `bsv-messagebox-cloudflare-public/src/routes/send_message.rs::process_send`
/// stored-body shape; it is NOT part of our wire spec — peel it here so
/// callers see only the canonical envelope.
///
/// Errors:
/// - `Json` if the outer string is not valid JSON.
/// - `Protocol` if the JSON doesn't have a string `message` field.
/// - `Envelope(EnvelopeReencodeMismatch)` for any §05.9.1 violation.
pub fn unwrap_inbound_body(server_body_str: &str) -> Result<MessageEnvelope> {
    let outer: Value = serde_json::from_str(server_body_str)?;
    let inner = outer.get("message").ok_or_else(|| {
        MessageBoxError::Protocol(format!(
            "InboundMessage.body must be JSON-stringified {{\"message\": <body>}} \
             per the server wrap; got: {server_body_str}"
        ))
    })?;
    unwrap_body_to_envelope(inner)
}

/// Decode a `MessagePayload.body` JSON value back into a canonical
/// MessageEnvelope. Enforces the strict-decode contract per §05.9.1 (the
/// byte-equivalent re-encode check runs inside `decode_strict`).
///
/// Use [`unwrap_inbound_body`] when peeling a server-side
/// `InboundMessage.body` — that variant handles the
/// `{"message": <body>}` wrap the relay adds at storage time.
///
/// Errors:
/// - `Protocol` if `body` is not a JSON string or hex is malformed.
/// - `Envelope(EnvelopeReencodeMismatch)` for any §05.9.1 violation.
pub fn unwrap_body_to_envelope(body: &Value) -> Result<MessageEnvelope> {
    let hex_str = body.as_str().ok_or_else(|| {
        MessageBoxError::Protocol(format!(
            "MessagePayload.body must be a JSON string of hex-encoded canonical \
             CBOR envelope; got {}",
            describe_value(body)
        ))
    })?;
    let bytes = hex::decode(hex_str)?;
    let env = MessageEnvelope::decode_strict(&bytes)?;
    Ok(env)
}

fn describe_value(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_mpc_core::envelope::ENVELOPE_VERSION_V1;
    use bsv_mpc_core::types::SessionId;
    use bsv_mpc_core::MpcError;

    fn sample_envelope() -> MessageEnvelope {
        MessageEnvelope {
            version: ENVELOPE_VERSION_V1,
            session_id: SessionId([0x11; 32]),
            joint_pubkey: {
                let mut p = [0u8; 33];
                p[0] = 0x02;
                p[32] = 0x42;
                p
            },
            phase: "sign".into(),
            round: 1,
            from_party: 0,
            to_party: 1,
            inner: vec![0xca, 0xfe, 0xba, 0xbe],
            sender_sig_brc31: vec![0x30, 0x44, 0x02, 0x20],
            execution_id_prefix: [0u8; 8],
            correlation_id: Some("corr-1".into()),
            traceparent: None,
        }
    }

    #[test]
    fn wrap_round_trip() {
        let env = sample_envelope();
        let body = wrap_envelope_to_body(&env);
        assert!(body.is_string(), "body must be a JSON string");
        let hex_str = body.as_str().unwrap();
        assert!(hex_str
            .chars()
            .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase())));

        let back = unwrap_body_to_envelope(&body).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn wrap_uses_lowercase_hex() {
        // Sanity: §05.9.1 byte-equivalent re-encode + lowercase hex
        // discipline. If we ever emitted uppercase, this would catch it.
        let env = sample_envelope();
        let body = wrap_envelope_to_body(&env);
        let s = body.as_str().unwrap();
        assert!(
            !s.chars().any(|c| c.is_ascii_uppercase()),
            "wrapped body must be lowercase hex (got {s})"
        );
    }

    #[test]
    fn unwrap_rejects_non_string_body() {
        let body = serde_json::json!({"cbor": "ac01"});
        let err = unwrap_body_to_envelope(&body).unwrap_err();
        match err {
            MessageBoxError::Protocol(msg) => {
                assert!(msg.contains("must be a JSON string"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_rejects_bad_hex() {
        let body = serde_json::json!("not hex at all!");
        let err = unwrap_body_to_envelope(&body).unwrap_err();
        assert!(matches!(err, MessageBoxError::Hex(_)));
    }

    #[test]
    fn unwrap_rejects_non_canonical_cbor() {
        // Take a valid envelope, encode, then mutate a byte to break canonical-
        // ity (e.g. flip the version value), and assert decode_strict refuses.
        let env = sample_envelope();
        let mut bytes = env.encode_canonical();
        // Version key/value are early; replace 0x01 (version=1) with 0xff to
        // make version=255 — still valid CBOR but the byte-equivalent
        // re-encode check would pass (any u8 is allowed). To trigger
        // EnvelopeReencodeMismatch, instead corrupt with a forbidden form:
        // change the map header `ac` (map 12) to `bc` (reserved info 28).
        bytes[0] = 0xbc; // reserved info 28 → §05.9.1 reserved-info violation
        let body = Value::String(hex::encode(&bytes));
        let err = unwrap_body_to_envelope(&body).unwrap_err();
        match err {
            MessageBoxError::Envelope(MpcError::EnvelopeReencodeMismatch {
                rule: "reserved-info",
                ..
            }) => {}
            other => panic!("expected reserved-info envelope rejection, got {other:?}"),
        }
    }
}
