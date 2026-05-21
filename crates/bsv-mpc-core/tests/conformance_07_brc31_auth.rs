//! §07 BRC-31 mutual-auth conformance — canonical client ↔ canonical server.
//!
//! Proves the wire bsv-mpc is converging onto (issue #8): a General message
//! signed EXACTLY as `bsv_rs::auth::Peer` signs it (peer.rs:582-608, i.e.
//! `SecurityLevel::Counterparty`, `AUTH_PROTOCOL_ID`, `AuthMessage::get_key_id`,
//! `signing_data`) verifies against the canonical `bsv-middleware-rs` server
//! verifier (the FIXED crate, pinned via git rev in Cargo.toml). This is the
//! basis for authoring MPC-Spec `conformance/test-vectors/07-brc31-auth.json`.
//!
//! Three §07 properties are asserted:
//!  1. interop      — canonical-client signature verifies (mutual auth works);
//!  2. identity     — a signature from a non-session-bound identity is rejected;
//!  3. body-binding — tampering the signed BRC-104 payload breaks the signature.
//!
//! NOTE: replay rejection (§07.1 "stale nonce MUST be rejected") is a
//! server-policy concern enforced ABOVE `verify_message_signature` (which is a
//! pure function): the consuming service tracks consumed per-request nonces.
//! That is exercised by the service-side e2e in the Phase B migration, not here.

use base64::Engine;
use bsv::auth::{AuthMessage, MessageType, AUTH_PROTOCOL_ID};
use bsv::primitives::PrivateKey;
use bsv::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use bsv::PublicKey;
use bsv_middleware_rs::transport::build_request_payload;
use bsv_middleware_rs::{verify_message_signature, StoredSession};

/// Real BRC-31 nonces are base64-encoded 32-byte values; bsv-rs key derivation
/// decodes the keyID nonce tokens, so tests must use realistic base64 nonces.
fn b64(seed: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode([seed; 32])
}

/// Build + sign a General request EXACTLY as `bsv_rs::auth::Peer` does.
fn canonical_client_general(
    client: &ProtoWallet,
    server_id: &PublicKey,
    server_session_nonce: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> AuthMessage {
    let request_id = [0x11u8; 32];
    let payload = build_request_payload(&request_id, method, path, "", &[], body);
    let mut msg = AuthMessage::new(MessageType::General, client.identity_key());
    msg.nonce = Some(b64(0xC3)); // fresh per-message nonce
    msg.your_nonce = Some(server_session_nonce.to_string());
    msg.payload = Some(payload);
    let key_id = msg.get_key_id(Some(server_session_nonce));
    let data = msg.signing_data();
    let sig = client
        .create_signature(CreateSignatureArgs {
            data: Some(data),
            hash_to_directly_sign: None,
            protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
            key_id,
            counterparty: Some(Counterparty::Other(server_id.clone())),
        })
        .expect("canonical client create_signature");
    msg.signature = Some(sig.signature);
    msg
}

/// Post-handshake server session bound to `client_id_hex`.
fn server_session(server_session_nonce: &str, client_id_hex: &str) -> StoredSession {
    let mut s = StoredSession::new(server_session_nonce.to_string(), client_id_hex.to_string());
    s.peer_nonce = Some(b64(0xB2));
    s.is_authenticated = true;
    s
}

#[test]
fn canonical_peer_client_verifies_against_canonical_server() {
    let client = ProtoWallet::new(Some(PrivateKey::random()));
    let server = ProtoWallet::new(Some(PrivateKey::random()));
    let ssn = b64(0xA1);
    let msg = canonical_client_general(
        &client,
        &server.identity_key(),
        &ssn,
        "POST",
        "/sign/init",
        br#"{"session_id":"c07","round":0}"#,
    );
    let session = server_session(&ssn, &client.identity_key().to_hex());
    assert!(
        verify_message_signature(&server, &msg, &session).unwrap(),
        "canonical Peer-client General message must verify against bsv-middleware-rs"
    );
}

#[test]
fn signature_from_unbound_identity_rejected() {
    let client = ProtoWallet::new(Some(PrivateKey::random()));
    let server = ProtoWallet::new(Some(PrivateKey::random()));
    let stranger = ProtoWallet::new(Some(PrivateKey::random()));
    let ssn = b64(0xA1);
    let msg = canonical_client_general(
        &client,
        &server.identity_key(),
        &ssn,
        "POST",
        "/sign/init",
        br#"{"session_id":"c07","round":0}"#,
    );
    // Session bound to a DIFFERENT identity than the actual signer.
    let session = server_session(&ssn, &stranger.identity_key().to_hex());
    assert!(
        !verify_message_signature(&server, &msg, &session).unwrap_or(false),
        "a signature from a non-session-bound identity must be rejected"
    );
}

#[test]
fn tampered_payload_breaks_signature() {
    let client = ProtoWallet::new(Some(PrivateKey::random()));
    let server = ProtoWallet::new(Some(PrivateKey::random()));
    let ssn = b64(0xA1);
    let mut msg = canonical_client_general(
        &client,
        &server.identity_key(),
        &ssn,
        "POST",
        "/sign/init",
        br#"{"session_id":"c07","round":0}"#,
    );
    // Flip the last byte of the signed BRC-104 payload AFTER signing.
    let p = msg.payload.as_mut().expect("payload");
    let n = p.len();
    p[n - 1] ^= 0xFF;
    let session = server_session(&ssn, &client.identity_key().to_hex());
    assert!(
        !verify_message_signature(&server, &msg, &session).unwrap_or(false),
        "tampering the request body must break the signature (payload binding)"
    );
}
