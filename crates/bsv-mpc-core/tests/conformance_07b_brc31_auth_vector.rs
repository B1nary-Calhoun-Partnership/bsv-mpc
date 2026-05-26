//! Conformance suite for MPC-Spec §07.11 BRC-31 mutual-auth vectors.
//!
//! Drives the vector at `tests/fixtures/07-brc31-auth.json` (vendored from the
//! MPC-Spec repo so this crate compiles standalone). This is the consuming
//! counterpart to `conformance_07_brc31_auth.rs` (which proves the wire
//! programmatically): here we reproduce the BYTE-LOCKED values from the
//! committed vector and assert byte-equality through the SAME proven wire
//! (`build_request_payload` + `AuthMessage` + `ProtoWallet::create_signature` +
//! `verify_message_signature`).
//!
//! For each vector:
//!  - rebuild the BRC-104 signable payload via the proven wire and assert it
//!    equals `expected.signable_payload_hex` byte-for-byte;
//!  - verify the signature via the canonical `verify_message_signature` and
//!    assert it matches the `verifies` expectation;
//!  - for the valid vector, re-sign and assert `signature_hex` byte-equality
//!    (RFC-6979 deterministic — locked).
//!
//! Native-only: links `bsv-middleware-rs` (canonical server verifier), which
//! does not build for wasm32. Same gate as `conformance_07_brc31_auth.rs`.
#![cfg(not(target_arch = "wasm32"))]

use base64::Engine;
use bsv::auth::{AuthMessage, MessageType, AUTH_PROTOCOL_ID};
use bsv::primitives::PrivateKey;
use bsv::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use bsv::PublicKey;
use bsv_middleware_rs::transport::{build_request_payload, filter_signable_headers};
use bsv_middleware_rs::{verify_message_signature, StoredSession};
use serde_json::Value;

const VECTORS: &str = include_str!("fixtures/07-brc31-auth.json");
const JSON_CONTENT_TYPE: &str = "application/json";

fn root() -> Value {
    let r: Value = serde_json::from_str(VECTORS).expect("vector json parses");
    assert_eq!(r["spec_section"], "07.11", "vector file is §07.11");
    r
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

fn wallet_from_hex(priv_hex: &str) -> ProtoWallet {
    let bytes = hex::decode(priv_hex).expect("priv hex decodes");
    let key = PrivateKey::from_bytes(&bytes).expect("valid priv key");
    ProtoWallet::new(Some(key))
}

/// Reproduce a signed General `AuthMessage` via the EXACT proven wire from
/// `Brc31Client::request_headers`, with the vector's fixed nonces/request_id.
#[allow(clippy::too_many_arguments)]
fn sign_general(
    client: &ProtoWallet,
    server_id: &PublicKey,
    server_session_nonce: &str,
    request_nonce: &str,
    request_id: &[u8; 32],
    method: &str,
    path: &str,
    body: &[u8],
) -> (AuthMessage, Vec<u8>, String) {
    let signable =
        filter_signable_headers(&[("content-type".to_string(), JSON_CONTENT_TYPE.to_string())]);
    let payload = build_request_payload(request_id, method, path, "", &signable, body);
    let mut msg = AuthMessage::new(MessageType::General, client.identity_key());
    msg.nonce = Some(request_nonce.to_string());
    msg.your_nonce = Some(server_session_nonce.to_string());
    msg.payload = Some(payload.clone());
    let key_id = msg.get_key_id(Some(server_session_nonce));
    let data = msg.signing_data();
    let sig = client
        .create_signature(CreateSignatureArgs {
            data: Some(data),
            hash_to_directly_sign: None,
            protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
            key_id: key_id.clone(),
            counterparty: Some(Counterparty::Other(server_id.clone())),
        })
        .expect("create_signature");
    msg.signature = Some(sig.signature);
    (msg, payload, key_id)
}

fn server_session(
    server_session_nonce: &str,
    client_id_hex: &str,
    peer_nonce: &str,
) -> StoredSession {
    let mut s = StoredSession::new(server_session_nonce.to_string(), client_id_hex.to_string());
    s.peer_nonce = Some(peer_nonce.to_string());
    s.is_authenticated = true;
    s
}

fn b32_from_b64(b64: &str) -> [u8; 32] {
    let v = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("base64 decodes");
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

#[test]
fn valid_general_message_reproduces_and_verifies() {
    let r = root();
    let v = &r["vectors"][0];
    assert_eq!(v["name"], "valid-general-message");
    let inp = &v["inputs"];
    let exp = &v["expected"];

    let sender = wallet_from_hex(s(inp, "sender_privkey_hex"));
    let server_id = PublicKey::from_hex(s(inp, "server_identity_hex")).expect("server id");

    let request_id_v = hex::decode(s(inp, "request_id_hex")).expect("request_id hex");
    let mut request_id = [0u8; 32];
    request_id.copy_from_slice(&request_id_v);

    let request_nonce = s(inp, "request_nonce_b64");
    let ssn = s(inp, "server_session_nonce_b64");
    let body = hex::decode(s(inp, "body_hex")).expect("body hex");

    let (msg, payload, key_id) = sign_general(
        &sender,
        &server_id,
        ssn,
        request_nonce,
        &request_id,
        s(inp, "method"),
        s(inp, "path"),
        &body,
    );

    // 1) Byte-lock: signable payload.
    assert_eq!(
        hex::encode(&payload),
        s(exp, "signable_payload_hex"),
        "signable payload must reproduce the locked vector byte-for-byte"
    );
    // 2) Byte-lock: key_id.
    assert_eq!(key_id, s(exp, "key_id"), "key_id must match locked vector");
    // 3) Byte-lock: deterministic RFC-6979 signature.
    assert_eq!(
        hex::encode(msg.signature.as_ref().expect("sig")),
        s(exp, "signature_hex"),
        "RFC-6979 deterministic signature must reproduce locked signature_hex"
    );

    // 4) Verify against the canonical server verifier. The verifier needs the
    // server's PRIVATE key (it derives the verification pubkey via ECDH with the
    // server's own key) — use the shared server_privkey from the vector.
    let server_wallet = wallet_from_hex(
        r["shared_inputs"]["server_privkey_hex"]
            .as_str()
            .expect("server_privkey_hex"),
    );
    let session = server_session(ssn, &sender.identity_key().to_hex(), request_nonce);
    let verifies = verify_message_signature(&server_wallet, &msg, &session).unwrap_or(false);
    assert_eq!(
        verifies,
        exp["verifies"].as_bool().unwrap(),
        "valid vector must verify against canonical server"
    );
}

#[test]
fn wrong_identity_rejected() {
    let r = root();
    let v = &r["vectors"][1];
    assert_eq!(v["name"], "wrong-identity-rejected");
    let inp = &v["inputs"];
    let exp = &v["expected"];

    let stranger = wallet_from_hex(s(inp, "actual_signer_privkey_hex"));
    let server_id = PublicKey::from_hex(s(inp, "server_identity_hex")).expect("server id");
    let server_wallet = wallet_from_hex(
        r["shared_inputs"]["server_privkey_hex"]
            .as_str()
            .expect("server_privkey_hex"),
    );

    let request_id = [0x11u8; 32];
    let request_nonce = s(inp, "request_nonce_b64");
    let ssn = s(inp, "server_session_nonce_b64");
    let body = hex::decode(s(inp, "body_hex")).expect("body hex");

    let (msg, payload, _) = sign_general(
        &stranger,
        &server_id,
        ssn,
        request_nonce,
        &request_id,
        s(inp, "method"),
        s(inp, "path"),
        &body,
    );
    assert_eq!(
        hex::encode(&payload),
        s(exp, "signable_payload_hex"),
        "payload still reproduces (only the identity differs)"
    );

    // Session bound to the LEGIT sender identity, signature from stranger → reject.
    let bound_id = s(inp, "session_bound_identity_hex");
    let session = server_session(ssn, bound_id, request_nonce);
    let verifies = verify_message_signature(&server_wallet, &msg, &session).unwrap_or(false);
    assert_eq!(
        verifies,
        exp["verifies"].as_bool().unwrap(),
        "signature from a non-session-bound identity must be rejected"
    );
}

#[test]
fn tampered_payload_rejected() {
    let r = root();
    let v = &r["vectors"][2];
    assert_eq!(v["name"], "tampered-payload-rejected");
    let inp = &v["inputs"];
    let exp = &v["expected"];

    let sender = wallet_from_hex(s(inp, "sender_privkey_hex"));
    let server_id = PublicKey::from_hex(s(inp, "server_identity_hex")).expect("server id");
    let server_wallet = wallet_from_hex(
        r["shared_inputs"]["server_privkey_hex"]
            .as_str()
            .expect("server_privkey_hex"),
    );

    let request_id_v = hex::decode(s(inp, "request_id_hex")).expect("request_id hex");
    let mut request_id = [0u8; 32];
    request_id.copy_from_slice(&request_id_v);
    let request_nonce = s(inp, "request_nonce_b64");
    let ssn = s(inp, "server_session_nonce_b64");
    let body = hex::decode(s(inp, "body_hex")).expect("body hex");

    let (mut msg, payload, _) = sign_general(
        &sender,
        &server_id,
        ssn,
        request_nonce,
        &request_id,
        s(inp, "method"),
        s(inp, "path"),
        &body,
    );

    // The freshly built payload equals the locked original_payload_hex.
    assert_eq!(
        hex::encode(&payload),
        s(inp, "original_payload_hex"),
        "original payload reproduces"
    );
    // The deterministic signature equals the locked signature_hex.
    assert_eq!(
        hex::encode(msg.signature.as_ref().expect("sig")),
        s(exp, "signature_hex"),
        "locked signature reproduces"
    );

    // Tamper: flip last payload byte → must equal the locked tampered_payload_hex.
    let p = msg.payload.as_mut().expect("payload");
    let n = p.len();
    p[n - 1] ^= 0xFF;
    assert_eq!(
        hex::encode(p),
        s(inp, "tampered_payload_hex"),
        "tampered payload reproduces locked value"
    );

    let valid_session = server_session(ssn, &sender.identity_key().to_hex(), request_nonce);
    let verifies = verify_message_signature(&server_wallet, &msg, &valid_session).unwrap_or(false);
    assert_eq!(
        verifies,
        exp["verifies"].as_bool().unwrap(),
        "tampering the signed payload must break verification"
    );
}

/// Sanity: the b64 nonces decode to the documented fixed test bytes.
#[test]
fn fixed_nonces_decode_as_documented() {
    let r = root();
    let inp = &r["vectors"][0]["inputs"];
    assert_eq!(
        b32_from_b64(s(inp, "server_session_nonce_b64")),
        [0xA1u8; 32]
    );
    assert_eq!(b32_from_b64(s(inp, "request_nonce_b64")), [0xC3u8; 32]);
}
