//! BRC-100 endpoint handler implementations.
//!
//! Each function in this module corresponds to a single BRC-100 wallet
//! endpoint. The function signatures match what axum expects: they take
//! shared state and a JSON body, and return a JSON response.
//!
//! ## Handler categories
//!
//! ### MPC-routed (require KSS communication)
//!
//! - [`get_public_key`] — Returns the joint MPC public key (or a derived child key).
//! - [`create_signature`] — Initiates a 2PC ECDSA signing ceremony with the KSS.
//! - [`create_action`] — The big one: UTXO selection + tx construction + fee injection + MPC signing + broadcast.
//! - [`internalize_action`] — Accept an incoming payment by internalizing its outputs into the UTXO set.
//!
//! ### Local-only (no MPC rounds)
//!
//! - [`encrypt`] / [`decrypt`] — Symmetric encryption using a locally-derived key (BRC-42).
//! - [`create_hmac`] / [`verify_hmac`] — HMAC-SHA256 with locally-derived key.
//! - [`list_outputs`] / [`list_actions`] — Query the local UTXO tracker and action history.
//! - [`relinquish_output`] — Mark an output as spent/released.
//! - [`verify_signature`] — Pure ECDSA verification (no secret key needed).
//! - [`get_network`] / [`get_version`] / [`is_authenticated`] — Static metadata.
//! - Certificate and discovery endpoints — local storage or overlay forwarding.
//!
//! ## Error handling
//!
//! All handlers return `Json<Value>` to match the bsv-wallet-cli response
//! format. Errors are returned as JSON objects with an `"error"` field,
//! which is what bsv-worm's `wallet.rs` checks for.

use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use axum::extract::State;
use axum::Json;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bsv::primitives::ec::{PublicKey, Signature};
use bsv_mpc_core::hd::{compute_brc42_hmac, compute_invoice, derive_child_pubkey};
use bsv_mpc_core::JointPublicKey;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::Sha256;

use crate::server::AppState;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Parse BRC-42 protocol parameters from a request body.
///
/// Extracts `protocolID` ([level, name]), `keyID`, and `counterparty` from the
/// JSON body. Returns `(security_level, protocol_name, key_id, counterparty)`.
fn parse_protocol_params(body: &Value) -> Result<(u8, String, String, String), String> {
    let protocol_id = body.get("protocolID").ok_or("missing protocolID")?;
    let level = protocol_id
        .get(0)
        .and_then(|v| v.as_u64())
        .ok_or("protocolID[0] must be a number")? as u8;
    let protocol_name = protocol_id
        .get(1)
        .and_then(|v| v.as_str())
        .ok_or("protocolID[1] must be a string")?
        .to_string();
    let key_id = body
        .get("keyID")
        .and_then(|v| v.as_str())
        .ok_or("missing keyID")?
        .to_string();
    let counterparty = body
        .get("counterparty")
        .and_then(|v| v.as_str())
        .unwrap_or("self")
        .to_string();
    Ok((level, protocol_name, key_id, counterparty))
}

/// Derive a 32-byte symmetric key for a given BRC-42 derivation path.
///
/// For "anyone" counterparty: purely local (0 MPC round-trips).
///   shared_secret = root_pubkey, key = HMAC-SHA256(compressed(root_pub), invoice)
///
/// For "self"/"other": requires bridge.partial_ecdh() (not yet implemented).
///   These counterparty types need MPC cooperation to compute the ECDH shared
///   secret, which will be added when bridge.rs is complete.
///
/// Pattern from POC 3 (key derivation) and POC 9 (encrypt/decrypt).
fn derive_symmetric_key(
    joint_key: &JointPublicKey,
    level: u8,
    protocol_name: &str,
    key_id: &str,
    counterparty: &str,
) -> Result<[u8; 32], String> {
    let root_pub = PublicKey::from_bytes(&joint_key.compressed)
        .map_err(|e| format!("invalid joint key: {}", e))?;
    let invoice = compute_invoice(level, protocol_name, key_id);

    match counterparty {
        "anyone" => {
            // For "anyone": shared_secret = root_pubkey (0 round-trips).
            // The "anyone" counterparty private key is scalar 1, so
            // ECDH(anyone_pub, root_priv) = G * root_priv = root_pubkey.
            // Proven in POC 3, Test 1.
            Ok(compute_brc42_hmac(&root_pub, &invoice))
        }
        "self" => {
            // TODO: needs bridge.partial_ecdh() — will be added when bridge.rs is done.
            // For "self": shared_secret = ECDH(root_pub, root_priv) requires MPC cooperation.
            // Algorithm (from POC 9): 2 partial ECDH rounds with Lagrange interpolation.
            Err(
                "counterparty 'self' requires bridge.partial_ecdh() — not yet implemented"
                    .to_string(),
            )
        }
        _ => {
            // Counterparty is a hex public key ("other" case).
            // TODO: needs bridge.partial_ecdh() — will be added when bridge.rs is done.
            // For "other(pk)": shared_secret = ECDH(other_pub, root_priv) requires MPC cooperation.
            Err(format!(
                "counterparty '{}' requires bridge.partial_ecdh() — not yet implemented",
                counterparty
            ))
        }
    }
}

/// Derive the expected BRC-42 child public key for signature verification.
///
/// `for_self=true`:  child = root_pub + G * HMAC(shared_secret, invoice)
/// `for_self=false`: child = counterparty_pub + G * HMAC(shared_secret, invoice)
///
/// For "anyone" counterparty, both paths are local. For "self"/"other",
/// shared_secret computation requires bridge.partial_ecdh().
fn derive_verification_pubkey(
    joint_key: &JointPublicKey,
    level: u8,
    protocol_name: &str,
    key_id: &str,
    counterparty: &str,
    for_self: bool,
) -> Result<PublicKey, String> {
    let root_pub = PublicKey::from_bytes(&joint_key.compressed)
        .map_err(|e| format!("invalid joint key: {}", e))?;
    let invoice = compute_invoice(level, protocol_name, key_id);

    match counterparty {
        "anyone" => {
            // For "anyone": shared_secret = root_pubkey (no MPC needed)
            if for_self {
                // child = root_pub + G * HMAC(root_pub, invoice)
                derive_child_pubkey(&root_pub, &root_pub, &invoice)
                    .map_err(|e| format!("key derivation failed: {}", e))
            } else {
                // child = anyone_pub + G * HMAC(root_pub, invoice)
                // anyone_pub = G (generator, private key = 1)
                let mut one = [0u8; 32];
                one[31] = 1;
                let anyone_pub = PublicKey::from_scalar_mul_generator(&one)
                    .map_err(|e| format!("generator failed: {}", e))?;
                derive_child_pubkey(&anyone_pub, &root_pub, &invoice)
                    .map_err(|e| format!("key derivation failed: {}", e))
            }
        }
        "self" => Err(
            "counterparty 'self' requires bridge.partial_ecdh() — not yet implemented".to_string(),
        ),
        _ => Err(format!(
            "counterparty '{}' requires bridge.partial_ecdh() — not yet implemented",
            counterparty
        )),
    }
}

// ─── Core signing (MPC) ─────────────────────────────────────────────────────

/// `POST /getPublicKey`
///
/// Returns the joint MPC public key, or a BRC-42 derived child key if
/// `protocolID` and `keyID` are specified in the request.
///
/// ## Request fields
///
/// - `identityKey` (bool) — If true, return the root identity key (no derivation).
/// - `protocolID` (array) — BRC-42 protocol identifier, e.g. `[2, "worm memory"]`.
/// - `keyID` (string) — Key identifier within the protocol.
/// - `counterparty` (string) — Counterparty public key or `"self"`.
/// - `forSelf` (bool) — Derive for self-encryption.
///
/// ## Response
///
/// ```json
/// { "publicKey": "02abc...def" }
/// ```
///
/// ## MPC involvement
///
/// For `identityKey: true`, returns the cached joint public key (no KSS call).
/// For derived keys with "anyone" counterparty, derives locally using BRC-42.
/// For "self"/"other" counterparties, needs bridge.partial_ecdh() (not yet implemented).
pub async fn get_public_key(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    // TODO: depends on bridge.rs for full implementation.
    // - identityKey: true → return state.bridge.joint_public_key() as hex
    // - "anyone" counterparty → derive_anyone_pubkey (local, no MPC)
    // - "self"/"other" → needs bridge.partial_ecdh()
    // See GitHub issue #15.
    todo!(
        "getPublicKey depends on bridge.rs — see issue #15.\n\
         1. If body.identityKey is true, return state.bridge.joint_public_key() as hex\n\
         2. Otherwise, extract protocolID, keyID, counterparty from body\n\
         3. For 'anyone': derive_anyone_pubkey (local, 0 round-trips)\n\
         4. For 'self'/'other': bridge.partial_ecdh() then derive_child_pubkey\n\
         5. Return {{ \"publicKey\": \"<hex>\" }}"
    )
}

/// `POST /createSignature`
///
/// Signs a message hash using the 2-party CGGMP'24 threshold ECDSA protocol.
/// This is the core MPC operation — it requires communication with the KSS.
///
/// ## Request fields
///
/// - `data` (string, hex) — The data to sign (typically a sighash).
/// - `protocolID` (array) — BRC-42 protocol for key derivation.
/// - `keyID` (string) — Key identifier for derivation.
/// - `counterparty` (string) — Counterparty for key derivation.
///
/// ## Response
///
/// ```json
/// { "signature": "3044..." }
/// ```
///
/// ## MPC flow
///
/// 1. Check presignature pool — if available, use single-round online signing.
/// 2. Otherwise, run the full 4-round interactive protocol with the KSS.
/// 3. Return the DER-encoded ECDSA signature.
///
/// Presignature signing takes ~50-100ms. Full protocol takes ~300-500ms.
pub async fn create_signature(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse data, protocolID, keyID, counterparty from body\n\
         2. Compute message hash (SHA-256 of data if not already 32 bytes)\n\
         3. Derive child share using BRC-42 derivation path\n\
         4. Try to take a presignature from the pool\n\
         5. Call state.bridge.sign(hash, presignature) for 2PC with KSS\n\
         6. Return {{ \"signature\": \"<DER hex>\" }}"
    )
}

/// `POST /verifySignature`
///
/// Verify an ECDSA signature against a BRC-42 derived public key. This is a
/// purely local operation — no MPC rounds or KSS communication needed.
///
/// For "anyone" counterparty: fully implemented (local key derivation).
/// For "self"/"other": requires bridge.partial_ecdh() (returns error).
///
/// ## Request fields
///
/// - `data` (string, hex) — The 32-byte message hash that was signed.
/// - `signature` (string, hex) — DER-encoded ECDSA signature.
/// - `protocolID` (array) — BRC-42 protocol for key derivation.
/// - `keyID` (string) — Key identifier.
/// - `counterparty` (string) — Counterparty: `"anyone"`, `"self"`, or hex pubkey.
/// - `forSelf` (bool) — Whether the signature was made by us (true) or the counterparty (false).
///
/// ## Response
///
/// ```json
/// { "valid": true }
/// ```
pub async fn verify_signature(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    // Parse protocol params
    let (level, protocol_name, key_id, counterparty) = match parse_protocol_params(&body) {
        Ok(params) => params,
        Err(e) => return Json(json!({ "error": e })),
    };

    // Parse data (hex-encoded 32-byte hash)
    let data_hex = match body.get("data").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Json(json!({ "error": "missing data" })),
    };
    let data_bytes = match hex::decode(data_hex) {
        Ok(bytes) => bytes,
        Err(e) => return Json(json!({ "error": format!("invalid hex data: {}", e) })),
    };
    if data_bytes.len() != 32 {
        return Json(json!({ "error": format!("data must be 32 bytes, got {}", data_bytes.len()) }));
    }
    let mut msg_hash = [0u8; 32];
    msg_hash.copy_from_slice(&data_bytes);

    // Parse DER signature
    let sig_hex = match body.get("signature").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Json(json!({ "error": "missing signature" })),
    };
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(bytes) => bytes,
        Err(e) => return Json(json!({ "error": format!("invalid hex signature: {}", e) })),
    };
    let signature = match Signature::from_der(&sig_bytes) {
        Ok(sig) => sig,
        Err(e) => return Json(json!({ "error": format!("invalid DER signature: {}", e) })),
    };

    let for_self = body
        .get("forSelf")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // Derive the expected public key via BRC-42
    let pubkey = match derive_verification_pubkey(
        state.bridge.joint_public_key(),
        level,
        &protocol_name,
        &key_id,
        &counterparty,
        for_self,
    ) {
        Ok(pk) => pk,
        Err(e) => return Json(json!({ "error": e })),
    };

    let valid = pubkey.verify(&msg_hash, &signature);
    Json(json!({ "valid": valid }))
}

/// `POST /createAction`
///
/// The primary transaction-building endpoint. This is what bsv-worm calls for
/// every on-chain operation: creating proofs, state tokens, payments, etc.
///
/// ## Processing pipeline
///
/// 1. **UTXO selection**: Select inputs from the local UTXO set matching the request.
/// 2. **Transaction construction**: Build the unsigned transaction with requested outputs.
/// 3. **Fee injection**: If enabled, add MPC signing fee output via `FeeInjector`.
/// 4. **Fee calculation**: Compute miner fee based on transaction size.
/// 5. **Change output**: Add change output if needed.
/// 6. **MPC signing**: For each input, derive the child key and run 2PC signing with KSS.
/// 7. **Broadcast**: Submit the signed transaction to the BSV network.
/// 8. **UTXO update**: Mark spent inputs, add new outputs to the local tracker.
pub async fn create_action(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse description, inputs, outputs, labels, options from body\n\
         2. Select UTXOs from local tracker for inputs\n\
         3. Build unsigned transaction with requested outputs\n\
         4. If fee_injector.is_enabled(), add MPC fee output\n\
         5. Calculate miner fee, add change output if needed\n\
         6. For each input:\n\
            a. Derive child share using BRC-42 derivation from input's protocolID/keyID\n\
            b. Compute sighash for this input\n\
            c. Try to take a presignature from the pool\n\
            d. Call bridge.sign(sighash, presignature) for 2PC with KSS\n\
            e. Apply signature to transaction input\n\
         7. Serialize signed transaction\n\
         8. Broadcast to BSV network\n\
         9. Update local UTXO set (mark spent inputs, track new outputs)\n\
         10. Return txid, rawTx, outputMap"
    )
}

/// `POST /internalizeAction`
///
/// Accept an incoming payment or BEEF envelope by internalizing its outputs
/// into the local UTXO set.
pub async fn internalize_action(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse tx (rawTx or BEEF), outputs, description, labels from body\n\
         2. Deserialize and validate the transaction\n\
         3. For each output to internalize:\n\
            a. Verify the locking script pays to a key we control\n\
            b. Derive the expected public key using BRC-42 derivation\n\
            c. Check script matches P2PKH of derived key\n\
         4. Add verified outputs to local UTXO tracker with baskets/tags\n\
         5. Return {{ \"accepted\": true, \"txid\": \"...\" }}"
    )
}

// ─── Encryption (local) ─────────────────────────────────────────────────────

/// `POST /encrypt`
///
/// Encrypt data using a BRC-42 derived symmetric key and AES-256-GCM.
///
/// For "anyone" counterparty: fully implemented (0 MPC round-trips).
/// For "self"/"other": requires bridge.partial_ecdh() (returns error).
///
/// ## Request fields
///
/// - `plaintext` (string, base64) — Data to encrypt.
/// - `protocolID` (array) — BRC-42 protocol for key derivation, e.g. `[2, "worm memory"]`.
/// - `keyID` (string) — Key identifier within the protocol.
/// - `counterparty` (string) — `"anyone"`, `"self"`, or hex public key.
///
/// ## Response
///
/// ```json
/// { "ciphertext": "<base64(nonce || ciphertext || tag)>" }
/// ```
///
/// ## Encryption format
///
/// Output is `nonce (12 bytes) || AES-GCM ciphertext || auth tag (16 bytes)`,
/// base64-encoded. The nonce is randomly generated per encryption.
pub async fn encrypt(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let (level, protocol_name, key_id, counterparty) = match parse_protocol_params(&body) {
        Ok(params) => params,
        Err(e) => return Json(json!({ "error": e })),
    };

    let plaintext_b64 = match body.get("plaintext").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Json(json!({ "error": "missing plaintext" })),
    };
    let plaintext = match BASE64.decode(plaintext_b64) {
        Ok(bytes) => bytes,
        Err(e) => return Json(json!({ "error": format!("invalid base64 plaintext: {}", e) })),
    };

    // Derive 32-byte symmetric key via BRC-42
    let sym_key = match derive_symmetric_key(
        state.bridge.joint_public_key(),
        level,
        &protocol_name,
        &key_id,
        &counterparty,
    ) {
        Ok(key) => key,
        Err(e) => return Json(json!({ "error": e })),
    };

    // AES-256-GCM encrypt with random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sym_key));

    let ciphertext = match cipher.encrypt(nonce, plaintext.as_ref()) {
        Ok(ct) => ct,
        Err(e) => return Json(json!({ "error": format!("encryption failed: {}", e) })),
    };

    // Output: nonce (12) || ciphertext || tag (16)
    // aes-gcm appends the 16-byte auth tag to ciphertext automatically
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Json(json!({ "ciphertext": BASE64.encode(&result) }))
}

/// `POST /decrypt`
///
/// Decrypt data using a BRC-42 derived symmetric key and AES-256-GCM.
/// Inverse of [`encrypt`].
///
/// For "anyone" counterparty: fully implemented (0 MPC round-trips).
/// For "self"/"other": requires bridge.partial_ecdh() (returns error).
///
/// ## Request fields
///
/// - `ciphertext` (string, base64) — `nonce (12) || ciphertext || tag (16)`.
/// - `protocolID` (array) — BRC-42 protocol for key derivation.
/// - `keyID` (string) — Key identifier.
/// - `counterparty` (string) — `"anyone"`, `"self"`, or hex public key.
///
/// ## Response
///
/// ```json
/// { "plaintext": "<base64>" }
/// ```
pub async fn decrypt(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let (level, protocol_name, key_id, counterparty) = match parse_protocol_params(&body) {
        Ok(params) => params,
        Err(e) => return Json(json!({ "error": e })),
    };

    let ciphertext_b64 = match body.get("ciphertext").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Json(json!({ "error": "missing ciphertext" })),
    };
    let data = match BASE64.decode(ciphertext_b64) {
        Ok(bytes) => bytes,
        Err(e) => return Json(json!({ "error": format!("invalid base64 ciphertext: {}", e) })),
    };

    // Minimum: 12 (nonce) + 16 (GCM tag) = 28 bytes
    if data.len() < 28 {
        return Json(json!({ "error": "ciphertext too short (need at least 28 bytes for nonce + tag)" }));
    }

    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    // Derive same symmetric key
    let sym_key = match derive_symmetric_key(
        state.bridge.joint_public_key(),
        level,
        &protocol_name,
        &key_id,
        &counterparty,
    ) {
        Ok(key) => key,
        Err(e) => return Json(json!({ "error": e })),
    };

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sym_key));

    let plaintext = match cipher.decrypt(nonce, ciphertext) {
        Ok(pt) => pt,
        Err(e) => return Json(json!({ "error": format!("decryption failed: {}", e) })),
    };

    Json(json!({ "plaintext": BASE64.encode(&plaintext) }))
}

/// `POST /createHmac`
///
/// Compute HMAC-SHA256 using a BRC-42 derived key.
///
/// For "anyone" counterparty: fully implemented (0 MPC round-trips).
/// For "self"/"other": requires bridge.partial_ecdh() (returns error).
///
/// ## Request fields
///
/// - `data` (string, base64) — Data to HMAC.
/// - `protocolID` (array) — BRC-42 protocol for key derivation.
/// - `keyID` (string) — Key identifier.
/// - `counterparty` (string) — `"anyone"`, `"self"`, or hex public key.
///
/// ## Response
///
/// ```json
/// { "hmac": "<hex>" }
/// ```
pub async fn create_hmac(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let (level, protocol_name, key_id, counterparty) = match parse_protocol_params(&body) {
        Ok(params) => params,
        Err(e) => return Json(json!({ "error": e })),
    };

    let data_b64 = match body.get("data").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Json(json!({ "error": "missing data" })),
    };
    let data = match BASE64.decode(data_b64) {
        Ok(bytes) => bytes,
        Err(e) => return Json(json!({ "error": format!("invalid base64 data: {}", e) })),
    };

    // Derive HMAC key via BRC-42 (same derivation path as encrypt/decrypt)
    let hmac_key = match derive_symmetric_key(
        state.bridge.joint_public_key(),
        level,
        &protocol_name,
        &key_id,
        &counterparty,
    ) {
        Ok(key) => key,
        Err(e) => return Json(json!({ "error": e })),
    };

    // HMAC-SHA256
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(&data);
    let result = mac.finalize();

    Json(json!({ "hmac": hex::encode(result.into_bytes()) }))
}

/// `POST /verifyHmac`
///
/// Verify an HMAC-SHA256 against a BRC-42 derived key.
/// Uses constant-time comparison to prevent timing attacks.
///
/// For "anyone" counterparty: fully implemented (0 MPC round-trips).
/// For "self"/"other": requires bridge.partial_ecdh() (returns error).
///
/// ## Request fields
///
/// - `data` (string, base64) — Original data.
/// - `hmac` (string, hex) — HMAC to verify.
/// - `protocolID` (array) — BRC-42 protocol for key derivation.
/// - `keyID` (string) — Key identifier.
/// - `counterparty` (string) — `"anyone"`, `"self"`, or hex public key.
///
/// ## Response
///
/// ```json
/// { "valid": true }
/// ```
pub async fn verify_hmac(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let (level, protocol_name, key_id, counterparty) = match parse_protocol_params(&body) {
        Ok(params) => params,
        Err(e) => return Json(json!({ "error": e })),
    };

    let data_b64 = match body.get("data").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Json(json!({ "error": "missing data" })),
    };
    let hmac_hex = match body.get("hmac").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Json(json!({ "error": "missing hmac" })),
    };

    let data = match BASE64.decode(data_b64) {
        Ok(bytes) => bytes,
        Err(e) => return Json(json!({ "error": format!("invalid base64 data: {}", e) })),
    };
    let expected_hmac = match hex::decode(hmac_hex) {
        Ok(bytes) => bytes,
        Err(e) => return Json(json!({ "error": format!("invalid hex hmac: {}", e) })),
    };

    // Derive HMAC key
    let hmac_key = match derive_symmetric_key(
        state.bridge.joint_public_key(),
        level,
        &protocol_name,
        &key_id,
        &counterparty,
    ) {
        Ok(key) => key,
        Err(e) => return Json(json!({ "error": e })),
    };

    // Compute HMAC and verify with constant-time comparison
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(&data);

    // verify_slice uses constant-time comparison (from subtle crate)
    let valid = mac.verify_slice(&expected_hmac).is_ok();

    Json(json!({ "valid": valid }))
}

// ─── UTXO management ────────────────────────────────────────────────────────

/// `POST /listOutputs`
///
/// Query the local UTXO set. Supports filtering by basket (BRC-46), tags,
/// and spending status.
pub async fn list_outputs(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let basket = body["basket"].as_str();
    let tags: Option<Vec<String>> = body["tags"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect());
    let include_locking_scripts = body["include"].as_str() == Some("locking scripts");
    let limit = body["limit"].as_u64().unwrap_or(100) as usize;
    let offset = body["offset"].as_u64().unwrap_or(0) as usize;

    let tracker = state.utxo_tracker.read().await;
    let unspent = tracker.list_unspent(basket, tags.as_deref());

    let total = unspent.len();

    let page: Vec<Value> = unspent
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|o| {
            let mut entry = json!({
                "outpoint": o.outpoint(),
                "satoshis": o.satoshis,
                "spendable": true,
            });
            if let Some(b) = &o.basket {
                entry["basket"] = json!(b);
            }
            if !o.tags.is_empty() {
                entry["tags"] = json!(o.tags);
            }
            if include_locking_scripts {
                entry["lockingScript"] = json!(hex::encode(&o.locking_script));
            }
            entry
        })
        .collect();

    Json(json!({
        "totalOutputs": total,
        "outputs": page,
    }))
}

/// `POST /listActions`
///
/// Query the action (transaction) history.
pub async fn list_actions(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse labels, labelQueryMode, include flags, limit, offset from body\n\
         2. Query local action history with filters\n\
         3. Optionally include inputs/outputs/labels per action\n\
         4. Return {{ \"totalActions\": N, \"actions\": [...] }}"
    )
}

/// `POST /relinquishOutput`
///
/// Mark an output as relinquished (no longer tracked).
pub async fn relinquish_output(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse basket and output (outpoint) from body\n\
         2. Find the output in the local UTXO tracker\n\
         3. Mark it as relinquished / remove from tracker\n\
         4. Return {{ \"relinquished\": true }}"
    )
}

// ─── Identity & auth ────────────────────────────────────────────────────────

/// `POST /getNetwork`
///
/// Returns the BSV network this proxy operates on.
pub async fn get_network(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    // Static response — MPC proxy always operates on mainnet.
    Json(json!({ "network": "mainnet" }))
}

/// `POST /getVersion`
///
/// Returns the proxy version, presenting itself as a BRC-100 wallet.
pub async fn get_version(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    Json(json!({
        "version": format!("bsv-mpc-proxy {}", env!("CARGO_PKG_VERSION"))
    }))
}

/// `POST /isAuthenticated`
///
/// Returns whether the proxy is initialized and ready to sign.
pub async fn is_authenticated(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    // If we got this far, the share is loaded and the bridge is initialized.
    Json(json!({ "authenticated": true }))
}

// ─── Certificates ───────────────────────────────────────────────────────────

/// `POST /listCertificates`
pub async fn list_certificates(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse certifiers, types, limit, offset from body\n\
         2. Query local certificate store with filters\n\
         3. Return {{ \"totalCertificates\": N, \"certificates\": [...] }}"
    )
}

/// `POST /proveCertificate`
pub async fn prove_certificate(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse certificate, fieldsToReveal, verifier from body\n\
         2. For each field to reveal, derive the field-specific encryption key\n\
         3. Create keyring entries that let the verifier decrypt those fields\n\
         4. Return {{ \"keyringForVerifier\": {{...}} }}"
    )
}

/// `POST /acquireCertificate`
pub async fn acquire_certificate(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse type, certifier, fields, acquisitionProtocol from body\n\
         2. If direct: store certificate locally with encrypted fields\n\
         3. If issuance: contact certifier to obtain signed certificate\n\
         4. Encrypt field values using BRC-42 derived keys\n\
         5. Store in local certificate store\n\
         6. Return the acquired certificate"
    )
}

/// `POST /relinquishCertificate`
pub async fn relinquish_certificate(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse type, certifier, serialNumber from body\n\
         2. Find the certificate in local store\n\
         3. Remove it\n\
         4. Return empty object (bsv-wallet-cli returns empty body)"
    )
}

// ─── Discovery ──────────────────────────────────────────────────────────────

/// `POST /discoverByIdentityKey`
pub async fn discover_by_identity_key(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse identityKey from body\n\
         2. Forward discovery request to overlay network\n\
         3. Return matching certificates"
    )
}

/// `POST /discoverByAttributes`
pub async fn discover_by_attributes(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse attributes from body\n\
         2. Forward discovery request to overlay network\n\
         3. Return matching certificates"
    )
}

// ─── Key linkage ────────────────────────────────────────────────────────────

/// `POST /revealCounterpartyKeyLinkage`
pub async fn reveal_counterparty_key_linkage(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse counterparty, verifier, protocolID, keyID from body\n\
         2. Derive the counterparty linkage key from local share\n\
         3. Encrypt the linkage key for the verifier\n\
         4. Return revelation keyring"
    )
}

/// `POST /revealSpecificKeyLinkage`
pub async fn reveal_specific_key_linkage(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse counterparty, verifier, protocolID, keyID from body\n\
         2. Derive the specific key linkage from local share\n\
         3. Encrypt for the verifier\n\
         4. Return revelation keyring"
    )
}

// ─── Health ─────────────────────────────────────────────────────────────────

/// `GET /health`
///
/// Liveness check for load balancers, monitoring systems, and bsv-worm's
/// startup health check.
pub async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    let presig_count = state.presign_manager.read().await.len();

    Json(json!({
        "status": "ok",
        "version": format!("bsv-mpc-proxy {}", env!("CARGO_PKG_VERSION")),
        "presignatures_available": presig_count,
        "kss_url": state.config.kss_url,
        "fee_per_signing_sats": state.config.fee_per_signing,
    }))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::MpcBridge;
    use crate::fee_injector::FeeInjector;
    use crate::presign_manager::PresignManager;
    use crate::utxo_tracker::UtxoTracker;
    use bsv::primitives::ec::PrivateKey;
    use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};
    use tokio::sync::RwLock;

    /// Same test key as POC 3 / POC 9 / hd.rs tests.
    const TEST_KEY_BYTES: [u8; 32] = [
        0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1,
        0xe2, 0xf3, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
        0xd0, 0xe1, 0xf2, 0x03,
    ];

    fn test_joint_key() -> JointPublicKey {
        let privkey = PrivateKey::from_bytes(&TEST_KEY_BYTES).expect("valid key");
        let pubkey = privkey.public_key();
        JointPublicKey {
            compressed: pubkey.to_compressed().to_vec(),
            address: "1TestAddress".to_string(),
        }
    }

    fn test_state() -> Arc<AppState> {
        let config = crate::config::ProxyConfig::from_env().unwrap();
        let bridge = MpcBridge::new_for_test(test_joint_key());
        Arc::new(AppState {
            config,
            bridge,
            presign_manager: Arc::new(RwLock::new(PresignManager::new(20))),
            fee_injector: FeeInjector::new(0, vec![], None),
            utxo_tracker: Arc::new(RwLock::new(UtxoTracker::new())),
        })
    }

    // ── Helper tests ────────────────────────────────────────────────────

    #[test]
    fn test_parse_protocol_params_valid() {
        let body = json!({
            "protocolID": [2, "worm memory"],
            "keyID": "block-42",
            "counterparty": "anyone"
        });
        let (level, proto, key_id, cp) = parse_protocol_params(&body).unwrap();
        assert_eq!(level, 2);
        assert_eq!(proto, "worm memory");
        assert_eq!(key_id, "block-42");
        assert_eq!(cp, "anyone");
    }

    #[test]
    fn test_parse_protocol_params_missing_protocol_id() {
        let body = json!({ "keyID": "k" });
        assert!(parse_protocol_params(&body).is_err());
    }

    #[test]
    fn test_parse_protocol_params_defaults_counterparty_to_self() {
        let body = json!({
            "protocolID": [2, "test"],
            "keyID": "k"
        });
        let (_, _, _, cp) = parse_protocol_params(&body).unwrap();
        assert_eq!(cp, "self");
    }

    #[test]
    fn test_derive_symmetric_key_anyone() {
        let jk = test_joint_key();
        let key = derive_symmetric_key(&jk, 2, "test-proto", "key1", "anyone").unwrap();
        assert_eq!(key.len(), 32);
        assert_ne!(key, [0u8; 32], "key should not be all zeros");
    }

    #[test]
    fn test_derive_symmetric_key_deterministic() {
        let jk = test_joint_key();
        let k1 = derive_symmetric_key(&jk, 2, "test-proto", "key1", "anyone").unwrap();
        let k2 = derive_symmetric_key(&jk, 2, "test-proto", "key1", "anyone").unwrap();
        assert_eq!(k1, k2, "same inputs must produce same key");
    }

    #[test]
    fn test_derive_symmetric_key_different_invoices() {
        let jk = test_joint_key();
        let k1 = derive_symmetric_key(&jk, 2, "test-proto", "key1", "anyone").unwrap();
        let k2 = derive_symmetric_key(&jk, 2, "test-proto", "key2", "anyone").unwrap();
        assert_ne!(k1, k2, "different key IDs must produce different keys");
    }

    #[test]
    fn test_derive_symmetric_key_self_returns_error() {
        let jk = test_joint_key();
        let result = derive_symmetric_key(&jk, 2, "test-proto", "key1", "self");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("bridge.partial_ecdh()"));
    }

    #[test]
    fn test_derive_symmetric_key_other_returns_error() {
        let jk = test_joint_key();
        let result = derive_symmetric_key(&jk, 2, "test-proto", "key1", "02abcd");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("bridge.partial_ecdh()"));
    }

    // ── Encrypt / Decrypt handler tests ─────────────────────────────────

    #[tokio::test]
    async fn test_encrypt_decrypt_round_trip_anyone() {
        let state = test_state();
        let plaintext = "Hello, MPC world!";
        let plaintext_b64 = BASE64.encode(plaintext.as_bytes());

        // Encrypt
        let encrypt_body = json!({
            "plaintext": plaintext_b64,
            "protocolID": [2, "test-proto"],
            "keyID": "test-key",
            "counterparty": "anyone"
        });
        let Json(enc_resp) = encrypt(State(state.clone()), Json(encrypt_body)).await;
        assert!(enc_resp.get("error").is_none(), "encrypt should succeed: {:?}", enc_resp);
        let ciphertext_b64 = enc_resp["ciphertext"].as_str().unwrap();

        // Verify ciphertext is different from plaintext
        assert_ne!(ciphertext_b64, plaintext_b64);

        // Decrypt
        let decrypt_body = json!({
            "ciphertext": ciphertext_b64,
            "protocolID": [2, "test-proto"],
            "keyID": "test-key",
            "counterparty": "anyone"
        });
        let Json(dec_resp) = decrypt(State(state.clone()), Json(decrypt_body)).await;
        assert!(dec_resp.get("error").is_none(), "decrypt should succeed: {:?}", dec_resp);
        let result_b64 = dec_resp["plaintext"].as_str().unwrap();
        let result = BASE64.decode(result_b64).unwrap();
        assert_eq!(result, plaintext.as_bytes());
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_empty_plaintext() {
        let state = test_state();
        let plaintext_b64 = BASE64.encode(b"");

        let encrypt_body = json!({
            "plaintext": plaintext_b64,
            "protocolID": [2, "test"],
            "keyID": "empty",
            "counterparty": "anyone"
        });
        let Json(enc_resp) = encrypt(State(state.clone()), Json(encrypt_body)).await;
        assert!(enc_resp.get("error").is_none());

        let decrypt_body = json!({
            "ciphertext": enc_resp["ciphertext"].as_str().unwrap(),
            "protocolID": [2, "test"],
            "keyID": "empty",
            "counterparty": "anyone"
        });
        let Json(dec_resp) = decrypt(State(state.clone()), Json(decrypt_body)).await;
        assert!(dec_resp.get("error").is_none());
        let result = BASE64.decode(dec_resp["plaintext"].as_str().unwrap()).unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_encrypt_produces_different_ciphertexts() {
        let state = test_state();
        let plaintext_b64 = BASE64.encode(b"same data");

        let body = json!({
            "plaintext": plaintext_b64,
            "protocolID": [2, "test"],
            "keyID": "k",
            "counterparty": "anyone"
        });
        let Json(r1) = encrypt(State(state.clone()), Json(body.clone())).await;
        let Json(r2) = encrypt(State(state.clone()), Json(body)).await;
        // Different random nonces should produce different ciphertexts
        assert_ne!(
            r1["ciphertext"].as_str().unwrap(),
            r2["ciphertext"].as_str().unwrap()
        );
    }

    #[tokio::test]
    async fn test_decrypt_wrong_key_fails() {
        let state = test_state();
        let plaintext_b64 = BASE64.encode(b"secret");

        // Encrypt with key "k1"
        let enc_body = json!({
            "plaintext": plaintext_b64,
            "protocolID": [2, "test"],
            "keyID": "k1",
            "counterparty": "anyone"
        });
        let Json(enc_resp) = encrypt(State(state.clone()), Json(enc_body)).await;

        // Decrypt with key "k2" — should fail (different derived key)
        let dec_body = json!({
            "ciphertext": enc_resp["ciphertext"].as_str().unwrap(),
            "protocolID": [2, "test"],
            "keyID": "k2",
            "counterparty": "anyone"
        });
        let Json(dec_resp) = decrypt(State(state.clone()), Json(dec_body)).await;
        assert!(dec_resp.get("error").is_some(), "wrong key should fail decryption");
    }

    #[tokio::test]
    async fn test_decrypt_short_ciphertext_rejected() {
        let state = test_state();
        // Less than 28 bytes (12 nonce + 16 tag)
        let short_ct = BASE64.encode(&[0u8; 20]);
        let body = json!({
            "ciphertext": short_ct,
            "protocolID": [2, "test"],
            "keyID": "k",
            "counterparty": "anyone"
        });
        let Json(resp) = decrypt(State(state), Json(body)).await;
        assert!(resp.get("error").is_some());
    }

    #[tokio::test]
    async fn test_encrypt_self_counterparty_returns_error() {
        let state = test_state();
        let body = json!({
            "plaintext": BASE64.encode(b"test"),
            "protocolID": [2, "worm memory"],
            "keyID": "block-1",
            "counterparty": "self"
        });
        let Json(resp) = encrypt(State(state), Json(body)).await;
        assert!(resp.get("error").is_some());
        assert!(resp["error"].as_str().unwrap().contains("partial_ecdh"));
    }

    // ── HMAC handler tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_hmac_anyone() {
        let state = test_state();
        let data_b64 = BASE64.encode(b"hello world");

        let body = json!({
            "data": data_b64,
            "protocolID": [2, "test-proto"],
            "keyID": "hmac-key",
            "counterparty": "anyone"
        });
        let Json(resp) = create_hmac(State(state), Json(body)).await;
        assert!(resp.get("error").is_none(), "create_hmac should succeed: {:?}", resp);
        let hmac_hex = resp["hmac"].as_str().unwrap();
        assert_eq!(hmac_hex.len(), 64, "HMAC-SHA256 should be 32 bytes = 64 hex chars");
    }

    #[tokio::test]
    async fn test_create_hmac_deterministic() {
        let state = test_state();
        let data_b64 = BASE64.encode(b"deterministic");

        let body = json!({
            "data": data_b64,
            "protocolID": [2, "test"],
            "keyID": "k",
            "counterparty": "anyone"
        });
        let Json(r1) = create_hmac(State(state.clone()), Json(body.clone())).await;
        let Json(r2) = create_hmac(State(state), Json(body)).await;
        assert_eq!(r1["hmac"], r2["hmac"], "same inputs must produce same HMAC");
    }

    #[tokio::test]
    async fn test_verify_hmac_valid() {
        let state = test_state();
        let data_b64 = BASE64.encode(b"verify me");

        // Create HMAC
        let create_body = json!({
            "data": data_b64,
            "protocolID": [2, "test"],
            "keyID": "verify-key",
            "counterparty": "anyone"
        });
        let Json(create_resp) = create_hmac(State(state.clone()), Json(create_body)).await;
        let hmac_hex = create_resp["hmac"].as_str().unwrap();

        // Verify HMAC
        let verify_body = json!({
            "data": data_b64,
            "hmac": hmac_hex,
            "protocolID": [2, "test"],
            "keyID": "verify-key",
            "counterparty": "anyone"
        });
        let Json(verify_resp) = verify_hmac(State(state), Json(verify_body)).await;
        assert!(verify_resp.get("error").is_none());
        assert_eq!(verify_resp["valid"], true);
    }

    #[tokio::test]
    async fn test_verify_hmac_invalid() {
        let state = test_state();
        let data_b64 = BASE64.encode(b"data");

        let body = json!({
            "data": data_b64,
            "hmac": "0000000000000000000000000000000000000000000000000000000000000000",
            "protocolID": [2, "test"],
            "keyID": "k",
            "counterparty": "anyone"
        });
        let Json(resp) = verify_hmac(State(state), Json(body)).await;
        assert!(resp.get("error").is_none());
        assert_eq!(resp["valid"], false);
    }

    #[tokio::test]
    async fn test_verify_hmac_wrong_data() {
        let state = test_state();

        // Create HMAC for "original"
        let create_body = json!({
            "data": BASE64.encode(b"original"),
            "protocolID": [2, "test"],
            "keyID": "k",
            "counterparty": "anyone"
        });
        let Json(create_resp) = create_hmac(State(state.clone()), Json(create_body)).await;
        let hmac_hex = create_resp["hmac"].as_str().unwrap();

        // Verify with "tampered" — should fail
        let verify_body = json!({
            "data": BASE64.encode(b"tampered"),
            "hmac": hmac_hex,
            "protocolID": [2, "test"],
            "keyID": "k",
            "counterparty": "anyone"
        });
        let Json(resp) = verify_hmac(State(state), Json(verify_body)).await;
        assert_eq!(resp["valid"], false);
    }

    // ── Verify signature handler tests ──────────────────────────────────

    #[tokio::test]
    async fn test_verify_signature_valid_anyone() {
        let state = test_state();

        // Use KeyDeriver to get the child private key for "anyone" counterparty
        let privkey = PrivateKey::from_bytes(&TEST_KEY_BYTES).unwrap();
        let deriver = KeyDeriver::new(Some(privkey));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "test sig");
        let child_priv = deriver
            .derive_private_key(&protocol, "sig-key", &Counterparty::Anyone)
            .expect("derivation should work");

        // Sign a message hash
        let msg_hash = [0x42u8; 32];
        let signature = child_priv.sign(&msg_hash).expect("signing should work");

        let body = json!({
            "data": hex::encode(msg_hash),
            "signature": hex::encode(signature.to_der()),
            "protocolID": [2, "test sig"],
            "keyID": "sig-key",
            "counterparty": "anyone",
            "forSelf": true
        });
        let Json(resp) = verify_signature(State(state), Json(body)).await;
        assert!(resp.get("error").is_none(), "verify should succeed: {:?}", resp);
        assert_eq!(resp["valid"], true);
    }

    #[tokio::test]
    async fn test_verify_signature_invalid_anyone() {
        let state = test_state();

        // Sign with a random key (not derived from root)
        let random_key = PrivateKey::from_bytes(&[0xAAu8; 32]).unwrap();
        let msg_hash = [0x42u8; 32];
        let signature = random_key.sign(&msg_hash).unwrap();

        let body = json!({
            "data": hex::encode(msg_hash),
            "signature": hex::encode(signature.to_der()),
            "protocolID": [2, "test sig"],
            "keyID": "sig-key",
            "counterparty": "anyone",
            "forSelf": true
        });
        let Json(resp) = verify_signature(State(state), Json(body)).await;
        assert!(resp.get("error").is_none());
        assert_eq!(resp["valid"], false);
    }

    #[tokio::test]
    async fn test_verify_signature_self_returns_error() {
        let state = test_state();
        let body = json!({
            "data": "00".repeat(32),
            "signature": "3044022000000000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000000000",
            "protocolID": [2, "test"],
            "keyID": "k",
            "counterparty": "self"
        });
        let Json(resp) = verify_signature(State(state), Json(body)).await;
        assert!(resp.get("error").is_some());
        assert!(resp["error"].as_str().unwrap().contains("partial_ecdh"));
    }

    #[tokio::test]
    async fn test_verify_signature_bad_data_length() {
        let state = test_state();
        let body = json!({
            "data": "aabb",
            "signature": "3044022000",
            "protocolID": [2, "test"],
            "keyID": "k",
            "counterparty": "anyone"
        });
        let Json(resp) = verify_signature(State(state), Json(body)).await;
        assert!(resp.get("error").is_some());
        assert!(resp["error"].as_str().unwrap().contains("32 bytes"));
    }

    // ── Large payload test ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_encrypt_decrypt_large_payload() {
        let state = test_state();
        let large_data: Vec<u8> = (0..10240).map(|i| (i % 256) as u8).collect();
        let plaintext_b64 = BASE64.encode(&large_data);

        let enc_body = json!({
            "plaintext": plaintext_b64,
            "protocolID": [2, "test"],
            "keyID": "large",
            "counterparty": "anyone"
        });
        let Json(enc_resp) = encrypt(State(state.clone()), Json(enc_body)).await;
        assert!(enc_resp.get("error").is_none());

        let dec_body = json!({
            "ciphertext": enc_resp["ciphertext"].as_str().unwrap(),
            "protocolID": [2, "test"],
            "keyID": "large",
            "counterparty": "anyone"
        });
        let Json(dec_resp) = decrypt(State(state), Json(dec_body)).await;
        assert!(dec_resp.get("error").is_none());
        let result = BASE64.decode(dec_resp["plaintext"].as_str().unwrap()).unwrap();
        assert_eq!(result, large_data);
    }

    // ── Cross-handler consistency ───────────────────────────────────────

    #[tokio::test]
    async fn test_hmac_and_encrypt_use_same_key_derivation() {
        // Both encrypt and createHmac should derive from the same BRC-42 path
        let jk = test_joint_key();
        let k1 = derive_symmetric_key(&jk, 2, "shared-proto", "shared-key", "anyone").unwrap();
        let k2 = derive_symmetric_key(&jk, 2, "shared-proto", "shared-key", "anyone").unwrap();
        assert_eq!(k1, k2, "encrypt and HMAC use the same key derivation");
    }

    #[tokio::test]
    async fn test_verify_signature_for_self_false_anyone() {
        let state = test_state();

        // For forSelf=false with "anyone" counterparty:
        // The signer is the "anyone" party (private key = 1).
        // The "anyone" party derives their child key using:
        //   shared_secret = ECDH(root_pub, anyone_priv=1) = root_pub * 1 = root_pub
        //   child_priv = anyone_priv + HMAC(root_pub, invoice) = 1 + hmac
        //
        // Use KeyDeriver with anyone's private key to derive the child key.
        let (anyone_priv, _anyone_pub) = KeyDeriver::anyone_key();
        let root_priv = PrivateKey::from_bytes(&TEST_KEY_BYTES).unwrap();
        let root_pub = root_priv.public_key();

        // The anyone party uses our root_pub as their counterparty
        let anyone_deriver = KeyDeriver::new(Some(anyone_priv));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "test sig");
        let child_priv = anyone_deriver
            .derive_private_key(&protocol, "for-self-false", &Counterparty::Other(root_pub))
            .expect("derivation should work");

        let msg_hash = [0x55u8; 32];
        let signature = child_priv.sign(&msg_hash).unwrap();

        let body = json!({
            "data": hex::encode(msg_hash),
            "signature": hex::encode(signature.to_der()),
            "protocolID": [2, "test sig"],
            "keyID": "for-self-false",
            "counterparty": "anyone",
            "forSelf": false
        });
        let Json(resp) = verify_signature(State(state), Json(body)).await;
        assert!(resp.get("error").is_none(), "should succeed: {:?}", resp);
        assert_eq!(resp["valid"], true);
    }
}
