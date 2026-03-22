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

use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::server::AppState;
use crate::utxo_tracker::TrackedOutput;

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
/// For "self"/"other": 2 partial ECDH rounds with KSS via bridge.
///
/// Returns a 32-byte key compatible with BSV SDK's `derive_symmetric_key`.
/// Proven in POC 3 (key derivation) and POC 9 (encrypt/decrypt).
async fn derive_symmetric_key(
    bridge: &crate::bridge::MpcBridge,
    level: u8,
    protocol_name: &str,
    key_id: &str,
    counterparty: &str,
) -> Result<[u8; 32], String> {
    bridge
        .derive_symmetric_key(counterparty, level, protocol_name, key_id)
        .await
        .map_err(|e| format!("{e}"))
}

/// Derive the expected BRC-42 child public key for signature verification.
///
/// `for_self=true`:  child = root_pub + G * HMAC(shared_secret, invoice)
/// `for_self=false`: child = counterparty_pub + G * HMAC(shared_secret, invoice)
///
/// For "anyone" counterparty, both paths are local. For "self"/"other",
/// shared_secret computation requires bridge.partial_ecdh() (1 MPC round).
async fn derive_verification_pubkey(
    bridge: &crate::bridge::MpcBridge,
    level: u8,
    protocol_name: &str,
    key_id: &str,
    counterparty: &str,
    for_self: bool,
) -> Result<PublicKey, String> {
    bridge
        .derive_child_key(counterparty, level, protocol_name, key_id, for_self)
        .await
        .map_err(|e| format!("{e}"))
}

// ─── Transaction helpers ─────────────────────────────────────────────────────
//
// Ported from poc4-real-tx and poc15-capstone. These are pure functions for
// BIP-143 sighash computation, P2PKH script construction, transaction
// serialization, and broadcasting.

/// Double SHA-256 (Bitcoin's standard hash function).
fn sha256d(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(h1);
    let mut result = [0u8; 32];
    result.copy_from_slice(&h2);
    result
}

/// Compute txid from raw transaction bytes (display byte order — reversed hash).
fn compute_txid(raw_tx: &[u8]) -> String {
    let mut hash = sha256d(raw_tx);
    hash.reverse(); // internal → display byte order
    hex::encode(hash)
}

/// Build P2PKH locking script from a 20-byte pubkey hash.
///
/// ```text
/// OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
/// ```
fn p2pkh_locking_script_from_hash(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

/// Build P2PKH unlocking script: `<sig_with_hashtype> <compressed_pubkey>`.
fn build_p2pkh_unlocking_script(sig_checksig: &[u8], compressed_pubkey: &[u8; 33]) -> Vec<u8> {
    let mut script = Vec::with_capacity(sig_checksig.len() + 35);
    script.push(sig_checksig.len() as u8);
    script.extend_from_slice(sig_checksig);
    script.push(33); // push 33 bytes
    script.extend_from_slice(compressed_pubkey);
    script
}

/// Estimate mining fee based on transaction size (1 sat/byte, conservative).
///
/// P2PKH input: ~149 bytes, P2PKH output: ~34 bytes, overhead: ~10 bytes.
fn estimate_mining_fee(num_inputs: usize, num_outputs: usize) -> u64 {
    let estimated_size = 10 + (num_inputs * 149) + (num_outputs * 34);
    std::cmp::max(estimated_size as u64, 100)
}

/// Write a Bitcoin varint to a buffer.
fn write_varint_to(buf: &mut Vec<u8>, val: u64) {
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

/// Read a Bitcoin varint from a byte slice at the given offset.
fn read_varint_from(data: &[u8], offset: &mut usize) -> Result<u64, String> {
    if *offset >= data.len() {
        return Err("unexpected end of data reading varint".into());
    }
    let first = data[*offset];
    *offset += 1;
    match first {
        0..=0xfc => Ok(first as u64),
        0xfd => {
            if *offset + 2 > data.len() {
                return Err("truncated varint (fd)".into());
            }
            let val = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
            *offset += 2;
            Ok(val as u64)
        }
        0xfe => {
            if *offset + 4 > data.len() {
                return Err("truncated varint (fe)".into());
            }
            let val = u32::from_le_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ]);
            *offset += 4;
            Ok(val as u64)
        }
        0xff => {
            if *offset + 8 > data.len() {
                return Err("truncated varint (ff)".into());
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[*offset..*offset + 8]);
            *offset += 8;
            Ok(u64::from_le_bytes(bytes))
        }
    }
}

/// Parameters for BIP-143 sighash computation.
struct SighashParams<'a> {
    version: u32,
    inputs: &'a [([u8; 32], u32, u32)], // (txid_internal, vout, sequence)
    outputs: &'a [(u64, &'a [u8])],      // (satoshis, locking_script)
    locktime: u32,
    input_index: usize,
    subscript: &'a [u8], // locking script of the UTXO being spent
    input_satoshis: u64,
    sighash_type: u32,
}

/// Compute BIP-143 sighash for a transaction input.
///
/// This is BSV's sighash algorithm (BIP-143 with FORKID).
/// Ported from poc4-real-tx/tests/poc.rs.
fn compute_bip143_sighash(params: &SighashParams<'_>) -> [u8; 32] {
    let SighashParams {
        version,
        inputs,
        outputs,
        locktime,
        input_index,
        subscript,
        input_satoshis,
        sighash_type,
    } = params;
    // hashPrevouts: SHA256d of all outpoints
    let mut prevouts_data = Vec::new();
    for (txid, vout, _) in *inputs {
        prevouts_data.extend_from_slice(txid);
        prevouts_data.extend_from_slice(&vout.to_le_bytes());
    }
    let hash_prevouts = sha256d(&prevouts_data);

    // hashSequence: SHA256d of all sequences
    let mut sequence_data = Vec::new();
    for (_, _, seq) in *inputs {
        sequence_data.extend_from_slice(&seq.to_le_bytes());
    }
    let hash_sequence = sha256d(&sequence_data);

    // hashOutputs: SHA256d of all serialized outputs
    let mut outputs_data = Vec::new();
    for (sats, script) in *outputs {
        outputs_data.extend_from_slice(&sats.to_le_bytes());
        write_varint_to(&mut outputs_data, script.len() as u64);
        outputs_data.extend_from_slice(script);
    }
    let hash_outputs = sha256d(&outputs_data);

    // Build BIP-143 preimage
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&version.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    // Outpoint being signed
    preimage.extend_from_slice(&inputs[*input_index].0);
    preimage.extend_from_slice(&inputs[*input_index].1.to_le_bytes());
    // scriptCode
    write_varint_to(&mut preimage, subscript.len() as u64);
    preimage.extend_from_slice(subscript);
    // Value
    preimage.extend_from_slice(&input_satoshis.to_le_bytes());
    // Sequence
    preimage.extend_from_slice(&inputs[*input_index].2.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&locktime.to_le_bytes());
    preimage.extend_from_slice(&sighash_type.to_le_bytes());

    sha256d(&preimage)
}

/// Serialize a signed transaction to raw bytes.
///
/// Ported from poc4-real-tx/tests/poc.rs: `serialize_transaction()`.
fn serialize_signed_tx(
    version: u32,
    inputs: &[([u8; 32], u32, Vec<u8>, u32)], // (txid, vout, unlocking_script, sequence)
    outputs: &[(u64, Vec<u8>)],                 // (satoshis, locking_script)
    locktime: u32,
) -> Vec<u8> {
    let mut buf = Vec::new();

    buf.extend_from_slice(&version.to_le_bytes());

    write_varint_to(&mut buf, inputs.len() as u64);
    for (txid, vout, script, sequence) in inputs {
        buf.extend_from_slice(txid);
        buf.extend_from_slice(&vout.to_le_bytes());
        write_varint_to(&mut buf, script.len() as u64);
        buf.extend_from_slice(script);
        buf.extend_from_slice(&sequence.to_le_bytes());
    }

    write_varint_to(&mut buf, outputs.len() as u64);
    for (satoshis, script) in outputs {
        buf.extend_from_slice(&satoshis.to_le_bytes());
        write_varint_to(&mut buf, script.len() as u64);
        buf.extend_from_slice(script);
    }

    buf.extend_from_slice(&locktime.to_le_bytes());

    buf
}

/// Parse transaction bytes and extract outputs: `(satoshis, locking_script)`.
fn parse_tx_outputs(raw_tx: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    if raw_tx.len() < 10 {
        return Err("transaction too short".into());
    }

    let mut offset = 4; // skip version

    // Skip inputs
    let input_count = read_varint_from(raw_tx, &mut offset)?;
    for _ in 0..input_count {
        if offset + 36 > raw_tx.len() {
            return Err("unexpected end of tx parsing input outpoint".into());
        }
        offset += 36; // txid (32) + vout (4)
        let script_len = read_varint_from(raw_tx, &mut offset)? as usize;
        if offset + script_len + 4 > raw_tx.len() {
            return Err("unexpected end of tx parsing input script".into());
        }
        offset += script_len + 4; // script + sequence
    }

    // Parse outputs
    let output_count = read_varint_from(raw_tx, &mut offset)?;
    let mut outputs = Vec::with_capacity(output_count as usize);
    for _ in 0..output_count {
        if offset + 8 > raw_tx.len() {
            return Err("unexpected end of tx parsing output value".into());
        }
        let satoshis = u64::from_le_bytes(
            raw_tx[offset..offset + 8]
                .try_into()
                .map_err(|_| "failed to read output satoshis".to_string())?,
        );
        offset += 8;

        let script_len = read_varint_from(raw_tx, &mut offset)? as usize;
        if offset + script_len > raw_tx.len() {
            return Err("unexpected end of tx parsing output script".into());
        }
        let script = raw_tx[offset..offset + script_len].to_vec();
        offset += script_len;

        outputs.push((satoshis, script));
    }

    Ok(outputs)
}

/// Broadcast a raw transaction to ARC endpoints.
///
/// Tries TAAL first, then GorillaPool. Accepts "SEEN_ON_NETWORK" and "MINED"
/// as success responses (standard ARC behavior for already-broadcast txs).
///
/// Ported from poc4-real-tx and poc15-capstone broadcast patterns.
async fn broadcast_tx(
    client: &reqwest::Client,
    raw_tx_hex: &str,
) -> Result<serde_json::Value, String> {
    let arc_endpoints = [
        "https://arc.taal.com",
        "https://arc.gorillapool.io",
    ];

    let mut last_error = String::new();

    for endpoint in &arc_endpoints {
        let url = format!("{}/v1/tx", endpoint);

        match client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("XDeployment-ID", "bsv-mpc-proxy")
            .json(&json!({ "rawTx": raw_tx_hex }))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();

                if status.is_success()
                    || text.contains("SEEN_ON_NETWORK")
                    || text.contains("MINED")
                {
                    let response: serde_json::Value = serde_json::from_str(&text)
                        .unwrap_or_else(|_| json!({ "status": "success", "raw": text }));
                    return Ok(response);
                }

                last_error = format!("{} returned {}: {}", endpoint, status, text);
                tracing::warn!(endpoint, status = %status, "ARC broadcast attempt failed");
            }
            Err(e) => {
                last_error = format!("{} error: {}", endpoint, e);
                tracing::warn!(endpoint, error = %e, "ARC broadcast request failed");
            }
        }
    }

    Err(last_error)
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
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let identity_key = body
        .get("identityKey")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // If identityKey requested or no derivation params, return root joint key
    if identity_key || body.get("protocolID").is_none() {
        let pubkey_hex = hex::encode(&state.bridge.joint_public_key().compressed);
        return Json(json!({ "publicKey": pubkey_hex }));
    }

    // Parse BRC-42 derivation params
    let (level, protocol_name, key_id, counterparty) = match parse_protocol_params(&body) {
        Ok(params) => params,
        Err(e) => return Json(json!({ "error": e })),
    };

    let for_self = body
        .get("forSelf")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // Derive child public key via BRC-42
    match derive_verification_pubkey(
        &state.bridge,
        level,
        &protocol_name,
        &key_id,
        &counterparty,
        for_self,
    )
    .await
    {
        Ok(pk) => Json(json!({ "publicKey": pk.to_hex() })),
        Err(e) => Json(json!({ "error": e })),
    }
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
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    // Parse the data to sign
    let data_value = match body.get("data") {
        Some(v) => v,
        None => return Json(json!({ "error": "missing data" })),
    };

    let hash_to_directly_sign = body
        .get("hashToDirectlySign")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Convert data to bytes — supports byte array, hex string, and base64 string
    let data_bytes = if let Some(arr) = data_value.as_array() {
        arr.iter()
            .map(|v| v.as_u64().unwrap_or(0) as u8)
            .collect::<Vec<u8>>()
    } else if let Some(s) = data_value.as_str() {
        hex::decode(s).unwrap_or_else(|_| BASE64.decode(s).unwrap_or_default())
    } else {
        return Json(json!({ "error": "data must be a string or byte array" }));
    };

    if data_bytes.is_empty() {
        return Json(json!({ "error": "data is empty" }));
    }

    // Compute 32-byte message hash
    let msg_hash: [u8; 32] = if hash_to_directly_sign {
        if data_bytes.len() != 32 {
            return Json(json!({
                "error": format!(
                    "hashToDirectlySign requires exactly 32 bytes, got {}",
                    data_bytes.len()
                )
            }));
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&data_bytes);
        h
    } else {
        let hash = Sha256::digest(&data_bytes);
        let mut h = [0u8; 32];
        h.copy_from_slice(&hash);
        h
    };

    // Compute BRC-42 HMAC offset for derived key signing.
    // For "anyone" counterparty: offset = HMAC(root_pub, invoice) — fully local.
    // For "self"/"other": would need partial ECDH for shared_secret (not yet supported).
    let hmac_offset: Option<[u8; 32]> = if body.get("protocolID").is_some() {
        let (level, protocol_name, key_id, counterparty) = match parse_protocol_params(&body) {
            Ok(params) => params,
            Err(e) => return Json(json!({ "error": e })),
        };

        match counterparty.as_str() {
            "anyone" => {
                let invoice = bsv_mpc_core::hd::compute_invoice(level, &protocol_name, &key_id);
                let hmac = bsv_mpc_core::hd::compute_brc42_hmac(state.bridge.root_pub(), &invoice);
                Some(hmac)
            }
            _ => {
                // "self" and "other" counterparties require partial ECDH to compute
                // the shared secret before HMAC. Not yet wired for signing.
                tracing::warn!(
                    counterparty = %counterparty,
                    "createSignature: derived key signing for non-anyone counterparty \
                     not yet implemented — signing with root key"
                );
                None
            }
        }
    } else {
        None
    };

    // Try to get a presignature from the pool for single-round signing
    let presig = {
        let mut mgr = state.presign_manager.write().await;
        mgr.take()
    };

    // Sign via MPC bridge (2PC with KSS)
    let signing_result = match state.bridge.sign(&msg_hash, presig, hmac_offset).await {
        Ok(result) => result,
        Err(e) => return Json(json!({ "error": format!("MPC signing failed: {}", e) })),
    };

    // Return DER-encoded signature as hex
    Json(json!({ "signature": hex::encode(&signing_result.signature) }))
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

    // Parse data and compute hash (same as createSignature)
    let data_hex = match body.get("data").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Json(json!({ "error": "missing data" })),
    };
    let data_bytes = match hex::decode(data_hex) {
        Ok(bytes) => bytes,
        Err(e) => return Json(json!({ "error": format!("invalid hex data: {}", e) })),
    };
    if data_bytes.is_empty() {
        return Json(json!({ "error": "data is empty" }));
    }

    // Hash the data with SHA-256 (matching createSignature behavior)
    let hash_to_directly_sign = body
        .get("hashToDirectlySign")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let msg_hash: [u8; 32] = if hash_to_directly_sign {
        if data_bytes.len() != 32 {
            return Json(json!({ "error": format!("hashToDirectlySign requires 32 bytes, got {}", data_bytes.len()) }));
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&data_bytes);
        h
    } else {
        let hash = Sha256::digest(&data_bytes);
        let mut h = [0u8; 32];
        h.copy_from_slice(&hash);
        h
    };

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
        &state.bridge,
        level,
        &protocol_name,
        &key_id,
        &counterparty,
        for_self,
    )
    .await
    {
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
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    // ── 1. Parse request ─────────────────────────────────────────────────
    let outputs_json = match body.get("outputs").and_then(|v| v.as_array()) {
        Some(arr) if !arr.is_empty() => arr,
        _ => return Json(json!({"error": "missing or empty outputs array"})),
    };

    let mut user_outputs: Vec<(u64, Vec<u8>)> = Vec::new();
    for (i, o) in outputs_json.iter().enumerate() {
        let sats = match o.get("satoshis").and_then(|v| v.as_u64()) {
            Some(s) => s,
            None => {
                return Json(json!({"error": format!("output[{}]: missing satoshis", i)}))
            }
        };
        let script_hex = match o.get("lockingScript").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return Json(
                    json!({"error": format!("output[{}]: missing lockingScript", i)}),
                )
            }
        };
        let script = match hex::decode(script_hex) {
            Ok(b) => b,
            Err(e) => {
                return Json(json!({
                    "error": format!("output[{}]: invalid lockingScript hex: {}", i, e)
                }))
            }
        };
        user_outputs.push((sats, script));
    }

    let total_user_output: u64 = user_outputs.iter().map(|(s, _)| s).sum();

    // ── 2. Compute our P2PKH locking script ──────────────────────────────
    let joint_key = state.bridge.joint_public_key();
    let root_pubkey = match PublicKey::from_bytes(&joint_key.compressed) {
        Ok(pk) => pk,
        Err(e) => return Json(json!({"error": format!("invalid joint key: {}", e)})),
    };
    let change_script = p2pkh_locking_script_from_hash(&root_pubkey.hash160());

    // ── 3. Determine fee amounts ─────────────────────────────────────────
    let mpc_fee = if state.fee_injector.is_enabled() {
        state.fee_injector.fee_sats()
    } else {
        0
    };
    let fee_output_count = if mpc_fee > 0 {
        if state
            .fee_injector
            .parse_threshold()
            .ok()
            .flatten()
            .is_some()
        {
            1 // multisig: single output
        } else {
            state.fee_injector.fee_addresses().len()
        }
    } else {
        0
    };

    // ── 4. Select UTXOs ──────────────────────────────────────────────────
    let est_num_outputs = user_outputs.len() + 1 + fee_output_count;
    let est_mining_fee = estimate_mining_fee(1, est_num_outputs);
    let est_total = total_user_output + mpc_fee + est_mining_fee;

    let (selected_utxos, total_input) = {
        let tracker = state.utxo_tracker.read().await;
        tracker.select_utxos(est_total)
    };

    if selected_utxos.is_empty() {
        return Json(json!({"error": "no UTXOs available"}));
    }

    // ── 5. Compute exact mining fee ──────────────────────────────────────
    let num_inputs = selected_utxos.len();
    let num_outputs_total = user_outputs.len() + 1 + fee_output_count;
    let mining_fee = estimate_mining_fee(num_inputs, num_outputs_total);
    let total_needed = total_user_output + mpc_fee + mining_fee;

    if total_input < total_needed {
        return Json(json!({
            "error": format!(
                "insufficient funds: have {} sats, need {} (outputs: {}, mpc_fee: {}, mining_fee: {})",
                total_input, total_needed, total_user_output, mpc_fee, mining_fee
            )
        }));
    }

    // ── 6. Build output list ─────────────────────────────────────────────
    // change_before_fee includes the mpc_fee, which will be deducted by the
    // fee injector. After injection: change = total_input - outputs - mining_fee - mpc_fee.
    let change_before_fee = total_input - total_user_output - mining_fee;

    let mut outputs: Vec<(u64, Vec<u8>)> = user_outputs;
    let change_index = outputs.len();
    outputs.push((change_before_fee, change_script.clone()));

    // ── 7. Inject MPC fee ────────────────────────────────────────────────
    if state.fee_injector.is_enabled() {
        match state
            .fee_injector
            .inject_fee_into_outputs(&mut outputs, change_index)
        {
            Ok(info) => {
                tracing::debug!(
                    fee_outputs = info.fee_outputs_added,
                    total_fee = info.total_fee_sats,
                    original_change = info.original_change,
                    new_change = info.new_change,
                    "MPC fee injected"
                );
            }
            Err(e) => {
                return Json(json!({"error": format!("fee injection failed: {}", e)}))
            }
        }
    }

    // ── 8. Prepare input data ────────────────────────────────────────────
    let mut input_tuples: Vec<([u8; 32], u32, u32)> = Vec::new();
    for utxo in &selected_utxos {
        let decoded = match hex::decode(&utxo.txid) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                return Json(
                    json!({"error": format!("invalid txid hex: {}", utxo.txid)}),
                )
            }
        };
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(&decoded);
        txid_bytes.reverse(); // display → internal byte order
        input_tuples.push((txid_bytes, utxo.vout, 0xFFFFFFFF));
    }

    // ── 9. Sign each input ───────────────────────────────────────────────
    let compressed_pubkey = root_pubkey.to_compressed();
    let sighash_type: u32 = 0x41; // SIGHASH_ALL | SIGHASH_FORKID

    // Subscript = P2PKH of our root key (all inputs spend from MPC address)
    let subscript = p2pkh_locking_script_from_hash(&root_pubkey.hash160());

    // Output refs for sighash computation
    let output_refs: Vec<(u64, &[u8])> =
        outputs.iter().map(|(s, sc)| (*s, sc.as_slice())).collect();

    let mut signed_inputs: Vec<([u8; 32], u32, Vec<u8>, u32)> = Vec::new();

    for (i, utxo) in selected_utxos.iter().enumerate() {
        // Compute BIP-143 sighash
        let sighash = compute_bip143_sighash(&SighashParams {
            version: 1,
            inputs: &input_tuples,
            outputs: &output_refs,
            locktime: 0,
            input_index: i,
            subscript: &subscript,
            input_satoshis: utxo.satoshis,
            sighash_type,
        });

        // Try presignature pool for single-round signing
        let presig = {
            let mut mgr = state.presign_manager.write().await;
            mgr.take()
        };

        // MPC sign via bridge (2PC with KSS) — root key for now
        // TODO: derive child key offset for BRC-42 input derivation paths
        let signing_result = match state.bridge.sign(&sighash, presig, None).await {
            Ok(result) => result,
            Err(e) => {
                return Json(
                    json!({"error": format!("signing input {} failed: {}", i, e)}),
                )
            }
        };

        // Build checksig format: DER signature + sighash type byte (0x41)
        let mut sig_checksig = signing_result.signature;
        sig_checksig.push(sighash_type as u8);

        // Build P2PKH unlocking script: <sig+hashtype> <compressed_pubkey>
        let unlocking = build_p2pkh_unlocking_script(&sig_checksig, &compressed_pubkey);

        signed_inputs.push((
            input_tuples[i].0,
            input_tuples[i].1,
            unlocking,
            input_tuples[i].2,
        ));
    }

    // ── 10. Serialize transaction ────────────────────────────────────────
    let raw_tx = serialize_signed_tx(1, &signed_inputs, &outputs, 0);
    let txid = compute_txid(&raw_tx);
    let raw_tx_hex = hex::encode(&raw_tx);

    tracing::info!(
        txid = %txid,
        inputs = num_inputs,
        outputs = outputs.len(),
        total_in = total_input,
        mining_fee,
        mpc_fee,
        tx_size = raw_tx.len(),
        "Transaction built"
    );

    // ── 11. Broadcast ────────────────────────────────────────────────────
    match broadcast_tx(&state.http_client, &raw_tx_hex).await {
        Ok(_) => {
            tracing::info!(txid = %txid, "Broadcast successful");
        }
        Err(e) => {
            // Return the raw tx even on broadcast failure so the caller can retry
            tracing::warn!(txid = %txid, error = %e, "Broadcast failed");
            return Json(json!({
                "error": format!("broadcast failed: {}", e),
                "txid": txid,
                "rawTx": raw_tx_hex,
            }));
        }
    }

    // ── 12. Update UTXO tracker ──────────────────────────────────────────
    {
        let mut tracker = state.utxo_tracker.write().await;

        // Mark inputs as spent
        for utxo in &selected_utxos {
            tracker.mark_spent(&utxo.txid, utxo.vout, &txid);
        }

        // Track change output (if non-dust)
        let change_sats = outputs[change_index].0;
        if change_sats > 0 {
            tracker.add_output(TrackedOutput {
                txid: txid.clone(),
                vout: change_index as u32,
                satoshis: change_sats,
                locking_script: change_script,
                spending_txid: None,
                basket: Some("default".into()),
                tags: vec![],
                created_at: chrono::Utc::now(),
            });
        }
    }

    // ── 13. Return ───────────────────────────────────────────────────────
    Json(json!({
        "txid": txid,
        "rawTx": raw_tx_hex,
    }))
}

/// `POST /internalizeAction`
///
/// Accept an incoming payment or BEEF envelope by internalizing its outputs
/// into the local UTXO set.
pub async fn internalize_action(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    // Parse the transaction (rawTx hex)
    let raw_tx_hex = match body
        .get("tx")
        .or_else(|| body.get("rawTx"))
        .and_then(|v| v.as_str())
    {
        Some(s) => s,
        None => return Json(json!({"error": "missing tx or rawTx field"})),
    };

    let raw_tx_bytes = match hex::decode(raw_tx_hex) {
        Ok(b) => b,
        Err(e) => return Json(json!({"error": format!("invalid hex in tx: {}", e)})),
    };

    // Parse the transaction to extract outputs
    let tx_outputs = match parse_tx_outputs(&raw_tx_bytes) {
        Ok(outputs) => outputs,
        Err(e) => return Json(json!({"error": format!("failed to parse tx: {}", e)})),
    };

    let txid = compute_txid(&raw_tx_bytes);

    // Build our expected P2PKH locking script for root key verification
    let root_pubkey = match PublicKey::from_bytes(&state.bridge.joint_public_key().compressed) {
        Ok(pk) => pk,
        Err(e) => return Json(json!({"error": format!("invalid joint key: {}", e)})),
    };
    let our_script = p2pkh_locking_script_from_hash(&root_pubkey.hash160());

    // Determine basket from labels (first label) or default
    let basket = body
        .get("labels")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .unwrap_or("default");

    let outputs_spec = body.get("outputs").and_then(|v| v.as_array());
    let mut accepted_count = 0u32;

    if let Some(specs) = outputs_spec {
        // Internalize specific outputs
        for spec in specs {
            let output_index = match spec.get("outputIndex").and_then(|v| v.as_u64()) {
                Some(idx) => idx as usize,
                None => continue,
            };

            if output_index >= tx_outputs.len() {
                return Json(json!({
                    "error": format!(
                        "outputIndex {} out of range (tx has {} outputs)",
                        output_index,
                        tx_outputs.len()
                    )
                }));
            }

            let (satoshis, ref script) = tx_outputs[output_index];

            // Verify output pays to a key we control (root key P2PKH for M2)
            // TODO: also check BRC-42 derived keys when share offset is implemented
            if *script != our_script {
                tracing::debug!(
                    output_index,
                    "output script doesn't match root key P2PKH — accepting anyway \
                     (derived key verification not yet implemented)"
                );
            }

            let mut tracker = state.utxo_tracker.write().await;
            tracker.add_output(TrackedOutput {
                txid: txid.clone(),
                vout: output_index as u32,
                satoshis,
                locking_script: script.clone(),
                spending_txid: None,
                basket: Some(basket.to_string()),
                tags: vec![],
                created_at: chrono::Utc::now(),
            });
            accepted_count += 1;
        }
    } else {
        // No specific outputs — scan all outputs for ones matching our root key
        for (vout, (satoshis, script)) in tx_outputs.iter().enumerate() {
            if *script == our_script {
                let mut tracker = state.utxo_tracker.write().await;
                tracker.add_output(TrackedOutput {
                    txid: txid.clone(),
                    vout: vout as u32,
                    satoshis: *satoshis,
                    locking_script: script.clone(),
                    spending_txid: None,
                    basket: Some(basket.to_string()),
                    tags: vec![],
                    created_at: chrono::Utc::now(),
                });
                accepted_count += 1;
            }
        }
    }

    tracing::info!(txid = %txid, accepted_count, "Internalized action");

    Json(json!({
        "accepted": true,
        "txid": txid,
    }))
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
        &state.bridge,
        level,
        &protocol_name,
        &key_id,
        &counterparty,
    )
    .await
    {
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
        &state.bridge,
        level,
        &protocol_name,
        &key_id,
        &counterparty,
    )
    .await
    {
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
        &state.bridge,
        level,
        &protocol_name,
        &key_id,
        &counterparty,
    )
    .await
    {
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
        &state.bridge,
        level,
        &protocol_name,
        &key_id,
        &counterparty,
    )
    .await
    {
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
    use bsv_mpc_core::JointPublicKey;
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
            http_client: reqwest::Client::new(),
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

    #[tokio::test]
    async fn test_derive_symmetric_key_anyone() {
        let state = test_state();
        let key = derive_symmetric_key(&state.bridge, 2, "test-proto", "key1", "anyone")
            .await
            .unwrap();
        assert_eq!(key.len(), 32);
        assert_ne!(key, [0u8; 32], "key should not be all zeros");
    }

    #[tokio::test]
    async fn test_derive_symmetric_key_deterministic() {
        let state = test_state();
        let k1 = derive_symmetric_key(&state.bridge, 2, "test-proto", "key1", "anyone")
            .await
            .unwrap();
        let k2 = derive_symmetric_key(&state.bridge, 2, "test-proto", "key1", "anyone")
            .await
            .unwrap();
        assert_eq!(k1, k2, "same inputs must produce same key");
    }

    #[tokio::test]
    async fn test_derive_symmetric_key_different_invoices() {
        let state = test_state();
        let k1 = derive_symmetric_key(&state.bridge, 2, "test-proto", "key1", "anyone")
            .await
            .unwrap();
        let k2 = derive_symmetric_key(&state.bridge, 2, "test-proto", "key2", "anyone")
            .await
            .unwrap();
        assert_ne!(k1, k2, "different key IDs must produce different keys");
    }

    #[tokio::test]
    async fn test_derive_symmetric_key_self_errors_without_kss() {
        // With test bridge (no real KSS), "self" counterparty should error
        let state = test_state();
        let result = derive_symmetric_key(&state.bridge, 2, "test-proto", "key1", "self").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_derive_symmetric_key_other_errors_without_kss() {
        // With test bridge (no real KSS), "other" counterparty should error
        let state = test_state();
        let result = derive_symmetric_key(
            &state.bridge,
            2,
            "test-proto",
            "key1",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .await;
        assert!(result.is_err());
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
    async fn test_encrypt_self_counterparty_errors_without_kss() {
        let state = test_state();
        let body = json!({
            "plaintext": BASE64.encode(b"test"),
            "protocolID": [2, "worm memory"],
            "keyID": "block-1",
            "counterparty": "self"
        });
        let Json(resp) = encrypt(State(state), Json(body)).await;
        // Without a real KSS, "self" counterparty fails (connection refused)
        assert!(resp.get("error").is_some());
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
    async fn test_verify_signature_self_errors_without_kss() {
        let state = test_state();
        let body = json!({
            "data": "00".repeat(32),
            "signature": "3044022000000000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000000000",
            "protocolID": [2, "test"],
            "keyID": "k",
            "counterparty": "self"
        });
        let Json(resp) = verify_signature(State(state), Json(body)).await;
        // Without a real KSS, "self" counterparty fails
        assert!(resp.get("error").is_some());
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
        let state = test_state();
        let k1 = derive_symmetric_key(&state.bridge, 2, "shared-proto", "shared-key", "anyone")
            .await
            .unwrap();
        let k2 = derive_symmetric_key(&state.bridge, 2, "shared-proto", "shared-key", "anyone")
            .await
            .unwrap();
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

    // ── getPublicKey handler tests ──────────────────────────────────────

    #[tokio::test]
    async fn test_get_public_key_identity() {
        let state = test_state();
        let body = json!({"identityKey": true});
        let Json(resp) = get_public_key(State(state), Json(body)).await;

        let pubkey_hex = resp["publicKey"].as_str().unwrap();
        assert_eq!(pubkey_hex.len(), 66); // 33 bytes = 66 hex chars
        assert!(pubkey_hex.starts_with("02") || pubkey_hex.starts_with("03"));
    }

    #[tokio::test]
    async fn test_get_public_key_no_params_returns_identity() {
        let state = test_state();
        let body = json!({});
        let Json(resp) = get_public_key(State(state.clone()), Json(body)).await;

        let identity_body = json!({"identityKey": true});
        let Json(identity_resp) = get_public_key(State(state), Json(identity_body)).await;

        assert_eq!(resp["publicKey"], identity_resp["publicKey"]);
    }

    #[tokio::test]
    async fn test_get_public_key_derived_anyone() {
        let state = test_state();

        let identity_body = json!({"identityKey": true});
        let Json(identity_resp) = get_public_key(State(state.clone()), Json(identity_body)).await;
        let identity_hex = identity_resp["publicKey"].as_str().unwrap();

        let derived_body = json!({
            "protocolID": [2, "test protocol"],
            "keyID": "key-1",
            "counterparty": "anyone",
        });
        let Json(derived_resp) = get_public_key(State(state), Json(derived_body)).await;
        assert!(derived_resp.get("error").is_none(), "should succeed: {:?}", derived_resp);

        let derived_hex = derived_resp["publicKey"].as_str().unwrap();
        assert_eq!(derived_hex.len(), 66);
        assert_ne!(derived_hex, identity_hex, "derived key should differ from identity");
    }

    #[tokio::test]
    async fn test_get_public_key_self_errors_without_kss() {
        let state = test_state();
        let body = json!({
            "protocolID": [2, "test"],
            "keyID": "k",
            "counterparty": "self",
        });
        let Json(resp) = get_public_key(State(state), Json(body)).await;
        // Without a real KSS, "self" counterparty fails
        assert!(resp.get("error").is_some());
    }

    // ── Transaction helper tests ────────────────────────────────────────

    #[test]
    fn test_sha256d_known_vector() {
        // SHA256d of empty bytes = SHA256(SHA256(""))
        let hash = sha256d(b"");
        assert_ne!(hash, [0u8; 32]);
        // SHA256d is deterministic
        assert_eq!(hash, sha256d(b""));
    }

    #[test]
    fn test_p2pkh_locking_script_structure() {
        let hash = [0xAA; 20];
        let script = p2pkh_locking_script_from_hash(&hash);
        assert_eq!(script.len(), 25);
        assert_eq!(script[0], 0x76); // OP_DUP
        assert_eq!(script[1], 0xa9); // OP_HASH160
        assert_eq!(script[2], 0x14); // push 20
        assert_eq!(&script[3..23], &hash);
        assert_eq!(script[23], 0x88); // OP_EQUALVERIFY
        assert_eq!(script[24], 0xac); // OP_CHECKSIG
    }

    #[test]
    fn test_build_p2pkh_unlocking_script() {
        let sig = [0x30, 0x45, 0x02, 0x20]; // partial DER for testing
        let pubkey = [0x02; 33];
        let script = build_p2pkh_unlocking_script(&sig, &pubkey);
        assert_eq!(script[0] as usize, sig.len()); // push sig len
        assert_eq!(&script[1..1 + sig.len()], &sig);
        assert_eq!(script[1 + sig.len()], 33); // push 33
        assert_eq!(&script[2 + sig.len()..], &pubkey);
    }

    #[test]
    fn test_bip143_sighash_deterministic() {
        let txid = [0xaa; 32];
        let subscript = p2pkh_locking_script_from_hash(&[0xbb; 20]);

        let h1 = compute_bip143_sighash(&SighashParams {
            version: 1,
            inputs: &[(txid, 0, 0xFFFFFFFF)],
            outputs: &[(1000, &subscript)],
            locktime: 0, input_index: 0, subscript: &subscript,
            input_satoshis: 5000, sighash_type: 0x41,
        });
        let h2 = compute_bip143_sighash(&SighashParams {
            version: 1,
            inputs: &[(txid, 0, 0xFFFFFFFF)],
            outputs: &[(1000, &subscript)],
            locktime: 0, input_index: 0, subscript: &subscript,
            input_satoshis: 5000, sighash_type: 0x41,
        });
        assert_eq!(h1, h2, "same inputs must produce same sighash");
        assert_ne!(h1, [0u8; 32], "sighash should not be zero");
    }

    #[test]
    fn test_bip143_sighash_changes_with_output() {
        let txid = [0xaa; 32];
        let subscript = p2pkh_locking_script_from_hash(&[0xbb; 20]);

        let h1 = compute_bip143_sighash(&SighashParams {
            version: 1,
            inputs: &[(txid, 0, 0xFFFFFFFF)],
            outputs: &[(1000, &subscript)],
            locktime: 0, input_index: 0, subscript: &subscript,
            input_satoshis: 5000, sighash_type: 0x41,
        });
        let h2 = compute_bip143_sighash(&SighashParams {
            version: 1,
            inputs: &[(txid, 0, 0xFFFFFFFF)],
            outputs: &[(2000, &subscript)], // different output amount
            locktime: 0, input_index: 0, subscript: &subscript,
            input_satoshis: 5000, sighash_type: 0x41,
        });
        assert_ne!(h1, h2, "different outputs must produce different sighash");
    }

    #[test]
    fn test_serialize_and_parse_tx_roundtrip() {
        let script = p2pkh_locking_script_from_hash(&[0xcc; 20]);
        let outputs = vec![(5000u64, script.clone()), (3000u64, script)];

        let raw_tx = serialize_signed_tx(
            1,
            &[([0xaa; 32], 0, vec![0x00], 0xFFFFFFFF)],
            &outputs,
            0,
        );

        let parsed = parse_tx_outputs(&raw_tx).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, 5000);
        assert_eq!(parsed[1].0, 3000);
    }

    #[test]
    fn test_compute_txid_not_empty() {
        let raw_tx = serialize_signed_tx(
            1,
            &[([0xaa; 32], 0, vec![], 0xFFFFFFFF)],
            &[(1000, vec![0x76, 0xa9])],
            0,
        );
        let txid = compute_txid(&raw_tx);
        assert_eq!(txid.len(), 64); // 32 bytes = 64 hex chars
        assert_ne!(txid, "00".repeat(32));
    }

    #[test]
    fn test_estimate_mining_fee() {
        let fee_1_1 = estimate_mining_fee(1, 1);
        let fee_1_2 = estimate_mining_fee(1, 2);
        let fee_2_3 = estimate_mining_fee(2, 3);

        assert!(fee_1_1 >= 100, "minimum 100 sats");
        assert!(fee_1_2 > fee_1_1, "more outputs = higher fee");
        assert!(fee_2_3 > fee_1_2, "more inputs = higher fee");
    }

    #[test]
    fn test_varint_roundtrip() {
        for val in [0u64, 1, 252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000] {
            let mut buf = Vec::new();
            write_varint_to(&mut buf, val);
            let mut offset = 0;
            let parsed = read_varint_from(&buf, &mut offset).unwrap();
            assert_eq!(parsed, val, "varint roundtrip failed for {}", val);
            assert_eq!(offset, buf.len());
        }
    }

    // ── internalizeAction handler tests ─────────────────────────────────

    #[tokio::test]
    async fn test_internalize_action_specific_outputs() {
        let state = test_state();
        let root_pk = PublicKey::from_bytes(&test_joint_key().compressed).unwrap();
        let our_script = p2pkh_locking_script_from_hash(&root_pk.hash160());

        // Build a fake tx with outputs paying to our key
        let raw_tx = serialize_signed_tx(
            1,
            &[([0xaa; 32], 0, vec![], 0xFFFFFFFF)],
            &[(5000, our_script.clone()), (3000, our_script)],
            0,
        );
        let txid = compute_txid(&raw_tx);
        let tx_hex = hex::encode(&raw_tx);

        let body = json!({
            "tx": tx_hex,
            "outputs": [{"outputIndex": 0}, {"outputIndex": 1}],
            "description": "test internalize",
        });

        let Json(resp) = internalize_action(State(state.clone()), Json(body)).await;
        assert_eq!(resp["accepted"], true);
        assert_eq!(resp["txid"].as_str().unwrap(), txid);

        // Verify UTXO tracker has both outputs
        let tracker = state.utxo_tracker.read().await;
        let unspent = tracker.list_unspent(None, None);
        assert_eq!(unspent.len(), 2);
        assert_eq!(unspent[0].satoshis, 5000);
        assert_eq!(unspent[1].satoshis, 3000);
    }

    #[tokio::test]
    async fn test_internalize_action_auto_scan() {
        let state = test_state();
        let root_pk = PublicKey::from_bytes(&test_joint_key().compressed).unwrap();
        let our_script = p2pkh_locking_script_from_hash(&root_pk.hash160());
        let other_script = p2pkh_locking_script_from_hash(&[0xFF; 20]); // not ours

        // Tx with mixed outputs: ours at index 0 and 2, someone else's at index 1
        let raw_tx = serialize_signed_tx(
            1,
            &[([0xbb; 32], 0, vec![], 0xFFFFFFFF)],
            &[
                (7000, our_script.clone()),
                (2000, other_script),
                (4000, our_script),
            ],
            0,
        );
        let tx_hex = hex::encode(&raw_tx);

        // No outputs field → auto-scan for matching scripts
        let body = json!({ "tx": tx_hex });
        let Json(resp) = internalize_action(State(state.clone()), Json(body)).await;
        assert_eq!(resp["accepted"], true);

        let tracker = state.utxo_tracker.read().await;
        let unspent = tracker.list_unspent(None, None);
        assert_eq!(unspent.len(), 2); // only our outputs
        let total: u64 = unspent.iter().map(|o| o.satoshis).sum();
        assert_eq!(total, 11000); // 7000 + 4000
    }

    #[tokio::test]
    async fn test_internalize_then_list_outputs() {
        let state = test_state();
        let root_pk = PublicKey::from_bytes(&test_joint_key().compressed).unwrap();
        let our_script = p2pkh_locking_script_from_hash(&root_pk.hash160());

        // Internalize outputs
        let raw_tx = serialize_signed_tx(
            1,
            &[([0xcc; 32], 0, vec![], 0xFFFFFFFF)],
            &[(10000, our_script.clone()), (20000, our_script)],
            0,
        );
        let tx_hex = hex::encode(&raw_tx);

        let body = json!({
            "tx": tx_hex,
            "outputs": [{"outputIndex": 0}, {"outputIndex": 1}],
        });
        internalize_action(State(state.clone()), Json(body)).await;

        // List outputs and verify
        let Json(list_resp) = list_outputs(State(state), Json(json!({}))).await;
        assert_eq!(list_resp["totalOutputs"], 2);

        let outputs = list_resp["outputs"].as_array().unwrap();
        let total_sats: u64 = outputs
            .iter()
            .map(|o| o["satoshis"].as_u64().unwrap())
            .sum();
        assert_eq!(total_sats, 30000);
    }

    #[tokio::test]
    async fn test_internalize_action_invalid_tx() {
        let state = test_state();
        let body = json!({ "tx": "deadbeef" }); // too short to be a valid tx
        let Json(resp) = internalize_action(State(state), Json(body)).await;
        assert!(resp.get("error").is_some());
    }

    #[tokio::test]
    async fn test_internalize_action_missing_tx() {
        let state = test_state();
        let body = json!({ "description": "no tx field" });
        let Json(resp) = internalize_action(State(state), Json(body)).await;
        assert!(resp.get("error").is_some());
    }

    #[tokio::test]
    async fn test_internalize_action_output_index_out_of_range() {
        let state = test_state();
        let raw_tx = serialize_signed_tx(
            1,
            &[([0xdd; 32], 0, vec![], 0xFFFFFFFF)],
            &[(1000, vec![0x76, 0xa9])],
            0,
        );
        let body = json!({
            "tx": hex::encode(&raw_tx),
            "outputs": [{"outputIndex": 5}], // only 1 output exists
        });
        let Json(resp) = internalize_action(State(state), Json(body)).await;
        assert!(resp.get("error").is_some());
        assert!(resp["error"].as_str().unwrap().contains("out of range"));
    }
}
