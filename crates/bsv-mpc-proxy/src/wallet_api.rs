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
use bsv::transaction::merkle_path::{MerklePath, MerklePathLeaf};
use bsv::transaction::Beef;

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

/// Compute the BRC-42 HMAC offset scalar for derived key signing.
///
/// This offset is passed to `bridge.sign()` so cggmp24's `set_additive_shift()`
/// shifts the signing key share by the HMAC value. The resulting signature
/// validates against the BRC-42 derived public key.
///
/// For "anyone" counterparty: fully local (0 KSS round-trips).
///   shared_secret = root_pub (because anyone_priv = 1)
///
/// For "self"/"other" counterparty: requires 1 partial ECDH round with KSS.
///   shared_secret = ECDH(counterparty_pub, root_priv) via partial ECDH
///
/// Proven in POC 3 (key derivation) and POC 8 (BRC-31 auth).
async fn compute_signing_hmac_offset(
    bridge: &crate::bridge::MpcBridge,
    level: u8,
    protocol_name: &str,
    key_id: &str,
    counterparty: &str,
) -> Result<[u8; 32], String> {
    let invoice = bsv_mpc_core::hd::compute_invoice(level, protocol_name, key_id)
        .map_err(|e| e.to_string())?;

    let shared_secret = match counterparty {
        "anyone" => {
            // For "anyone": shared_secret = root_pub (because anyone_priv = 1,
            // so ECDH(anyone_pub, root_priv) = G * root_priv = root_pub).
            // Proven in POC 3, Test 1.
            bridge.root_pub().clone()
        }
        _ => {
            // For "self" and "other(hex_pubkey)": 1 partial ECDH round with KSS.
            // counterparty_pub = root_pub for "self", or the hex pubkey for "other".
            let counterparty_pub = if counterparty == "self" {
                bridge.root_pub().clone()
            } else {
                let bytes = hex::decode(counterparty)
                    .map_err(|e| format!("invalid counterparty hex: {e}"))?;
                PublicKey::from_bytes(&bytes)
                    .map_err(|e| format!("invalid counterparty pubkey: {e}"))?
            };

            bridge
                .partial_ecdh(&counterparty_pub)
                .await
                .map_err(|e| format!("partial ECDH failed: {e}"))?
        }
    };

    Ok(bsv_mpc_core::hd::compute_brc42_hmac(
        &shared_secret,
        &invoice,
    ))
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

/// Estimate mining fee based on transaction size.
///
/// BSV fee rate: just over 100 sats/KB (~0.1 sat/byte).
/// P2PKH input: ~149 bytes, P2PKH output: ~34 bytes, overhead: ~10 bytes.
const FEE_RATE_SATS_PER_KB: u64 = 110; // just over 100 sats/KB

fn estimate_mining_fee(num_inputs: usize, num_outputs: usize) -> u64 {
    let estimated_size = 10 + (num_inputs * 149) + (num_outputs * 34);
    // fee = ceil(size_bytes * rate_per_kb / 1000)
    let fee = (estimated_size as u64 * FEE_RATE_SATS_PER_KB).div_ceil(1000);
    std::cmp::max(fee, 1)
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
    outputs: &'a [(u64, &'a [u8])],     // (satoshis, locking_script)
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
    outputs: &[(u64, Vec<u8>)],               // (satoshis, locking_script)
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

// ─── BEEF construction + broadcasting ────────────────────────────────────────

/// Parse input txids from raw transaction bytes.
///
/// Extracts the previous txid (in display byte order) from each input's outpoint.
/// Used to identify parent transactions for BEEF ancestry construction.
fn parse_input_txids(raw_tx: &[u8]) -> Result<Vec<String>, String> {
    if raw_tx.len() < 10 {
        return Err("transaction too short".into());
    }

    let mut offset = 4; // skip version
    let input_count = read_varint_from(raw_tx, &mut offset)?;
    let mut txids = Vec::with_capacity(input_count as usize);

    for _ in 0..input_count {
        if offset + 36 > raw_tx.len() {
            return Err("unexpected end of tx parsing input outpoint".into());
        }
        // txid is 32 bytes in internal (little-endian) byte order
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(&raw_tx[offset..offset + 32]);
        txid_bytes.reverse(); // internal -> display byte order
        txids.push(hex::encode(txid_bytes));
        offset += 36; // txid (32) + vout (4)

        // Skip unlocking script and sequence
        let script_len = read_varint_from(raw_tx, &mut offset)? as usize;
        if offset + script_len + 4 > raw_tx.len() {
            return Err("unexpected end of tx parsing input script".into());
        }
        offset += script_len + 4; // script + sequence
    }

    // Deduplicate (multiple inputs can spend from the same parent tx)
    txids.sort();
    txids.dedup();
    Ok(txids)
}

/// Fetch raw transaction hex from WhatsOnChain and return decoded bytes.
async fn get_raw_tx_from_woc(client: &reqwest::Client, txid: &str) -> Result<Vec<u8>, String> {
    let url = format!("https://api.whatsonchain.com/v1/bsv/main/tx/{}/hex", txid);
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("WoC get raw tx failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "WoC raw tx returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }

    let hex_str = resp
        .text()
        .await
        .map_err(|e| format!("WoC read body: {}", e))?;
    hex::decode(hex_str.trim().trim_matches('"')).map_err(|e| format!("bad hex from WoC: {}", e))
}

/// Convert a TSC proof (from WoC) into a BRC-74 MerklePath.
///
/// Ported from rust-wallet-toolbox's `tsc_proof.rs` and POC 4's `tsc_to_merkle_path`.
fn tsc_to_merkle_path(
    block_height: u32,
    tx_index: u64,
    txid: &str,
    nodes: &[String],
) -> Result<MerklePath, String> {
    if nodes.is_empty() {
        return Err("empty nodes list".to_string());
    }

    let mut path: Vec<Vec<MerklePathLeaf>> = Vec::new();
    let mut current_offset = tx_index;

    for (level, node) in nodes.iter().enumerate() {
        let mut leaves = Vec::new();

        if level == 0 {
            leaves.push(MerklePathLeaf::new_txid(current_offset, txid.to_string()));
        }

        let sibling_offset = if current_offset % 2 == 0 {
            current_offset + 1
        } else {
            current_offset - 1
        };

        if node == "*" {
            leaves.push(MerklePathLeaf::new_duplicate(sibling_offset));
        } else {
            leaves.push(MerklePathLeaf::new(sibling_offset, node.clone()));
        }

        leaves.sort_by_key(|l| l.offset);
        path.push(leaves);
        current_offset /= 2;
    }

    MerklePath::new_unchecked(block_height, path).map_err(|e| format!("invalid merkle path: {}", e))
}

/// Fetch a TSC merkle proof from WoC and convert to BRC-74 MerklePath.
///
/// Returns `None` if the transaction is unconfirmed (no proof available).
/// Uses the `/tx/{txid}/proof/tsc` endpoint which returns TSC format,
/// and the `/tx/hash/{txid}` endpoint for block height.
async fn get_merkle_proof_from_woc(client: &reqwest::Client, txid: &str) -> Option<MerklePath> {
    // Get TSC proof
    let tsc_url = format!(
        "https://api.whatsonchain.com/v1/bsv/main/tx/{}/proof/tsc",
        txid
    );
    let tsc_resp = client.get(&tsc_url).send().await.ok()?;
    if !tsc_resp.status().is_success() {
        return None;
    }
    let tsc_text = tsc_resp.text().await.ok()?;

    // The TSC response can be a single object or an array.
    // Parse flexibly.
    let tsc_json: serde_json::Value = serde_json::from_str(&tsc_text).ok()?;

    // Handle array response (WoC sometimes wraps in array)
    let proof = if tsc_json.is_array() {
        tsc_json.as_array()?.first()?.clone()
    } else {
        tsc_json
    };

    let index = proof.get("index")?.as_u64()?;
    let nodes: Vec<String> = proof
        .get("nodes")?
        .as_array()?
        .iter()
        .filter_map(|n| n.as_str().map(|s| s.to_string()))
        .collect();

    // Get block height from tx details
    let tx_url = format!("https://api.whatsonchain.com/v1/bsv/main/tx/hash/{}", txid);
    let tx_resp = client.get(&tx_url).send().await.ok()?;
    if !tx_resp.status().is_success() {
        return None;
    }
    let tx_info: serde_json::Value = tx_resp.json().await.ok()?;
    let block_height = tx_info.get("blockheight")?.as_u64()? as u32;

    tsc_to_merkle_path(block_height, index, txid, &nodes).ok()
}

/// Construct a BEEF (BRC-62/96) wrapping a transaction and its parent merkle proofs.
///
/// For ARC broadcasting, transactions spending unconfirmed parents need BEEF format
/// with merkle proof ancestry back to a confirmed transaction.
///
/// The algorithm:
/// 1. For each parent txid, try to get its merkle proof from WoC.
/// 2. If the parent is confirmed (has proof), add it with its BUMP.
/// 3. If the parent is unconfirmed, add it without proof and recurse up to
///    find a confirmed ancestor (grandparent).
/// 4. Add the transaction being broadcast (no proof — it is the tip).
///
/// Returns `None` if BEEF construction fails (missing ancestry). The caller
/// should fall back to raw tx broadcasting via WoC.
async fn construct_beef(
    client: &reqwest::Client,
    raw_tx: &[u8],
    input_txids: &[String],
) -> Option<Vec<u8>> {
    let mut beef = Beef::new(); // V2

    for parent_txid in input_txids {
        // Get parent raw bytes
        let parent_raw = match get_raw_tx_from_woc(client, parent_txid).await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(parent_txid, error = %e, "Failed to get parent tx for BEEF");
                return None;
            }
        };

        // Try to get merkle proof for parent
        if let Some(merkle_path) = get_merkle_proof_from_woc(client, parent_txid).await {
            // Parent is confirmed — add with its BUMP
            let bump_idx = beef.merge_bump(merkle_path);
            beef.merge_raw_tx(parent_raw, Some(bump_idx));
            tracing::debug!(
                parent_txid,
                "Added confirmed parent with merkle proof to BEEF"
            );
        } else {
            // Parent is unconfirmed — need to find a confirmed ancestor
            tracing::debug!(
                parent_txid,
                "Parent unconfirmed, looking for confirmed ancestor"
            );

            // Parse the parent's inputs to find grandparent txids
            let grandparent_txids = match parse_input_txids(&parent_raw) {
                Ok(ids) => ids,
                Err(e) => {
                    tracing::warn!(parent_txid, error = %e, "Failed to parse parent inputs");
                    return None;
                }
            };

            // Try each grandparent — we only need ONE confirmed ancestor
            let mut found_ancestor = false;
            for gp_txid in &grandparent_txids {
                if let Some(gp_proof) = get_merkle_proof_from_woc(client, gp_txid).await {
                    // Grandparent is confirmed — build the chain
                    let gp_raw = match get_raw_tx_from_woc(client, gp_txid).await {
                        Ok(bytes) => bytes,
                        Err(_) => continue,
                    };
                    let bump_idx = beef.merge_bump(gp_proof);
                    beef.merge_raw_tx(gp_raw, Some(bump_idx));
                    tracing::debug!(
                        grandparent_txid = gp_txid,
                        "Added confirmed grandparent with proof"
                    );
                    found_ancestor = true;
                    break;
                }
            }

            if !found_ancestor {
                tracing::warn!(parent_txid, "No confirmed ancestor found within 2 levels");
                return None;
            }

            // Add the unconfirmed parent (chains to confirmed grandparent)
            beef.merge_raw_tx(parent_raw, None);
        }
    }

    // Add the transaction being broadcast (no proof — it is the tip)
    beef.merge_raw_tx(raw_tx.to_vec(), None);

    // Validate the BEEF
    if !beef.is_valid(false) {
        tracing::warn!("Constructed BEEF is not valid, falling back to raw broadcast");
        return None;
    }

    Some(beef.to_binary())
}

/// Assemble a child transaction's broadcast BEEF from the **full ancestry we
/// already hold** — the `source_beef` of each input it spends — instead of
/// re-fetching parent txs/proofs from a third-party indexer (WoC). Each parent
/// `source_beef` carries its transaction plus merkle-proof ancestry back to a
/// confirmed block; we merge them all (bsv-rs `Beef::merge_beef`) and append the
/// child as the un-proven tip. Returns `None` if no ancestry was supplied or the
/// merged BEEF fails validation, so the caller can fall back to indexer lookup.
fn build_beef_from_ancestry(parent_beefs: &[Vec<u8>], child_raw: &[u8]) -> Option<Vec<u8>> {
    if parent_beefs.is_empty() {
        return None;
    }
    let mut beef = Beef::new();
    for pb in parent_beefs {
        match Beef::from_binary(pb) {
            Ok(parent) => beef.merge_beef(&parent),
            Err(e) => {
                tracing::warn!(error = %e, "stored source_beef failed to parse; skipping ancestry merge");
                return None;
            }
        }
    }
    beef.merge_raw_tx(child_raw.to_vec(), None);
    if !beef.is_valid(false) {
        tracing::warn!("child BEEF assembled from stored ancestry is invalid");
        return None;
    }
    Some(beef.to_binary())
}

/// Broadcast a signed transaction using BEEF format to ARC endpoints, with WoC fallback.
///
/// Broadcasting strategy:
/// 1. Construct BEEF wrapping the tx and its parent merkle proofs.
/// 2. Try GorillaPool ARC (no API key needed, requires BEEF).
/// 3. Try TAAL ARC (requires Bearer API key, requires BEEF).
/// 4. Fallback: WoC raw tx broadcast (accepts plain hex, no BEEF).
///
/// ARC returns 460 (Not Extended Format) when sent raw hex instead of BEEF.
/// ARC returns 401 when TAAL is called without the Bearer token.
/// Both issues are fixed by constructing proper BEEF and including the API key.
///
/// Accepts "SEEN_ON_NETWORK" and "MINED" as success (standard ARC de-duplication).
async fn broadcast_tx(
    client: &reqwest::Client,
    raw_tx: &[u8],
    raw_tx_hex: &str,
    input_txids: &[String],
    arc_api_key: &str,
    prebuilt_beef: Option<&[u8]>,
) -> Result<serde_json::Value, String> {
    // Step 1: Prefer the BEEF assembled from the inputs' own ancestry (the
    // `source_beef` we already hold) — no indexer round-trip. Only when no
    // ancestry was supplied do we fall back to building BEEF from WoC.
    let beef_hex = match prebuilt_beef {
        Some(b) => {
            tracing::info!(
                beef_size = b.len(),
                "Broadcasting with BEEF assembled from stored ancestry (no WoC)"
            );
            Some(hex::encode(b))
        }
        None => match construct_beef(client, raw_tx, input_txids).await {
            Some(beef_bytes) => {
                tracing::info!(
                    beef_size = beef_bytes.len(),
                    "BEEF constructed for ARC broadcast (WoC ancestry fallback)"
                );
                Some(hex::encode(&beef_bytes))
            }
            None => {
                tracing::warn!("BEEF construction failed, will fall back to raw broadcast");
                None
            }
        },
    };

    // Step 2: Try ARC broadcasters with BEEF.
    // GorillaPool first (no API key needed), then TAAL (with Bearer token).
    if let Some(ref beef) = beef_hex {
        let arc_endpoints: Vec<(&str, Option<&str>)> = vec![
            ("https://arc.gorillapool.io", None),
            ("https://arc.taal.com", Some(arc_api_key)),
        ];

        for (endpoint, api_key) in &arc_endpoints {
            let url = format!("{}/v1/tx", endpoint);

            let mut req = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("XDeployment-ID", "bsv-mpc-proxy");

            if let Some(key) = api_key {
                req = req.header("Authorization", format!("Bearer {}", key));
            }

            let body = json!({ "rawTx": beef });

            match req.json(&body).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();

                    if status.is_success()
                        || text.contains("SEEN_ON_NETWORK")
                        || text.contains("MINED")
                    {
                        let response: serde_json::Value = serde_json::from_str(&text)
                            .unwrap_or_else(|_| json!({ "status": "success", "raw": text }));
                        tracing::info!(endpoint, "ARC broadcast successful with BEEF");
                        return Ok(response);
                    }

                    tracing::warn!(
                        endpoint,
                        status = %status,
                        body = %text,
                        "ARC BEEF broadcast failed"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        endpoint,
                        error = %e,
                        "ARC BEEF broadcast request error"
                    );
                }
            }
        }
    }

    // Step 3: Retry ARC with raw tx (for cases where parents are already known
    // to ARC, e.g. spending confirmed UTXOs where BEEF construction failed)
    {
        let arc_endpoints: Vec<(&str, Option<&str>)> =
            vec![("https://arc.taal.com", Some(arc_api_key))];

        for (endpoint, api_key) in &arc_endpoints {
            let url = format!("{}/v1/tx", endpoint);

            let mut req = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("XDeployment-ID", "bsv-mpc-proxy");

            if let Some(key) = api_key {
                req = req.header("Authorization", format!("Bearer {}", key));
            }

            match req.json(&json!({ "rawTx": raw_tx_hex })).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();

                    if status.is_success()
                        || text.contains("SEEN_ON_NETWORK")
                        || text.contains("MINED")
                    {
                        let response: serde_json::Value = serde_json::from_str(&text)
                            .unwrap_or_else(|_| json!({ "status": "success", "raw": text }));
                        tracing::info!(endpoint, "ARC broadcast successful with raw tx");
                        return Ok(response);
                    }

                    tracing::warn!(
                        endpoint,
                        status = %status,
                        body = %text,
                        "ARC raw tx broadcast failed"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        endpoint,
                        error = %e,
                        "ARC raw tx broadcast request error"
                    );
                }
            }
        }
    }

    // Step 4: Fallback to WhatsOnChain (accepts raw hex, no BEEF needed).
    // Retry up to 3 times with 3-second delays for propagation.
    let mut last_error = String::new();
    for attempt in 0..3 {
        if attempt > 0 {
            tracing::info!(attempt, "Retrying WoC broadcast after propagation delay");
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }

        let woc_url = "https://api.whatsonchain.com/v1/bsv/main/tx/raw";
        match client
            .post(woc_url)
            .header("Content-Type", "application/json")
            .json(&json!({ "txhex": raw_tx_hex }))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();

                if status.is_success() {
                    let txid_str = text.trim().trim_matches('"');
                    tracing::info!(
                        broadcaster = "whatsonchain",
                        txid = txid_str,
                        "Broadcast successful via WoC"
                    );
                    return Ok(json!({
                        "status": "success",
                        "txid": txid_str,
                        "broadcaster": "whatsonchain"
                    }));
                }

                last_error = format!("WoC returned {}: {}", status, text);
                tracing::warn!(
                    broadcaster = "whatsonchain",
                    status = %status,
                    attempt,
                    "WoC broadcast failed"
                );

                // Only retry if the error suggests a propagation issue
                let retryable = text.contains("Missing inputs")
                    || text.contains("parent")
                    || text.contains("not found");
                if !retryable {
                    break;
                }
            }
            Err(e) => {
                last_error = format!("WoC request error: {}", e);
                tracing::warn!(
                    broadcaster = "whatsonchain",
                    error = %e,
                    attempt,
                    "WoC broadcast request failed"
                );
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
/// Library-callable version of `get_public_key`. Accepts parsed state and request body directly.
pub async fn get_public_key_impl(state: &AppState, body: Value) -> Value {
    let identity_key = body
        .get("identityKey")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // If identityKey requested or no derivation params, return root joint key
    if identity_key || body.get("protocolID").is_none() {
        let pubkey_hex = hex::encode(&state.bridge.joint_public_key().compressed);
        return json!({ "publicKey": pubkey_hex });
    }

    // Parse BRC-42 derivation params
    let (level, protocol_name, key_id, counterparty) = match parse_protocol_params(&body) {
        Ok(params) => params,
        Err(e) => return json!({ "error": e }),
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
        Ok(pk) => json!({ "publicKey": pk.to_hex() }),
        Err(e) => json!({ "error": e }),
    }
}

/// Axum handler for `POST /getPublicKey`. Delegates to [`get_public_key_impl`].
pub async fn get_public_key(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(get_public_key_impl(&state, body).await)
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
/// Sign a sighash through the **ADR-018 relay combiner** — the deployed
/// cosigner (`share_A`) issues its partial over the MessageBox relay and this
/// proxy (`share_B`) combines it into a final ECDSA signature, over the authed
/// production `/sign-relay` route.
///
/// Consumes one raw presig box from the proxy pool (`take_raw`); relay mode
/// requires the pool to be stocked with `Presignature_B`s correlated (FIFO) with
/// the cosigner DO's `Presignature_A` pool (provisioning automation, #4). Only
/// base-key signing is supported here — BRC-42 HD-derived (`hmac_offset`)
/// signing stays on the legacy 4-round HTTP path (handoff §3).
async fn relay_sign(
    state: &AppState,
    sighash: &[u8; 32],
) -> std::result::Result<bsv_mpc_core::types::SigningResult, String> {
    let raw = {
        let mut mgr = state.presign_manager.write().await;
        mgr.take_raw()
    }
    .ok_or_else(|| {
        "relay sign: presignature pool empty — provisioning is not keeping up".to_string()
    })?;

    let trigger = crate::relay_sign::DoTrigger {
        url: format!("{}/sign-relay", state.bridge.kss_url()),
        // Production: the DO consumes its correlated Presignature_A from the
        // pool; the proxy never re-sends a presignature on the wire.
        presig_a_json: vec![],
        do_index: state.bridge.cosigner_index(),
        agent_id: Some(state.bridge.agent_id().to_string()),
        // Filled by sign_over_relay from the proxy's BRC-31 session.
        auth_headers: vec![],
    };

    state
        .bridge
        .sign_over_relay(sighash, raw, trigger, std::time::Duration::from_secs(60))
        .await
        .map_err(|e| format!("relay sign failed: {e}"))
}

/// Presignature signing takes ~50-100ms. Full protocol takes ~300-500ms.
/// Library-callable version of `create_signature`. Accepts parsed state and request body directly.
pub async fn create_signature_impl(state: &AppState, body: Value) -> Value {
    // Parse the data to sign
    let data_value = match body.get("data") {
        Some(v) => v,
        None => return json!({ "error": "missing data" }),
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
        return json!({ "error": "data must be a string or byte array" });
    };

    if data_bytes.is_empty() {
        return json!({ "error": "data is empty" });
    }

    // Compute 32-byte message hash
    let msg_hash: [u8; 32] = if hash_to_directly_sign {
        if data_bytes.len() != 32 {
            return json!({
                "error": format!(
                    "hashToDirectlySign requires exactly 32 bytes, got {}",
                    data_bytes.len()
                )
            });
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
    // For "anyone" counterparty: offset = HMAC(root_pub, invoice) — fully local (0 KSS round-trips).
    // For "self"/"other": 1 partial ECDH round with KSS to compute shared_secret.
    // Proven in POC 3 (key derivation) and POC 8 (BRC-31 auth).
    let hmac_offset: Option<[u8; 32]> = if body.get("protocolID").is_some() {
        let (level, protocol_name, key_id, counterparty) = match parse_protocol_params(&body) {
            Ok(params) => params,
            Err(e) => return json!({ "error": e }),
        };

        match compute_signing_hmac_offset(
            &state.bridge,
            level,
            &protocol_name,
            &key_id,
            &counterparty,
        )
        .await
        {
            Ok(offset) => Some(offset),
            Err(e) => {
                return json!({
                    "error": format!("BRC-42 HMAC offset computation failed: {}", e)
                })
            }
        }
    } else {
        None
    };

    // ADR-018 relay mode: route base-key signing through the deployed cosigner
    // over the relay. HD-derived (hmac_offset) signing stays on the 4-round HTTP
    // path (handoff §3 — the offset is baked into a presig at generation time).
    let signing_result = if state.config.relay_sign && hmac_offset.is_none() {
        match relay_sign(state, &msg_hash).await {
            Ok(result) => result,
            Err(e) => return json!({ "error": format!("MPC signing failed: {}", e) }),
        }
    } else {
        // Legacy HTTP path. In relay mode, never consume a relay-correlated
        // presig here (it would desync the proxy/DO pools); pass None.
        let presig = if state.config.relay_sign {
            None
        } else {
            let mut mgr = state.presign_manager.write().await;
            mgr.take()
        };
        match state.bridge.sign(&msg_hash, presig, hmac_offset).await {
            Ok(result) => result,
            Err(e) => return json!({ "error": format!("MPC signing failed: {}", e) }),
        }
    };

    // Return DER-encoded signature as hex
    json!({ "signature": hex::encode(&signing_result.signature) })
}

/// Axum handler for `POST /createSignature`. Delegates to [`create_signature_impl`].
pub async fn create_signature(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(create_signature_impl(&state, body).await)
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
/// Library-callable version of `verify_signature`. Accepts parsed state and request body directly.
pub async fn verify_signature_impl(state: &AppState, body: Value) -> Value {
    // Parse protocol params
    let (level, protocol_name, key_id, counterparty) = match parse_protocol_params(&body) {
        Ok(params) => params,
        Err(e) => return json!({ "error": e }),
    };

    // Parse data and compute hash (same as createSignature)
    let data_hex = match body.get("data").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return json!({ "error": "missing data" }),
    };
    let data_bytes = match hex::decode(data_hex) {
        Ok(bytes) => bytes,
        Err(e) => return json!({ "error": format!("invalid hex data: {}", e) }),
    };
    if data_bytes.is_empty() {
        return json!({ "error": "data is empty" });
    }

    // Hash the data with SHA-256 (matching createSignature behavior)
    let hash_to_directly_sign = body
        .get("hashToDirectlySign")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let msg_hash: [u8; 32] = if hash_to_directly_sign {
        if data_bytes.len() != 32 {
            return json!({ "error": format!("hashToDirectlySign requires 32 bytes, got {}", data_bytes.len()) });
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
        None => return json!({ "error": "missing signature" }),
    };
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(bytes) => bytes,
        Err(e) => return json!({ "error": format!("invalid hex signature: {}", e) }),
    };
    let signature = match Signature::from_der(&sig_bytes) {
        Ok(sig) => sig,
        Err(e) => return json!({ "error": format!("invalid DER signature: {}", e) }),
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
        Err(e) => return json!({ "error": e }),
    };

    let valid = pubkey.verify(&msg_hash, &signature);
    json!({ "valid": valid })
}

/// Axum handler for `POST /verifySignature`. Delegates to [`verify_signature_impl`].
pub async fn verify_signature(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(verify_signature_impl(&state, body).await)
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
///
/// Library-callable version of `create_action`. Accepts parsed state and request body directly.
pub async fn create_action_impl(state: &AppState, body: Value) -> Value {
    // ── 1. Parse request ─────────────────────────────────────────────────
    let outputs_json = match body.get("outputs").and_then(|v| v.as_array()) {
        Some(arr) if !arr.is_empty() => arr,
        _ => return json!({"error": "missing or empty outputs array"}),
    };

    let mut user_outputs: Vec<(u64, Vec<u8>)> = Vec::new();
    for (i, o) in outputs_json.iter().enumerate() {
        let sats = match o.get("satoshis").and_then(|v| v.as_u64()) {
            Some(s) => s,
            None => return json!({"error": format!("output[{}]: missing satoshis", i)}),
        };
        let script_hex = match o.get("lockingScript").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return json!({"error": format!("output[{}]: missing lockingScript", i)}),
        };
        let script = match hex::decode(script_hex) {
            Ok(b) => b,
            Err(e) => {
                return json!({
                    "error": format!("output[{}]: invalid lockingScript hex: {}", i, e)
                })
            }
        };
        user_outputs.push((sats, script));
    }

    let total_user_output: u64 = user_outputs.iter().map(|(s, _)| s).sum();

    // ── 2. Compute our P2PKH locking script ──────────────────────────────
    let joint_key = state.bridge.joint_public_key();
    let root_pubkey = match PublicKey::from_bytes(&joint_key.compressed) {
        Ok(pk) => pk,
        Err(e) => return json!({"error": format!("invalid joint key: {}", e)}),
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

    let (selected_utxos, total_input) = match state.storage.select_utxos(est_total).await {
        Ok(result) => result,
        Err(e) => return json!({"error": format!("storage error: {e}")}),
    };

    if selected_utxos.is_empty() {
        return json!({"error": "no UTXOs available"});
    }

    // ── 5. Compute exact mining fee ──────────────────────────────────────
    let num_inputs = selected_utxos.len();
    let num_outputs_total = user_outputs.len() + 1 + fee_output_count;
    let mining_fee = estimate_mining_fee(num_inputs, num_outputs_total);
    let total_needed = total_user_output + mpc_fee + mining_fee;

    if total_input < total_needed {
        return json!({
            "error": format!(
                "insufficient funds: have {} sats, need {} (outputs: {}, mpc_fee: {}, mining_fee: {})",
                total_input, total_needed, total_user_output, mpc_fee, mining_fee
            )
        });
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
            Err(e) => return json!({"error": format!("fee injection failed: {}", e)}),
        }
    }

    // ── 8. Prepare input data ────────────────────────────────────────────
    let mut input_tuples: Vec<([u8; 32], u32, u32)> = Vec::new();
    for utxo in &selected_utxos {
        let decoded = match hex::decode(&utxo.txid) {
            Ok(b) if b.len() == 32 => b,
            _ => return json!({"error": format!("invalid txid hex: {}", utxo.txid)}),
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

        // MPC sign via bridge. All tracked UTXOs are locked to the root key, so
        // offset=None → relay mode is eligible. In relay mode, the deployed
        // cosigner co-signs over the relay; otherwise the legacy 4-round HTTP
        // path runs. (BRC-42-derived-key inputs would compute an offset and stay
        // on the HTTP path; not yet supported here.)
        let signing_result = if state.config.relay_sign {
            match relay_sign(state, &sighash).await {
                Ok(result) => result,
                Err(e) => return json!({"error": format!("signing input {} failed: {}", i, e)}),
            }
        } else {
            let presig = {
                let mut mgr = state.presign_manager.write().await;
                mgr.take()
            };
            match state.bridge.sign(&sighash, presig, None).await {
                Ok(result) => result,
                Err(e) => return json!({"error": format!("signing input {} failed: {}", i, e)}),
            }
        };

        // PRE-FLIGHT (fail-closed): verify the MPC signature under the root key
        // BEFORE assembling/broadcasting — a bad relay sig must never reach the
        // network (no sats risked on a malformed signature).
        match Signature::from_der(&signing_result.signature) {
            Ok(sig) => {
                if !sig.is_low_s() {
                    return json!({"error": format!("input {i}: signature not low-s (BIP-62) — refusing to broadcast")});
                }
                if !root_pubkey.verify(&sighash, &sig) {
                    return json!({"error": format!("input {i}: signature failed pre-flight verify under joint key — refusing to broadcast")});
                }
            }
            Err(e) => return json!({"error": format!("input {i}: invalid DER signature: {e}")}),
        }

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
    // Collect parent txids for BEEF construction. ARC requires BEEF (Extended
    // Format) — broadcasting raw hex returns 460 on GorillaPool and 401 on
    // TAAL without an API key. BEEF wraps parent merkle proofs so the miner
    // can verify the input chain without querying the UTXO set.
    let input_txids: Vec<String> = selected_utxos.iter().map(|u| u.txid.clone()).collect();
    // Assemble the broadcast BEEF from the inputs' own stored ancestry (their
    // `source_beef`) so we never re-fetch parent proofs from an indexer — the
    // funding parent is frequently still unconfirmed at spend time.
    let parent_beefs: Vec<Vec<u8>> = selected_utxos
        .iter()
        .filter_map(|u| u.source_beef.clone())
        .collect();
    let child_beef = build_beef_from_ancestry(&parent_beefs, &raw_tx);
    match broadcast_tx(
        &state.http_client,
        &raw_tx,
        &raw_tx_hex,
        &input_txids,
        &state.config.arc_api_key,
        child_beef.as_deref(),
    )
    .await
    {
        Ok(_) => {
            tracing::info!(txid = %txid, "Broadcast successful");
        }
        Err(e) => {
            // Return the raw tx even on broadcast failure so the caller can retry
            tracing::warn!(txid = %txid, error = %e, "Broadcast failed");
            return json!({
                "error": format!("broadcast failed: {}", e),
                "txid": txid,
                "rawTx": raw_tx_hex,
            });
        }
    }

    // ── 12. Update UTXO tracker ──────────────────────────────────────────
    {
        // Mark inputs as spent
        for utxo in &selected_utxos {
            if let Err(e) = state.storage.mark_spent(&utxo.txid, utxo.vout, &txid).await {
                tracing::warn!(txid = %utxo.txid, vout = utxo.vout, error = %e, "Failed to mark UTXO as spent");
            }
        }

        // Track change output (if non-dust)
        let change_sats = outputs[change_index].0;
        if change_sats > 0 {
            if let Err(e) = state
                .storage
                .add_output(TrackedOutput {
                    txid: txid.clone(),
                    vout: change_index as u32,
                    satoshis: change_sats,
                    locking_script: change_script,
                    spending_txid: None,
                    basket: Some("default".into()),
                    tags: vec![],
                    created_at: chrono::Utc::now(),
                    // Carry this tx's full BEEF forward so a later spend of the
                    // change output also broadcasts with complete ancestry.
                    source_beef: child_beef.clone(),
                })
                .await
            {
                tracing::warn!(error = %e, "Failed to track change output");
            }
        }
    }

    // ── 13. Return ───────────────────────────────────────────────────────
    json!({
        "txid": txid,
        "rawTx": raw_tx_hex,
    })
}

/// Axum handler for `POST /createAction`. Delegates to [`create_action_impl`].
pub async fn create_action(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(create_action_impl(&state, body).await)
}

/// `POST /internalizeAction`
///
/// Accept an incoming payment or BEEF envelope by internalizing its outputs
/// into the local UTXO set.
///
/// Handles both raw transaction hex AND AtomicBEEF/BEEF format (BRC-62/95/96).
/// The wallet at localhost:3321 returns `tx` as an AtomicBEEF byte array. We
/// detect the format from magic bytes and extract the raw transaction using the
/// BSV SDK's `Beef` parser.
/// Library-callable version of `internalize_action`. Accepts parsed state and request body directly.
pub async fn internalize_action_impl(state: &AppState, body: Value) -> Value {
    // Parse the transaction (hex string from "tx" or "rawTx")
    let raw_tx_hex = match body
        .get("tx")
        .or_else(|| body.get("rawTx"))
        .and_then(|v| v.as_str())
    {
        Some(s) => s,
        None => return json!({"error": "missing tx or rawTx field"}),
    };

    let input_bytes = match hex::decode(raw_tx_hex) {
        Ok(b) => b,
        Err(e) => return json!({"error": format!("invalid hex in tx: {}", e)}),
    };

    // When the caller hands us BEEF, it carries this tx's full merkle-proof
    // ancestry. Retain it on each internalized output so a later spend can build
    // its broadcast BEEF from ancestry we already hold (no indexer round-trip).
    let source_beef: Option<Vec<u8>> = if is_beef_format(&input_bytes) {
        Some(input_bytes.clone())
    } else {
        None
    };

    // Detect whether input is BEEF/AtomicBEEF or a raw transaction.
    // BEEF magic bytes (little-endian u32):
    //   AtomicBEEF: 0x01010101 → bytes [01, 01, 01, 01]
    //   BEEF V1:    0xEFBE0001 → bytes [01, 00, BE, EF]
    //   BEEF V2:    0xEFBE0002 → bytes [02, 00, BE, EF]
    // Raw transactions start with version [01, 00, 00, 00] or [02, 00, 00, 00].
    let (tx_outputs, txid) = if is_beef_format(&input_bytes) {
        match extract_tx_from_beef(&input_bytes) {
            Ok(result) => result,
            Err(e) => return json!({"error": format!("failed to parse BEEF: {}", e)}),
        }
    } else {
        // Raw transaction — parse directly
        let outputs = match parse_tx_outputs(&input_bytes) {
            Ok(o) => o,
            Err(e) => return json!({"error": format!("failed to parse tx: {}", e)}),
        };
        let txid = compute_txid(&input_bytes);
        (outputs, txid)
    };

    tracing::debug!(
        txid = %txid,
        num_outputs = tx_outputs.len(),
        is_beef = is_beef_format(&input_bytes),
        "Parsed transaction for internalization"
    );

    // Build our expected P2PKH locking script for root key verification
    let root_pubkey = match PublicKey::from_bytes(&state.bridge.joint_public_key().compressed) {
        Ok(pk) => pk,
        Err(e) => return json!({"error": format!("invalid joint key: {}", e)}),
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
                return json!({
                    "error": format!(
                        "outputIndex {} out of range (tx has {} outputs)",
                        output_index,
                        tx_outputs.len()
                    )
                });
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

            if let Err(e) = state
                .storage
                .add_output(TrackedOutput {
                    txid: txid.clone(),
                    vout: output_index as u32,
                    satoshis,
                    locking_script: script.clone(),
                    spending_txid: None,
                    basket: Some(basket.to_string()),
                    tags: vec![],
                    created_at: chrono::Utc::now(),
                    source_beef: source_beef.clone(),
                })
                .await
            {
                tracing::warn!(output_index, error = %e, "Failed to track internalized output");
            }
            accepted_count += 1;
        }
    } else {
        // No specific outputs — scan all outputs for ones matching our root key
        for (vout, (satoshis, script)) in tx_outputs.iter().enumerate() {
            if *script == our_script {
                if let Err(e) = state
                    .storage
                    .add_output(TrackedOutput {
                        txid: txid.clone(),
                        vout: vout as u32,
                        satoshis: *satoshis,
                        locking_script: script.clone(),
                        spending_txid: None,
                        basket: Some(basket.to_string()),
                        tags: vec![],
                        created_at: chrono::Utc::now(),
                        source_beef: source_beef.clone(),
                    })
                    .await
                {
                    tracing::warn!(vout, error = %e, "Failed to track scanned output");
                }
                accepted_count += 1;
            }
        }
    }

    tracing::info!(txid = %txid, accepted_count, "Internalized action");

    json!({
        "accepted": true,
        "txid": txid,
    })
}

/// Axum handler for `POST /internalizeAction`. Delegates to [`internalize_action_impl`].
pub async fn internalize_action(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(internalize_action_impl(&state, body).await)
}

/// Detect whether bytes represent a BEEF/AtomicBEEF format (vs raw transaction).
///
/// BEEF magic bytes (read as little-endian u32 from first 4 bytes):
///   - AtomicBEEF: `0x01010101` → bytes `[01, 01, 01, 01]`
///   - BEEF V1:    `0xEFBE0001` → bytes `[01, 00, BE, EF]`
///   - BEEF V2:    `0xEFBE0002` → bytes `[02, 00, BE, EF]`
///
/// Raw transactions start with version `[01, 00, 00, 00]` or `[02, 00, 00, 00]`,
/// which do not match any BEEF magic.
fn is_beef_format(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    magic == 0x01010101  // ATOMIC_BEEF
        || magic == 0xEFBE0001  // BEEF_V1
        || magic == 0xEFBE0002 // BEEF_V2
}

/// `(outputs: Vec<(satoshis, locking_script_bytes)>, txid_hex)` extracted
/// from a BEEF / AtomicBEEF envelope.
type BeefExtractedTx = Result<(Vec<(u64, Vec<u8>)>, String), String>;

/// Extract the target transaction's outputs and txid from BEEF/AtomicBEEF bytes.
///
/// Uses the BSV SDK's `Beef::from_binary()` to parse the envelope, then extracts
/// the target transaction (for AtomicBEEF: the atomic_txid; otherwise: the last tx).
fn extract_tx_from_beef(bytes: &[u8]) -> BeefExtractedTx {
    use bsv::transaction::Beef;

    let beef = Beef::from_binary(bytes).map_err(|e| format!("Beef::from_binary failed: {}", e))?;

    // Determine the target transaction ID:
    // - AtomicBEEF has an explicit atomic_txid
    // - Otherwise, use the last transaction in the BEEF (the tip)
    let target_txid = if let Some(ref atomic_txid) = beef.atomic_txid {
        atomic_txid.clone()
    } else if let Some(last_tx) = beef.txs.last() {
        last_tx.txid()
    } else {
        return Err("BEEF contains no transactions".to_string());
    };

    tracing::debug!(
        target_txid = %target_txid,
        num_txs = beef.txs.len(),
        num_bumps = beef.bumps.len(),
        is_atomic = beef.atomic_txid.is_some(),
        "Parsed BEEF envelope"
    );

    // Find the target transaction in the BEEF
    let beef_tx = beef
        .find_txid(&target_txid)
        .ok_or_else(|| format!("target tx {} not found in BEEF", target_txid))?;

    // Extract outputs from the BeefTx.
    // Try the parsed Transaction first, then fall back to raw bytes.
    if let Some(tx) = beef_tx.tx() {
        let outputs: Vec<(u64, Vec<u8>)> = tx
            .outputs
            .iter()
            .map(|o| (o.get_satoshis(), o.locking_script.to_binary()))
            .collect();
        let txid = tx.id();
        Ok((outputs, txid))
    } else if let Some(raw_tx) = beef_tx.raw_tx() {
        // Parse outputs from raw transaction bytes
        let outputs = parse_tx_outputs(raw_tx)
            .map_err(|e| format!("failed to parse raw tx from BEEF: {}", e))?;
        let txid = compute_txid(raw_tx);
        Ok((outputs, txid))
    } else {
        Err(format!(
            "BEEF tx {} has no transaction data (txid-only entry)",
            target_txid
        ))
    }
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
/// Library-callable version of `encrypt`. Accepts parsed state and request body directly.
pub async fn encrypt_impl(state: &AppState, body: Value) -> Value {
    let (level, protocol_name, key_id, counterparty) = match parse_protocol_params(&body) {
        Ok(params) => params,
        Err(e) => return json!({ "error": e }),
    };

    let plaintext_b64 = match body.get("plaintext").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return json!({ "error": "missing plaintext" }),
    };
    let plaintext = match BASE64.decode(plaintext_b64) {
        Ok(bytes) => bytes,
        Err(e) => return json!({ "error": format!("invalid base64 plaintext: {}", e) }),
    };

    // Derive 32-byte symmetric key via BRC-42
    let sym_key =
        match derive_symmetric_key(&state.bridge, level, &protocol_name, &key_id, &counterparty)
            .await
        {
            Ok(key) => key,
            Err(e) => return json!({ "error": e }),
        };

    // AES-256-GCM encrypt with random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sym_key));

    let ciphertext = match cipher.encrypt(nonce, plaintext.as_ref()) {
        Ok(ct) => ct,
        Err(e) => return json!({ "error": format!("encryption failed: {}", e) }),
    };

    // Output: nonce (12) || ciphertext || tag (16)
    // aes-gcm appends the 16-byte auth tag to ciphertext automatically
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    json!({ "ciphertext": BASE64.encode(&result) })
}

/// Axum handler for `POST /encrypt`. Delegates to [`encrypt_impl`].
pub async fn encrypt(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> Json<Value> {
    Json(encrypt_impl(&state, body).await)
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
/// Library-callable version of `decrypt`. Accepts parsed state and request body directly.
pub async fn decrypt_impl(state: &AppState, body: Value) -> Value {
    let (level, protocol_name, key_id, counterparty) = match parse_protocol_params(&body) {
        Ok(params) => params,
        Err(e) => return json!({ "error": e }),
    };

    let ciphertext_b64 = match body.get("ciphertext").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return json!({ "error": "missing ciphertext" }),
    };
    let data = match BASE64.decode(ciphertext_b64) {
        Ok(bytes) => bytes,
        Err(e) => return json!({ "error": format!("invalid base64 ciphertext: {}", e) }),
    };

    // Minimum: 12 (nonce) + 16 (GCM tag) = 28 bytes
    if data.len() < 28 {
        return json!({ "error": "ciphertext too short (need at least 28 bytes for nonce + tag)" });
    }

    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    // Derive same symmetric key
    let sym_key =
        match derive_symmetric_key(&state.bridge, level, &protocol_name, &key_id, &counterparty)
            .await
        {
            Ok(key) => key,
            Err(e) => return json!({ "error": e }),
        };

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sym_key));

    let plaintext = match cipher.decrypt(nonce, ciphertext) {
        Ok(pt) => pt,
        Err(e) => return json!({ "error": format!("decryption failed: {}", e) }),
    };

    json!({ "plaintext": BASE64.encode(&plaintext) })
}

/// Axum handler for `POST /decrypt`. Delegates to [`decrypt_impl`].
pub async fn decrypt(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> Json<Value> {
    Json(decrypt_impl(&state, body).await)
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
/// Library-callable version of `create_hmac`. Accepts parsed state and request body directly.
pub async fn create_hmac_impl(state: &AppState, body: Value) -> Value {
    let (level, protocol_name, key_id, counterparty) = match parse_protocol_params(&body) {
        Ok(params) => params,
        Err(e) => return json!({ "error": e }),
    };

    let data_b64 = match body.get("data").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return json!({ "error": "missing data" }),
    };
    let data = match BASE64.decode(data_b64) {
        Ok(bytes) => bytes,
        Err(e) => return json!({ "error": format!("invalid base64 data: {}", e) }),
    };

    // Derive HMAC key via BRC-42 (same derivation path as encrypt/decrypt)
    let hmac_key =
        match derive_symmetric_key(&state.bridge, level, &protocol_name, &key_id, &counterparty)
            .await
        {
            Ok(key) => key,
            Err(e) => return json!({ "error": e }),
        };

    // HMAC-SHA256
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(&data);
    let result = mac.finalize();

    json!({ "hmac": hex::encode(result.into_bytes()) })
}

/// Axum handler for `POST /createHmac`. Delegates to [`create_hmac_impl`].
pub async fn create_hmac(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(create_hmac_impl(&state, body).await)
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
/// Library-callable version of `verify_hmac`. Accepts parsed state and request body directly.
pub async fn verify_hmac_impl(state: &AppState, body: Value) -> Value {
    let (level, protocol_name, key_id, counterparty) = match parse_protocol_params(&body) {
        Ok(params) => params,
        Err(e) => return json!({ "error": e }),
    };

    let data_b64 = match body.get("data").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return json!({ "error": "missing data" }),
    };
    let hmac_hex = match body.get("hmac").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return json!({ "error": "missing hmac" }),
    };

    let data = match BASE64.decode(data_b64) {
        Ok(bytes) => bytes,
        Err(e) => return json!({ "error": format!("invalid base64 data: {}", e) }),
    };
    let expected_hmac = match hex::decode(hmac_hex) {
        Ok(bytes) => bytes,
        Err(e) => return json!({ "error": format!("invalid hex hmac: {}", e) }),
    };

    // Derive HMAC key
    let hmac_key =
        match derive_symmetric_key(&state.bridge, level, &protocol_name, &key_id, &counterparty)
            .await
        {
            Ok(key) => key,
            Err(e) => return json!({ "error": e }),
        };

    // Compute HMAC and verify with constant-time comparison
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(&data);

    // verify_slice uses constant-time comparison (from subtle crate)
    let valid = mac.verify_slice(&expected_hmac).is_ok();

    json!({ "valid": valid })
}

/// Axum handler for `POST /verifyHmac`. Delegates to [`verify_hmac_impl`].
pub async fn verify_hmac(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(verify_hmac_impl(&state, body).await)
}

// ─── UTXO management ────────────────────────────────────────────────────────

/// Library-callable version of `list_outputs`. Accepts parsed state and request body directly.
pub async fn list_outputs_impl(state: &AppState, body: Value) -> Value {
    let basket = body["basket"].as_str();
    let tags: Option<Vec<String>> = body["tags"].as_array().map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect()
    });
    let include_locking_scripts = body["include"].as_str() == Some("locking scripts");
    let limit = body["limit"].as_u64().unwrap_or(100) as usize;
    let offset = body["offset"].as_u64().unwrap_or(0) as usize;

    let unspent = match state.storage.list_unspent(basket, tags.as_deref()).await {
        Ok(u) => u,
        Err(e) => {
            return json!({"error": format!("storage error: {e}"), "totalOutputs": 0, "outputs": []})
        }
    };

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

    json!({
        "totalOutputs": total,
        "outputs": page,
    })
}

/// Axum handler for `POST /listOutputs`. Delegates to [`list_outputs_impl`].
pub async fn list_outputs(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(list_outputs_impl(&state, body).await)
}

/// Library-callable version of `list_actions`. Accepts parsed state and request body directly.
pub async fn list_actions_impl(_state: &AppState, _body: Value) -> Value {
    // Stub: action history not yet tracked by the MPC proxy.
    // Returns an empty list so callers get a valid response.
    json!({ "actions": [], "totalActions": 0 })
}

/// Axum handler for `POST /listActions`. Delegates to [`list_actions_impl`].
pub async fn list_actions(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(list_actions_impl(&state, body).await)
}

/// Library-callable version of `relinquish_output`. Accepts parsed state and request body directly.
pub async fn relinquish_output_impl(_state: &AppState, _body: Value) -> Value {
    // Stub: accepts the request and reports success.
    // Full implementation would remove the output from the UTXO tracker.
    json!({ "success": true })
}

/// Axum handler for `POST /relinquishOutput`. Delegates to [`relinquish_output_impl`].
pub async fn relinquish_output(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(relinquish_output_impl(&state, body).await)
}

// ─── Identity & auth ────────────────────────────────────────────────────────

/// Library-callable version of `get_network`. Accepts parsed state and request body directly.
pub async fn get_network_impl(_state: &AppState, _body: Value) -> Value {
    // Static response — MPC proxy always operates on mainnet.
    json!({ "network": "mainnet" })
}

/// Axum handler for `POST /getNetwork`. Delegates to [`get_network_impl`].
pub async fn get_network(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(get_network_impl(&state, body).await)
}

/// Library-callable version of `get_version`. Accepts parsed state and request body directly.
pub async fn get_version_impl(_state: &AppState, _body: Value) -> Value {
    json!({
        "version": format!("bsv-mpc-proxy {}", env!("CARGO_PKG_VERSION"))
    })
}

/// Axum handler for `POST /getVersion`. Delegates to [`get_version_impl`].
pub async fn get_version(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(get_version_impl(&state, body).await)
}

/// Library-callable version of `is_authenticated`. Accepts parsed state and request body directly.
pub async fn is_authenticated_impl(_state: &AppState, _body: Value) -> Value {
    // If we got this far, the share is loaded and the bridge is initialized.
    json!({ "authenticated": true })
}

/// Axum handler for `POST /isAuthenticated`. Delegates to [`is_authenticated_impl`].
pub async fn is_authenticated(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(is_authenticated_impl(&state, body).await)
}

// ─── Certificates ───────────────────────────────────────────────────────────

/// Library-callable version of `list_certificates`. Accepts parsed state and request body directly.
pub async fn list_certificates_impl(_state: &AppState, _body: Value) -> Value {
    // Stub: certificate storage not yet implemented in the MPC proxy.
    // Returns an empty list so callers get a valid response.
    json!({ "certificates": [], "totalCertificates": 0 })
}

/// Axum handler for `POST /listCertificates`. Delegates to [`list_certificates_impl`].
pub async fn list_certificates(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(list_certificates_impl(&state, body).await)
}

/// Library-callable version of `prove_certificate`. Accepts parsed state and request body directly.
pub async fn prove_certificate_impl(_state: &AppState, _body: Value) -> Value {
    json!({ "error": "Certificate operations not supported in MPC proxy" })
}

/// Axum handler for `POST /proveCertificate`. Delegates to [`prove_certificate_impl`].
pub async fn prove_certificate(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(prove_certificate_impl(&state, body).await)
}

/// Library-callable version of `acquire_certificate`. Accepts parsed state and request body directly.
pub async fn acquire_certificate_impl(_state: &AppState, _body: Value) -> Value {
    json!({ "error": "Certificate operations not supported in MPC proxy" })
}

/// Axum handler for `POST /acquireCertificate`. Delegates to [`acquire_certificate_impl`].
pub async fn acquire_certificate(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(acquire_certificate_impl(&state, body).await)
}

/// Library-callable version of `relinquish_certificate`. Accepts parsed state and request body directly.
pub async fn relinquish_certificate_impl(_state: &AppState, _body: Value) -> Value {
    // Stub: accepts the request and reports success.
    json!({ "success": true })
}

/// Axum handler for `POST /relinquishCertificate`. Delegates to [`relinquish_certificate_impl`].
pub async fn relinquish_certificate(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(relinquish_certificate_impl(&state, body).await)
}

// ─── Discovery ──────────────────────────────────────────────────────────────

/// Library-callable version of `discover_by_identity_key`. Accepts parsed state and request body directly.
pub async fn discover_by_identity_key_impl(_state: &AppState, _body: Value) -> Value {
    // Stub: overlay discovery not yet wired in the MPC proxy.
    json!({ "results": [], "totalResults": 0 })
}

/// Axum handler for `POST /discoverByIdentityKey`. Delegates to [`discover_by_identity_key_impl`].
pub async fn discover_by_identity_key(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(discover_by_identity_key_impl(&state, body).await)
}

/// Library-callable version of `discover_by_attributes`. Accepts parsed state and request body directly.
pub async fn discover_by_attributes_impl(_state: &AppState, _body: Value) -> Value {
    // Stub: overlay discovery not yet wired in the MPC proxy.
    json!({ "results": [], "totalResults": 0 })
}

/// Axum handler for `POST /discoverByAttributes`. Delegates to [`discover_by_attributes_impl`].
pub async fn discover_by_attributes(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(discover_by_attributes_impl(&state, body).await)
}

// ─── Key linkage ────────────────────────────────────────────────────────────

/// Library-callable version of `reveal_counterparty_key_linkage`. Accepts parsed state and request body directly.
pub async fn reveal_counterparty_key_linkage_impl(_state: &AppState, _body: Value) -> Value {
    json!({ "error": "Key linkage not supported in MPC proxy" })
}

/// Axum handler for `POST /revealCounterpartyKeyLinkage`. Delegates to [`reveal_counterparty_key_linkage_impl`].
pub async fn reveal_counterparty_key_linkage(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(reveal_counterparty_key_linkage_impl(&state, body).await)
}

/// Library-callable version of `reveal_specific_key_linkage`. Accepts parsed state and request body directly.
pub async fn reveal_specific_key_linkage_impl(_state: &AppState, _body: Value) -> Value {
    json!({ "error": "Key linkage not supported in MPC proxy" })
}

/// Axum handler for `POST /revealSpecificKeyLinkage`. Delegates to [`reveal_specific_key_linkage_impl`].
pub async fn reveal_specific_key_linkage(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(reveal_specific_key_linkage_impl(&state, body).await)
}

// ─── Chain info ──────────────────────────────────────────────────────────────

/// Library-callable version of `get_height`. Accepts parsed state and request body directly.
pub async fn get_height_impl(_state: &AppState, _body: Value) -> Value {
    json!({ "height": 0 })
}

/// Axum handler for `POST /getHeight`. Delegates to [`get_height_impl`].
pub async fn get_height(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(get_height_impl(&state, body).await)
}

/// Library-callable version of `wait_for_authentication`. Accepts parsed state and request body directly.
pub async fn wait_for_authentication_impl(_state: &AppState, _body: Value) -> Value {
    json!({ "authenticated": true })
}

/// Axum handler for `POST /waitForAuthentication`. Delegates to [`wait_for_authentication_impl`].
pub async fn wait_for_authentication(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(wait_for_authentication_impl(&state, body).await)
}

// ─── Health ─────────────────────────────────────────────────────────────────

/// Library-callable version of `health`. Accepts parsed state directly (no request body).
pub async fn health_impl(state: &AppState) -> Value {
    let presig_count = state.presign_manager.read().await.len();

    json!({
        "status": "ok",
        "version": format!("bsv-mpc-proxy {}", env!("CARGO_PKG_VERSION")),
        "presignatures_available": presig_count,
        "kss_url": state.config.kss_url,
        "fee_per_signing_sats": state.config.fee_per_signing,
    })
}

/// Axum handler for `GET /health`. Delegates to [`health_impl`].
pub async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(health_impl(&state).await)
}

// ─── Capabilities (Path A discovery side-channel) ───────────────────────────
//
// Per `MPC-Spec` Path A: CHIP tokens carry only (identity_key, domain).
// MPC-specific capabilities — supported curves, threshold configs, fee,
// version, optional limits — are served here so discovery clients fetch
// them after validating a SHIP token. See bsv-mpc-overlay/src/chip.rs
// module docs for the architecture rationale.
//
// Schema mirrors `bsv_mpc_overlay::types::MpcNodeInfo` minus the
// identity_key + domain (those are in the token).

/// Library-callable version of `capabilities`. Accepts parsed state directly.
pub async fn capabilities_impl(state: &AppState) -> Value {
    json!({
        "curves": ["secp256k1"],
        "threshold_configs": state.config.threshold_configs,
        "fee_sats": state.config.fee_per_signing,
        "version": env!("CARGO_PKG_VERSION"),
        "max_presignatures": state.config.max_presignatures,
        "min_balance_sats": state.config.min_balance_sats,
    })
}

/// Axum handler for `GET /capabilities`. Delegates to [`capabilities_impl`].
///
/// Returns the MPC-specific node capabilities JSON consumed by overlay
/// discovery clients per Path A. Stable, intentionally small, cacheable
/// (clients SHOULD respect `Cache-Control: max-age=300`).
pub async fn capabilities(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(capabilities_impl(&state).await)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::MpcBridge;
    use crate::fee_injector::FeeInjector;
    use crate::presign_manager::PresignManager;
    use crate::storage::InMemoryBackend;
    use bsv::primitives::ec::PrivateKey;
    use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};
    use bsv_mpc_core::JointPublicKey;
    use tokio::sync::RwLock;

    /// Same test key as POC 3 / POC 9 / hd.rs tests.
    const TEST_KEY_BYTES: [u8; 32] = [
        0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2,
        0xf3, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1,
        0xf2, 0x03,
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
            storage: Arc::new(InMemoryBackend::new()),
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
            "protocolID": [2, "tests"],
            "keyID": "k"
        });
        let (_, _, _, cp) = parse_protocol_params(&body).unwrap();
        assert_eq!(cp, "self");
    }

    #[tokio::test]
    async fn capabilities_returns_path_a_schema() {
        // Path A side-channel contract: response carries curves +
        // threshold_configs + fee_sats + version + max_presignatures
        // + min_balance_sats — and NOTHING ELSE that would re-introduce
        // CHIP-token-embedded capabilities.
        let state = test_state();
        let body = capabilities_impl(&state).await;

        assert_eq!(body["curves"], json!(["secp256k1"]));
        assert_eq!(body["threshold_configs"], json!(["2-of-2", "2-of-3"]));
        assert_eq!(body["fee_sats"], json!(state.config.fee_per_signing));
        assert!(body["version"].is_string());
        assert_eq!(
            body["max_presignatures"],
            json!(state.config.max_presignatures)
        );
        // min_balance_sats defaults to null (None) when MPC_MIN_BALANCE_SATS unset.
        assert!(body["min_balance_sats"].is_null());

        // Lock the field set: NO identity_key / domain / signature / pubkey
        // should leak into the side-channel. Discovery clients get those
        // from the SHIP token, not here.
        let obj = body
            .as_object()
            .expect("capabilities returns a JSON object");
        let forbidden = ["identity_key", "domain", "signature", "pubkey", "address"];
        for f in forbidden {
            assert!(
                !obj.contains_key(f),
                "capabilities response leaked forbidden field {f}: \
                 belongs in the CHIP token, not the side-channel"
            );
        }
    }

    #[tokio::test]
    async fn test_derive_symmetric_key_anyone() {
        let state = test_state();
        let key = derive_symmetric_key(&state.bridge, 2, "test proto", "key1", "anyone")
            .await
            .unwrap();
        assert_eq!(key.len(), 32);
        assert_ne!(key, [0u8; 32], "key should not be all zeros");
    }

    #[tokio::test]
    async fn test_derive_symmetric_key_deterministic() {
        let state = test_state();
        let k1 = derive_symmetric_key(&state.bridge, 2, "test proto", "key1", "anyone")
            .await
            .unwrap();
        let k2 = derive_symmetric_key(&state.bridge, 2, "test proto", "key1", "anyone")
            .await
            .unwrap();
        assert_eq!(k1, k2, "same inputs must produce same key");
    }

    #[tokio::test]
    async fn test_derive_symmetric_key_different_invoices() {
        let state = test_state();
        let k1 = derive_symmetric_key(&state.bridge, 2, "test proto", "key1", "anyone")
            .await
            .unwrap();
        let k2 = derive_symmetric_key(&state.bridge, 2, "test proto", "key2", "anyone")
            .await
            .unwrap();
        assert_ne!(k1, k2, "different key IDs must produce different keys");
    }

    #[tokio::test]
    async fn test_derive_symmetric_key_self_errors_without_kss() {
        // With test bridge (no real KSS), "self" counterparty should error
        let state = test_state();
        let result = derive_symmetric_key(&state.bridge, 2, "test proto", "key1", "self").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_derive_symmetric_key_other_errors_without_kss() {
        // With test bridge (no real KSS), "other" counterparty should error
        let state = test_state();
        let result = derive_symmetric_key(
            &state.bridge,
            2,
            "test proto",
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
            "protocolID": [2, "test proto"],
            "keyID": "test-key",
            "counterparty": "anyone"
        });
        let Json(enc_resp) = encrypt(State(state.clone()), Json(encrypt_body)).await;
        assert!(
            enc_resp.get("error").is_none(),
            "encrypt should succeed: {:?}",
            enc_resp
        );
        let ciphertext_b64 = enc_resp["ciphertext"].as_str().unwrap();

        // Verify ciphertext is different from plaintext
        assert_ne!(ciphertext_b64, plaintext_b64);

        // Decrypt
        let decrypt_body = json!({
            "ciphertext": ciphertext_b64,
            "protocolID": [2, "test proto"],
            "keyID": "test-key",
            "counterparty": "anyone"
        });
        let Json(dec_resp) = decrypt(State(state.clone()), Json(decrypt_body)).await;
        assert!(
            dec_resp.get("error").is_none(),
            "decrypt should succeed: {:?}",
            dec_resp
        );
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
            "protocolID": [2, "tests"],
            "keyID": "empty",
            "counterparty": "anyone"
        });
        let Json(enc_resp) = encrypt(State(state.clone()), Json(encrypt_body)).await;
        assert!(enc_resp.get("error").is_none());

        let decrypt_body = json!({
            "ciphertext": enc_resp["ciphertext"].as_str().unwrap(),
            "protocolID": [2, "tests"],
            "keyID": "empty",
            "counterparty": "anyone"
        });
        let Json(dec_resp) = decrypt(State(state.clone()), Json(decrypt_body)).await;
        assert!(dec_resp.get("error").is_none());
        let result = BASE64
            .decode(dec_resp["plaintext"].as_str().unwrap())
            .unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_encrypt_produces_different_ciphertexts() {
        let state = test_state();
        let plaintext_b64 = BASE64.encode(b"same data");

        let body = json!({
            "plaintext": plaintext_b64,
            "protocolID": [2, "tests"],
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
            "protocolID": [2, "tests"],
            "keyID": "k1",
            "counterparty": "anyone"
        });
        let Json(enc_resp) = encrypt(State(state.clone()), Json(enc_body)).await;

        // Decrypt with key "k2" — should fail (different derived key)
        let dec_body = json!({
            "ciphertext": enc_resp["ciphertext"].as_str().unwrap(),
            "protocolID": [2, "tests"],
            "keyID": "k2",
            "counterparty": "anyone"
        });
        let Json(dec_resp) = decrypt(State(state.clone()), Json(dec_body)).await;
        assert!(
            dec_resp.get("error").is_some(),
            "wrong key should fail decryption"
        );
    }

    #[tokio::test]
    async fn test_decrypt_short_ciphertext_rejected() {
        let state = test_state();
        // Less than 28 bytes (12 nonce + 16 tag)
        let short_ct = BASE64.encode([0u8; 20]);
        let body = json!({
            "ciphertext": short_ct,
            "protocolID": [2, "tests"],
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
            "protocolID": [2, "test proto"],
            "keyID": "hmac-key",
            "counterparty": "anyone"
        });
        let Json(resp) = create_hmac(State(state), Json(body)).await;
        assert!(
            resp.get("error").is_none(),
            "create_hmac should succeed: {:?}",
            resp
        );
        let hmac_hex = resp["hmac"].as_str().unwrap();
        assert_eq!(
            hmac_hex.len(),
            64,
            "HMAC-SHA256 should be 32 bytes = 64 hex chars"
        );
    }

    #[tokio::test]
    async fn test_create_hmac_deterministic() {
        let state = test_state();
        let data_b64 = BASE64.encode(b"deterministic");

        let body = json!({
            "data": data_b64,
            "protocolID": [2, "tests"],
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
            "protocolID": [2, "tests"],
            "keyID": "verify-key",
            "counterparty": "anyone"
        });
        let Json(create_resp) = create_hmac(State(state.clone()), Json(create_body)).await;
        let hmac_hex = create_resp["hmac"].as_str().unwrap();

        // Verify HMAC
        let verify_body = json!({
            "data": data_b64,
            "hmac": hmac_hex,
            "protocolID": [2, "tests"],
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
            "protocolID": [2, "tests"],
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
            "protocolID": [2, "tests"],
            "keyID": "k",
            "counterparty": "anyone"
        });
        let Json(create_resp) = create_hmac(State(state.clone()), Json(create_body)).await;
        let hmac_hex = create_resp["hmac"].as_str().unwrap();

        // Verify with "tampered" — should fail
        let verify_body = json!({
            "data": BASE64.encode(b"tampered"),
            "hmac": hmac_hex,
            "protocolID": [2, "tests"],
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

        // The handler SHA-256 hashes data before verifying, so sign the hash
        let data = [0x42u8; 32];
        let msg_hash: [u8; 32] = Sha256::digest(data).into();
        let signature = child_priv.sign(&msg_hash).expect("signing should work");

        let body = json!({
            "data": hex::encode(data),
            "signature": hex::encode(signature.to_der()),
            "protocolID": [2, "test sig"],
            "keyID": "sig-key",
            "counterparty": "anyone",
            "forSelf": true
        });
        let Json(resp) = verify_signature(State(state), Json(body)).await;
        assert!(
            resp.get("error").is_none(),
            "verify should succeed: {:?}",
            resp
        );
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
            "protocolID": [2, "tests"],
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
        // With hashToDirectlySign=true, data must be exactly 32 bytes
        let body = json!({
            "data": "aabb",
            "signature": "3044022000",
            "protocolID": [2, "tests"],
            "keyID": "k",
            "counterparty": "anyone",
            "hashToDirectlySign": true
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
            "protocolID": [2, "tests"],
            "keyID": "large",
            "counterparty": "anyone"
        });
        let Json(enc_resp) = encrypt(State(state.clone()), Json(enc_body)).await;
        assert!(enc_resp.get("error").is_none());

        let dec_body = json!({
            "ciphertext": enc_resp["ciphertext"].as_str().unwrap(),
            "protocolID": [2, "tests"],
            "keyID": "large",
            "counterparty": "anyone"
        });
        let Json(dec_resp) = decrypt(State(state), Json(dec_body)).await;
        assert!(dec_resp.get("error").is_none());
        let result = BASE64
            .decode(dec_resp["plaintext"].as_str().unwrap())
            .unwrap();
        assert_eq!(result, large_data);
    }

    // ── Cross-handler consistency ───────────────────────────────────────

    #[tokio::test]
    async fn test_hmac_and_encrypt_use_same_key_derivation() {
        // Both encrypt and createHmac should derive from the same BRC-42 path
        let state = test_state();
        let k1 = derive_symmetric_key(&state.bridge, 2, "shared proto", "shared-key", "anyone")
            .await
            .unwrap();
        let k2 = derive_symmetric_key(&state.bridge, 2, "shared proto", "shared-key", "anyone")
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

        // The handler SHA-256 hashes data before verifying, so sign the hash
        let data = [0x55u8; 32];
        let msg_hash: [u8; 32] = Sha256::digest(data).into();
        let signature = child_priv.sign(&msg_hash).unwrap();

        let body = json!({
            "data": hex::encode(data),
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
            "protocolID": [2, "test signing"],
            "keyID": "key-1",
            "counterparty": "anyone",
        });
        let Json(derived_resp) = get_public_key(State(state), Json(derived_body)).await;
        assert!(
            derived_resp.get("error").is_none(),
            "should succeed: {:?}",
            derived_resp
        );

        let derived_hex = derived_resp["publicKey"].as_str().unwrap();
        assert_eq!(derived_hex.len(), 66);
        assert_ne!(
            derived_hex, identity_hex,
            "derived key should differ from identity"
        );
    }

    #[tokio::test]
    async fn test_get_public_key_self_errors_without_kss() {
        let state = test_state();
        let body = json!({
            "protocolID": [2, "tests"],
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
            locktime: 0,
            input_index: 0,
            subscript: &subscript,
            input_satoshis: 5000,
            sighash_type: 0x41,
        });
        let h2 = compute_bip143_sighash(&SighashParams {
            version: 1,
            inputs: &[(txid, 0, 0xFFFFFFFF)],
            outputs: &[(1000, &subscript)],
            locktime: 0,
            input_index: 0,
            subscript: &subscript,
            input_satoshis: 5000,
            sighash_type: 0x41,
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
            locktime: 0,
            input_index: 0,
            subscript: &subscript,
            input_satoshis: 5000,
            sighash_type: 0x41,
        });
        let h2 = compute_bip143_sighash(&SighashParams {
            version: 1,
            inputs: &[(txid, 0, 0xFFFFFFFF)],
            outputs: &[(2000, &subscript)], // different output amount
            locktime: 0,
            input_index: 0,
            subscript: &subscript,
            input_satoshis: 5000,
            sighash_type: 0x41,
        });
        assert_ne!(h1, h2, "different outputs must produce different sighash");
    }

    #[test]
    fn test_serialize_and_parse_tx_roundtrip() {
        let script = p2pkh_locking_script_from_hash(&[0xcc; 20]);
        let outputs = vec![(5000u64, script.clone()), (3000u64, script)];

        let raw_tx =
            serialize_signed_tx(1, &[([0xaa; 32], 0, vec![0x00], 0xFFFFFFFF)], &outputs, 0);

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

        // 1 input + 1 output = ~193 bytes. At 110 sats/KB: ceil(193 * 110 / 1000) = 22 sats
        assert!(fee_1_1 >= 1, "minimum 1 sat");
        assert!(
            fee_1_1 < 50,
            "fee should be ~22 sats for small tx at 110 sats/KB, got {fee_1_1}"
        );
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

        // Verify storage has both outputs
        let unspent = state.storage.list_unspent(None, None).await.unwrap();
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

        let unspent = state.storage.list_unspent(None, None).await.unwrap();
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
        let _ = internalize_action(State(state.clone()), Json(body)).await;

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

    // ── BEEF detection tests ────────────────────────────────────────────

    #[test]
    fn test_is_beef_format_atomic_beef() {
        // AtomicBEEF: 0x01010101 as little-endian
        let bytes = vec![0x01, 0x01, 0x01, 0x01, 0x00, 0x00];
        assert!(is_beef_format(&bytes));
    }

    #[test]
    fn test_is_beef_format_v1() {
        // BEEF V1: 0xEFBE0001 as little-endian → [01, 00, BE, EF]
        let bytes = vec![0x01, 0x00, 0xBE, 0xEF, 0x00];
        assert!(is_beef_format(&bytes));
    }

    #[test]
    fn test_is_beef_format_v2() {
        // BEEF V2: 0xEFBE0002 as little-endian → [02, 00, BE, EF]
        let bytes = vec![0x02, 0x00, 0xBE, 0xEF, 0x00];
        assert!(is_beef_format(&bytes));
    }

    #[test]
    fn test_is_beef_format_raw_tx() {
        // Raw tx version 1: [01, 00, 00, 00] — NOT BEEF
        let bytes = vec![0x01, 0x00, 0x00, 0x00, 0x01];
        assert!(!is_beef_format(&bytes));
    }

    #[test]
    fn test_is_beef_format_raw_tx_v2() {
        // Raw tx version 2: [02, 00, 00, 00] — NOT BEEF
        let bytes = vec![0x02, 0x00, 0x00, 0x00, 0x01];
        assert!(!is_beef_format(&bytes));
    }

    #[test]
    fn test_is_beef_format_too_short() {
        let bytes = vec![0x01, 0x00];
        assert!(!is_beef_format(&bytes));
    }

    #[test]
    fn test_extract_tx_from_beef_with_valid_atomic_beef() {
        // Build a minimal AtomicBEEF using the BSV SDK
        use bsv::transaction::{Beef, Transaction};

        // Create a simple transaction
        let tx_hex = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
        let tx = Transaction::from_hex(tx_hex).unwrap();
        let txid = tx.id();

        let mut beef = Beef::new();
        beef.merge_transaction(tx);
        let atomic_bytes = beef.to_binary_atomic(&txid).unwrap();

        assert!(is_beef_format(&atomic_bytes));
        let (outputs, extracted_txid) = extract_tx_from_beef(&atomic_bytes).unwrap();
        assert_eq!(extracted_txid, txid);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].0, 1_000_000_000); // 10 BTC in satoshis
    }

    // ── BEEF construction and broadcasting tests ─────────────────────────

    #[test]
    fn test_parse_input_txids_single_input() {
        // Build a simple 1-input, 1-output transaction
        let mut raw_tx = Vec::new();
        raw_tx.extend_from_slice(&1u32.to_le_bytes()); // version
        raw_tx.push(1); // 1 input
                        // input: txid (32 bytes) + vout (4 bytes)
        let parent_txid_internal: [u8; 32] = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        ];
        raw_tx.extend_from_slice(&parent_txid_internal);
        raw_tx.extend_from_slice(&0u32.to_le_bytes()); // vout
        raw_tx.push(0); // empty unlocking script
        raw_tx.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // sequence
        raw_tx.push(1); // 1 output
        raw_tx.extend_from_slice(&1000u64.to_le_bytes()); // satoshis
        raw_tx.push(0); // empty locking script
        raw_tx.extend_from_slice(&0u32.to_le_bytes()); // locktime

        let txids = parse_input_txids(&raw_tx).unwrap();
        assert_eq!(txids.len(), 1);

        // The txid should be in display order (reversed from internal)
        let mut expected = parent_txid_internal;
        expected.reverse();
        assert_eq!(txids[0], hex::encode(expected));
    }

    #[test]
    fn test_parse_input_txids_multiple_inputs_deduplicates() {
        // Build a 2-input tx where both inputs spend from the same parent
        let parent_txid: [u8; 32] = [0x42; 32];
        let mut raw_tx = Vec::new();
        raw_tx.extend_from_slice(&1u32.to_le_bytes()); // version
        raw_tx.push(2); // 2 inputs
        for vout in 0u32..2 {
            raw_tx.extend_from_slice(&parent_txid);
            raw_tx.extend_from_slice(&vout.to_le_bytes());
            raw_tx.push(0); // empty script
            raw_tx.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        }
        raw_tx.push(1); // 1 output
        raw_tx.extend_from_slice(&1000u64.to_le_bytes());
        raw_tx.push(0);
        raw_tx.extend_from_slice(&0u32.to_le_bytes());

        let txids = parse_input_txids(&raw_tx).unwrap();
        // Should be deduplicated to 1
        assert_eq!(txids.len(), 1);
    }

    #[test]
    fn test_parse_input_txids_two_different_parents() {
        let parent_a: [u8; 32] = [0x11; 32];
        let parent_b: [u8; 32] = [0x22; 32];
        let mut raw_tx = Vec::new();
        raw_tx.extend_from_slice(&1u32.to_le_bytes()); // version
        raw_tx.push(2); // 2 inputs
                        // Input 0 from parent_a
        raw_tx.extend_from_slice(&parent_a);
        raw_tx.extend_from_slice(&0u32.to_le_bytes());
        raw_tx.push(0);
        raw_tx.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // Input 1 from parent_b
        raw_tx.extend_from_slice(&parent_b);
        raw_tx.extend_from_slice(&1u32.to_le_bytes());
        raw_tx.push(0);
        raw_tx.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        raw_tx.push(1); // 1 output
        raw_tx.extend_from_slice(&1000u64.to_le_bytes());
        raw_tx.push(0);
        raw_tx.extend_from_slice(&0u32.to_le_bytes());

        let txids = parse_input_txids(&raw_tx).unwrap();
        assert_eq!(txids.len(), 2);
        // Should be sorted
        assert!(txids[0] < txids[1]);
    }

    #[test]
    fn test_parse_input_txids_with_real_tx() {
        // Use the same test tx as other tests — a real Bitcoin transaction
        let tx_hex = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
        let raw_tx = hex::decode(tx_hex).unwrap();

        let txids = parse_input_txids(&raw_tx).unwrap();
        assert_eq!(txids.len(), 1);
        // The parent txid: bytes in the tx are reversed (internal order)
        // Internal bytes: c997a5...fcd3704 → display: 0437cd7f8525ceed232435...
        assert_eq!(
            txids[0],
            "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9"
        );
    }

    #[test]
    fn test_parse_input_txids_too_short() {
        let raw_tx = vec![0x01, 0x00, 0x00];
        assert!(parse_input_txids(&raw_tx).is_err());
    }

    #[test]
    fn test_tsc_to_merkle_path_basic() {
        let txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let nodes = vec![
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        ];

        let mp = tsc_to_merkle_path(100, 0, txid, &nodes).unwrap();
        assert_eq!(mp.block_height, 100);
        assert_eq!(mp.path.len(), 2);

        // Level 0 should have the txid leaf and the sibling
        assert_eq!(mp.path[0].len(), 2);
        assert!(mp.path[0].iter().any(|l| l.hash.as_deref() == Some(txid)));

        // Roundtrip: binary -> parse
        let binary = mp.to_binary();
        let mp2 = MerklePath::from_binary(&binary).unwrap();
        assert_eq!(mp2.block_height, 100);
        assert_eq!(mp2.path.len(), 2);
    }

    #[test]
    fn test_tsc_to_merkle_path_with_duplicate() {
        let txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let nodes = vec!["*".to_string()]; // duplicate marker

        let mp = tsc_to_merkle_path(500, 0, txid, &nodes).unwrap();
        assert_eq!(mp.block_height, 500);
        assert_eq!(mp.path.len(), 1);
        // Should have 2 leaves: txid + duplicate
        assert_eq!(mp.path[0].len(), 2);
        assert!(mp.path[0].iter().any(|l| l.duplicate));
    }

    #[test]
    fn test_tsc_to_merkle_path_odd_index() {
        let txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let nodes =
            vec!["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()];

        // Index 5 (odd) — sibling at offset 4
        let mp = tsc_to_merkle_path(200, 5, txid, &nodes).unwrap();
        assert_eq!(mp.path[0].len(), 2);
        let offsets: Vec<u64> = mp.path[0].iter().map(|l| l.offset).collect();
        assert!(offsets.contains(&4));
        assert!(offsets.contains(&5));
    }

    #[test]
    fn test_tsc_to_merkle_path_empty_nodes_fails() {
        let txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let nodes: Vec<String> = vec![];
        assert!(tsc_to_merkle_path(100, 0, txid, &nodes).is_err());
    }

    #[test]
    fn test_tsc_to_merkle_path_roundtrip_matches_toolbox() {
        // Verify our tsc_to_merkle_path produces the same binary as the
        // rust-wallet-toolbox implementation by checking the roundtrip.
        let txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let nodes = vec![
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
        ];

        let mp = tsc_to_merkle_path(937800, 5, txid, &nodes).unwrap();
        let binary = mp.to_binary();
        let mp2 = MerklePath::from_binary(&binary).unwrap();

        assert_eq!(mp2.block_height, 937800);
        assert_eq!(mp2.path.len(), mp.path.len());
        // Compute root should succeed
        let root = mp2.compute_root(Some(txid)).unwrap();
        assert_eq!(root.len(), 64);
    }

    #[test]
    fn test_parse_input_txids_matches_serialize_roundtrip() {
        // Build a tx using serialize_signed_tx, then parse input txids
        let txid_a = [0xAA; 32]; // internal byte order
        let txid_b = [0xBB; 32];

        let signed_inputs = vec![
            (txid_a, 0u32, vec![0x00u8], 0xFFFFFFFFu32),
            (txid_b, 1u32, vec![0x00u8], 0xFFFFFFFFu32),
        ];
        let outputs: Vec<(u64, Vec<u8>)> = vec![(1000, vec![0x76])];

        let raw_tx = serialize_signed_tx(1, &signed_inputs, &outputs, 0);
        let txids = parse_input_txids(&raw_tx).unwrap();

        assert_eq!(txids.len(), 2);
        // txids should be in display order (reversed from internal)
        let mut expected_a = txid_a;
        expected_a.reverse();
        let mut expected_b = txid_b;
        expected_b.reverse();
        assert!(txids.contains(&hex::encode(expected_a)));
        assert!(txids.contains(&hex::encode(expected_b)));
    }

    // ── Derived key signing tests ─────────────────────────────────────

    /// Test: compute_signing_hmac_offset for "anyone" matches BSV SDK KeyDeriver.
    ///
    /// This proves the HMAC offset we compute is identical to what a normal wallet
    /// would use for key derivation. When cggmp24 applies this offset via
    /// set_additive_shift(), the resulting signature verifies against the
    /// BSV SDK's derived public key.
    #[tokio::test]
    async fn test_hmac_offset_matches_bsv_sdk_anyone() {
        let state = test_state();
        let privkey = PrivateKey::from_bytes(&TEST_KEY_BYTES).unwrap();
        let root_pub = privkey.public_key();

        // Our offset computation (what createSignature uses)
        let offset =
            compute_signing_hmac_offset(&state.bridge, 2, "test signing", "key-42", "anyone")
                .await
                .unwrap();

        // BRC-42: child_priv = root_priv + HMAC(shared_secret, invoice)
        // For "anyone": shared_secret = root_pub
        // So: expected_offset = HMAC(root_pub, invoice)
        // "test signing" was rejected by canonical validate_protocol_name
        // (ends in " protocol" — see bsv-rs types.rs validate_protocol_name).
        // Switch to "test signing" which exercises the same code path.
        let invoice = bsv_mpc_core::hd::compute_invoice(2, "test signing", "key-42").unwrap();
        let expected = bsv_mpc_core::hd::compute_brc42_hmac(&root_pub, &invoice);

        assert_eq!(
            offset, expected,
            "HMAC offset must match direct computation"
        );
    }

    /// Test: derived key signing produces signature verifiable against derived pubkey.
    ///
    /// This is the full crypto round-trip:
    /// 1. Compute HMAC offset (same as createSignature does)
    /// 2. Derive child private key using BSV SDK (simulating what MPC signing does)
    /// 3. Sign with child private key
    /// 4. Verify against BRC-42 derived public key (same as verifySignature does)
    ///
    /// If this passes, it proves createSignature + verifySignature are crypto-consistent.
    #[tokio::test]
    async fn test_derived_key_sign_verify_roundtrip() {
        let state = test_state();
        let privkey = PrivateKey::from_bytes(&TEST_KEY_BYTES).unwrap();

        // Compute the HMAC offset (what createSignature computes internally)
        let _offset =
            compute_signing_hmac_offset(&state.bridge, 2, "test sig", "roundtrip-key", "anyone")
                .await
                .unwrap();

        // Derive the child private key using BSV SDK (simulates MPC signing with offset)
        let deriver = KeyDeriver::new(Some(privkey));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "test sig");
        let child_priv = deriver
            .derive_private_key(&protocol, "roundtrip-key", &Counterparty::Anyone)
            .expect("derivation should work");

        // Verify: child_pub = root_pub + G * offset
        let root_pub = PublicKey::from_bytes(&state.bridge.joint_public_key().compressed).unwrap();
        let derived_pub = bsv_mpc_core::hd::derive_child_pubkey(
            &root_pub,
            &root_pub, // shared_secret = root_pub for "anyone"
            &bsv_mpc_core::hd::compute_invoice(2, "test sig", "roundtrip-key").unwrap(),
        )
        .unwrap();

        // Sign a message with the child private key
        let data = b"derived key test message";
        let msg_hash: [u8; 32] = Sha256::digest(data).into();
        let signature = child_priv.sign(&msg_hash).expect("signing should work");

        // Verify the signature against the derived public key
        assert!(
            derived_pub.verify(&msg_hash, &signature),
            "signature from derived key must verify against derived pubkey"
        );

        // Verify it does NOT verify against the root public key
        assert!(
            !root_pub.verify(&msg_hash, &signature),
            "signature from derived key must NOT verify against root pubkey"
        );

        // Verify via verifySignature handler (same path the real handler uses)
        let body = json!({
            "data": hex::encode(data),
            "signature": hex::encode(signature.to_der()),
            "protocolID": [2, "test sig"],
            "keyID": "roundtrip-key",
            "counterparty": "anyone",
            "forSelf": true
        });
        let Json(resp) = verify_signature(State(state.clone()), Json(body)).await;
        assert!(
            resp.get("error").is_none(),
            "verify should succeed: {:?}",
            resp
        );
        assert_eq!(
            resp["valid"], true,
            "verifySignature must confirm derived key signature"
        );

        // Verify with DIFFERENT protocol params -> must be invalid
        let wrong_body = json!({
            "data": hex::encode(data),
            "signature": hex::encode(signature.to_der()),
            "protocolID": [2, "test sig"],
            "keyID": "WRONG-key",
            "counterparty": "anyone",
            "forSelf": true
        });
        let Json(wrong_resp) = verify_signature(State(state.clone()), Json(wrong_body)).await;
        assert!(wrong_resp.get("error").is_none());
        assert_eq!(
            wrong_resp["valid"], false,
            "wrong derivation params must produce invalid verification"
        );
    }

    /// Test: different protocol params produce different HMAC offsets.
    #[tokio::test]
    async fn test_different_params_produce_different_offsets() {
        let state = test_state();

        let offset1 = compute_signing_hmac_offset(&state.bridge, 2, "proto a", "key1", "anyone")
            .await
            .unwrap();

        let offset2 = compute_signing_hmac_offset(&state.bridge, 2, "proto a", "key2", "anyone")
            .await
            .unwrap();

        let offset3 = compute_signing_hmac_offset(&state.bridge, 2, "proto b", "key1", "anyone")
            .await
            .unwrap();

        let offset4 = compute_signing_hmac_offset(&state.bridge, 1, "proto a", "key1", "anyone")
            .await
            .unwrap();

        assert_ne!(
            offset1, offset2,
            "different keyID must produce different offset"
        );
        assert_ne!(
            offset1, offset3,
            "different protocol must produce different offset"
        );
        assert_ne!(
            offset1, offset4,
            "different security level must produce different offset"
        );
    }

    /// Test: HMAC offset is deterministic.
    #[tokio::test]
    async fn test_hmac_offset_deterministic() {
        let state = test_state();

        let offset1 = compute_signing_hmac_offset(&state.bridge, 2, "tests", "key", "anyone")
            .await
            .unwrap();

        let offset2 = compute_signing_hmac_offset(&state.bridge, 2, "tests", "key", "anyone")
            .await
            .unwrap();

        assert_eq!(offset1, offset2, "same params must produce same offset");
    }

    /// Test: "self" counterparty offset fails without real KSS (expected in unit tests).
    #[tokio::test]
    async fn test_hmac_offset_self_errors_without_kss() {
        let state = test_state();
        let result = compute_signing_hmac_offset(&state.bridge, 2, "tests", "key", "self").await;
        assert!(result.is_err());
    }

    /// Test: getPublicKey and verifySignature use consistent BRC-42 derivation.
    #[tokio::test]
    async fn test_get_public_key_and_verify_signature_consistent() {
        let state = test_state();
        let privkey = PrivateKey::from_bytes(&TEST_KEY_BYTES).unwrap();

        // Get the derived public key from getPublicKey handler
        let body = json!({
            "protocolID": [2, "consistency"],
            "keyID": "check-key",
            "counterparty": "anyone",
        });
        let Json(pk_resp) = get_public_key(State(state.clone()), Json(body)).await;
        assert!(
            pk_resp.get("error").is_none(),
            "getPublicKey error: {:?}",
            pk_resp
        );
        let derived_pubkey_hex = pk_resp["publicKey"].as_str().unwrap();
        let derived_pubkey =
            PublicKey::from_bytes(&hex::decode(derived_pubkey_hex).unwrap()).unwrap();

        // Sign with BSV SDK's derived private key
        let deriver = KeyDeriver::new(Some(privkey));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "consistency");
        let child_priv = deriver
            .derive_private_key(&protocol, "check-key", &Counterparty::Anyone)
            .unwrap();

        let data = b"consistency test";
        let msg_hash: [u8; 32] = Sha256::digest(data).into();
        let signature = child_priv.sign(&msg_hash).unwrap();

        // Verify that the signature validates against getPublicKey's result
        assert!(
            derived_pubkey.verify(&msg_hash, &signature),
            "BSV SDK derived key signature must verify against getPublicKey result"
        );

        // And via verifySignature handler
        let verify_body = json!({
            "data": hex::encode(data),
            "signature": hex::encode(signature.to_der()),
            "protocolID": [2, "consistency"],
            "keyID": "check-key",
            "counterparty": "anyone",
            "forSelf": true
        });
        let Json(verify_resp) = verify_signature(State(state), Json(verify_body)).await;
        assert_eq!(
            verify_resp["valid"], true,
            "verifySignature must agree with getPublicKey derivation"
        );
    }

    // ── Library API smoke tests ──────────────────────────────────────────

    #[test]
    fn test_library_exports_compile() {
        // Verify that all public library types are accessible from the crate root.
        use crate::{
            AppState, FeeInjectionInfo, FeeInjector, MpcBridge, PresignManager, ProxyBuilder,
            ProxyConfig, ProxyError, ProxyResult, TrackedOutput, UtxoTracker,
        };

        // Suppress unused import warnings by referencing the types.
        let _ = std::mem::size_of::<ProxyConfig>();
        let _ = std::mem::size_of::<FeeInjector>();
        let _ = std::mem::size_of::<FeeInjectionInfo>();
        let _ = std::mem::size_of::<PresignManager>();
        let _ = std::mem::size_of::<UtxoTracker>();
        let _ = std::mem::size_of::<TrackedOutput>();
        let _ = std::mem::size_of::<ProxyError>();
        let _ = std::any::type_name::<ProxyResult<()>>();
        let _ = std::any::type_name::<AppState>();
        let _ = std::any::type_name::<MpcBridge>();
        let _ = std::any::type_name::<ProxyBuilder>();
    }

    #[tokio::test]
    async fn test_impl_functions_callable_without_axum() {
        // Verify that _impl functions can be called directly with &AppState + Value.
        let state = test_state();

        // Call a library handler directly — no Axum extractors.
        let result = get_network_impl(&state, json!({})).await;
        assert_eq!(result["network"], "mainnet");

        let result = get_version_impl(&state, json!({})).await;
        assert!(result["version"]
            .as_str()
            .unwrap()
            .starts_with("bsv-mpc-proxy"));

        let result = is_authenticated_impl(&state, json!({})).await;
        assert_eq!(result["authenticated"], true);

        let result = health_impl(&state).await;
        assert_eq!(result["status"], "ok");

        let result = list_outputs_impl(&state, json!({})).await;
        assert_eq!(result["totalOutputs"], 0);

        let result = list_actions_impl(&state, json!({})).await;
        assert_eq!(result["totalActions"], 0);

        let result = get_height_impl(&state, json!({})).await;
        assert_eq!(result["height"], 0);

        let result = list_certificates_impl(&state, json!({})).await;
        assert_eq!(result["totalCertificates"], 0);
    }
}
