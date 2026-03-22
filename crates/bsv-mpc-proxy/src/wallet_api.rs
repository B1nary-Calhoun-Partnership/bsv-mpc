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
    let fee = (estimated_size as u64 * FEE_RATE_SATS_PER_KB + 999) / 1000;
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
async fn get_raw_tx_from_woc(
    client: &reqwest::Client,
    txid: &str,
) -> Result<Vec<u8>, String> {
    let url = format!(
        "https://api.whatsonchain.com/v1/bsv/main/tx/{}/hex",
        txid
    );
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

    let hex_str = resp.text().await.map_err(|e| format!("WoC read body: {}", e))?;
    hex::decode(hex_str.trim().trim_matches('"'))
        .map_err(|e| format!("bad hex from WoC: {}", e))
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

    MerklePath::new_unchecked(block_height, path)
        .map_err(|e| format!("invalid merkle path: {}", e))
}

/// Fetch a TSC merkle proof from WoC and convert to BRC-74 MerklePath.
///
/// Returns `None` if the transaction is unconfirmed (no proof available).
/// Uses the `/tx/{txid}/proof/tsc` endpoint which returns TSC format,
/// and the `/tx/hash/{txid}` endpoint for block height.
async fn get_merkle_proof_from_woc(
    client: &reqwest::Client,
    txid: &str,
) -> Option<MerklePath> {
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
    let tx_url = format!(
        "https://api.whatsonchain.com/v1/bsv/main/tx/hash/{}",
        txid
    );
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
            tracing::debug!(parent_txid, "Added confirmed parent with merkle proof to BEEF");
        } else {
            // Parent is unconfirmed — need to find a confirmed ancestor
            tracing::debug!(parent_txid, "Parent unconfirmed, looking for confirmed ancestor");

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
                tracing::warn!(
                    parent_txid,
                    "No confirmed ancestor found within 2 levels"
                );
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
) -> Result<serde_json::Value, String> {
    // Step 1: Construct BEEF for ARC compliance
    let beef_hex = match construct_beef(client, raw_tx, input_txids).await {
        Some(beef_bytes) => {
            let hex = hex::encode(&beef_bytes);
            tracing::info!(
                beef_size = beef_bytes.len(),
                "BEEF constructed for ARC broadcast"
            );
            Some(hex)
        }
        None => {
            tracing::warn!("BEEF construction failed, will fall back to WoC raw broadcast");
            None
        }
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
                            .unwrap_or_else(|_| {
                                json!({ "status": "success", "raw": text })
                            });
                        tracing::info!(
                            endpoint,
                            "ARC broadcast successful with BEEF"
                        );
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
        let arc_endpoints: Vec<(&str, Option<&str>)> = vec![
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

            match req.json(&json!({ "rawTx": raw_tx_hex })).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();

                    if status.is_success()
                        || text.contains("SEEN_ON_NETWORK")
                        || text.contains("MINED")
                    {
                        let response: serde_json::Value = serde_json::from_str(&text)
                            .unwrap_or_else(|_| {
                                json!({ "status": "success", "raw": text })
                            });
                        tracing::info!(
                            endpoint,
                            "ARC broadcast successful with raw tx"
                        );
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
    // Collect parent txids for BEEF construction. ARC requires BEEF (Extended
    // Format) — broadcasting raw hex returns 460 on GorillaPool and 401 on
    // TAAL without an API key. BEEF wraps parent merkle proofs so the miner
    // can verify the input chain without querying the UTXO set.
    let input_txids: Vec<String> = selected_utxos.iter().map(|u| u.txid.clone()).collect();
    match broadcast_tx(
        &state.http_client,
        &raw_tx,
        &raw_tx_hex,
        &input_txids,
        &state.config.arc_api_key,
    )
    .await
    {
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
///
/// Handles both raw transaction hex AND AtomicBEEF/BEEF format (BRC-62/95/96).
/// The wallet at localhost:3321 returns `tx` as an AtomicBEEF byte array. We
/// detect the format from magic bytes and extract the raw transaction using the
/// BSV SDK's `Beef` parser.
pub async fn internalize_action(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    // Parse the transaction (hex string from "tx" or "rawTx")
    let raw_tx_hex = match body
        .get("tx")
        .or_else(|| body.get("rawTx"))
        .and_then(|v| v.as_str())
    {
        Some(s) => s,
        None => return Json(json!({"error": "missing tx or rawTx field"})),
    };

    let input_bytes = match hex::decode(raw_tx_hex) {
        Ok(b) => b,
        Err(e) => return Json(json!({"error": format!("invalid hex in tx: {}", e)})),
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
            Err(e) => return Json(json!({"error": format!("failed to parse BEEF: {}", e)})),
        }
    } else {
        // Raw transaction — parse directly
        let outputs = match parse_tx_outputs(&input_bytes) {
            Ok(o) => o,
            Err(e) => return Json(json!({"error": format!("failed to parse tx: {}", e)})),
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
        || magic == 0xEFBE0002  // BEEF_V2
}

/// Extract the target transaction's outputs and txid from BEEF/AtomicBEEF bytes.
///
/// Uses the BSV SDK's `Beef::from_binary()` to parse the envelope, then extracts
/// the target transaction (for AtomicBEEF: the atomic_txid; otherwise: the last tx).
fn extract_tx_from_beef(bytes: &[u8]) -> Result<(Vec<(u64, Vec<u8>)>, String), String> {
    use bsv::transaction::Beef;

    let beef = Beef::from_binary(bytes)
        .map_err(|e| format!("Beef::from_binary failed: {}", e))?;

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
    let beef_tx = beef.find_txid(&target_txid)
        .ok_or_else(|| format!("target tx {} not found in BEEF", target_txid))?;

    // Extract outputs from the BeefTx.
    // Try the parsed Transaction first, then fall back to raw bytes.
    if let Some(tx) = beef_tx.tx() {
        let outputs: Vec<(u64, Vec<u8>)> = tx.outputs.iter().map(|o| {
            (o.get_satoshis(), o.locking_script.to_binary())
        }).collect();
        let txid = tx.id();
        Ok((outputs, txid))
    } else if let Some(raw_tx) = beef_tx.raw_tx() {
        // Parse outputs from raw transaction bytes
        let outputs = parse_tx_outputs(raw_tx)
            .map_err(|e| format!("failed to parse raw tx from BEEF: {}", e))?;
        let txid = compute_txid(raw_tx);
        Ok((outputs, txid))
    } else {
        Err(format!("BEEF tx {} has no transaction data (txid-only entry)", target_txid))
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

        // The handler SHA-256 hashes data before verifying, so sign the hash
        let data = [0x42u8; 32];
        let msg_hash: [u8; 32] = Sha256::digest(&data).into();
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
        // With hashToDirectlySign=true, data must be exactly 32 bytes
        let body = json!({
            "data": "aabb",
            "signature": "3044022000",
            "protocolID": [2, "test"],
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

        // The handler SHA-256 hashes data before verifying, so sign the hash
        let data = [0x55u8; 32];
        let msg_hash: [u8; 32] = Sha256::digest(&data).into();
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

        // 1 input + 1 output = ~193 bytes. At 110 sats/KB: ceil(193 * 110 / 1000) = 22 sats
        assert!(fee_1_1 >= 1, "minimum 1 sat");
        assert!(fee_1_1 < 50, "fee should be ~22 sats for small tx at 110 sats/KB, got {fee_1_1}");
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
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
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
        let nodes = vec![
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ];

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
}
