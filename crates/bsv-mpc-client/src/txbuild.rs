//! Pure, wasm-safe transaction-construction helpers.
//!
//! Greenfield copies of the proxy's mainnet-proven tx primitives
//! (`bsv-mpc-proxy/src/wallet_api.rs:186-452`), lifted here so the native client
//! owns them with **zero** proxy/toolbox dependency. Everything in this module is
//! pure byte manipulation over `sha2` + `hex` + `std` — no async, no I/O, no
//! `bsv-rs` — so it compiles and runs **byte-identically on native and wasm32**
//! (proven in `tests/wasm32_txbuild.rs`). The MPC sign hot path (Phase 3) feeds
//! [`compute_bip143_sighash`] into `bsv_mpc_core::signing`.

use sha2::{Digest, Sha256};

/// SHA-256d (double SHA-256).
pub(crate) fn sha256d(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(h1);
    let mut result = [0u8; 32];
    result.copy_from_slice(&h2);
    result
}

/// Compute txid from raw transaction bytes (display byte order — reversed hash).
pub fn compute_txid(raw_tx: &[u8]) -> String {
    let mut hash = sha256d(raw_tx);
    hash.reverse(); // internal → display byte order
    hex::encode(hash)
}

/// Build P2PKH locking script from a 20-byte pubkey hash:
/// `OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn p2pkh_locking_script_from_hash(pubkey_hash: &[u8; 20]) -> Vec<u8> {
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
pub fn build_p2pkh_unlocking_script(sig_checksig: &[u8], compressed_pubkey: &[u8; 33]) -> Vec<u8> {
    let mut script = Vec::with_capacity(sig_checksig.len() + 35);
    script.push(sig_checksig.len() as u8);
    script.extend_from_slice(sig_checksig);
    script.push(33); // push 33 bytes
    script.extend_from_slice(compressed_pubkey);
    script
}

/// BSV fee rate: just over 100 sats/KB (~0.1 sat/byte).
const FEE_RATE_SATS_PER_KB: u64 = 110;

/// Estimate mining fee from input/output counts (P2PKH sizing).
pub fn estimate_mining_fee(num_inputs: usize, num_outputs: usize) -> u64 {
    let estimated_size = 10 + (num_inputs * 149) + (num_outputs * 34);
    let fee = (estimated_size as u64 * FEE_RATE_SATS_PER_KB).div_ceil(1000);
    std::cmp::max(fee, 1)
}

/// Write a Bitcoin varint to a buffer.
pub(crate) fn write_varint_to(buf: &mut Vec<u8>, val: u64) {
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

/// Read a Bitcoin varint from a byte slice at `offset` (advances it).
pub(crate) fn read_varint_from(data: &[u8], offset: &mut usize) -> Result<u64, String> {
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
pub struct SighashParams<'a> {
    pub version: u32,
    /// `(txid_internal, vout, sequence)` per input.
    pub inputs: &'a [([u8; 32], u32, u32)],
    /// `(satoshis, locking_script)` per output.
    pub outputs: &'a [(u64, &'a [u8])],
    pub locktime: u32,
    pub input_index: usize,
    /// Locking script of the UTXO being spent.
    pub subscript: &'a [u8],
    pub input_satoshis: u64,
    pub sighash_type: u32,
}

/// Compute the BIP-143 sighash (BSV: BIP-143 with FORKID) for a transaction input.
pub fn compute_bip143_sighash(params: &SighashParams<'_>) -> [u8; 32] {
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

    // hashPrevouts: SHA256d of all outpoints.
    let mut prevouts_data = Vec::new();
    for (txid, vout, _) in *inputs {
        prevouts_data.extend_from_slice(txid);
        prevouts_data.extend_from_slice(&vout.to_le_bytes());
    }
    let hash_prevouts = sha256d(&prevouts_data);

    // hashSequence: SHA256d of all sequences.
    let mut sequence_data = Vec::new();
    for (_, _, seq) in *inputs {
        sequence_data.extend_from_slice(&seq.to_le_bytes());
    }
    let hash_sequence = sha256d(&sequence_data);

    // hashOutputs: SHA256d of all serialized outputs.
    let mut outputs_data = Vec::new();
    for (sats, script) in *outputs {
        outputs_data.extend_from_slice(&sats.to_le_bytes());
        write_varint_to(&mut outputs_data, script.len() as u64);
        outputs_data.extend_from_slice(script);
    }
    let hash_outputs = sha256d(&outputs_data);

    // BIP-143 preimage.
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&version.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    preimage.extend_from_slice(&inputs[*input_index].0);
    preimage.extend_from_slice(&inputs[*input_index].1.to_le_bytes());
    write_varint_to(&mut preimage, subscript.len() as u64);
    preimage.extend_from_slice(subscript);
    preimage.extend_from_slice(&input_satoshis.to_le_bytes());
    preimage.extend_from_slice(&inputs[*input_index].2.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&locktime.to_le_bytes());
    preimage.extend_from_slice(&sighash_type.to_le_bytes());

    sha256d(&preimage)
}

/// Serialize a signed transaction to raw bytes.
///
/// `inputs`: `(txid, vout, unlocking_script, sequence)` per input.
/// `outputs`: `(satoshis, locking_script)` per output.
pub fn serialize_signed_tx(
    version: u32,
    inputs: &[([u8; 32], u32, Vec<u8>, u32)],
    outputs: &[(u64, Vec<u8>)],
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
pub fn parse_tx_outputs(raw_tx: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    if raw_tx.len() < 10 {
        return Err("transaction too short".into());
    }
    let mut offset = 4; // skip version

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

// ── Shared deterministic test vector ─────────────────────────────────────────
// A single fixed (sighash, serialized-tx) vector exercised by BOTH the native
// unit test below AND the wasm32 test (`tests/wasm32_txbuild.rs`). Both assert
// the SAME golden bytes — passing on both targets proves byte-identical output.

/// Fixed 1-in/2-out tx vector → BIP-143 sighash. Deterministic.
pub fn demo_sighash() -> [u8; 32] {
    let prev_txid = [0x11u8; 32];
    let subscript = p2pkh_locking_script_from_hash(&[0x22u8; 20]);
    let out0 = p2pkh_locking_script_from_hash(&[0x33u8; 20]);
    let out1 = p2pkh_locking_script_from_hash(&[0x44u8; 20]);
    let inputs = [(prev_txid, 0u32, 0xffff_ffffu32)];
    let outputs = [(50_000u64, out0.as_slice()), (49_000u64, out1.as_slice())];
    compute_bip143_sighash(&SighashParams {
        version: 1,
        inputs: &inputs,
        outputs: &outputs,
        locktime: 0,
        input_index: 0,
        subscript: &subscript,
        input_satoshis: 100_000,
        sighash_type: 0x41, // SIGHASH_ALL | FORKID
    })
}

/// The same fixed tx, serialized with a dummy unlocking script. Deterministic.
pub fn demo_serialized() -> Vec<u8> {
    let prev_txid = [0x11u8; 32];
    let unlocking = build_p2pkh_unlocking_script(&[0x55u8; 72], &[0x02u8; 33]);
    let out0 = p2pkh_locking_script_from_hash(&[0x33u8; 20]);
    let out1 = p2pkh_locking_script_from_hash(&[0x44u8; 20]);
    serialize_signed_tx(
        1,
        &[(prev_txid, 0, unlocking, 0xffff_ffff)],
        &[(50_000, out0), (49_000, out1)],
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden bytes for the shared vector. The wasm32 test asserts the SAME
    // constants (tests/wasm32_txbuild.rs) — equal on both targets ⇒ byte-identical.
    pub(crate) const GOLDEN_SIGHASH_HEX: &str =
        "96168d5c91a6893797a4eda3354831340c51951a468e8ca32bad7c2ea8418934";
    pub(crate) const GOLDEN_TXID_HEX: &str =
        "67f647fe4eabce169056d3533a51f6e27202d413e1896fab5f8a761b942bb634";

    #[test]
    fn demo_vector_matches_golden() {
        assert_eq!(hex::encode(demo_sighash()), GOLDEN_SIGHASH_HEX);
        assert_eq!(compute_txid(&demo_serialized()), GOLDEN_TXID_HEX);
    }

    #[test]
    fn sighash_is_deterministic_and_sensitive() {
        assert_eq!(demo_sighash(), demo_sighash(), "must be deterministic");
        // Sensitivity: flipping an output value changes the sighash.
        let sub = p2pkh_locking_script_from_hash(&[0x22u8; 20]);
        let o = p2pkh_locking_script_from_hash(&[0x33u8; 20]);
        let inputs = [([0x11u8; 32], 0u32, 0xffff_ffffu32)];
        let mk = |sats: u64| {
            compute_bip143_sighash(&SighashParams {
                version: 1,
                inputs: &inputs,
                outputs: &[(sats, o.as_slice())],
                locktime: 0,
                input_index: 0,
                subscript: &sub,
                input_satoshis: 100_000,
                sighash_type: 0x41,
            })
        };
        assert_ne!(mk(10), mk(11), "sighash must change with output value");
    }

    #[test]
    fn serialize_then_parse_outputs_roundtrips() {
        let raw = demo_serialized();
        let outs = parse_tx_outputs(&raw).expect("parse");
        assert_eq!(outs.len(), 2);
        assert_eq!(outs[0].0, 50_000);
        assert_eq!(outs[1].0, 49_000);
        // Rejects truncation FOR THE RIGHT REASON (validate-don't-skip).
        assert!(parse_tx_outputs(&raw[..6]).is_err());
    }
}
