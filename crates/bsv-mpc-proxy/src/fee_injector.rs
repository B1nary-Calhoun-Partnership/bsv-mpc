//! MPC signing fee injection.
//!
//! Every `createAction` transaction can optionally include an additional output
//! that pays the MPC node operators for their participation in the signing
//! ceremony. This module handles constructing and injecting that fee output.
//!
//! ## Fee distribution models
//!
//! ### Multisig (when `fee_threshold` is set)
//!
//! The fee output is a bare P2MS (pay-to-multisig) script requiring `t` of
//! the `n` fee addresses to spend. This is appropriate when the MPC node
//! operators are a known, fixed set and want shared custody of accumulated fees.
//!
//! Example: With `fee_threshold = "2-of-3"` and three addresses, the output
//! script is `OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG`.
//!
//! ### Split P2PKH (default)
//!
//! When no threshold is set, the fee is split equally among the fee addresses
//! as individual P2PKH outputs. Each operator gets their share independently.
//!
//! ## Usage
//!
//! The `FeeInjector` is constructed once at proxy startup and called from
//! the `createAction` handler after transaction construction but before
//! MPC signing.

use bsv::primitives::ec::PublicKey;
use bsv::script::Address;

/// Result of fee injection into a transaction's output set.
#[derive(Debug, Clone)]
pub struct FeeInjectionInfo {
    /// Number of fee outputs added.
    pub fee_outputs_added: usize,
    /// Total fee satoshis injected.
    pub total_fee_sats: u64,
    /// Original change amount before fee deduction.
    pub original_change: u64,
    /// New change amount after fee deduction.
    pub new_change: u64,
}

/// Injects MPC signing fee output(s) into a transaction before signing.
///
/// The fee compensates MPC node operators for their participation in the
/// threshold signing ceremony. It is transparent to the calling application
/// (bsv-worm) — the fee appears as an additional output in the transaction.
pub struct FeeInjector {
    /// Fee amount in satoshis per signing operation.
    ///
    /// This is the total fee — if split across multiple addresses, each
    /// address receives `fee_sats / n` satoshis.
    fee_sats: u64,

    /// Public keys or addresses of the MPC node operators who receive fees.
    ///
    /// Supported formats:
    /// - Hex-encoded compressed public keys (66 hex chars, starts with 02/03)
    /// - BSV mainnet P2PKH addresses (Base58Check, starts with 1)
    ///
    /// For multisig mode, all entries must be hex-encoded compressed public keys.
    fee_addresses: Vec<String>,

    /// Multisig threshold configuration (e.g., `"2-of-3"`).
    ///
    /// When set, the fee output uses a bare P2MS script. When `None`,
    /// the fee is split into individual P2PKH outputs.
    fee_threshold: Option<String>,
}

impl FeeInjector {
    /// Create a new fee injector.
    ///
    /// # Arguments
    ///
    /// - `fee_sats` — Total fee per signing in satoshis.
    /// - `fee_addresses` — Addresses of MPC node operators.
    /// - `fee_threshold` — Optional multisig threshold (e.g., `"2-of-3"`).
    pub fn new(fee_sats: u64, fee_addresses: Vec<String>, fee_threshold: Option<String>) -> Self {
        Self {
            fee_sats,
            fee_addresses,
            fee_threshold,
        }
    }

    /// Add fee output(s) to a serialized transaction.
    ///
    /// Parses the raw transaction bytes, injects fee output(s), reduces the
    /// change output (assumed to be the last output), and re-serializes.
    ///
    /// # Arguments
    ///
    /// - `tx_bytes` — The serialized unsigned transaction.
    ///
    /// # Returns
    ///
    /// The modified transaction bytes with fee output(s) appended. If fee
    /// injection is disabled (`!is_enabled()`), returns the input unchanged.
    pub fn inject_fee(&self, tx_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        if !self.is_enabled() {
            return Ok(tx_bytes.to_vec());
        }

        let mut tx = parse_raw_tx(tx_bytes)?;
        anyhow::ensure!(!tx.outputs.is_empty(), "Transaction has no outputs");

        // Assume last output is change (standard wallet convention).
        let change_index = tx.outputs.len() - 1;
        self.inject_fee_into_outputs(&mut tx.outputs, change_index)?;

        Ok(serialize_raw_tx(&tx))
    }

    /// Inject fee output(s) directly into an output list.
    ///
    /// This is the primary method for `createAction`, which builds the output
    /// list before serialization and knows the change index explicitly.
    ///
    /// Ported from `poc7-fee-injection/src/lib.rs`: `inject_fee_output` and
    /// `inject_split_fee`.
    ///
    /// # Arguments
    ///
    /// - `outputs` — Mutable list of (satoshis, locking_script) tuples.
    /// - `change_index` — Index of the change output to reduce.
    pub fn inject_fee_into_outputs(
        &self,
        outputs: &mut Vec<(u64, Vec<u8>)>,
        change_index: usize,
    ) -> anyhow::Result<FeeInjectionInfo> {
        if !self.is_enabled() {
            return Ok(FeeInjectionInfo {
                fee_outputs_added: 0,
                total_fee_sats: 0,
                original_change: outputs.get(change_index).map_or(0, |o| o.0),
                new_change: outputs.get(change_index).map_or(0, |o| o.0),
            });
        }

        anyhow::ensure!(
            change_index < outputs.len(),
            "Change index {} out of bounds ({} outputs)",
            change_index,
            outputs.len()
        );

        let original_change = outputs[change_index].0;
        anyhow::ensure!(
            original_change >= self.fee_sats,
            "Insufficient change ({} sats) to cover fee ({} sats)",
            original_change,
            self.fee_sats
        );

        let threshold = self.parse_threshold()?;

        let fee_outputs = if let Some((t, _n)) = threshold {
            // Multisig: single P2MS output with all fee collected together
            let pubkeys = self.resolve_fee_pubkeys()?;
            let script = build_p2ms_script(t, &pubkeys);
            vec![(self.fee_sats, script)]
        } else {
            // Split P2PKH: one output per address, fee divided equally
            let scripts = self.resolve_fee_locking_scripts()?;
            split_fee_outputs(self.fee_sats, &scripts)?
        };

        let total_fee: u64 = fee_outputs.iter().map(|(s, _)| s).sum();
        let new_change = original_change - total_fee;
        outputs[change_index].0 = new_change;

        let fee_outputs_added = fee_outputs.len();
        for (amount, script) in fee_outputs {
            outputs.push((amount, script));
        }

        Ok(FeeInjectionInfo {
            fee_outputs_added,
            total_fee_sats: total_fee,
            original_change,
            new_change,
        })
    }

    /// Check if fee injection is enabled.
    ///
    /// Fee injection requires both a non-zero fee amount and at least one
    /// fee address. If either is missing, fee injection is silently skipped.
    pub fn is_enabled(&self) -> bool {
        self.fee_sats > 0 && !self.fee_addresses.is_empty()
    }

    /// Get the total fee in satoshis.
    pub fn fee_sats(&self) -> u64 {
        self.fee_sats
    }

    /// Get the fee addresses.
    pub fn fee_addresses(&self) -> &[String] {
        &self.fee_addresses
    }

    /// Parse the threshold string (e.g., `"2-of-3"`) into `(t, n)`.
    ///
    /// Returns `None` if no threshold is configured.
    /// Returns an error if the format is invalid.
    pub fn parse_threshold(&self) -> anyhow::Result<Option<(u16, u16)>> {
        match &self.fee_threshold {
            None => Ok(None),
            Some(s) => {
                let parts: Vec<&str> = s.split("-of-").collect();
                if parts.len() != 2 {
                    anyhow::bail!(
                        "Invalid fee threshold format '{}' — expected 't-of-n' (e.g., '2-of-3')",
                        s
                    );
                }
                let t: u16 = parts[0]
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid threshold 't' in '{}'", s))?;
                let n: u16 = parts[1]
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid threshold 'n' in '{}'", s))?;

                if t == 0 {
                    anyhow::bail!("Threshold t must be >= 1, got 0");
                }
                if t > n {
                    anyhow::bail!("Threshold t ({t}) cannot exceed n ({n})");
                }
                if n as usize != self.fee_addresses.len() {
                    anyhow::bail!(
                        "Threshold n ({n}) does not match fee_addresses count ({})",
                        self.fee_addresses.len()
                    );
                }

                Ok(Some((t, n)))
            }
        }
    }

    /// Resolve fee addresses to P2PKH locking scripts.
    fn resolve_fee_locking_scripts(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        self.fee_addresses
            .iter()
            .map(|addr| resolve_address_to_p2pkh_script(addr))
            .collect()
    }

    /// Resolve fee addresses to public keys (required for multisig).
    fn resolve_fee_pubkeys(&self) -> anyhow::Result<Vec<PublicKey>> {
        self.fee_addresses
            .iter()
            .map(|addr| {
                PublicKey::from_hex(addr).map_err(|e| {
                    anyhow::anyhow!(
                        "Multisig fee requires hex public keys, but '{}' is not valid: {}",
                        addr,
                        e
                    )
                })
            })
            .collect()
    }
}

// ─── Script construction helpers ─────────────────────────────────────────────
//
// Ported from poc7-fee-injection/tests/poc.rs: p2pkh_locking_script()

/// Resolve a fee address string to a P2PKH locking script.
///
/// Supports:
/// - Hex-encoded compressed public keys (66 hex chars, starts with 02/03)
/// - BSV mainnet P2PKH addresses (Base58Check, starts with 1)
fn resolve_address_to_p2pkh_script(addr: &str) -> anyhow::Result<Vec<u8>> {
    // Try as hex compressed pubkey first (66 hex chars, 02/03 prefix)
    if addr.len() == 66 && (addr.starts_with("02") || addr.starts_with("03")) {
        let pubkey = PublicKey::from_hex(addr)
            .map_err(|e| anyhow::anyhow!("Invalid hex public key '{}': {}", addr, e))?;
        return Ok(p2pkh_locking_script(&pubkey.hash160()));
    }

    // Try as BSV address (Base58Check)
    let address = Address::new_from_string(addr)
        .map_err(|e| anyhow::anyhow!("Invalid BSV address '{}': {}", addr, e))?;
    let hash = address.public_key_hash();
    let mut hash20 = [0u8; 20];
    hash20.copy_from_slice(hash);
    Ok(p2pkh_locking_script(&hash20))
}

/// Build a P2PKH locking script from a 20-byte pubkey hash.
///
/// ```text
/// OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
/// ```
///
/// Ported from poc7-fee-injection/tests/poc.rs.
fn p2pkh_locking_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

/// Build a bare P2MS (pay-to-multisig) locking script.
///
/// ```text
/// OP_t <pk1> ... <pkn> OP_n OP_CHECKMULTISIG
/// ```
fn build_p2ms_script(threshold: u16, pubkeys: &[PublicKey]) -> Vec<u8> {
    let mut script = Vec::new();
    script.push(0x50 + threshold as u8); // OP_1..OP_16
    for pk in pubkeys {
        let compressed = pk.to_compressed();
        script.push(33); // push 33 bytes
        script.extend_from_slice(&compressed);
    }
    script.push(0x50 + pubkeys.len() as u8); // OP_n
    script.push(0xae); // OP_CHECKMULTISIG
    script
}

/// Split a fee equally among multiple locking scripts.
///
/// Returns `(satoshis, locking_script)` tuples. The first address receives
/// any remainder from integer division.
///
/// Ported from poc7-fee-injection/src/lib.rs: `split_fee_outputs()`.
fn split_fee_outputs(fee_sats: u64, scripts: &[Vec<u8>]) -> anyhow::Result<Vec<(u64, Vec<u8>)>> {
    anyhow::ensure!(!scripts.is_empty(), "No fee addresses provided");

    let n = scripts.len() as u64;
    let per_address = fee_sats / n;
    let remainder = fee_sats % n;

    anyhow::ensure!(
        per_address > 0,
        "Fee {} sats too small to split among {} addresses",
        fee_sats,
        scripts.len()
    );

    let mut outputs = Vec::with_capacity(scripts.len());
    for (i, script) in scripts.iter().enumerate() {
        let amount = if i == 0 {
            per_address + remainder
        } else {
            per_address
        };
        outputs.push((amount, script.clone()));
    }

    Ok(outputs)
}

// ─── Raw transaction parsing/serialization ───────────────────────────────────
//
// Minimal BSV transaction parser for fee injection. Handles the standard
// Bitcoin transaction format (version 1, no SegWit). Ported from the
// serialize_transaction() pattern in poc7-fee-injection/tests/poc.rs.

/// Parsed raw transaction (internal to fee injection).
struct RawTx {
    version: i32,
    inputs: Vec<RawTxInput>,
    outputs: Vec<(u64, Vec<u8>)>,
    locktime: u32,
}

/// Parsed raw transaction input.
struct RawTxInput {
    txid: [u8; 32],
    vout: u32,
    script: Vec<u8>,
    sequence: u32,
}

/// Read a Bitcoin varint from a byte slice at the given offset.
fn read_varint(data: &[u8], offset: &mut usize) -> anyhow::Result<u64> {
    anyhow::ensure!(
        *offset < data.len(),
        "Unexpected end of data reading varint"
    );
    let first = data[*offset];
    *offset += 1;
    match first {
        0..=0xfc => Ok(first as u64),
        0xfd => {
            anyhow::ensure!(*offset + 2 <= data.len(), "Truncated varint (fd)");
            let val = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
            *offset += 2;
            Ok(val as u64)
        }
        0xfe => {
            anyhow::ensure!(*offset + 4 <= data.len(), "Truncated varint (fe)");
            let bytes: [u8; 4] = data[*offset..*offset + 4].try_into()?;
            let val = u32::from_le_bytes(bytes);
            *offset += 4;
            Ok(val as u64)
        }
        0xff => {
            anyhow::ensure!(*offset + 8 <= data.len(), "Truncated varint (ff)");
            let bytes: [u8; 8] = data[*offset..*offset + 8].try_into()?;
            let val = u64::from_le_bytes(bytes);
            *offset += 8;
            Ok(val)
        }
    }
}

/// Encode a value as a Bitcoin varint.
fn write_varint(val: u64) -> Vec<u8> {
    if val < 0xfd {
        vec![val as u8]
    } else if val <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(val as u16).to_le_bytes());
        v
    } else if val <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(val as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&val.to_le_bytes());
        v
    }
}

/// Read `len` bytes from data at offset, advancing the offset.
fn read_bytes(data: &[u8], offset: &mut usize, len: usize) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        *offset + len <= data.len(),
        "Unexpected end of data reading {} bytes at offset {}",
        len,
        *offset
    );
    let result = data[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(result)
}

/// Parse a raw BSV transaction from bytes.
fn parse_raw_tx(data: &[u8]) -> anyhow::Result<RawTx> {
    anyhow::ensure!(
        data.len() >= 10,
        "Transaction too short ({} bytes)",
        data.len()
    );

    let mut offset = 0;

    let version = i32::from_le_bytes(data[offset..offset + 4].try_into()?);
    offset += 4;

    let input_count = read_varint(data, &mut offset)? as usize;
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let txid_bytes = read_bytes(data, &mut offset, 32)?;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);

        let vout_bytes = read_bytes(data, &mut offset, 4)?;
        let vout = u32::from_le_bytes(vout_bytes.try_into().unwrap());

        let script_len = read_varint(data, &mut offset)? as usize;
        let script = read_bytes(data, &mut offset, script_len)?;

        let seq_bytes = read_bytes(data, &mut offset, 4)?;
        let sequence = u32::from_le_bytes(seq_bytes.try_into().unwrap());

        inputs.push(RawTxInput {
            txid,
            vout,
            script,
            sequence,
        });
    }

    let output_count = read_varint(data, &mut offset)? as usize;
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let val_bytes = read_bytes(data, &mut offset, 8)?;
        let value = u64::from_le_bytes(val_bytes.try_into().unwrap());

        let script_len = read_varint(data, &mut offset)? as usize;
        let script = read_bytes(data, &mut offset, script_len)?;

        outputs.push((value, script));
    }

    let lt_bytes = read_bytes(data, &mut offset, 4)?;
    let locktime = u32::from_le_bytes(lt_bytes.try_into().unwrap());

    Ok(RawTx {
        version,
        inputs,
        outputs,
        locktime,
    })
}

/// Serialize a raw transaction to bytes.
///
/// Inverse of `parse_raw_tx`. Matches the format used by
/// poc7-fee-injection/tests/poc.rs: `serialize_transaction()`.
fn serialize_raw_tx(tx: &RawTx) -> Vec<u8> {
    let mut buf = Vec::new();

    buf.extend_from_slice(&tx.version.to_le_bytes());

    buf.extend_from_slice(&write_varint(tx.inputs.len() as u64));
    for input in &tx.inputs {
        buf.extend_from_slice(&input.txid);
        buf.extend_from_slice(&input.vout.to_le_bytes());
        buf.extend_from_slice(&write_varint(input.script.len() as u64));
        buf.extend_from_slice(&input.script);
        buf.extend_from_slice(&input.sequence.to_le_bytes());
    }

    buf.extend_from_slice(&write_varint(tx.outputs.len() as u64));
    for (value, script) in &tx.outputs {
        buf.extend_from_slice(&value.to_le_bytes());
        buf.extend_from_slice(&write_varint(script.len() as u64));
        buf.extend_from_slice(script);
    }

    buf.extend_from_slice(&tx.locktime.to_le_bytes());

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test pubkey hex (secp256k1 generator point compressed — well-known, deterministic)
    const TEST_PUBKEY_HEX: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn dummy_p2pkh_script(id: u8) -> Vec<u8> {
        p2pkh_locking_script(&[id; 20])
    }

    /// Build a minimal valid serialized transaction for testing.
    fn build_test_tx(outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let tx = RawTx {
            version: 1,
            inputs: vec![RawTxInput {
                txid: [0xaa; 32],
                vout: 0,
                script: vec![],
                sequence: 0xffffffff,
            }],
            outputs: outputs.to_vec(),
            locktime: 0,
        };
        serialize_raw_tx(&tx)
    }

    // ── Existing tests (preserved) ───────────────────────────────────────────

    #[test]
    fn disabled_when_no_fee() {
        let injector = FeeInjector::new(0, vec!["addr1".into()], None);
        assert!(!injector.is_enabled());
    }

    #[test]
    fn disabled_when_no_addresses() {
        let injector = FeeInjector::new(1000, vec![], None);
        assert!(!injector.is_enabled());
    }

    #[test]
    fn enabled_with_fee_and_addresses() {
        let injector = FeeInjector::new(1000, vec!["addr1".into()], None);
        assert!(injector.is_enabled());
    }

    #[test]
    fn parse_threshold_valid() {
        let injector = FeeInjector::new(
            1000,
            vec!["a".into(), "b".into(), "c".into()],
            Some("2-of-3".into()),
        );
        let (t, n) = injector.parse_threshold().unwrap().unwrap();
        assert_eq!(t, 2);
        assert_eq!(n, 3);
    }

    #[test]
    fn parse_threshold_none() {
        let injector = FeeInjector::new(1000, vec!["a".into()], None);
        assert!(injector.parse_threshold().unwrap().is_none());
    }

    #[test]
    fn parse_threshold_invalid_format() {
        let injector = FeeInjector::new(1000, vec!["a".into()], Some("2/3".into()));
        assert!(injector.parse_threshold().is_err());
    }

    #[test]
    fn parse_threshold_t_exceeds_n() {
        let injector = FeeInjector::new(1000, vec!["a".into(), "b".into()], Some("3-of-2".into()));
        assert!(injector.parse_threshold().is_err());
    }

    #[test]
    fn parse_threshold_n_mismatch() {
        let injector = FeeInjector::new(1000, vec!["a".into(), "b".into()], Some("2-of-3".into()));
        assert!(injector.parse_threshold().is_err());
    }

    #[test]
    fn inject_fee_noop_when_disabled() {
        let injector = FeeInjector::new(0, vec![], None);
        let tx_bytes = vec![1, 2, 3, 4];
        let result = injector.inject_fee(&tx_bytes).unwrap();
        assert_eq!(result, tx_bytes);
    }

    // ── New tests: inject_fee_into_outputs ───────────────────────────────────

    #[test]
    fn inject_fee_into_outputs_single_address() {
        let injector = FeeInjector::new(1000, vec![TEST_PUBKEY_HEX.into()], None);

        let mut outputs = vec![
            (5000u64, dummy_p2pkh_script(1)), // recipient
            (4900u64, dummy_p2pkh_script(2)), // change
        ];
        let info = injector.inject_fee_into_outputs(&mut outputs, 1).unwrap();

        assert_eq!(outputs.len(), 3);
        assert_eq!(outputs[0].0, 5000); // recipient unchanged
        assert_eq!(outputs[1].0, 3900); // change reduced by 1000
        assert_eq!(outputs[2].0, 1000); // fee output
        assert_eq!(info.fee_outputs_added, 1);
        assert_eq!(info.total_fee_sats, 1000);
        assert_eq!(info.original_change, 4900);
        assert_eq!(info.new_change, 3900);
    }

    #[test]
    fn inject_fee_into_outputs_split_two_addresses() {
        let injector = FeeInjector::new(
            1000,
            vec![TEST_PUBKEY_HEX.into(), TEST_PUBKEY_HEX.into()],
            None,
        );

        let mut outputs = vec![
            (5000u64, dummy_p2pkh_script(1)),
            (4000u64, dummy_p2pkh_script(2)),
        ];
        let info = injector.inject_fee_into_outputs(&mut outputs, 1).unwrap();

        assert_eq!(outputs.len(), 4); // recipient + change + 2 fee
        assert_eq!(outputs[1].0, 3000); // change reduced by 1000
        assert_eq!(outputs[2].0, 500); // first gets half
        assert_eq!(outputs[3].0, 500); // second gets half
        assert_eq!(info.fee_outputs_added, 2);
    }

    #[test]
    fn inject_fee_into_outputs_split_remainder() {
        let injector = FeeInjector::new(
            1000,
            vec![
                TEST_PUBKEY_HEX.into(),
                TEST_PUBKEY_HEX.into(),
                TEST_PUBKEY_HEX.into(),
            ],
            None,
        );

        let mut outputs = vec![
            (2000u64, dummy_p2pkh_script(1)),
            (7900u64, dummy_p2pkh_script(2)),
        ];
        let info = injector.inject_fee_into_outputs(&mut outputs, 1).unwrap();

        assert_eq!(outputs.len(), 5); // recipient + change + 3 fee
        assert_eq!(outputs[1].0, 6900); // 7900 - 1000
        assert_eq!(outputs[2].0, 334); // 333 + 1 remainder
        assert_eq!(outputs[3].0, 333);
        assert_eq!(outputs[4].0, 333);
        // Verify total is exact
        let total_fee: u64 = outputs[2..].iter().map(|(s, _)| s).sum();
        assert_eq!(total_fee, 1000);
        assert_eq!(info.fee_outputs_added, 3);
    }

    #[test]
    fn inject_fee_into_outputs_insufficient_change() {
        let injector = FeeInjector::new(1000, vec![TEST_PUBKEY_HEX.into()], None);

        let mut outputs = vec![
            (5000u64, dummy_p2pkh_script(1)),
            (500u64, dummy_p2pkh_script(2)), // not enough
        ];
        let result = injector.inject_fee_into_outputs(&mut outputs, 1);
        assert!(result.is_err());
        // Outputs should be unchanged on error
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[1].0, 500);
    }

    #[test]
    fn inject_fee_into_outputs_exact_change() {
        let injector = FeeInjector::new(1000, vec![TEST_PUBKEY_HEX.into()], None);

        let mut outputs = vec![
            (5000u64, dummy_p2pkh_script(1)),
            (1000u64, dummy_p2pkh_script(2)), // exactly equals fee
        ];
        let info = injector.inject_fee_into_outputs(&mut outputs, 1).unwrap();

        assert_eq!(outputs[1].0, 0); // change goes to zero
        assert_eq!(info.new_change, 0);
    }

    #[test]
    fn inject_fee_into_outputs_change_at_index_0() {
        let injector = FeeInjector::new(1000, vec![TEST_PUBKEY_HEX.into()], None);

        let mut outputs = vec![
            (8000u64, dummy_p2pkh_script(1)), // change is first
            (1900u64, dummy_p2pkh_script(2)), // recipient is second
        ];
        let info = injector.inject_fee_into_outputs(&mut outputs, 0).unwrap();

        assert_eq!(outputs[0].0, 7000); // change reduced
        assert_eq!(outputs[1].0, 1900); // recipient unchanged
        assert_eq!(outputs[2].0, 1000); // fee appended
        assert_eq!(info.original_change, 8000);
    }

    #[test]
    fn inject_fee_into_outputs_noop_when_disabled() {
        let injector = FeeInjector::new(0, vec![], None);

        let mut outputs = vec![
            (5000u64, dummy_p2pkh_script(1)),
            (4000u64, dummy_p2pkh_script(2)),
        ];
        let info = injector.inject_fee_into_outputs(&mut outputs, 1).unwrap();

        assert_eq!(outputs.len(), 2); // unchanged
        assert_eq!(info.fee_outputs_added, 0);
        assert_eq!(info.total_fee_sats, 0);
    }

    #[test]
    fn inject_fee_into_outputs_multisig() {
        let injector = FeeInjector::new(
            1000,
            vec![TEST_PUBKEY_HEX.into(), TEST_PUBKEY_HEX.into()],
            Some("1-of-2".into()),
        );

        let mut outputs = vec![
            (5000u64, dummy_p2pkh_script(1)),
            (4000u64, dummy_p2pkh_script(2)),
        ];
        let info = injector.inject_fee_into_outputs(&mut outputs, 1).unwrap();

        assert_eq!(outputs.len(), 3); // recipient + change + 1 multisig
        assert_eq!(outputs[1].0, 3000); // change reduced
        assert_eq!(outputs[2].0, 1000); // single P2MS output
        assert_eq!(info.fee_outputs_added, 1);

        // Verify P2MS script structure: OP_1 <pk> <pk> OP_2 OP_CHECKMULTISIG
        let script = &outputs[2].1;
        assert_eq!(script[0], 0x51); // OP_1 (threshold)
        assert_eq!(script[1], 33); // push 33 bytes
        assert_eq!(script[35], 33); // push 33 bytes
        assert_eq!(script[69], 0x52); // OP_2 (n)
        assert_eq!(script[70], 0xae); // OP_CHECKMULTISIG
    }

    // ── New tests: inject_fee (serialized tx round-trip) ─────────────────────

    #[test]
    fn inject_fee_roundtrip_single() {
        let injector = FeeInjector::new(1000, vec![TEST_PUBKEY_HEX.into()], None);

        let original_outputs = vec![
            (5000u64, dummy_p2pkh_script(1)), // recipient
            (3900u64, dummy_p2pkh_script(2)), // change
        ];
        let tx_bytes = build_test_tx(&original_outputs);

        let modified = injector.inject_fee(&tx_bytes).unwrap();
        let parsed = parse_raw_tx(&modified).unwrap();

        assert_eq!(parsed.outputs.len(), 3);
        assert_eq!(parsed.outputs[0].0, 5000); // recipient unchanged
        assert_eq!(parsed.outputs[1].0, 2900); // change reduced by 1000
        assert_eq!(parsed.outputs[2].0, 1000); // fee output
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.locktime, 0);
    }

    #[test]
    fn inject_fee_roundtrip_split() {
        let injector = FeeInjector::new(
            900,
            vec![
                TEST_PUBKEY_HEX.into(),
                TEST_PUBKEY_HEX.into(),
                TEST_PUBKEY_HEX.into(),
            ],
            None,
        );

        let original_outputs = vec![
            (1000u64, dummy_p2pkh_script(1)),
            (5000u64, dummy_p2pkh_script(2)),
        ];
        let tx_bytes = build_test_tx(&original_outputs);

        let modified = injector.inject_fee(&tx_bytes).unwrap();
        let parsed = parse_raw_tx(&modified).unwrap();

        assert_eq!(parsed.outputs.len(), 5); // 2 original + 3 fee
        assert_eq!(parsed.outputs[1].0, 4100); // 5000 - 900
        assert_eq!(parsed.outputs[2].0, 300);
        assert_eq!(parsed.outputs[3].0, 300);
        assert_eq!(parsed.outputs[4].0, 300);
    }

    #[test]
    fn balance_equation_holds_after_injection() {
        let injector = FeeInjector::new(1000, vec![TEST_PUBKEY_HEX.into()], None);

        let input_sats: u64 = 10000;
        let mining_fee: u64 = 100;
        let recipient_sats: u64 = 5000;
        let change_sats: u64 = input_sats - recipient_sats - mining_fee; // 4900

        let mut outputs = vec![
            (recipient_sats, dummy_p2pkh_script(1)),
            (change_sats, dummy_p2pkh_script(2)),
        ];

        injector.inject_fee_into_outputs(&mut outputs, 1).unwrap();

        let total_outputs: u64 = outputs.iter().map(|(s, _)| s).sum();
        assert_eq!(input_sats, total_outputs + mining_fee);
        assert_eq!(total_outputs, 5000 + 3900 + 1000); // 9900
    }

    // ── New tests: tx parse/serialize round-trip ─────────────────────────────

    #[test]
    fn tx_parse_serialize_roundtrip() {
        let outputs = vec![
            (12345u64, dummy_p2pkh_script(1)),
            (67890u64, dummy_p2pkh_script(2)),
        ];
        let original = build_test_tx(&outputs);
        let parsed = parse_raw_tx(&original).unwrap();
        let reserialized = serialize_raw_tx(&parsed);
        assert_eq!(original, reserialized);
    }

    #[test]
    fn tx_parse_empty_outputs_rejected_for_injection() {
        let injector = FeeInjector::new(1000, vec![TEST_PUBKEY_HEX.into()], None);
        let tx = RawTx {
            version: 1,
            inputs: vec![RawTxInput {
                txid: [0; 32],
                vout: 0,
                script: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![],
            locktime: 0,
        };
        let tx_bytes = serialize_raw_tx(&tx);
        assert!(injector.inject_fee(&tx_bytes).is_err());
    }

    // ── New tests: address resolution ────────────────────────────────────────

    #[test]
    fn resolve_hex_pubkey_to_p2pkh() {
        let script = resolve_address_to_p2pkh_script(TEST_PUBKEY_HEX).unwrap();
        assert_eq!(script.len(), 25);
        assert_eq!(script[0], 0x76); // OP_DUP
        assert_eq!(script[1], 0xa9); // OP_HASH160
        assert_eq!(script[2], 0x14); // push 20
        assert_eq!(script[23], 0x88); // OP_EQUALVERIFY
        assert_eq!(script[24], 0xac); // OP_CHECKSIG
    }

    #[test]
    fn resolve_bsv_address_to_p2pkh() {
        // Well-known address for the secp256k1 generator pubkey
        let pubkey = PublicKey::from_hex(TEST_PUBKEY_HEX).unwrap();
        let address = pubkey.to_address();

        let script_from_addr = resolve_address_to_p2pkh_script(&address).unwrap();
        let script_from_hex = resolve_address_to_p2pkh_script(TEST_PUBKEY_HEX).unwrap();

        // Both should produce the same P2PKH script
        assert_eq!(script_from_addr, script_from_hex);
    }

    #[test]
    fn resolve_invalid_address_fails() {
        assert!(resolve_address_to_p2pkh_script("not_a_valid_address").is_err());
        assert!(resolve_address_to_p2pkh_script("").is_err());
    }

    // ── New tests: P2MS script ───────────────────────────────────────────────

    #[test]
    fn p2ms_script_structure() {
        let pk = PublicKey::from_hex(TEST_PUBKEY_HEX).unwrap();
        let script = build_p2ms_script(2, &[pk.clone(), pk.clone(), pk]);

        // OP_2 <33-byte pk> <33-byte pk> <33-byte pk> OP_3 OP_CHECKMULTISIG
        assert_eq!(script.len(), 1 + 3 * 34 + 1 + 1); // 105
        assert_eq!(script[0], 0x52); // OP_2
        assert_eq!(script[103], 0x53); // OP_3
        assert_eq!(script[104], 0xae); // OP_CHECKMULTISIG
    }

    // ── New tests: split fee ─────────────────────────────────────────────────

    #[test]
    fn split_fee_even() {
        let scripts = vec![dummy_p2pkh_script(1), dummy_p2pkh_script(2)];
        let outputs = split_fee_outputs(1000, &scripts).unwrap();
        assert_eq!(outputs[0].0, 500);
        assert_eq!(outputs[1].0, 500);
    }

    #[test]
    fn split_fee_too_small() {
        let scripts = vec![
            dummy_p2pkh_script(1),
            dummy_p2pkh_script(2),
            dummy_p2pkh_script(3),
        ];
        assert!(split_fee_outputs(2, &scripts).is_err());
    }

    #[test]
    fn split_fee_no_addresses() {
        assert!(split_fee_outputs(1000, &[]).is_err());
    }
}
