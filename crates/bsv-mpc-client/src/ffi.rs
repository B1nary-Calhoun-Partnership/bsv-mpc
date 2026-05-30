//! UniFFI skin (native shells: iOS / Android) — compiled only under `--features native`.
//!
//! UniFFI 0.28 proc-macro mode (no `.udl`). Three surfaces:
//! - **sync tx helpers** + the host-driven [`FfiSigningSession`] state machine (the
//!   `sans-io` pattern: the shell owns I/O + the biometric and pumps round messages;
//!   kept as the lower-level primitive).
//! - **[`FfiDeployedSigner`]** (#63 / #41-4d) — the HIGH-LEVEL async `sign()` running
//!   the full §06.17.1 deployed-cosigner ceremony INTERNALLY (relay transport
//!   Rust-owned; the host injects ONLY the Secure Enclave via the [`FfiKeyStore`]
//!   callback interface). This is what `RealMpcCeremonyService` binds to.
//! - **[`WalletStorageConn`]** (#64) — the BRC-103/104 storage seam: `rpc(method,
//!   params) -> json` (Rust owns all the auth crypto). Bound by `RealWalletStorageService`.

use crate::txbuild;

/// FFI-friendly error.
///
/// The internal [`ClientError`](crate::ClientError) carries `&'static str` fields
/// (not FFI-representable), so the boundary uses this String-based error instead.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("{0}")]
    Client(String),
}

/// Swift/Kotlin-callable: txid (display hex) of a raw transaction hex.
#[uniffi::export]
pub fn ffi_tx_txid(raw_tx_hex: String) -> Result<String, FfiError> {
    let raw = hex::decode(&raw_tx_hex).map_err(|e| FfiError::Client(format!("bad hex: {e}")))?;
    Ok(txbuild::compute_txid(&raw))
}

/// Swift/Kotlin-callable: output satoshi values of a raw transaction hex, in order.
#[uniffi::export]
pub fn ffi_tx_output_sats(raw_tx_hex: String) -> Result<Vec<u64>, FfiError> {
    let raw = hex::decode(&raw_tx_hex).map_err(|e| FfiError::Client(format!("bad hex: {e}")))?;
    let outs = txbuild::parse_tx_outputs(&raw).map_err(FfiError::Client)?;
    Ok(outs.into_iter().map(|(sats, _script)| sats).collect())
}

// ── Send-path FFI (issue #68) ─────────────────────────────────────────────────
//
// Rust owns ALL tx-serialization + sighash + encoding (load-bearing rule: Swift
// never reimplements BIP-143 / tx assembly / base58 / secp256k1). These are pure,
// deterministic wrappers around `txbuild` + `bsv_mpc_core::approval` + bsv-rs — no
// network, no funds. Golden-vector tests assert FFI output == in-crate output
// byte-for-byte. All txids cross the FFI in **display** (big-endian) hex — the same
// order 100cash sees in `createAction` / BEEF — and are reversed to the internal
// (little-endian) wire order INSIDE Rust, so the host never byte-swaps.

/// Decode hex, mapping failure to a clear FFI error.
fn dehex(s: &str, what: &str) -> Result<Vec<u8>, FfiError> {
    hex::decode(s).map_err(|e| FfiError::Client(format!("{what}: bad hex: {e}")))
}

/// Decode a 32-byte **display** (big-endian) txid hex into the internal
/// (little-endian) `[u8; 32]` the wire format uses.
fn txid_display_to_internal(txid_hex: &str) -> Result<[u8; 32], FfiError> {
    let mut v = dehex(txid_hex, "txid")?;
    if v.len() != 32 {
        return Err(FfiError::Client(format!(
            "txid must be 32 bytes (64 hex chars), got {}",
            v.len()
        )));
    }
    v.reverse();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&v);
    Ok(arr)
}

/// An output: satoshis + locking-script hex.
#[derive(uniffi::Record)]
pub struct FfiTxOutput {
    pub satoshis: u64,
    pub locking_script_hex: String,
}

/// One input for the BIP-143 sighash preimage (no scripts — only the outpoint +
/// sequence; the spent UTXO's script/value are `subscript_hex`/`input_satoshis`).
#[derive(uniffi::Record)]
pub struct FfiSighashInput {
    /// Previous txid in **display** (big-endian) hex.
    pub prev_txid_hex: String,
    pub vout: u32,
    pub sequence: u32,
}

/// Everything needed to recompute one input's BIP-143 (FORKID) sighash locally.
#[derive(uniffi::Record)]
pub struct FfiSighashRequest {
    pub version: u32,
    pub inputs: Vec<FfiSighashInput>,
    pub outputs: Vec<FfiTxOutput>,
    pub locktime: u32,
    /// Which input this sighash is for.
    pub input_index: u32,
    /// Locking script of the UTXO being spent (hex).
    pub subscript_hex: String,
    pub input_satoshis: u64,
    /// e.g. `0x41` = SIGHASH_ALL | FORKID.
    pub sighash_type: u32,
}

/// Recompute an input's BIP-143 (FORKID) sighash — the device MUST derive this
/// locally from the `createAction` template, never trust a server-supplied digest.
#[uniffi::export]
pub fn ffi_bip143_sighash(req: FfiSighashRequest) -> Result<Vec<u8>, FfiError> {
    let inputs: Vec<([u8; 32], u32, u32)> = req
        .inputs
        .iter()
        .map(|i| {
            Ok((
                txid_display_to_internal(&i.prev_txid_hex)?,
                i.vout,
                i.sequence,
            ))
        })
        .collect::<Result<_, FfiError>>()?;
    // Decode output scripts into owned buffers, then borrow them for SighashParams.
    let out_scripts: Vec<Vec<u8>> = req
        .outputs
        .iter()
        .map(|o| dehex(&o.locking_script_hex, "output locking_script"))
        .collect::<Result<_, FfiError>>()?;
    let outputs: Vec<(u64, &[u8])> = req
        .outputs
        .iter()
        .zip(&out_scripts)
        .map(|(o, s)| (o.satoshis, s.as_slice()))
        .collect();
    let subscript = dehex(&req.subscript_hex, "subscript")?;
    let input_index = req.input_index as usize;
    if input_index >= inputs.len() {
        return Err(FfiError::Client(format!(
            "input_index {input_index} out of range for {} inputs",
            inputs.len()
        )));
    }
    let sighash = txbuild::compute_bip143_sighash(&txbuild::SighashParams {
        version: req.version,
        inputs: &inputs,
        outputs: &outputs,
        locktime: req.locktime,
        input_index,
        subscript: &subscript,
        input_satoshis: req.input_satoshis,
        sighash_type: req.sighash_type,
    });
    Ok(sighash.to_vec())
}

/// One fully-signed input.
#[derive(uniffi::Record)]
pub struct FfiSignedInput {
    /// Previous txid in **display** (big-endian) hex.
    pub prev_txid_hex: String,
    pub vout: u32,
    /// The complete unlocking script (scriptSig) hex (e.g. `<sig+0x41> <pubkey>`).
    pub unlocking_script_hex: String,
    pub sequence: u32,
}

/// A fully-signed transaction to assemble into raw bytes for `processAction`.
#[derive(uniffi::Record)]
pub struct FfiSignedTxRequest {
    pub version: u32,
    pub inputs: Vec<FfiSignedInput>,
    pub outputs: Vec<FfiTxOutput>,
    pub locktime: u32,
}

/// Assemble the fully-signed rawTx (hex) from the MPC-produced unlocking scripts.
#[uniffi::export]
pub fn ffi_serialize_signed_tx(req: FfiSignedTxRequest) -> Result<String, FfiError> {
    let inputs: Vec<([u8; 32], u32, Vec<u8>, u32)> = req
        .inputs
        .iter()
        .map(|i| {
            Ok((
                txid_display_to_internal(&i.prev_txid_hex)?,
                i.vout,
                dehex(&i.unlocking_script_hex, "unlocking_script")?,
                i.sequence,
            ))
        })
        .collect::<Result<_, FfiError>>()?;
    let outputs: Vec<(u64, Vec<u8>)> = req
        .outputs
        .iter()
        .map(|o| {
            Ok((
                o.satoshis,
                dehex(&o.locking_script_hex, "output locking_script")?,
            ))
        })
        .collect::<Result<_, FfiError>>()?;
    let raw = txbuild::serialize_signed_tx(req.version, &inputs, &outputs, req.locktime);
    Ok(hex::encode(raw))
}

/// Assemble a P2PKH unlocking script hex (`<sig‖sighash_flag> <compressed_pubkey>`)
/// from an MPC-produced DER signature, its sighash flag, and the joint compressed
/// pubkey. The single-byte `sighash_type` flag (e.g. `0x41` = SIGHASH_ALL|FORKID) is
/// appended to the DER signature exactly as the scriptSig requires. Swift never
/// hand-rolls scriptSig assembly (load-bearing rule); it feeds this straight into
/// [`ffi_serialize_signed_tx`] as each input's `unlocking_script_hex`.
#[uniffi::export]
pub fn ffi_p2pkh_unlocking_script_hex(
    sig_der_hex: String,
    sighash_type: u32,
    pubkey_hex: String,
) -> Result<String, FfiError> {
    if sighash_type > 0xff {
        return Err(FfiError::Client(format!(
            "sighash_type {sighash_type} does not fit in the one scriptSig flag byte"
        )));
    }
    let mut sig_checksig = dehex(&sig_der_hex, "signature DER")?;
    sig_checksig.push(sighash_type as u8);
    let pubkey = dehex(&pubkey_hex, "compressed pubkey")?;
    let pubkey33: [u8; 33] = pubkey.as_slice().try_into().map_err(|_| {
        FfiError::Client(format!(
            "compressed pubkey must be 33 bytes (66 hex chars), got {}",
            pubkey.len()
        ))
    })?;
    Ok(hex::encode(txbuild::build_p2pkh_unlocking_script(
        &sig_checksig,
        &pubkey33,
    )))
}

/// Recipient descriptor for the WYSIWYS view-hash — mirrors
/// [`bsv_mpc_core::approval::Recipient`].
#[derive(uniffi::Enum)]
pub enum FfiRecipient {
    /// A single recipient (CBOR text string).
    Single { address: String },
    /// Multiple recipients (CBOR array of text strings).
    Multi { addresses: Vec<String> },
}

/// Inputs to the §09.5.1 WYSIWYS canonical-CBOR request-view-hash (keys 1..8). All
/// text MUST already be NFC-normalized UTF-8.
#[derive(uniffi::Record)]
pub struct FfiViewHashRequest {
    pub amount: u64,
    pub recipient: FfiRecipient,
    pub sighash_hex: String,
    pub execution_id_hex: String,
    pub policy_id_hex: String,
    pub manifest_ack_hex: String,
    pub human_locale: String,
    pub rendered_text: String,
}

/// The WYSIWYS digest + the exact canonical-CBOR preimage that was hashed.
#[derive(uniffi::Record)]
pub struct FfiViewHash {
    pub hash: Vec<u8>,
    pub preimage: Vec<u8>,
}

/// Compute the §09.5.1 WYSIWYS request-view-hash the approval (#43) binds to.
#[uniffi::export]
pub fn ffi_request_view_hash(req: FfiViewHashRequest) -> Result<FfiViewHash, FfiError> {
    use bsv_mpc_core::approval::{request_view_hash, Recipient};
    let recipient = match req.recipient {
        FfiRecipient::Single { address } => Recipient::Single(address),
        FfiRecipient::Multi { addresses } => Recipient::Multi(addresses),
    };
    let rvh = request_view_hash(
        req.amount,
        &recipient,
        &req.sighash_hex,
        &req.execution_id_hex,
        &req.policy_id_hex,
        &req.manifest_ack_hex,
        &req.human_locale,
        &req.rendered_text,
    );
    Ok(FfiViewHash {
        hash: rvh.hash.to_vec(),
        preimage: rvh.preimage,
    })
}

/// One parsed input from a BEEF: the outpoint + its prev-output (value + script) so
/// the device can build the sighash without trusting server-supplied values.
#[derive(uniffi::Record)]
pub struct FfiParsedInput {
    /// Source txid in **display** (big-endian) hex.
    pub prev_txid_hex: String,
    pub vout: u32,
    pub sequence: u32,
    /// The spent output's value (`0` if the BEEF lacked the source tx).
    pub prev_satoshis: u64,
    /// The spent output's locking script hex (empty if absent).
    pub prev_locking_script_hex: String,
}

/// A BEEF-parsed transaction: version/locktime + inputs (with prev-outputs) +
/// outputs — everything needed to recompute each input's BIP-143 sighash.
#[derive(uniffi::Record)]
pub struct FfiParsedTx {
    pub version: u32,
    pub locktime: u32,
    pub inputs: Vec<FfiParsedInput>,
    pub outputs: Vec<FfiTxOutput>,
}

/// Independently re-parse the unsigned tx + its input prev-outputs from a BEEF
/// (`createAction.inputBeef`), so the device recomputes sighashes from first
/// principles. Accepts AtomicBEEF or BEEF v1/v2.
#[uniffi::export]
pub fn ffi_parse_beef_tx(beef_hex: String) -> Result<FfiParsedTx, FfiError> {
    let beef_bytes = dehex(&beef_hex, "beef")?;
    // `Beef::from_binary` parses BEEF v1/v2 AND AtomicBEEF (it strips the atomic
    // prefix). The subject (the new/unsigned tx) is the last tx (BEEF orders
    // ancestors first); each input's prev-output is resolved from the BEEF's own tx
    // set by source txid — `find_transaction_for_signing` does NOT link sources.
    let beef = bsv::transaction::Beef::from_binary(&beef_bytes)
        .map_err(|e| FfiError::Client(format!("parse BEEF: {e}")))?;
    let subject = beef
        .txs
        .last()
        .and_then(|t| t.tx())
        .ok_or_else(|| FfiError::Client("BEEF has no subject transaction".into()))?
        .clone();

    let mut inputs = Vec::with_capacity(subject.inputs.len());
    for inp in &subject.inputs {
        let prev_txid_hex = inp.get_source_txid().unwrap_or_default();
        let vout = inp.source_output_index;
        // Resolve the prev-output: from the BEEF tx set first, else a linked
        // source_transaction if present.
        let prevout = beef
            .find_txid(&prev_txid_hex)
            .and_then(|bt| bt.tx())
            .or(inp.source_transaction.as_deref())
            .and_then(|src| src.outputs.get(vout as usize))
            .map(|o| (o.satoshis.unwrap_or(0), o.locking_script.to_hex()));
        let (prev_satoshis, prev_locking_script_hex) = prevout.unwrap_or((0, String::new()));
        inputs.push(FfiParsedInput {
            prev_txid_hex,
            vout,
            sequence: inp.sequence,
            prev_satoshis,
            prev_locking_script_hex,
        });
    }
    let outputs = subject
        .outputs
        .iter()
        .map(|o| FfiTxOutput {
            satoshis: o.satoshis.unwrap_or(0),
            locking_script_hex: o.locking_script.to_hex(),
        })
        .collect();
    Ok(FfiParsedTx {
        version: subject.version,
        locktime: subject.lock_time,
        inputs,
        outputs,
    })
}

/// Extract the SUBJECT (last) transaction's raw bytes (hex) from a BEEF — e.g.
/// the wallet-signed funding tx a BRC-100 `createAction` returns as its `tx`
/// (atomic BEEF). Needed to re-broadcast that funding tx through a public
/// broadcaster (ARC) when the wallet's own broadcaster doesn't propagate. Swift
/// never parses BEEF/tx bytes itself (load-bearing rule). Accepts AtomicBEEF or
/// BEEF v1/v2 (mirrors [`ffi_parse_beef_tx`]'s subject selection).
#[uniffi::export]
pub fn ffi_beef_subject_raw_tx_hex(beef_hex: String) -> Result<String, FfiError> {
    let beef_bytes = dehex(&beef_hex, "beef")?;
    let beef = bsv::transaction::Beef::from_binary(&beef_bytes)
        .map_err(|e| FfiError::Client(format!("parse BEEF: {e}")))?;
    let subject = beef
        .txs
        .last()
        .and_then(|t| t.tx())
        .ok_or_else(|| FfiError::Client("BEEF has no subject transaction".into()))?;
    Ok(subject.to_hex())
}

/// Derive the P2PKH locking-script hex from a base58check address — the encoding
/// the device must NOT hand-roll in Swift. Validates the base58check checksum and
/// the 25-byte `version ‖ hash160 ‖ checksum` layout.
#[uniffi::export]
pub fn ffi_address_to_locking_script_hex(address: String) -> Result<String, FfiError> {
    // `Address::new_from_string` validates the base58check checksum + layout.
    let addr = bsv::script::Address::new_from_string(&address)
        .map_err(|e| FfiError::Client(format!("invalid BSV address '{address}': {e}")))?;
    let hash = addr.public_key_hash();
    let mut hash20 = [0u8; 20];
    if hash.len() != 20 {
        return Err(FfiError::Client(format!(
            "address pubkey-hash must be 20 bytes, got {}",
            hash.len()
        )));
    }
    hash20.copy_from_slice(hash);
    Ok(hex::encode(txbuild::p2pkh_locking_script_from_hash(
        &hash20,
    )))
}

/// Compressed (33-byte, `02`/`03`-prefixed) public-key hex for a BRC-31 device
/// identity private key (32-byte hex) — for device enrollment. Swift never touches
/// secp256k1.
#[uniffi::export]
pub fn ffi_identity_pubkey_compressed_hex(priv_hex: String) -> Result<String, FfiError> {
    let bytes = dehex(&priv_hex, "identity priv")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| FfiError::Client("identity priv must be 32 bytes".into()))?;
    let sk = bsv::primitives::ec::PrivateKey::from_bytes(&arr)
        .map_err(|e| FfiError::Client(format!("identity priv: {e}")))?;
    Ok(hex::encode(sk.public_key().to_compressed()))
}

// ── Host-driven signing session (the proven `sans-io` FFI pattern) ────────────
//
// The native shell (Swift/Kotlin) owns all I/O and the biometric unseal; it
// passes the *already-unsealed* cggmp24 key-share JSON in, then pumps round
// messages between this session and the cosigner over its own transport. Rust
// stays a pure, synchronous state machine — no async, no foreign callbacks.

use std::sync::{Arc, Mutex};

/// One step of the host-driven signing ceremony.
#[derive(uniffi::Enum)]
pub enum FfiSignStep {
    /// More rounds to go — send these messages to the cosigner, then call
    /// `process` again with the cosigner's reply.
    NextRound { messages: Vec<Vec<u8>> },
    /// Done — the combined signature.
    Complete {
        signature_der: Vec<u8>,
        r: Vec<u8>,
        s: Vec<u8>,
    },
}

/// A host-driven threshold-signing session over a single share.
#[derive(uniffi::Object)]
pub struct FfiSigningSession {
    inner: Mutex<bsv_mpc_core::signing::SigningCoordinator>,
}

fn msgs_to_bytes(msgs: Vec<bsv_mpc_core::RoundMessage>) -> Result<Vec<Vec<u8>>, FfiError> {
    msgs.iter()
        .map(|m| serde_json::to_vec(m).map_err(|e| FfiError::Client(format!("encode msg: {e}"))))
        .collect()
}

fn bytes_to_msgs(raw: Vec<Vec<u8>>) -> Result<Vec<bsv_mpc_core::RoundMessage>, FfiError> {
    raw.iter()
        .map(|b| {
            serde_json::from_slice(b).map_err(|e| FfiError::Client(format!("decode msg: {e}")))
        })
        .collect()
}

#[uniffi::export]
impl FfiSigningSession {
    /// Create a session from the host-unsealed cggmp24 key-share JSON + the
    /// signing metadata (everything `StoredShare` holds, plus the joint pubkey).
    #[uniffi::constructor]
    pub fn new(
        share_json: Vec<u8>,
        joint_pubkey_compressed: Vec<u8>,
        session_id: Vec<u8>,
        share_index: u16,
        threshold: u16,
        parties: u16,
    ) -> Result<Arc<Self>, FfiError> {
        use bsv_mpc_core::signing::SigningCoordinator;
        use bsv_mpc_core::{EncryptedShare, SessionId, ShareIndex, ThresholdConfig};

        let config = ThresholdConfig::new(threshold, parties)
            .map_err(|e| FfiError::Client(e.to_string()))?;
        let sid: [u8; 32] = session_id
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::Client("session_id must be 32 bytes".into()))?;
        let session = SessionId::from_bytes(sid);
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: share_json,
            session_id: session,
            share_index: ShareIndex(share_index),
            config,
            joint_pubkey_compressed,
        };
        let participants: Vec<u16> = (0..parties).collect();
        let coord = SigningCoordinator::new(session, share, config, participants);
        Ok(Arc::new(Self {
            inner: Mutex::new(coord),
        }))
    }

    /// Begin signing `sighash` (32 bytes). Returns this party's round-1 messages.
    pub fn init(
        &self,
        sighash: Vec<u8>,
        brc42_offset: Option<Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>, FfiError> {
        let hash: [u8; 32] = sighash
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::Client("sighash must be 32 bytes".into()))?;
        let offset: Option<[u8; 32]> = match brc42_offset {
            Some(o) => Some(
                o.as_slice()
                    .try_into()
                    .map_err(|_| FfiError::Client("brc42_offset must be 32 bytes".into()))?,
            ),
            None => None,
        };
        let mut coord = self.inner.lock().expect("session lock");
        let msgs = coord
            .init_round(&hash, offset)
            .map_err(|e| FfiError::Client(e.to_string()))?;
        msgs_to_bytes(msgs)
    }

    /// Feed the cosigner's messages for the current round; advance the ceremony.
    pub fn process(&self, incoming: Vec<Vec<u8>>) -> Result<FfiSignStep, FfiError> {
        use bsv_mpc_core::signing::SigningRoundResult;
        let msgs = bytes_to_msgs(incoming)?;
        let mut coord = self.inner.lock().expect("session lock");
        match coord
            .process_round(msgs)
            .map_err(|e| FfiError::Client(e.to_string()))?
        {
            SigningRoundResult::NextRound(next) => Ok(FfiSignStep::NextRound {
                messages: msgs_to_bytes(next)?,
            }),
            SigningRoundResult::Complete(res) => Ok(FfiSignStep::Complete {
                signature_der: res.signature,
                r: res.r,
                s: res.s,
            }),
        }
    }
}

// ── High-level deployed-cosigner SIGN seam over UniFFI (issue #63 / #41-4d) ───
//
// The locked design (handoff §4.5 Decision 1): a HIGH-LEVEL async `sign()` that
// runs the FULL §06.17.1 deployed-cosigner ceremony INTERNALLY in Rust (unseal →
// take a ready presig bundle → ONE relay round-trip → combine → fail-closed
// pre-flight). The host injects ONLY the Secure Enclave as a callback interface;
// the relay/HTTP transport is Rust-owned. NOT the sans-io `FfiSigningSession`
// (that stays as the lower-level primitive). Native-only.

/// Host-implemented Secure-Enclave callback — the ONLY crypto-adjacent host code
/// for the deployed sign seam. Swift/Kotlin implement biometric-gated unseal of
/// the device-sealed cggmp24 key-share. Async: the unseal awaits a biometric.
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait FfiKeyStore: Send + Sync {
    /// Device-seal the freshly-provisioned share JSON for `agent_id` (write side —
    /// called once at `create_wallet`). The host wraps it in the Secure Enclave.
    async fn seal_share(&self, agent_id: String, share: Vec<u8>) -> Result<(), FfiError>;

    /// Unseal the device-sealed share JSON for `agent_id`, showing `reason` as the
    /// biometric prompt. Returns the plaintext cggmp24 KeyShare JSON bytes.
    async fn unseal_share(&self, agent_id: String, reason: String) -> Result<Vec<u8>, FfiError>;
}

/// Adapts the foreign [`FfiKeyStore`] to the internal `NativeKeyStore`.
#[cfg(not(target_arch = "wasm32"))]
struct FfiKeyStoreAdapter(std::sync::Arc<dyn FfiKeyStore>);

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl crate::native_io::keystore::NativeKeyStore for FfiKeyStoreAdapter {
    async fn seal_share(
        &self,
        agent_id: &str,
        share_plaintext: &[u8],
    ) -> Result<(), crate::error::ClientError> {
        self.0
            .seal_share(agent_id.to_string(), share_plaintext.to_vec())
            .await
            .map_err(|e| crate::error::ClientError::Host {
                seam: "keystore",
                reason: e.to_string(),
            })
    }

    async fn unseal_share(
        &self,
        agent_id: &str,
        reason: &str,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, crate::error::ClientError> {
        let bytes = self
            .0
            .unseal_share(agent_id.to_string(), reason.to_string())
            .await
            .map_err(|e| crate::error::ClientError::Unseal(e.to_string()))?;
        Ok(zeroize::Zeroizing::new(bytes))
    }
}

// ── Device Paillier prime pool (Lever B / ADR-0041 / issue #100) ──────────────
//
// The device pre-generates Paillier safe-prime sets in the BACKGROUND and stores
// them encrypted-at-rest, so signup's aux-info phase consumes a warm pooled set
// instead of grinding ~250s of inline safe-prime gen on the critical path. The
// host owns ONLY opaque-ciphertext persistence; the primes are AES-256-GCM-sealed
// by `bsv_mpc_core::paillier_pool` (key BRC-42-derived from the at-rest root,
// never persisted), so the host never sees plaintext primes and never derives the
// pool key. PERFORMANCE-only: byte-equivalent to inline gen, no protocol change.

/// One at-rest-encrypted Paillier safe-prime set blob — FFI-friendly 1:1 mirror of
/// [`bsv_mpc_core::paillier_pool::EncryptedPrimes`] (which uses `nonce: [u8; 12]`).
/// Opaque to the host: it stores/returns these bytes verbatim and never decrypts.
#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Record)]
pub struct FfiEncryptedPrimes {
    /// AES-GCM 12-byte nonce.
    pub nonce: Vec<u8>,
    /// AES-GCM ciphertext + 16-byte authentication tag (appended).
    pub ciphertext: Vec<u8>,
}

/// Host-implemented FIFO encrypted-prime-pool store — the device-side persistence
/// for Lever B. Mirrors the [`FfiKeyStore`] foreign-callback pattern. SYNC: the
/// underlying [`bsv_mpc_core::paillier_pool::PrimePoolStorage`] is sync and the
/// calls are infrequent (backfill / one take per held index) + fast (a queue
/// push/pop on the host), so no async bridge is needed. Implementations MUST
/// preserve FIFO ordering (oldest-first drain).
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export(with_foreign)]
pub trait FfiPrimePoolStore: Send + Sync {
    /// Append an encrypted blob to the end of the queue.
    fn put_encrypted(&self, blob: FfiEncryptedPrimes) -> Result<(), FfiError>;

    /// Remove and return the oldest encrypted blob, or `None` if empty.
    fn take_encrypted(&self) -> Result<Option<FfiEncryptedPrimes>, FfiError>;

    /// Number of blobs currently stored.
    fn count(&self) -> Result<u32, FfiError>;
}

/// Adapts the foreign [`FfiPrimePoolStore`] to the core
/// [`bsv_mpc_core::paillier_pool::PrimePoolStorage`] (sync ↔ sync). Converts
/// between [`FfiEncryptedPrimes`] (Vec-backed nonce) and the core
/// [`bsv_mpc_core::paillier_pool::EncryptedPrimes`] (`[u8; 12]` nonce).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct FfiPrimePoolStoreAdapter(pub std::sync::Arc<dyn FfiPrimePoolStore>);

#[cfg(not(target_arch = "wasm32"))]
impl bsv_mpc_core::paillier_pool::PrimePoolStorage for FfiPrimePoolStoreAdapter {
    fn put_encrypted(
        &self,
        blob: bsv_mpc_core::paillier_pool::EncryptedPrimes,
    ) -> bsv_mpc_core::error::Result<()> {
        self.0
            .put_encrypted(FfiEncryptedPrimes {
                nonce: blob.nonce.to_vec(),
                ciphertext: blob.ciphertext.clone(),
            })
            .map_err(|e| bsv_mpc_core::error::MpcError::ShareStorage(e.to_string()))
    }

    fn take_encrypted(
        &self,
    ) -> bsv_mpc_core::error::Result<Option<bsv_mpc_core::paillier_pool::EncryptedPrimes>> {
        let Some(blob) = self
            .0
            .take_encrypted()
            .map_err(|e| bsv_mpc_core::error::MpcError::ShareStorage(e.to_string()))?
        else {
            return Ok(None);
        };
        let nonce: [u8; 12] = blob.nonce.as_slice().try_into().map_err(|_| {
            bsv_mpc_core::error::MpcError::ShareStorage(format!(
                "prime-pool nonce must be 12 bytes, got {}",
                blob.nonce.len()
            ))
        })?;
        Ok(Some(bsv_mpc_core::paillier_pool::EncryptedPrimes {
            nonce,
            ciphertext: blob.ciphertext,
        }))
    }

    fn count(&self) -> bsv_mpc_core::error::Result<usize> {
        self.0
            .count()
            .map(|c| c as usize)
            .map_err(|e| bsv_mpc_core::error::MpcError::ShareStorage(e.to_string()))
    }
}

/// Background safe-prime backfill (Lever C pre-warm entrypoint). Fills the device
/// prime pool up to `floor` sets, generating any shortfall on a blocking thread
/// (safe-prime gen is CPU-bound — must NOT block the async runtime). Idempotent /
/// skip-if-full and best-effort: if the pool is already at `floor` it returns 0.
/// Returns the number of new sets added.
///
/// * `at_rest_root_hex` — the device's 32-byte at-rest root (same value carried in
///   [`FfiSignerConfig::at_rest_root_hex`]); BRC-42-derives the pool encryption key.
/// * `pool_id_hex` — domain-separation bytes (e.g. the device identity pubkey hex).
/// * `floor` — minimum pool size to maintain (device recommendation: `2 * w`).
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export(async_runtime = "tokio")]
pub async fn ffi_prime_pool_backfill(
    at_rest_root_hex: String,
    pool_id_hex: String,
    floor: u32,
    store: std::sync::Arc<dyn FfiPrimePoolStore>,
) -> Result<u32, FfiError> {
    let root = hex32(&at_rest_root_hex, "at_rest_root")?;
    let pool_id = dehex(&pool_id_hex, "pool_id")?;
    // Safe-prime gen has a multi-GiB transient RSS peak and is CPU-bound for
    // seconds-to-minutes per set — run it on a blocking thread so the async
    // runtime workers stay free (the core `generate_serialized` RSS gate still
    // serializes against any concurrent inline gen in this process).
    let added = tokio::task::spawn_blocking(move || {
        let pool = bsv_mpc_core::paillier_pool::PaillierPool::new(
            FfiPrimePoolStoreAdapter(store),
            &root,
            &pool_id,
            floor as usize,
        );
        pool.backfill_to_floor(&mut rand::rngs::OsRng)
    })
    .await
    .map_err(|e| FfiError::Client(format!("prime-pool backfill task panicked: {e}")))?
    .map_err(|e| FfiError::Client(format!("prime-pool backfill: {e}")))?;
    Ok(added as u32)
}

/// FFI config for a provisioned wallet's deployed signer (all hex/primitive — no
/// FFI-opaque crypto types crossing the boundary).
#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Record)]
pub struct FfiSignerConfig {
    pub relay_url: String,
    pub container_url: String,
    /// §07.4 device identity private key (64-char hex). Distinct from the MPC share.
    pub identity_key_hex: String,
    /// Device secret rooting the at-rest seal of bundle presig bytes (64-char hex).
    pub at_rest_root_hex: String,
    /// Durable presig-pool directory (app storage path).
    pub bundle_dir: String,
    /// §09 policy hash (64-char hex; empty ⇒ all-zero).
    pub policy_id_hex: String,
    /// Joint pubkey hex (the wallet id + owner-authz key).
    pub agent_id: String,
    /// 33-byte compressed joint pubkey (66-char hex).
    pub joint_pubkey_hex: String,
    /// Base58Check P2PKH address of the joint key.
    pub joint_address: String,
    pub threshold: u16,
    pub parties: u16,
    pub participants: Vec<u16>,
    /// This device's PRIMARY signing index (`= my_indices[0]`).
    pub device_share_index: u16,
    /// ALL keygen indices this device holds (ADR-0052 device-holds-(t−1)). Length
    /// 1 for a 2-of-2 wallet; length `w = t−1` for a multi-share wallet.
    pub my_indices: Vec<u16>,
    /// The cosigner keygen index that co-signs to complete the quorum.
    pub cosigner_party: u16,
    /// **#85 MITM gate.** The completing cosigner's MASTER identity pubkey hex,
    /// PINNED out-of-band (empty = unpinned 2-of-2 / dev). The n-party presign
    /// verifies the cosigner's fetched identity equals this.
    #[uniffi(default = "")]
    pub cosigner_master_pub: String,
    /// Share-metadata session id (32-byte hex).
    pub dkg_session_id_hex: String,
}

/// A combined BSV-ready signature (DER + raw r/s), pre-flight-verified before return.
#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Record)]
pub struct FfiSignature {
    pub signature_der: Vec<u8>,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

#[cfg(not(target_arch = "wasm32"))]
fn hex32(s: &str, what: &str) -> Result<[u8; 32], FfiError> {
    let v = hex::decode(s).map_err(|e| FfiError::Client(format!("{what} hex: {e}")))?;
    v.as_slice()
        .try_into()
        .map_err(|_| FfiError::Client(format!("{what} must be 32 bytes")))
}

/// The high-level deployed signer. Construct with [`FfiDeployedSigner::connect`].
#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Object)]
pub struct FfiDeployedSigner {
    inner: crate::native_io::signer::DeployedSigner,
}

#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export(async_runtime = "tokio")]
impl FfiDeployedSigner {
    /// Connect to a provisioned wallet's deployed cosigner (BRC-31 handshake) +
    /// open the durable presig pool. `keystore` is the host's Secure Enclave.
    #[uniffi::constructor]
    pub async fn connect(
        config: FfiSignerConfig,
        keystore: std::sync::Arc<dyn FfiKeyStore>,
    ) -> Result<std::sync::Arc<Self>, FfiError> {
        use bsv::primitives::ec::PrivateKey;
        use bsv_mpc_core::types::{JointPublicKey, PolicyId, SessionId, ThresholdConfig};

        let identity = {
            let bytes = hex32(&config.identity_key_hex, "identity_key")?;
            PrivateKey::from_bytes(&bytes)
                .map_err(|e| FfiError::Client(format!("identity key: {e}")))?
        };
        let at_rest_root = hex32(&config.at_rest_root_hex, "at_rest_root")?;
        let policy_id = if config.policy_id_hex.is_empty() {
            PolicyId([0u8; 32])
        } else {
            PolicyId(hex32(&config.policy_id_hex, "policy_id")?)
        };
        let joint_compressed = hex::decode(&config.joint_pubkey_hex)
            .map_err(|e| FfiError::Client(format!("joint_pubkey hex: {e}")))?;
        let config_t = ThresholdConfig::new(config.threshold, config.parties)
            .map_err(|e| FfiError::Client(e.to_string()))?;
        let dkg_session_id =
            SessionId::from_bytes(hex32(&config.dkg_session_id_hex, "dkg_session_id")?);

        let signer_config = crate::native_io::signer::DeployedSignerConfig {
            relay_url: config.relay_url,
            container_url: config.container_url,
            identity,
            at_rest_root,
            bundle_dir: std::path::PathBuf::from(config.bundle_dir),
            policy_id,
            meta: crate::native_io::signer::WalletMeta {
                agent_id: config.agent_id,
                joint_key: JointPublicKey {
                    compressed: joint_compressed,
                    address: config.joint_address,
                },
                config: config_t,
                participants: config.participants,
                device_share_index: config.device_share_index,
                my_indices: if config.my_indices.is_empty() {
                    // Back-compat: a host that predates `my_indices` (2-of-2)
                    // sends none → the lone device index.
                    vec![config.device_share_index]
                } else {
                    config.my_indices
                },
                cosigner_party: config.cosigner_party,
                cosigner_master_pub: if config.cosigner_master_pub.is_empty() {
                    None
                } else {
                    Some(config.cosigner_master_pub)
                },
                dkg_session_id,
            },
        };
        let keystore: std::sync::Arc<dyn crate::native_io::keystore::NativeKeyStore> =
            std::sync::Arc::new(FfiKeyStoreAdapter(keystore));
        let inner = crate::native_io::signer::DeployedSigner::connect(signer_config, keystore)
            .await
            .map_err(|e| FfiError::Client(e.to_string()))?;
        Ok(std::sync::Arc::new(Self { inner }))
    }

    /// Ready presig bundles in the pool.
    pub fn pool_len(&self) -> u32 {
        self.inner.pool_len() as u32
    }

    /// Opportunistic top-up: one biometric mints `n` durable presig bundles (heavy;
    /// off the tap path). Returns how many were minted.
    pub async fn top_up_presigs(
        &self,
        n: u32,
        reason: String,
        timeout_secs: u64,
    ) -> Result<u32, FfiError> {
        self.inner
            .top_up_presigs(
                n as usize,
                &reason,
                std::time::Duration::from_secs(timeout_secs),
            )
            .await
            .map(|m| m as u32)
            .map_err(|e| FfiError::Client(e.to_string()))
    }

    /// The high-level deployed sign: biometric-gated, fast (pool) online sign with a
    /// fail-closed pre-flight. `sighash` is 32 bytes; `brc42_offset` (32 bytes) is the
    /// optional BRC-42 derived-key shift.
    pub async fn sign(
        &self,
        sighash: Vec<u8>,
        reason: String,
        brc42_offset: Option<Vec<u8>>,
        recv_timeout_secs: u64,
        presign_timeout_secs: u64,
    ) -> Result<FfiSignature, FfiError> {
        let hash: [u8; 32] = sighash
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::Client("sighash must be 32 bytes".into()))?;
        let offset: Option<[u8; 32]> = match brc42_offset {
            Some(o) => Some(
                o.as_slice()
                    .try_into()
                    .map_err(|_| FfiError::Client("brc42_offset must be 32 bytes".into()))?,
            ),
            None => None,
        };
        let res = self
            .inner
            .sign(
                &hash,
                &reason,
                offset,
                std::time::Duration::from_secs(recv_timeout_secs),
                std::time::Duration::from_secs(presign_timeout_secs),
            )
            .await
            .map_err(|e| FfiError::Client(e.to_string()))?;
        Ok(FfiSignature {
            signature_der: res.signature,
            r: res.r,
            s: res.s,
        })
    }

    /// **#91 — derive the BRC-42 offset + child key for a counterparty, atomically.**
    /// `Anyone` is local (0 MPC); `Self_`/`Other` run the distributed ECDH INTERNALLY
    /// (unseal the device's held shares → local partials → ONE #90 relay round to the
    /// pinned cosigner → Lagrange-combine). Returns the `brc42_offset` (feed to
    /// [`Self::sign`]), the derived pubkey hex (the scriptSig key), the P2PKH locking
    /// script (the sighash subscript), and the receive address — ALL from one shared
    /// secret. `reason` is the biometric prompt for the share unseal (ignored for
    /// `Anyone`). `timeout_secs` bounds the relay round.
    pub async fn derive_offset_for_counterparty(
        &self,
        counterparty: FfiCounterparty,
        protocol_name: String,
        key_id: String,
        security_level: u8,
        reason: String,
        timeout_secs: u64,
    ) -> Result<FfiDerivedKey, FfiError> {
        use crate::native_io::DerivationCounterparty;
        let cp = match counterparty {
            FfiCounterparty::SelfWallet => DerivationCounterparty::SelfWallet,
            FfiCounterparty::Anyone => DerivationCounterparty::Anyone,
            FfiCounterparty::Other { pubkey_hex } => {
                DerivationCounterparty::Other(parse_pubkey33(&pubkey_hex, "counterparty pubkey")?)
            }
        };
        let dk = self
            .inner
            .derive_offset_for_counterparty(
                cp,
                &protocol_name,
                &key_id,
                security_level,
                &reason,
                std::time::Duration::from_secs(timeout_secs),
            )
            .await
            .map_err(|e| FfiError::Client(e.to_string()))?;
        Ok(ffi_derived_key(dk))
    }
}

// ── Provisioning seam over UniFFI (issue #65) ────────────────────────────────
//
// The create side, completing the FFI trio (#63 sign, #64 storage, this =
// provision). Runs the real distributed DKG vs the deployed cosigner INTERNALLY,
// device-seals share_B via the host's `FfiKeyStore.seal_share`, and returns the
// fully-populated `FfiSignerConfig` the host persists + feeds straight to
// `FfiDeployedSigner::connect`. Keygen-over-FFI is exposed ONLY here (not raw rounds).

/// Provision a new 2-party wallet with the deployed cosigner. The host injects the
/// Secure Enclave (`FfiKeyStore`); on return the freshly-DKG'd share is sealed and
/// the returned `FfiSignerConfig` is ready for `FfiDeployedSigner::connect`.
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::too_many_arguments)]
#[uniffi::export(async_runtime = "tokio")]
pub async fn create_wallet(
    relay_url: String,
    container_url: String,
    identity_key_hex: String,
    at_rest_root_hex: String,
    bundle_dir: String,
    policy_id_hex: String,
    threshold: u16,
    parties: u16,
    keystore: std::sync::Arc<dyn FfiKeyStore>,
) -> Result<FfiSignerConfig, FfiError> {
    use bsv::primitives::ec::PrivateKey;
    use bsv_mpc_core::types::ThresholdConfig;

    let identity = {
        let bytes = hex32(&identity_key_hex, "identity_key")?;
        PrivateKey::from_bytes(&bytes)
            .map_err(|e| FfiError::Client(format!("identity key: {e}")))?
    };
    let config =
        ThresholdConfig::new(threshold, parties).map_err(|e| FfiError::Client(e.to_string()))?;
    let ks: std::sync::Arc<dyn crate::native_io::keystore::NativeKeyStore> =
        std::sync::Arc::new(FfiKeyStoreAdapter(keystore));

    let w = crate::native_io::provision::provision_wallet(
        &container_url,
        identity,
        config,
        ks.as_ref(),
    )
    .await
    .map_err(|e| FfiError::Client(e.to_string()))?;

    Ok(FfiSignerConfig {
        relay_url,
        container_url,
        identity_key_hex,
        at_rest_root_hex,
        bundle_dir,
        policy_id_hex,
        agent_id: w.agent_id,
        joint_pubkey_hex: hex::encode(&w.joint_key.compressed),
        joint_address: w.joint_key.address,
        threshold,
        parties,
        participants: w.participants,
        device_share_index: w.device_share_index,
        my_indices: vec![w.device_share_index],
        cosigner_party: w.cosigner_party,
        cosigner_master_pub: String::new(), // 2-party: unpinned (no n-party Notary)
        dkg_session_id_hex: w.dkg_session_id.hex(),
    })
}

// ── n-party (device-holds-(t−1)) provisioning over UniFFI (issue #69 PR-2) ───
//
// The multi-share generalization of `create_wallet`: a genuine n-party DKG over
// the relay where the device drives `w = t−1` keygen parties and the `cosigners`
// drive the rest (one MAY hold several indices). On return the device's `w`
// signable shares are sealed composite-keyed `"{agent_id}#{index}"` and the
// `FfiSignerConfig` is ready for `FfiDeployedSigner::connect`. The 2-of-2
// `create_wallet` above is unchanged (back-compat).

/// One network-side cosigner for [`create_wallet_nparty`]: its base URL + the
/// absolute keygen indices it drives (`indices.len() > 1` = one Notary holding
/// several indices).
#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Record)]
pub struct FfiNpartyCosigner {
    pub container_url: String,
    pub indices: Vec<u16>,
    /// **#85 MITM gate.** This Notary's MASTER identity pubkey hex, PINNED
    /// out-of-band (the host ships the named Notary's identity). When set, the DKG
    /// verifies every per-index relay pub's attestation against it + runs a post-DKG
    /// liveness challenge before returning a fundable wallet. Empty = unpinned
    /// (dev/test only — NOT for funded production).
    pub expected_master_pub: String,
}

/// Generous ceiling for the n-party DKG-over-relay (parallel safe-prime gen
/// dominates; ~6 min observed for 4-of-6). A bound, not a sleep.
#[cfg(not(target_arch = "wasm32"))]
const NPARTY_PROVISION_TIMEOUT_SECS: u64 = 600;

/// Provision an n-party (device-holds-(t−1)) wallet via a genuine n-party DKG
/// over the relay (ADR-0052 Model B / §06.22). `device_indices` MUST be exactly
/// `w = t−1` indices and `device_indices` + every cosigner's `indices` MUST
/// partition `0..parties` (validated fail-closed before any network). The signer
/// connects to the FIRST cosigner for the sign-time relay trigger; the device
/// folds its `w` partials locally and that one cosigner completes the quorum.
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::too_many_arguments)]
#[uniffi::export(async_runtime = "tokio")]
pub async fn create_wallet_nparty(
    relay_url: String,
    identity_key_hex: String,
    at_rest_root_hex: String,
    bundle_dir: String,
    policy_id_hex: String,
    threshold: u16,
    parties: u16,
    device_indices: Vec<u16>,
    cosigners: Vec<FfiNpartyCosigner>,
    keystore: std::sync::Arc<dyn FfiKeyStore>,
    // Lever B (#99) — OPTIONAL device Paillier prime pool. When the host supplies a
    // pool store, the device draws its `w` aux-info safe-prime sets from the warm
    // on-device pool (microseconds) instead of grinding them inline (~250s for
    // 4-of-6). A miss/empty pool falls back to inline gen, so this is strictly
    // Pareto. `None` ⇒ today's always-inline behavior. The pool seals at rest under
    // a key BRC-42-derived from `at_rest_root_hex` + the device identity pubkey (the
    // `pool_id`); the host stores only opaque ciphertext.
    prime_pool_store: Option<std::sync::Arc<dyn FfiPrimePoolStore>>,
) -> Result<FfiSignerConfig, FfiError> {
    use bsv::primitives::ec::PrivateKey;
    use bsv_mpc_core::types::ThresholdConfig;

    let identity = {
        let bytes = hex32(&identity_key_hex, "identity_key")?;
        PrivateKey::from_bytes(&bytes)
            .map_err(|e| FfiError::Client(format!("identity key: {e}")))?
    };
    let config =
        ThresholdConfig::new(threshold, parties).map_err(|e| FfiError::Client(e.to_string()))?;
    let ks: std::sync::Arc<dyn crate::native_io::keystore::NativeKeyStore> =
        std::sync::Arc::new(FfiKeyStoreAdapter(keystore));

    // The sign-time relay trigger is the FIRST cosigner's first index (one
    // cosigner partial completes the t-quorum alongside the device's `w`).
    let primary_container = cosigners
        .first()
        .map(|c| c.container_url.clone())
        .ok_or_else(|| {
            FfiError::Client("create_wallet_nparty: at least one cosigner required".into())
        })?;
    let cosigner_party = cosigners
        .first()
        .and_then(|c| c.indices.first().copied())
        .ok_or_else(|| {
            FfiError::Client("create_wallet_nparty: first cosigner has no index".into())
        })?;

    // #85: the completing cosigner (the one driving `cosigner_party`) is the FIRST
    // Notary — pin its master into the signer config so sign-time presigns verify it.
    let cosigner_master_pub = cosigners
        .first()
        .map(|c| c.expected_master_pub.clone())
        .unwrap_or_default();

    let cosigner_endpoints: Vec<crate::native_io::provision::NpartyCosigner> = cosigners
        .into_iter()
        .map(|c| crate::native_io::provision::NpartyCosigner {
            container_url: c.container_url,
            indices: c.indices,
            // Empty hex string ⇒ unpinned (dev/test); Some ⇒ #85-verified.
            expected_master_pub: if c.expected_master_pub.is_empty() {
                None
            } else {
                Some(c.expected_master_pub)
            },
        })
        .collect();

    // Lever B (#99): if the host supplied a prime-pool store, wrap it in the core
    // adapter + carry the at-rest root and pool_id (the device identity pubkey
    // bytes) so the relay path draws warm sets per held index. `None` ⇒ inline gen.
    let prime_pool = match prime_pool_store {
        Some(store) => {
            let at_rest_root = hex32(&at_rest_root_hex, "at_rest_root")?;
            // pool_id = device identity pubkey bytes (domain separation). `to_hex`
            // is the canonical compressed-pubkey hex; decode it back to bytes.
            let pool_id = hex::decode(identity.public_key().to_hex())
                .map_err(|e| FfiError::Client(format!("identity pubkey hex: {e}")))?;
            Some(crate::native_io::provision::ProvisionPrimePool {
                storage: std::sync::Arc::new(FfiPrimePoolStoreAdapter(store)),
                at_rest_root,
                pool_id,
            })
        }
        None => None,
    };

    let w = crate::native_io::provision::provision_wallet_nparty(
        &relay_url,
        identity,
        config,
        device_indices,
        cosigner_endpoints,
        std::time::Duration::from_secs(NPARTY_PROVISION_TIMEOUT_SECS),
        ks.as_ref(),
        prime_pool,
    )
    .await
    .map_err(|e| FfiError::Client(e.to_string()))?;

    // Sign-time participant set = the device's `w` indices + the one trigger
    // cosigner = `t` signers (the `device_holds_combine` quorum).
    let device_primary = *w
        .my_indices
        .first()
        .ok_or_else(|| FfiError::Client("create_wallet_nparty: device holds no index".into()))?;
    let mut participants = w.my_indices.clone();
    participants.push(cosigner_party);
    participants.sort_unstable();
    participants.dedup();

    Ok(FfiSignerConfig {
        relay_url,
        container_url: primary_container,
        identity_key_hex,
        at_rest_root_hex,
        bundle_dir,
        policy_id_hex,
        agent_id: w.agent_id,
        joint_pubkey_hex: hex::encode(&w.joint_key.compressed),
        joint_address: w.joint_key.address,
        threshold,
        parties,
        participants,
        device_share_index: device_primary,
        my_indices: w.my_indices,
        cosigner_party,
        cosigner_master_pub,
        dkg_session_id_hex: w.dkg_session_id.hex(),
    })
}

// ── Recovery seam over UniFFI (issue #66) ────────────────────────────────────
//
// The 4th FFI seam, completing the quartet (#65 create, #63 sign, #64 storage,
// this = recover). Runs the ADDRESS-PRESERVING reshare of the EXISTING wallet onto
// THIS fresh / lost-phone device from the host's L1 backup share B INTERNALLY in
// Rust, device-seals the rotated share via the host's `FfiKeyStore.seal_share`, and
// returns the SAME-shaped `FfiSignerConfig` the host persists + feeds straight to
// `FfiDeployedSigner::connect` (joint pubkey UNCHANGED ⇒ same address). Removes the
// last `notImplemented` mock on 100cash's `recoverOntoThisDevice()`.

/// Generous upper bound for the reshare-over-relay ceremony (throwaway DKG +
/// container safe-prime gen + cross-(t,n) PSS). A ceiling, not a sleep — matched to
/// the proven proxy reshare path (`recovery_spend_deployed_mainnet_e2e` uses 360s).
#[cfg(not(target_arch = "wasm32"))]
const RECOVER_TIMEOUT_SECS: u64 = 360;

/// Recover an EXISTING 2-of-2 wallet onto THIS device from the passkey-PRF-unwrapped
/// backup share B (`backup_factor`). The host injects the Secure Enclave
/// (`FfiKeyStore`); on return the rotated device share is sealed and the returned
/// `FfiSignerConfig` (SAME joint pubkey + address as before loss) is ready for
/// `FfiDeployedSigner::connect`. `identity_key_hex` MUST be the SAME §07.4 key
/// recorded as owner at create time (owner-authz §08.1).
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::too_many_arguments)]
#[uniffi::export(async_runtime = "tokio")]
pub async fn recover_wallet(
    relay_url: String,
    container_url: String,
    identity_key_hex: String,
    at_rest_root_hex: String,
    bundle_dir: String,
    policy_id_hex: String,
    backup_factor: Vec<u8>,
    // #85 MITM gate: the cosigner's MASTER identity pubkey hex, PINNED out-of-band
    // (empty = unpinned dev/legacy). When set, the reshare verifies the fetched
    // container identity == it + runs a post-reshare liveness challenge.
    cosigner_master_pub: String,
    keystore: std::sync::Arc<dyn FfiKeyStore>,
) -> Result<FfiSignerConfig, FfiError> {
    use bsv::primitives::ec::PrivateKey;

    let identity = {
        let bytes = hex32(&identity_key_hex, "identity_key")?;
        PrivateKey::from_bytes(&bytes)
            .map_err(|e| FfiError::Client(format!("identity key: {e}")))?
    };
    let ks: std::sync::Arc<dyn crate::native_io::keystore::NativeKeyStore> =
        std::sync::Arc::new(FfiKeyStoreAdapter(keystore));

    let w = crate::native_io::recover::recover_wallet(
        &relay_url,
        &container_url,
        identity,
        backup_factor,
        if cosigner_master_pub.is_empty() {
            None
        } else {
            Some(cosigner_master_pub)
        },
        std::time::Duration::from_secs(RECOVER_TIMEOUT_SECS),
        ks.as_ref(),
    )
    .await
    .map_err(|e| FfiError::Client(e.to_string()))?;

    Ok(FfiSignerConfig {
        relay_url,
        container_url,
        identity_key_hex,
        at_rest_root_hex,
        bundle_dir,
        policy_id_hex,
        agent_id: w.agent_id,
        joint_pubkey_hex: hex::encode(&w.joint_key.compressed),
        joint_address: w.joint_key.address,
        threshold: w.config.threshold,
        parties: w.config.parties,
        participants: w.participants,
        device_share_index: w.device_share_index,
        my_indices: vec![w.device_share_index],
        cosigner_party: w.cosigner_party,
        cosigner_master_pub: String::new(), // 2-party: unpinned (no n-party Notary)
        dkg_session_id_hex: w.dkg_session_id.hex(),
    })
}

// ── High-level BRC-103/104 storage seam over UniFFI (issue #64) ───────────────
//
// Rust owns ALL the BRC-31/103/104 crypto/auth; the native shell only supplies
// the device identity key (held device-sealed) + the JSON method/params, and
// receives parsed JSON back. Exposed as a `uniffi::Object` with **async**
// methods (UniFFI 0.28 runtime-agnostic async export) because the underlying
// transport is async `reqwest`. Native-only — never in the wasm build.

/// An open, authenticated (Phase-A handshake complete) storage connection.
#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Object)]
pub struct WalletStorageConn {
    inner: crate::native_io::storage::StorageClient,
}

#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export(async_runtime = "tokio")]
impl WalletStorageConn {
    /// Open a connection: runs the BRC-103/104 Phase-A handshake against
    /// `base_url` using the device identity private key (64-char hex).
    #[uniffi::constructor]
    pub async fn open(
        base_url: String,
        identity_key_hex: String,
    ) -> Result<std::sync::Arc<Self>, FfiError> {
        let inner = crate::native_io::storage::StorageClient::open(&base_url, &identity_key_hex)
            .await
            .map_err(|e| FfiError::Client(e.to_string()))?;
        Ok(std::sync::Arc::new(Self { inner }))
    }

    /// Run a signed (Phase-B) JSON-RPC call. `params_json` is a JSON array
    /// string of params; returns the JSON-encoded `result`. The server's
    /// response signature is verified (fail-closed) inside this call.
    pub async fn rpc(&self, method: String, params_json: String) -> Result<String, FfiError> {
        let params: Vec<serde_json::Value> = serde_json::from_str(&params_json)
            .map_err(|e| FfiError::Client(format!("params_json must be a JSON array: {e}")))?;
        let result = self
            .inner
            .rpc(&method, params)
            .await
            .map_err(|e| FfiError::Client(e.to_string()))?;
        serde_json::to_string(&result).map_err(|e| FfiError::Client(format!("encode result: {e}")))
    }
}

// ── ADR-0044 / #75 canonical wallet renderer over FFI ────────────────────────
//
// Exposes `bsv_mpc_core::approval::canonical_render` to the native shell so the
// 100cash send path (Person B's 100cash#15) gets the EXACT same `rendered_text`
// the cosigner will bind into `request_view_hash` (key 8). The CBOR wire shape
// matches the serde derives on `Intent` (internally-tagged on `kind`, snake_case,
// `deny_unknown_fields`) — i.e. a CBOR map with a `kind` text key and per-kind
// flat fields. We deserialize via ciborium and call the core renderer; any
// CBOR-shape or schema rejection comes back as `FfiError::Client(...)`.

/// Render an [`Intent`](bsv_mpc_core::approval::Intent) to its canonical
/// `rendered_text` (ADR-0044 §2). The shell encodes the typed intent as CBOR
/// matching the serde shape and gets back the WYSIWYS string the cosigner will
/// bind to via `request_view_hash`.
///
/// Returns `Err(FfiError::Client)` if the CBOR is malformed, the `kind` is
/// unknown, a required field is missing, an unknown field is present, OR a
/// type mismatches the typed schema. The negative path is asserted in
/// `ffi_canonical_render_rejects_unknown_kind` below.
#[uniffi::export]
pub fn ffi_canonical_render(intent_cbor: Vec<u8>) -> Result<String, FfiError> {
    use bsv_mpc_core::approval::{canonical_render, Intent};
    let intent: Intent = ciborium::de::from_reader(intent_cbor.as_slice())
        .map_err(|e| FfiError::Client(format!("intent CBOR decode: {e}")))?;
    canonical_render(&intent).map_err(|e| FfiError::Client(e.to_string()))
}

/// **100cash#15 enabler.** A Payment-output pair (`{script, value_sats}`) the
/// helper below assembles into the recipient_outputs list. Mirrors the Rust
/// `PaymentOutput` schema 1:1 so the encoded CBOR is byte-identical.
#[derive(uniffi::Record)]
pub struct FfiPaymentOutput {
    pub script_hex: String,
    pub value_sats: u64,
}

/// **100cash#15 enabler — build the CBOR for the `payment` Intent.**
///
/// 100cash (Swift) MUST NOT hand-roll the CBOR encoding because Person A's
/// `canonical_render` requires byte-for-byte agreement with Rust's serde-CBOR
/// emission (any divergence breaks WYSIWYS: device shows one rendered_text,
/// cosigner binds to another). This helper assembles a typed Rust `Intent::Payment`
/// from primitives the Swift side already has and serializes it through the
/// same `ciborium` path `ffi_canonical_render` deserializes — closing the
/// circle so the two ends cannot disagree.
///
/// Returns the CBOR bytes to feed straight into [`ffi_canonical_render`].
/// Used by 100cash's `WalletStore.approval(...)` to compute the real
/// `request_view_hash` for the §43 approval gate.
///
/// Schema (ADR-0044 §2.1):
/// - `amount_satoshis`: total spend in sats
/// - `recipient_outputs`: each pair carried verbatim as `PaymentOutput`
/// - `human_address`: pre-resolved address text the wallet displays
/// - `fee_sats`: pre-resolved miner fee (caller's fee derivation)
/// - `counterparty_pubkey_hex`: 66-char compressed-secp256k1 pubkey if known;
///   pass empty string for anonymous (renders as `"anonymous"` per ADR-0044
///   when `cert_name: None`)
/// - `fiat_estimate` / `fiat_currency`: REQUIRED by `Intent::Payment` (e.g.
///   `"$50.00"` + `"USD"`). Callers without a fiat source can pass placeholder
///   strings (e.g. `"—"` + `""`) — the values are opaque text the renderer
///   substitutes verbatim into `rendered_text`.
/// - `human_locale`: BCP-47 tag (e.g. `"en-US"`)
#[allow(clippy::too_many_arguments)]
#[uniffi::export]
pub fn ffi_build_payment_intent_cbor(
    amount_satoshis: u64,
    recipient_outputs: Vec<FfiPaymentOutput>,
    human_address: String,
    fee_sats: u64,
    counterparty_pubkey_hex: String,
    fiat_estimate: String,
    fiat_currency: String,
    human_locale: String,
) -> Result<Vec<u8>, FfiError> {
    use bsv_mpc_core::approval::{Counterparty, Intent, PaymentOutput};
    let intent = Intent::Payment {
        amount_satoshis,
        recipient_outputs: recipient_outputs
            .into_iter()
            .map(|o| PaymentOutput {
                script: o.script_hex,
                value_sats: o.value_sats,
            })
            .collect(),
        human_address,
        fee_sats,
        counterparty_identity: Counterparty {
            pubkey: counterparty_pubkey_hex,
            cert_name: None,
        },
        fiat_estimate,
        fiat_currency,
        human_locale,
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&intent, &mut buf)
        .map_err(|e| FfiError::Client(format!("intent CBOR encode: {e}")))?;
    Ok(buf)
}

// ── #89 BRC-42 "Anyone"-derivation FFI (0-MPC, pure local) ────────────────────
//
// THE M1 floor + the send-E2E gate. Pure local wrappers over the SDK-validated
// `bsv_mpc_core::hd` derivation — `hd::test_anyone_matches_bsv_sdk_key_deriver`
// already pins it byte-equal to `bsv-rs::KeyDeriver` for the Anyone counterparty,
// so this is a PORT, not new crypto. 0 MPC round-trips: for "Anyone" the BRC-42
// ECDH shared secret IS the root (joint) pubkey (the anyone counterparty key is
// scalar 1, so `ECDH(G, root) = root_pub`), so the device derives every receive
// address + spend offset locally with no cosigner.
//
// The send loop these four close (mirrors `bsv-wallet-cli::brc29::deposit_address`,
// the reference path):
//   receive:  ffi_brc42_child_address_anyone(joint, proto, key_id, 2) -> deposit addr
//   spend:    ffi_brc42_offset_anyone(...)        -> brc42_offset for FfiDeployedSigner::sign
//             ffi_brc42_child_pubkey_anyone(...)  -> the derived pubkey for the P2PKH
//                                                    scriptSig (ffi_p2pkh_unlocking_script_hex)
// The offset and the child pubkey are consistent BY CONSTRUCTION — both are built
// from the SAME `hmac = HMAC-SHA256(compressed(root_pub), invoice)`: the offset IS
// `hmac`, and `child_pub = root_pub + G*hmac`. So a signature produced with
// `set_additive_shift(offset)` (the cggmp24-fork additive shift) verifies under the
// child pubkey, whose hash160 is the deposit address — proven in the keystone test
// below. BRC-29 is just this with `proto = "3241645161d8"`, `key_id = "{prefix} {suffix}"`.
//
// Argument order is uniform across all four (`protocol_name, key_id, security_level`
// as the trailing trio, root pubkey first where applicable) so a Swift caller can
// never transpose them between calls.

/// Parse + validate a 33-byte compressed secp256k1 root (joint) pubkey from hex.
/// A wrong length / bad hex / non-point input fails closed with a clear message —
/// the device must never derive against a malformed key.
fn parse_root_pubkey(root_pubkey_hex: &str) -> Result<bsv::primitives::ec::PublicKey, FfiError> {
    let bytes = dehex(root_pubkey_hex, "root pubkey")?;
    if bytes.len() != 33 {
        return Err(FfiError::Client(format!(
            "root pubkey must be 33 bytes (66 hex chars), got {}",
            bytes.len()
        )));
    }
    bsv::primitives::ec::PublicKey::from_bytes(&bytes)
        .map_err(|e| FfiError::Client(format!("invalid root pubkey: {e}")))
}

/// **#89.** Build the canonical BRC-42 invoice string `"{level}-{proto}-{key_id}"`.
///
/// Routes through `bsv_mpc_core::hd::compute_invoice`, which canonicalizes the
/// protocol name (`trim().to_lowercase()` + format validation) and validates the
/// key id via the SAME `bsv-rs` path every conformant SDK uses — so two impls
/// never derive different keys for inputs differing only in case/whitespace
/// (the cross-impl wire-compat floor, MPC-Spec §03). Rejects `security_level > 2`,
/// an invalid protocol name, or an invalid key id.
#[uniffi::export]
pub fn ffi_brc42_invoice(
    protocol_name: String,
    key_id: String,
    security_level: u8,
) -> Result<String, FfiError> {
    bsv_mpc_core::hd::compute_invoice(security_level, &protocol_name, &key_id)
        .map_err(|e| FfiError::Client(e.to_string()))
}

/// **#89.** The 32-byte BRC-42 additive OFFSET for the "Anyone" counterparty — the
/// scalar the device adds to its key share(s) to sign for the derived child key.
/// Feed it straight into [`FfiDeployedSigner::sign`]'s `brc42_offset` (or
/// [`FfiSigningSession::init`]'s). For "Anyone" the shared secret is the root
/// pubkey, so `offset = HMAC-SHA256(compressed(root_pub), invoice)` — identical to
/// the shift baked into [`ffi_brc42_child_pubkey_anyone`]'s child key, so a sig made
/// with this offset verifies under that child pubkey (keystone test below).
#[uniffi::export]
pub fn ffi_brc42_offset_anyone(
    root_pubkey_hex: String,
    protocol_name: String,
    key_id: String,
    security_level: u8,
) -> Result<Vec<u8>, FfiError> {
    let root_pub = parse_root_pubkey(&root_pubkey_hex)?;
    let invoice = bsv_mpc_core::hd::compute_invoice(security_level, &protocol_name, &key_id)
        .map_err(|e| FfiError::Client(e.to_string()))?;
    Ok(bsv_mpc_core::hd::compute_brc42_hmac(&root_pub, &invoice).to_vec())
}

/// **#89.** The derived child compressed pubkey hex (33 bytes) for "Anyone":
/// `child_pub = root_pub + G * offset`. This is the pubkey that goes in the spend's
/// P2PKH scriptSig (via [`ffi_p2pkh_unlocking_script_hex`]) and whose hash160 is the
/// deposit address ([`ffi_brc42_child_address_anyone`]). Thin wrapper over the
/// SDK-validated `bsv_mpc_core::hd::derive_anyone_pubkey`.
#[uniffi::export]
pub fn ffi_brc42_child_pubkey_anyone(
    root_pubkey_hex: String,
    protocol_name: String,
    key_id: String,
    security_level: u8,
) -> Result<String, FfiError> {
    let root_pub = parse_root_pubkey(&root_pubkey_hex)?;
    let child =
        bsv_mpc_core::hd::derive_anyone_pubkey(&root_pub, &protocol_name, &key_id, security_level)
            .map_err(|e| FfiError::Client(e.to_string()))?;
    Ok(hex::encode(child.to_compressed()))
}

/// **#89.** The BRC-29/BRC-42 "Anyone" receive (deposit) Base58Check P2PKH address
/// for the derived child key — the address the wallet shows to receive funds and
/// that the later spend unlocks. Reuses the SDK-validated
/// `bsv_mpc_core::hd::derive_anyone_joint_key` (which owns the address encoding)
/// verbatim, so the address is byte-identical to the core/`bsv-rs` path.
#[uniffi::export]
pub fn ffi_brc42_child_address_anyone(
    root_pubkey_hex: String,
    protocol_name: String,
    key_id: String,
    security_level: u8,
) -> Result<String, FfiError> {
    let root_pub = parse_root_pubkey(&root_pubkey_hex)?;
    // `derive_anyone_joint_key` reads only `.compressed`; the `address` field on the
    // input is ignored, so seeding it empty is fine. It internally re-derives the
    // child pubkey + encodes the address via the SDK-validated `pubkey_to_joint_key`.
    let joint = bsv_mpc_core::JointPublicKey {
        compressed: root_pub.to_compressed().to_vec(),
        address: String::new(),
    };
    let child =
        bsv_mpc_core::hd::derive_anyone_joint_key(&joint, &protocol_name, &key_id, security_level)
            .map_err(|e| FfiError::Client(e.to_string()))?;
    Ok(child.address)
}

// ── #91 Self_/Other distributed-ECDH offset FFI ───────────────────────────────
//
// Group-B: the DIRECTED (Self_/Other) BRC-42 derivation. Unlike #89 (Anyone, 0 MPC,
// local), Self_/Other need the ECDH shared secret `counterparty_pub * root_priv`,
// which is split across shares — so the device computes its `w` local partials and
// combines them with the cosigner's partial(s) from the #90 relay round. Two surfaces:
//   - LOW-LEVEL host-driven combine: `ffi_ecdh_device_partial` (one partial per
//     unsealed share) + `ffi_ecdh_combine_offset` (partials → the atomic FfiDerivedKey).
//   - HIGH-LEVEL: `FfiDeployedSigner::derive_offset_for_counterparty` (below) runs the
//     whole thing internally (unseal → local partials → relay round → combine).
// Always the core Lagrange path (`combine_partials_lagrange`) — NOT additive
// aggregation, which is wrong for cggmp24 VSS shares.

/// One distributed-ECDH partial: `counterparty_pub * share(party_index)` (33-byte
/// compressed point) + the VSS eval point `I[party_index]` (32 bytes) to Lagrange-pair
/// it with.
#[derive(uniffi::Record)]
pub struct FfiEcdhPartial {
    /// 33-byte compressed partial-ECDH point.
    pub partial: Vec<u8>,
    /// 32-byte VSS evaluation point for this partial's party.
    pub vss_point: Vec<u8>,
}

/// A fully-derived BRC-42 child key (#91) — every field from ONE ECDH shared secret
/// so they can never disagree (the loss-of-funds invariant).
#[derive(uniffi::Record)]
pub struct FfiDerivedKey {
    /// 32-byte BRC-42 additive offset — feed to `FfiDeployedSigner::sign`'s `brc42_offset`.
    pub brc42_offset: Vec<u8>,
    /// Derived child compressed pubkey hex (66 chars) — goes in the spend's scriptSig.
    pub derived_pubkey_compressed_hex: String,
    /// Derived key's P2PKH locking-script hex (the sighash subscript).
    pub derived_p2pkh_locking_script_hex: String,
    /// Derived key's Base58Check P2PKH receive address.
    pub derived_address: String,
}

/// The BRC-42 counterparty for [`FfiDeployedSigner::derive_offset_for_counterparty`].
#[derive(uniffi::Enum)]
pub enum FfiCounterparty {
    /// `Self_` — derive against the wallet's own joint pubkey.
    SelfWallet,
    /// `Anyone` — the publicly-derivable counterparty (0 MPC, local).
    Anyone,
    /// `Other` — a specific external counterparty (33-byte compressed pubkey hex).
    Other { pubkey_hex: String },
}

/// Parse a 33-byte compressed secp256k1 pubkey from hex with a contextual label.
fn parse_pubkey33(hex_str: &str, what: &str) -> Result<bsv::primitives::ec::PublicKey, FfiError> {
    let bytes = dehex(hex_str, what)?;
    if bytes.len() != 33 {
        return Err(FfiError::Client(format!(
            "{what} must be 33 bytes (66 hex chars), got {}",
            bytes.len()
        )));
    }
    bsv::primitives::ec::PublicKey::from_bytes(&bytes)
        .map_err(|e| FfiError::Client(format!("invalid {what}: {e}")))
}

/// **#91 low-level.** Compute the device's OWN distributed-ECDH partial for one
/// unsealed share: `counterparty_pub * share(party_index)` + the party's VSS eval
/// point. For host-driven combine (the host unseals each held share, calls this per
/// share, then [`ffi_ecdh_combine_offset`]). Pure, local, 0 network.
#[uniffi::export]
pub fn ffi_ecdh_device_partial(
    counterparty_pub_hex: String,
    share_json: Vec<u8>,
    party_index: u16,
) -> Result<FfiEcdhPartial, FfiError> {
    let counterparty_pub = parse_pubkey33(&counterparty_pub_hex, "counterparty pubkey")?;
    let scalar = bsv_mpc_core::ecdh::parse_share_scalar(&share_json)
        .map_err(|e| FfiError::Client(format!("parse share scalar: {e}")))?;
    let vss = bsv_mpc_core::ecdh::parse_share_vss_points(&share_json)
        .map_err(|e| FfiError::Client(format!("parse VSS points: {e}")))?;
    let vss_point = *vss.get(party_index as usize).ok_or_else(|| {
        FfiError::Client(format!(
            "party_index {party_index} out of range for {} VSS points",
            vss.len()
        ))
    })?;
    let partial = bsv_mpc_core::ecdh::compute_partial_ecdh_point(&counterparty_pub, &scalar)
        .map_err(|e| FfiError::Client(e.to_string()))?;
    Ok(FfiEcdhPartial {
        partial: partial.to_compressed().to_vec(),
        vss_point: vss_point.to_vec(),
    })
}

/// **#91 low-level.** Lagrange-combine `t` distributed-ECDH partials into the BRC-42
/// shared secret, then derive the atomic [`FfiDerivedKey`] (offset + child pubkey +
/// locking script + address). The partials MUST be `t` distinct parties (the device's
/// `w` from [`ffi_ecdh_device_partial`] + the cosigner's from the #90 relay round).
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export]
pub fn ffi_ecdh_combine_offset(
    joint_pubkey_hex: String,
    partials: Vec<FfiEcdhPartial>,
    protocol_name: String,
    key_id: String,
    security_level: u8,
) -> Result<FfiDerivedKey, FfiError> {
    let joint_pub = parse_pubkey33(&joint_pubkey_hex, "joint pubkey")?;
    let invoice = bsv_mpc_core::hd::compute_invoice(security_level, &protocol_name, &key_id)
        .map_err(|e| FfiError::Client(e.to_string()))?;
    let mut pts: Vec<(bsv::primitives::ec::PublicKey, [u8; 32])> =
        Vec::with_capacity(partials.len());
    for p in &partials {
        let partial = bsv::primitives::ec::PublicKey::from_bytes(&p.partial)
            .map_err(|e| FfiError::Client(format!("bad partial point: {e}")))?;
        let vss_point: [u8; 32] = p
            .vss_point
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::Client("vss_point must be 32 bytes".into()))?;
        pts.push((partial, vss_point));
    }
    let shared_secret = bsv_mpc_core::ecdh::combine_partials_lagrange(&pts)
        .map_err(|e| FfiError::Client(e.to_string()))?;
    let dk = crate::native_io::derived_key_from_shared_secret(&joint_pub, &shared_secret, &invoice)
        .map_err(|e| FfiError::Client(e.to_string()))?;
    Ok(ffi_derived_key(dk))
}

/// Map the native `DerivedKey` to the hex-encoded FFI record (single mapper so the
/// low-level combine + the high-level signer method emit identical shapes).
#[cfg(not(target_arch = "wasm32"))]
fn ffi_derived_key(dk: crate::native_io::DerivedKey) -> FfiDerivedKey {
    FfiDerivedKey {
        brc42_offset: dk.brc42_offset.to_vec(),
        derived_pubkey_compressed_hex: hex::encode(dk.derived_pubkey.to_compressed()),
        derived_p2pkh_locking_script_hex: hex::encode(dk.derived_p2pkh_locking_script),
        derived_address: dk.derived_address,
    }
}

// ── #68 send-path golden-vector tests (FFI == in-crate, byte-for-byte) ─────────
#[cfg(test)]
mod send_path_tests {
    use super::*;
    use crate::txbuild;

    fn p2pkh_hex(hash: [u8; 20]) -> String {
        hex::encode(txbuild::p2pkh_locking_script_from_hash(&hash))
    }

    /// The FFI sighash MUST equal the in-crate `demo_sighash()` byte-for-byte for the
    /// same logical tx (display txid "11"*32 reverses to the demo's internal [0x11;32]).
    #[test]
    fn ffi_sighash_matches_in_crate_golden() {
        let req = FfiSighashRequest {
            version: 1,
            inputs: vec![FfiSighashInput {
                prev_txid_hex: hex::encode([0x11u8; 32]),
                vout: 0,
                sequence: 0xffff_ffff,
            }],
            outputs: vec![
                FfiTxOutput {
                    satoshis: 50_000,
                    locking_script_hex: p2pkh_hex([0x33u8; 20]),
                },
                FfiTxOutput {
                    satoshis: 49_000,
                    locking_script_hex: p2pkh_hex([0x44u8; 20]),
                },
            ],
            locktime: 0,
            input_index: 0,
            subscript_hex: p2pkh_hex([0x22u8; 20]),
            input_satoshis: 100_000,
            sighash_type: 0x41,
        };
        let got = ffi_bip143_sighash(req).expect("ffi sighash");
        assert_eq!(
            got,
            txbuild::demo_sighash().to_vec(),
            "FFI sighash != in-crate golden"
        );
    }

    /// Prove the FFI reverses display→internal txid: a NON-palindrome txid through the
    /// FFI must equal the in-crate sighash computed with the REVERSED (internal) bytes.
    #[test]
    fn ffi_sighash_reverses_display_txid() {
        let display: [u8; 32] = core::array::from_fn(|i| i as u8); // 00,01,..,1f — not a palindrome
        let mut internal = display;
        internal.reverse();
        let subscript = txbuild::p2pkh_locking_script_from_hash(&[0x22u8; 20]);
        let out0 = txbuild::p2pkh_locking_script_from_hash(&[0x33u8; 20]);
        let in_crate = txbuild::compute_bip143_sighash(&txbuild::SighashParams {
            version: 1,
            inputs: &[(internal, 0, 0xffff_ffff)],
            outputs: &[(50_000, out0.as_slice())],
            locktime: 0,
            input_index: 0,
            subscript: &subscript,
            input_satoshis: 100_000,
            sighash_type: 0x41,
        });
        let got = ffi_bip143_sighash(FfiSighashRequest {
            version: 1,
            inputs: vec![FfiSighashInput {
                prev_txid_hex: hex::encode(display),
                vout: 0,
                sequence: 0xffff_ffff,
            }],
            outputs: vec![FfiTxOutput {
                satoshis: 50_000,
                locking_script_hex: p2pkh_hex([0x33u8; 20]),
            }],
            locktime: 0,
            input_index: 0,
            subscript_hex: p2pkh_hex([0x22u8; 20]),
            input_satoshis: 100_000,
            sighash_type: 0x41,
        })
        .expect("ffi sighash");
        assert_eq!(
            got,
            in_crate.to_vec(),
            "FFI must reverse display txid to internal"
        );
    }

    /// The FFI unlocking-script MUST equal the in-crate `build_p2pkh_unlocking_script`
    /// byte-for-byte: a 72-byte DER sig with the `0x41` flag appended + a compressed
    /// pubkey. This is the assembly Swift drives after the MPC ceremony.
    #[test]
    fn ffi_unlocking_script_matches_in_crate_golden() {
        let der = [0x30u8; 72]; // stand-in DER signature body
        let pubkey = [0x02u8; 33];
        // In-crate truth: DER ‖ flag, then the builder.
        let mut sig_with_flag = der.to_vec();
        sig_with_flag.push(0x41);
        let expected = hex::encode(txbuild::build_p2pkh_unlocking_script(
            &sig_with_flag,
            &pubkey,
        ));
        let got = ffi_p2pkh_unlocking_script_hex(hex::encode(der), 0x41, hex::encode(pubkey))
            .expect("ffi unlocking script");
        assert_eq!(got, expected, "FFI unlocking script != in-crate golden");
        // And it must round-trip into a serializable rawTx with a valid txid.
        let raw = ffi_serialize_signed_tx(FfiSignedTxRequest {
            version: 1,
            inputs: vec![FfiSignedInput {
                prev_txid_hex: hex::encode([0x11u8; 32]),
                vout: 0,
                unlocking_script_hex: got,
                sequence: 0xffff_ffff,
            }],
            outputs: vec![FfiTxOutput {
                satoshis: 49_000,
                locking_script_hex: p2pkh_hex([0x44u8; 20]),
            }],
            locktime: 0,
        })
        .expect("serialize with assembled unlocking script");
        assert_eq!(ffi_tx_txid(raw).expect("txid").len(), 64);
    }

    /// A pubkey that isn't 33 bytes MUST be rejected — never silently truncated.
    #[test]
    fn ffi_unlocking_script_rejects_bad_pubkey_len() {
        let err = ffi_p2pkh_unlocking_script_hex("30".repeat(72), 0x41, "02".repeat(20))
            .expect_err("must reject 20-byte pubkey");
        assert!(format!("{err}").contains("33 bytes"), "got: {err}");
    }

    /// The FFI serialized rawTx MUST equal the in-crate `demo_serialized()` hex.
    #[test]
    fn ffi_serialize_matches_in_crate_golden() {
        let unlocking = txbuild::build_p2pkh_unlocking_script(&[0x55u8; 72], &[0x02u8; 33]);
        let req = FfiSignedTxRequest {
            version: 1,
            inputs: vec![FfiSignedInput {
                prev_txid_hex: hex::encode([0x11u8; 32]),
                vout: 0,
                unlocking_script_hex: hex::encode(&unlocking),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![
                FfiTxOutput {
                    satoshis: 50_000,
                    locking_script_hex: p2pkh_hex([0x33u8; 20]),
                },
                FfiTxOutput {
                    satoshis: 49_000,
                    locking_script_hex: p2pkh_hex([0x44u8; 20]),
                },
            ],
            locktime: 0,
        };
        let got = ffi_serialize_signed_tx(req).expect("ffi serialize");
        assert_eq!(
            got,
            hex::encode(txbuild::demo_serialized()),
            "FFI rawTx != in-crate golden"
        );
    }

    /// The FFI view-hash MUST equal `bsv_mpc_core::approval::request_view_hash` exactly
    /// (digest AND canonical-CBOR preimage).
    #[test]
    fn ffi_view_hash_matches_core() {
        use bsv_mpc_core::approval::{request_view_hash, Recipient};
        let in_crate = request_view_hash(
            12_345,
            &Recipient::Single("1RecipientAddrXXXXXXXXXXXXXXXXXXXXX".into()),
            "aa".repeat(32).as_str(),
            "bb".repeat(16).as_str(),
            "cc".repeat(32).as_str(),
            "dd".repeat(32).as_str(),
            "en-US",
            "Send 12345 sats",
        );
        let got = ffi_request_view_hash(FfiViewHashRequest {
            amount: 12_345,
            recipient: FfiRecipient::Single {
                address: "1RecipientAddrXXXXXXXXXXXXXXXXXXXXX".into(),
            },
            sighash_hex: "aa".repeat(32),
            execution_id_hex: "bb".repeat(16),
            policy_id_hex: "cc".repeat(32),
            manifest_ack_hex: "dd".repeat(32),
            human_locale: "en-US".into(),
            rendered_text: "Send 12345 sats".into(),
        })
        .expect("ffi view hash");
        assert_eq!(
            got.hash,
            in_crate.hash.to_vec(),
            "view-hash digest mismatch"
        );
        assert_eq!(
            got.preimage, in_crate.preimage,
            "view-hash CBOR preimage mismatch"
        );
    }

    /// Known mainnet address (Satoshi's genesis P2PKH) → its known P2PKH script.
    #[test]
    fn ffi_address_to_script_golden() {
        // 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa → hash160 62e907b15cbf27d5425399ebf6f0fb50ebb88f18
        let script = ffi_address_to_locking_script_hex("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".into())
            .expect("address decode");
        assert_eq!(
            script, "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
            "P2PKH script for the genesis address must match the known vector"
        );
    }

    /// priv = 1 → the secp256k1 generator point G (a canonical golden vector).
    #[test]
    fn ffi_identity_pubkey_generator_vector() {
        let mut priv_bytes = [0u8; 32];
        priv_bytes[31] = 1;
        let got = ffi_identity_pubkey_compressed_hex(hex::encode(priv_bytes)).expect("pubkey");
        assert_eq!(
            got, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "priv=1 must yield the secp256k1 generator G"
        );
    }

    /// BEEF round-trip: a spend tx whose input carries its source tx → `ffi_parse_beef_tx`
    /// recovers version/locktime/outputs + the input's prev-output (value + script).
    #[test]
    fn ffi_parse_beef_round_trips_prevouts() {
        use bsv::script::LockingScript;
        use bsv::transaction::{Transaction, TransactionInput, TransactionOutput};

        let prev_script_hex = p2pkh_hex([0x33u8; 20]);
        let mut src = Transaction::new();
        src.add_output(TransactionOutput {
            satoshis: Some(100_000),
            locking_script: LockingScript::from_hex(&prev_script_hex).unwrap(),
            change: false,
        })
        .unwrap();
        let src_txid = src.id();

        let mut spend = Transaction::new();
        spend.version = 1;
        spend.lock_time = 0;
        spend
            .add_input(TransactionInput::with_source_transaction(src, 0))
            .unwrap();
        spend
            .add_output(TransactionOutput {
                satoshis: Some(99_000),
                locking_script: LockingScript::from_hex(&p2pkh_hex([0x44u8; 20])).unwrap(),
                change: false,
            })
            .unwrap();

        let beef = spend.to_beef_v1(true).expect("to_beef_v1");
        let spend_hex = spend.to_hex();
        // The subject raw-tx extracted from the BEEF MUST equal the subject's own
        // serialization, and its txid must match — the funding-rebroadcast path.
        let subject_hex =
            ffi_beef_subject_raw_tx_hex(hex::encode(&beef)).expect("beef subject raw hex");
        assert_eq!(
            subject_hex, spend_hex,
            "BEEF subject raw hex != subject tx hex"
        );
        assert_eq!(
            ffi_tx_txid(subject_hex.clone()).unwrap(),
            spend.id(),
            "subject raw-tx txid must match"
        );
        let parsed = ffi_parse_beef_tx(hex::encode(&beef)).expect("parse beef");

        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.locktime, 0);
        assert_eq!(parsed.outputs.len(), 1);
        assert_eq!(parsed.outputs[0].satoshis, 99_000);
        assert_eq!(
            parsed.outputs[0].locking_script_hex,
            p2pkh_hex([0x44u8; 20])
        );
        assert_eq!(parsed.inputs.len(), 1);
        assert_eq!(parsed.inputs[0].vout, 0);
        assert_eq!(
            parsed.inputs[0].prev_satoshis, 100_000,
            "prev-output value from BEEF"
        );
        assert_eq!(
            parsed.inputs[0].prev_locking_script_hex, prev_script_hex,
            "prev-output script"
        );
        assert_eq!(
            parsed.inputs[0].prev_txid_hex, src_txid,
            "prev txid (display order)"
        );
    }

    // ── rejection paths (validate-don't-skip) ────────────────────────────────
    #[test]
    fn ffi_sighash_rejects_bad_txid_and_oob_index() {
        let base_in = || FfiSighashInput {
            prev_txid_hex: hex::encode([0x11u8; 32]),
            vout: 0,
            sequence: 0,
        };
        let out = || FfiTxOutput {
            satoshis: 1,
            locking_script_hex: p2pkh_hex([0x33u8; 20]),
        };
        // Bad txid hex.
        let bad_hex = ffi_bip143_sighash(FfiSighashRequest {
            version: 1,
            inputs: vec![FfiSighashInput {
                prev_txid_hex: "zz".into(),
                vout: 0,
                sequence: 0,
            }],
            outputs: vec![out()],
            locktime: 0,
            input_index: 0,
            subscript_hex: "00".into(),
            input_satoshis: 1,
            sighash_type: 0x41,
        });
        assert!(
            matches!(bad_hex, Err(FfiError::Client(m)) if m.contains("txid")),
            "bad txid must reject"
        );
        // input_index out of range.
        let oob = ffi_bip143_sighash(FfiSighashRequest {
            version: 1,
            inputs: vec![base_in()],
            outputs: vec![out()],
            locktime: 0,
            input_index: 5,
            subscript_hex: "00".into(),
            input_satoshis: 1,
            sighash_type: 0x41,
        });
        assert!(
            matches!(oob, Err(FfiError::Client(m)) if m.contains("out of range")),
            "oob index must reject"
        );
    }

    #[test]
    fn ffi_address_rejects_garbage_and_bad_checksum() {
        // Non-base58 garbage.
        assert!(ffi_address_to_locking_script_hex("not_a_valid_address".into()).is_err());
        // The genesis address with its last char mutated (Na -> Nb) → checksum fails.
        assert!(
            ffi_address_to_locking_script_hex("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb".into()).is_err(),
            "a corrupted-checksum address must reject"
        );
        // Sanity: the UNcorrupted genesis address still decodes (guards against a
        // false-positive where everything rejects).
        assert!(
            ffi_address_to_locking_script_hex("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".into()).is_ok(),
            "the valid genesis address must decode"
        );
    }

    #[test]
    fn ffi_identity_pubkey_rejects_wrong_length() {
        let short = ffi_identity_pubkey_compressed_hex(hex::encode([0u8; 31]));
        assert!(
            matches!(short, Err(FfiError::Client(m)) if m.contains("32 bytes")),
            "31-byte priv must reject"
        );
    }

    // ── ADR-0044 / #75 `ffi_canonical_render` golden-vector tests ────────────
    //
    // FFI byte-equivalence gate: build the Intent in Rust, encode via ciborium,
    // pass through `ffi_canonical_render`, and assert the returned String
    // equals the in-crate `canonical_render` output exactly. Negative cases
    // (malformed CBOR / unknown kind / missing field) assert FfiError carries
    // the right rejection reason — "skipping is lazy".

    /// Helper: serialize an Intent to CBOR via ciborium for the FFI call.
    fn intent_to_cbor(intent: &bsv_mpc_core::approval::Intent) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(intent, &mut buf).expect("cbor encode");
        buf
    }

    #[test]
    fn ffi_canonical_render_matches_core_payment() {
        use bsv_mpc_core::approval::{canonical_render, Counterparty, Intent, PaymentOutput};
        let intent = Intent::Payment {
            amount_satoshis: 100_000_000,
            recipient_outputs: vec![PaymentOutput {
                script: "76a914abcdef...88ac".into(),
                value_sats: 100_000_000,
            }],
            human_address: "1A1zP1...EQK...".into(),
            fee_sats: 333,
            counterparty_identity: Counterparty {
                pubkey: "02abcd123456789012345678901234567890123456789012345678901234567890".into(),
                cert_name: None,
            },
            fiat_estimate: "$50.00".into(),
            fiat_currency: "USD".into(),
            human_locale: "en-US".into(),
        };
        let in_crate = canonical_render(&intent).expect("in-crate render");
        let cbor = intent_to_cbor(&intent);
        let got = ffi_canonical_render(cbor).expect("ffi render");
        assert_eq!(got, in_crate, "FFI render != in-crate render");
        assert_eq!(
            got,
            "Send 100000000 sats (~$50.00 USD) to 1A1zP1...EQK... with fee 333 sats. Counterparty: anonymous + 0x02abcd12...",
            "FFI render != locked vector"
        );
    }

    #[test]
    fn ffi_canonical_render_matches_core_multi() {
        use bsv_mpc_core::approval::{canonical_render, Intent, MultiOutput};
        let intent = Intent::Multi {
            outputs: vec![
                MultiOutput::Payment {
                    amount_satoshis: 50_000_000,
                    recipient: "1A...".into(),
                },
                MultiOutput::Payment {
                    amount_satoshis: 25_000_000,
                    recipient: "1B...".into(),
                },
                MultiOutput::Fee {
                    amount_satoshis: 333,
                },
            ],
            human_locale: "en-US".into(),
        };
        let in_crate = canonical_render(&intent).expect("in-crate render");
        let cbor = intent_to_cbor(&intent);
        let got = ffi_canonical_render(cbor).expect("ffi render");
        assert_eq!(got, in_crate, "FFI render != in-crate render");
        assert_eq!(
            got,
            "Compound transaction with 3 outputs: Send 50000000 sats to 1A...; Send 25000000 sats to 1B...; Fee output 333 sats.",
            "FFI render != locked vector"
        );
    }

    #[test]
    fn ffi_canonical_render_rejects_malformed_cbor() {
        // 0xFF is a CBOR break stop-code that isn't valid at top level.
        let err = ffi_canonical_render(vec![0xff]).expect_err("malformed must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("CBOR"),
            "expected CBOR-decode rejection, got: {msg}"
        );
    }

    #[test]
    fn ffi_canonical_render_rejects_unknown_kind() {
        // CBOR map {"kind": "airdrop", "amount_satoshis": 1, ...} — an unknown
        // discriminant value MUST hard-reject per ADR-0044 §2.1.
        let mut buf = Vec::new();
        ciborium::ser::into_writer(
            &serde_json::json!({
                "kind": "airdrop",
                "amount_satoshis": 1,
                "recipient": "1X",
                "human_locale": "en-US"
            }),
            &mut buf,
        )
        .expect("encode bad cbor");
        let err = ffi_canonical_render(buf).expect_err("unknown kind must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown variant") && msg.contains("airdrop"),
            "expected unknown-variant rejection naming `airdrop`, got: {msg}"
        );
    }

    #[test]
    fn ffi_canonical_render_rejects_missing_required_field() {
        // payment missing `human_address` — the §2.3-amendment required field.
        let mut buf = Vec::new();
        ciborium::ser::into_writer(
            &serde_json::json!({
                "kind": "payment",
                "amount_satoshis": 100,
                "recipient_outputs": [{"script": "76a9...", "value_sats": 100}],
                "fee_sats": 1,
                "counterparty_identity": {
                    "pubkey": "02abcd1234567890123456789012345678901234567890123456789012345678",
                    "cert_name": null
                },
                "fiat_estimate": "$1",
                "fiat_currency": "USD",
                "human_locale": "en-US"
            }),
            &mut buf,
        )
        .expect("encode bad cbor");
        let err = ffi_canonical_render(buf).expect_err("missing field must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("missing field") && msg.contains("human_address"),
            "expected missing-field rejection naming `human_address`, got: {msg}"
        );
    }
}

// ── #89 BRC-42 "Anyone"-derivation FFI tests ──────────────────────────────────
//
// Four gates, no asterisks:
//   1. FFI == core, byte-for-byte (the established FFI-wrapper invariant).
//   2. KEYSTONE: the offset IS the canonical BRC-42 additive shift — `(root_priv +
//      offset) mod n` reconstructs exactly `bsv-rs::KeyDeriver::derive_private_key`
//      for the Anyone counterparty, and that key's pubkey/address are the FFI
//      child pubkey/address. This is the property the deployed sign path relies on:
//      `FfiDeployedSigner::sign(.., brc42_offset = offset)` produces a signature
//      valid for the deposit address's key.
//   3. ZERO-DRIFT: frozen byte literals for a fixed root key (incl. the real BRC-29
//      protocol/key_id) — any change to the derivation flips them.
//   4. Rejections asserted on the RIGHT reason (validate, don't skip).
#[cfg(test)]
mod brc42_anyone_tests {
    use super::*;
    use bsv::primitives::ec::PrivateKey;
    use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

    /// Fixed test root private key — same bytes as `bsv_mpc_core::hd`'s `test_root_key`,
    /// so the frozen vectors here are cross-referenceable with the core test suite.
    const ROOT_PRIV: [u8; 32] = [
        0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2,
        0xf3, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1,
        0xf2, 0x03,
    ];

    fn root_priv() -> PrivateKey {
        PrivateKey::from_bytes(&ROOT_PRIV).expect("valid test root priv")
    }

    fn root_pub_hex() -> String {
        hex::encode(root_priv().public_key().to_compressed())
    }

    /// BRC-29 payment protocol (the standard receive-address protocol) — matches
    /// `bsv-wallet-cli::brc29::PROTOCOL` and the bsv-wallet-toolbox-rs test vectors.
    const BRC29_PROTOCOL: &str = "3241645161d8";
    const BRC29_KEY_ID: &str = "SfKxPIJNgdI= NaGLC6fMH50=";

    /// (1) The FFI invoice equals the core canonical path, canonicalizes case, and
    /// is frozen for the common (worm memory, block-42) input.
    #[test]
    fn ffi_brc42_invoice_matches_core_and_canonicalizes() {
        let got = ffi_brc42_invoice("worm memory".into(), "block-42".into(), 2).unwrap();
        assert_eq!(
            got,
            bsv_mpc_core::hd::compute_invoice(2, "worm memory", "block-42").unwrap(),
            "FFI invoice != core compute_invoice"
        );
        assert_eq!(
            got, "2-worm memory-block-42",
            "frozen invoice vector drifted"
        );
        // Canonicalization rides through (uppercase + whitespace → lowercased/trimmed).
        assert_eq!(
            ffi_brc42_invoice("  WORM Memory  ".into(), "block-42".into(), 2).unwrap(),
            "2-worm memory-block-42",
            "FFI invoice must canonicalize protocol name"
        );
    }

    /// (1) Offset / child pubkey / address all equal the core path byte-for-byte.
    #[test]
    fn ffi_brc42_anyone_matches_core() {
        let rp = root_priv().public_key();
        let rp_hex = root_pub_hex();
        let invoice = bsv_mpc_core::hd::compute_invoice(2, "worm memory", "block-42").unwrap();

        let off =
            ffi_brc42_offset_anyone(rp_hex.clone(), "worm memory".into(), "block-42".into(), 2)
                .unwrap();
        assert_eq!(
            off,
            bsv_mpc_core::hd::compute_brc42_hmac(&rp, &invoice).to_vec(),
            "FFI offset != core compute_brc42_hmac"
        );

        let child_pub = ffi_brc42_child_pubkey_anyone(
            rp_hex.clone(),
            "worm memory".into(),
            "block-42".into(),
            2,
        )
        .unwrap();
        assert_eq!(
            child_pub,
            hex::encode(
                bsv_mpc_core::hd::derive_anyone_pubkey(&rp, "worm memory", "block-42", 2)
                    .unwrap()
                    .to_compressed()
            ),
            "FFI child pubkey != core derive_anyone_pubkey"
        );

        let addr =
            ffi_brc42_child_address_anyone(rp_hex, "worm memory".into(), "block-42".into(), 2)
                .unwrap();
        let joint = bsv_mpc_core::JointPublicKey {
            compressed: rp.to_compressed().to_vec(),
            address: String::new(),
        };
        assert_eq!(
            addr,
            bsv_mpc_core::hd::derive_anyone_joint_key(&joint, "worm memory", "block-42", 2)
                .unwrap()
                .address,
            "FFI address != core derive_anyone_joint_key"
        );
    }

    /// (2) KEYSTONE — the offset is the canonical BRC-42 additive shift for the
    /// deposit key. Cross-checked against `bsv-rs::KeyDeriver` (the reference wallet
    /// derivation): the FFI child pubkey/address equal `derive_public_key(Anyone)`'s,
    /// and `(root_priv + offset) mod n` reconstructs `derive_private_key(Anyone)`
    /// exactly. So a signature made with `set_additive_shift(offset)` verifies under
    /// the FFI child pubkey, whose hash160 is the FFI deposit address.
    #[test]
    fn ffi_brc42_offset_is_canonical_additive_shift() {
        use cggmp24::supported_curves::Secp256k1;
        use generic_ec::Scalar;

        let root = root_priv();
        let rp_hex = root_pub_hex();

        // Reference (canonical wallet) derivation for the Anyone counterparty.
        let deriver = KeyDeriver::new(Some(root.clone()));
        let protocol = Protocol::new(SecurityLevel::Counterparty, BRC29_PROTOCOL);
        let ref_child_pub = deriver
            .derive_public_key(&protocol, BRC29_KEY_ID, &Counterparty::Anyone, true)
            .unwrap();
        let ref_child_priv = deriver
            .derive_private_key(&protocol, BRC29_KEY_ID, &Counterparty::Anyone)
            .unwrap();

        // (a) FFI child pubkey == the reference derived public key.
        let ffi_child_pub = ffi_brc42_child_pubkey_anyone(
            rp_hex.clone(),
            BRC29_PROTOCOL.into(),
            BRC29_KEY_ID.into(),
            2,
        )
        .unwrap();
        assert_eq!(
            ffi_child_pub,
            hex::encode(ref_child_pub.to_compressed()),
            "FFI child pubkey != bsv-rs KeyDeriver derive_public_key(Anyone)"
        );

        // (b) FFI deposit address == the reference derived key's P2PKH address.
        let ffi_addr = ffi_brc42_child_address_anyone(
            rp_hex.clone(),
            BRC29_PROTOCOL.into(),
            BRC29_KEY_ID.into(),
            2,
        )
        .unwrap();
        assert_eq!(
            ffi_addr,
            bsv::Address::new_from_public_key(&ref_child_pub, true)
                .unwrap()
                .to_string(),
            "FFI address != address of the canonical derived key"
        );

        // (c) The offset IS the additive shift: (root_priv + offset) mod n == the
        // canonical derived PRIVATE key. This is what makes set_additive_shift work.
        let offset =
            ffi_brc42_offset_anyone(rp_hex, BRC29_PROTOCOL.into(), BRC29_KEY_ID.into(), 2).unwrap();
        let offset32: [u8; 32] = offset.as_slice().try_into().expect("offset is 32 bytes");
        let root_s = Scalar::<Secp256k1>::from_be_bytes_mod_order(root.to_bytes());
        let off_s = Scalar::<Secp256k1>::from_be_bytes_mod_order(offset32);
        let recon = (root_s + off_s).to_be_bytes();
        assert_eq!(
            recon.as_bytes(),
            &ref_child_priv.to_bytes()[..],
            "(root_priv + offset) mod n != canonical derive_private_key(Anyone) — \
             the offset is NOT the BRC-42 additive shift for the deposit key"
        );

        // And the reconstructed child priv's pubkey is the FFI child pubkey (ties it
        // all together: offset → signable child key → deposit address).
        let recon_priv = PrivateKey::from_bytes(recon.as_bytes()).unwrap();
        assert_eq!(
            hex::encode(recon_priv.public_key().to_compressed()),
            ffi_child_pub,
            "reconstructed child priv pubkey != FFI child pubkey"
        );
    }

    /// (3) ZERO-DRIFT frozen vectors for the real BRC-29 deposit derivation, plus a
    /// canonical cross-check so the frozen bytes are pinned to the reference wallet,
    /// not just to ourselves.
    #[test]
    fn ffi_brc42_brc29_deposit_frozen_and_canonical() {
        let rp_hex = root_pub_hex();

        let offset = ffi_brc42_offset_anyone(
            rp_hex.clone(),
            BRC29_PROTOCOL.into(),
            BRC29_KEY_ID.into(),
            2,
        )
        .unwrap();
        let child_pub = ffi_brc42_child_pubkey_anyone(
            rp_hex.clone(),
            BRC29_PROTOCOL.into(),
            BRC29_KEY_ID.into(),
            2,
        )
        .unwrap();
        let addr =
            ffi_brc42_child_address_anyone(rp_hex, BRC29_PROTOCOL.into(), BRC29_KEY_ID.into(), 2)
                .unwrap();

        // Frozen — pins the EXACT bytes for ROOT_PRIV + BRC-29 (proto/key_id).
        assert_eq!(
            hex::encode(&offset),
            "2c5733294d597e40682ce2365697b02974ebff8f12ebde61f9f962201312decd",
            "BRC-29 offset drifted"
        );
        assert_eq!(
            child_pub, "0358f53693f66b01e3f13694ff666dd211cfefbd3818a52572c1bd8d41e3e6b5cd",
            "BRC-29 child pubkey drifted"
        );
        assert_eq!(
            addr, "13xfx3Sa6NrXyq7tbe6RvuLzbcjXHDPkKp",
            "BRC-29 deposit address drifted"
        );

        // Canonical cross-check: the frozen address is also what the reference
        // wallet (bsv-rs KeyDeriver) computes for the same root key + BRC-29.
        let deriver = KeyDeriver::new(Some(root_priv()));
        let protocol = Protocol::new(SecurityLevel::Counterparty, BRC29_PROTOCOL);
        let ref_pub = deriver
            .derive_public_key(&protocol, BRC29_KEY_ID, &Counterparty::Anyone, true)
            .unwrap();
        assert_eq!(
            addr,
            bsv::Address::new_from_public_key(&ref_pub, true)
                .unwrap()
                .to_string(),
            "frozen BRC-29 address != canonical bsv-rs KeyDeriver address"
        );
    }

    /// (4) Rejections — bad root pubkey (hex / length / non-point) fails closed.
    #[test]
    fn ffi_brc42_rejects_bad_root_pubkey() {
        // Bad hex.
        let e = ffi_brc42_child_pubkey_anyone("zz".into(), "worm memory".into(), "k".into(), 2)
            .unwrap_err();
        assert!(
            matches!(&e, FfiError::Client(m) if m.contains("bad hex")),
            "got: {e}"
        );
        // Wrong length (32 bytes, not 33).
        let e = ffi_brc42_offset_anyone("11".repeat(32), "worm memory".into(), "k".into(), 2)
            .unwrap_err();
        assert!(
            matches!(&e, FfiError::Client(m) if m.contains("33 bytes")),
            "got: {e}"
        );
        // Right length, not a valid curve point (33 bytes of 0x00).
        let e =
            ffi_brc42_child_address_anyone("00".repeat(33), "worm memory".into(), "k".into(), 2)
                .unwrap_err();
        assert!(
            matches!(&e, FfiError::Client(m) if m.contains("invalid root pubkey")),
            "got: {e}"
        );
    }

    /// (4) Rejections — invalid invoice inputs fail closed with the right reason.
    #[test]
    fn ffi_brc42_invoice_rejects_invalid_inputs() {
        // security_level > 2.
        let e = ffi_brc42_invoice("worm memory".into(), "block-42".into(), 3).unwrap_err();
        assert!(
            matches!(&e, FfiError::Client(m) if m.contains("security_level")),
            "got: {e}"
        );
        // protocol_name too short (< 5 chars).
        let e = ffi_brc42_invoice("wm".into(), "block-42".into(), 2).unwrap_err();
        assert!(
            matches!(&e, FfiError::Client(m) if m.contains("protocol_name")),
            "got: {e}"
        );
        // empty key_id.
        let e = ffi_brc42_invoice("worm memory".into(), "".into(), 2).unwrap_err();
        assert!(
            matches!(&e, FfiError::Client(m) if m.contains("key_id")),
            "got: {e}"
        );
        // A bad protocol name also rejects through the derivation entry points (not
        // just the standalone invoice fn).
        let e = ffi_brc42_offset_anyone(root_pub_hex(), "worm  memory".into(), "k".into(), 2)
            .unwrap_err();
        assert!(
            matches!(&e, FfiError::Client(m) if m.contains("consecutive spaces") || m.contains("protocol_name")),
            "got: {e}"
        );
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod prime_pool_adapter_tests {
    //! Lever B (#100) — the FFI adapter bridges a foreign `FfiPrimePoolStore` to the
    //! core `PrimePoolStorage`, converting `FfiEncryptedPrimes` (Vec nonce) ↔ core
    //! `EncryptedPrimes` ([u8;12] nonce). These are fast (no safe-prime gen): a fake
    //! in-memory `FfiPrimePoolStore` proves a `PaillierPool` built on the adapter
    //! drains pre-seeded sets FIFO before it would inline-generate.

    use super::*;
    use bsv_mpc_core::paillier_pool::{PaillierPool, PrimePoolStorage};
    use std::sync::{Arc, Mutex};

    /// Minimal FIFO fake of the host's `FfiPrimePoolStore` (mirrors what Swift's
    /// keychain queue does), so the adapter + pool path can be tested in isolation.
    struct FakeFfiStore(Mutex<Vec<FfiEncryptedPrimes>>);

    impl FfiPrimePoolStore for FakeFfiStore {
        fn put_encrypted(&self, blob: FfiEncryptedPrimes) -> Result<(), FfiError> {
            self.0.lock().unwrap().push(blob);
            Ok(())
        }
        fn take_encrypted(&self) -> Result<Option<FfiEncryptedPrimes>, FfiError> {
            let mut g = self.0.lock().unwrap();
            Ok(if g.is_empty() {
                None
            } else {
                Some(g.remove(0))
            })
        }
        fn count(&self) -> Result<u32, FfiError> {
            Ok(self.0.lock().unwrap().len() as u32)
        }
    }

    /// The adapter round-trips a core `EncryptedPrimes` through the foreign store
    /// byte-for-byte (the 12-byte nonce survives the Vec↔array conversion).
    #[test]
    fn adapter_round_trips_encrypted_blob_byte_for_byte() {
        let fake: Arc<dyn FfiPrimePoolStore> = Arc::new(FakeFfiStore(Mutex::new(Vec::new())));
        let adapter = FfiPrimePoolStoreAdapter(fake);

        let original = bsv_mpc_core::paillier_pool::EncryptedPrimes {
            nonce: [7u8; 12],
            ciphertext: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        };
        adapter.put_encrypted(original.clone()).unwrap();
        assert_eq!(adapter.count().unwrap(), 1);

        let back = adapter
            .take_encrypted()
            .unwrap()
            .expect("non-empty after put");
        assert_eq!(back.nonce, original.nonce, "nonce must round-trip exactly");
        assert_eq!(
            back.ciphertext, original.ciphertext,
            "ciphertext must round-trip"
        );
        assert_eq!(adapter.count().unwrap(), 0, "FIFO drained");
        assert!(
            adapter.take_encrypted().unwrap().is_none(),
            "empty ⇒ None (miss → fallback)"
        );
    }

    /// A non-12-byte nonce from a buggy/hostile host is rejected as a storage error
    /// (treated as a miss by the caller, never a panic / silent wrong-length nonce).
    #[test]
    fn adapter_rejects_bad_nonce_length() {
        let fake = Arc::new(FakeFfiStore(Mutex::new(vec![FfiEncryptedPrimes {
            nonce: vec![0u8; 8], // wrong: must be 12
            ciphertext: vec![1, 2, 3],
        }])));
        let adapter = FfiPrimePoolStoreAdapter(fake);
        assert!(
            adapter.take_encrypted().is_err(),
            "11≠12 byte nonce must error"
        );
    }

    /// REPRO: the runtime prewarm→createWallet cross-instance round-trip. Pool A
    /// (prewarm: pool_id from `ffi_identity_pubkey_compressed_hex` → `dehex`) puts; pool B
    /// (createWallet: pool_id from `identity.public_key().to_hex()` → `hex::decode`) takes.
    /// If the two pool_ids differ, or the cross-instance key/decrypt fails, this fails —
    /// exactly the on-device Lever B miss (drained pool, decrypt error, inline fallback).
    #[test]
    fn prewarm_createwallet_cross_instance_roundtrip() {
        use bsv_mpc_core::paillier_pool::InMemoryPoolStorage;
        use cggmp24::security_level::{SecurityLevel, SecurityLevel128};
        use cggmp24::PregeneratedPrimes;
        use rand::RngCore;

        fn gen_blum<R: RngCore>(rng: &mut R, bits: u32) -> cggmp24::backend::Integer {
            use cggmp24::backend::Integer;
            loop {
                let n = Integer::generate_prime(rng, bits);
                if n.mod_u(4) == 3 {
                    break n;
                }
            }
        }
        fn fast_primes<R: RngCore>(rng: &mut R) -> PregeneratedPrimes<SecurityLevel128> {
            let bits = SecurityLevel128::RSA_PRIME_BITLEN;
            PregeneratedPrimes::try_from([
                gen_blum(rng, bits),
                gen_blum(rng, bits),
                gen_blum(rng, bits),
                gen_blum(rng, bits),
            ])
            .expect("Blum primes")
        }

        let priv_hex = hex::encode([0x6du8; 32]);
        let identity = bsv::primitives::ec::PrivateKey::from_bytes(&[0x6du8; 32]).unwrap();
        let at_rest = [0x4fu8; 32];

        // The TWO pool_id derivations used at runtime — MUST be byte-equal.
        let prewarm_poolid = dehex(
            &ffi_identity_pubkey_compressed_hex(priv_hex).unwrap(),
            "poolid",
        )
        .unwrap();
        let createwallet_poolid = hex::decode(identity.public_key().to_hex()).unwrap();
        assert_eq!(
            prewarm_poolid,
            createwallet_poolid,
            "POOL_ID MISMATCH: prewarm {} vs createWallet {}",
            hex::encode(&prewarm_poolid),
            hex::encode(&createwallet_poolid)
        );

        // Cross-instance round-trip over the REAL FFI-foreign-store path (the iOS path:
        // two PaillierPools over FfiPrimePoolStoreAdapter wrapping one shared foreign store).
        let _ = InMemoryPoolStorage::new(); // (kept import honest)
        let fake: std::sync::Arc<dyn FfiPrimePoolStore> =
            std::sync::Arc::new(FakeFfiStore(Mutex::new(Vec::new())));
        let mut rng = rand::rngs::OsRng;
        let pre_pool = PaillierPool::new(
            FfiPrimePoolStoreAdapter(fake.clone()),
            &at_rest,
            &prewarm_poolid,
            1,
        );
        pre_pool.put(fast_primes(&mut rng)).unwrap();
        let cw_pool = PaillierPool::new(
            FfiPrimePoolStoreAdapter(fake.clone()),
            &at_rest,
            &createwallet_poolid,
            1,
        );
        let taken = cw_pool.take().expect("take must not error");
        assert!(
            taken.is_some(),
            "createWallet pool MUST take+decrypt prewarm's prime over the FFI adapter (cross-instance)"
        );
    }

    /// A `PaillierPool` built on the adapter drains real (Blum-fast) pre-seeded sets
    /// FIFO — the warm-pool path the device's `coordinate_dkg_over_relay` consumes.
    #[test]
    fn pool_over_adapter_drains_seeded_sets() {
        use cggmp24::security_level::{SecurityLevel, SecurityLevel128};
        use cggmp24::PregeneratedPrimes;
        use rand::RngCore;

        fn gen_blum<R: RngCore>(rng: &mut R, bits: u32) -> cggmp24::backend::Integer {
            use cggmp24::backend::Integer;
            loop {
                let n = Integer::generate_prime(rng, bits);
                if n.mod_u(4) == 3 {
                    break n;
                }
            }
        }
        fn fast_primes<R: RngCore>(rng: &mut R) -> PregeneratedPrimes<SecurityLevel128> {
            let bits = SecurityLevel128::RSA_PRIME_BITLEN;
            PregeneratedPrimes::try_from([
                gen_blum(rng, bits),
                gen_blum(rng, bits),
                gen_blum(rng, bits),
                gen_blum(rng, bits),
            ])
            .expect("Blum primes have correct bit size")
        }

        let mut rng = rand::rngs::OsRng;
        let fake: Arc<dyn FfiPrimePoolStore> = Arc::new(FakeFfiStore(Mutex::new(Vec::new())));
        let adapter = FfiPrimePoolStoreAdapter(fake);
        let pool = PaillierPool::new(adapter, &[0x33u8; 32], b"adapter-seam", 2);

        let a = fast_primes(&mut rng);
        let a_bytes = serde_json::to_vec(&a).unwrap();
        pool.put(a).unwrap();
        assert_eq!(pool.storage().count().unwrap(), 1);

        let drawn = pool
            .take()
            .unwrap()
            .expect("warm pool yields the seeded set");
        assert_eq!(
            serde_json::to_vec(&drawn).unwrap(),
            a_bytes,
            "pooled set must round-trip through the FFI adapter byte-for-byte"
        );
        assert!(
            pool.take().unwrap().is_none(),
            "drained ⇒ None (caller falls back to inline)"
        );
    }
}
