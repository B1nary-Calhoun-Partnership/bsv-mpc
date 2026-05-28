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
    /// This device's signing index (the coordinator party).
    pub device_share_index: u16,
    /// The deployed cosigner's keygen index.
    pub cosigner_party: u16,
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
                cosigner_party: config.cosigner_party,
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
        cosigner_party: w.cosigner_party,
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
        cosigner_party: w.cosigner_party,
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
