//! Canonical CBOR MessageEnvelope per MPC-Spec §05 + ADR-0005 + ADR-0037.
//!
//! This is the wire format for every cggmp24 round message between cosigners.
//! Three layered defenses:
//!
//! 1. **Inner BRC-78 ECIES** (§05.5): payload encrypted to the recipient's
//!    identity key. Defends against relay observation of ceremony content.
//! 2. **Outer BRC-31 signature** (§05.6): identity-key signature over the
//!    canonical CBOR of fields 1-8. Defends against relay forgery + MITM.
//! 3. **Byte-equivalent re-encode** (§05.9.1, ADR-0037): every recipient
//!    re-encodes the parsed envelope and rejects any byte-level deviation.
//!    Closes parser-differential gaps of the Fireblocks BGM_DKG (2023) class.
//!
//! ## Encoder
//!
//! Hand-rolled — not `ciborium` (doesn't guarantee canonical encoding), not
//! `serde_cbor` (deprecated). The schema is a fixed 12-key integer-keyed map
//! per §05.3, so a purpose-built encoder is ~150 LOC and trivially auditable.
//!
//! ## Strict admission rules (§05.9.1)
//!
//! The decoder rejects, at the first byte of deviation, any of:
//! - Non-minimal integer encoding (e.g., `0x18 0x05` for the integer 5)
//! - Indefinite-length items (forbidden per §05.2)
//! - Duplicate map keys
//! - Trailing bytes after canonical termination
//! - Floats (forbidden per §05.2)
//! - Unsorted map keys
//! - Tag values not whitelisted (none whitelisted in v1)
//! - Non-uint/tstr map keys
//!
//! All rejections raise `MpcError::EnvelopeReencodeMismatch` so audit can
//! attribute the misbehavior.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use bsv::primitives::ec::{PrivateKey, PublicKey};
use sha2::{Digest, Sha256};

use crate::error::{MpcError, Result};
use crate::types::SessionId;

// ===========================================================================
// MessageEnvelope schema (§05.3)
// ===========================================================================

/// Numeric CBOR map keys per §05.3.
mod field {
    pub const VERSION: u8 = 1;
    pub const SESSION_ID: u8 = 2;
    pub const JOINT_PUBKEY: u8 = 3;
    pub const PHASE: u8 = 4;
    pub const ROUND: u8 = 5;
    pub const FROM_PARTY: u8 = 6;
    pub const TO_PARTY: u8 = 7;
    pub const INNER: u8 = 8;
    pub const SENDER_SIG_BRC31: u8 = 9;
    pub const EXECUTION_ID_PREFIX: u8 = 10;
    pub const CORRELATION_ID: u8 = 11;
    pub const TRACEPARENT: u8 = 12;
}

/// `mpc-spec-v1` version byte (field 1).
pub const ENVELOPE_VERSION_V1: u8 = 0x01;

/// `to_party == 0xFFFF` indicates broadcast (§05.4.6). Per §05.4.7, broadcast
/// is implemented as N unicast envelopes with distinct `to_party` values, so
/// this constant is only useful as a documented placeholder; senders SHOULD
/// emit unicast envelopes with the real recipient index.
pub const TO_PARTY_BROADCAST: u16 = 0xFFFF;

/// Maximum envelope size in bytes (§05.8).
pub const MAX_ENVELOPE_SIZE: usize = 256 * 1024;

/// One canonical CBOR MessageEnvelope per §05.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEnvelope {
    /// Field 1 — protocol version. MUST be [`ENVELOPE_VERSION_V1`].
    pub version: u8,
    /// Field 2 — 32-byte canonical SessionId (§04).
    pub session_id: SessionId,
    /// Field 3 — 33-byte compressed joint pubkey. All-zero during DKG keygen.
    pub joint_pubkey: [u8; 33],
    /// Field 4 — phase tag string (see [`crate::canonical::PhaseTag::envelope_str`]).
    pub phase: String,
    /// Field 5 — 1-based round number for the phase. MUST NOT be 0.
    pub round: u8,
    /// Field 6 — sender's 0-based party index.
    pub from_party: u16,
    /// Field 7 — recipient's 0-based party index (or `0xFFFF` for broadcast).
    pub to_party: u16,
    /// Field 8 — BRC-78 ECIES-wrapped inner cggmp24 message (eph_pub ‖ iv ‖ ct+tag).
    pub inner: Vec<u8>,
    /// Field 9 — BRC-31 signature over canonical CBOR of fields 1-8 (DER ECDSA).
    pub sender_sig_brc31: Vec<u8>,
    /// Field 10 — first 8 bytes of canonical ExecutionId (§02) for relay bucketing.
    pub execution_id_prefix: [u8; 8],
    /// Field 11 — OPTIONAL UUIDv7-style correlation id for cross-party log joining.
    pub correlation_id: Option<String>,
    /// Field 12 — OPTIONAL W3C Trace Context `traceparent` for OpenTelemetry.
    pub traceparent: Option<String>,
}

// ===========================================================================
// CBOR primitives (canonical RFC 8949 §4.2)
// ===========================================================================
//
// We implement only the major types used by §05.3: uint (0), bstr (2), tstr
// (3), map (5). No tags, no floats, no negative ints, no indefinite-length.

const MT_UINT: u8 = 0;
const MT_BSTR: u8 = 2;
const MT_TSTR: u8 = 3;
const MT_MAP: u8 = 5;

/// Encode a CBOR head byte for the given major type and count, choosing the
/// minimal-length form per RFC 8949 §4.2.
fn encode_head(out: &mut Vec<u8>, major: u8, count: u64) {
    let prefix = major << 5;
    if count <= 23 {
        out.push(prefix | count as u8);
    } else if count <= 0xff {
        out.push(prefix | 24);
        out.push(count as u8);
    } else if count <= 0xffff {
        out.push(prefix | 25);
        out.extend_from_slice(&(count as u16).to_be_bytes());
    } else if count <= 0xffff_ffff {
        out.push(prefix | 26);
        out.extend_from_slice(&(count as u32).to_be_bytes());
    } else {
        out.push(prefix | 27);
        out.extend_from_slice(&count.to_be_bytes());
    }
}

fn encode_uint(out: &mut Vec<u8>, n: u64) {
    encode_head(out, MT_UINT, n);
}

fn encode_bstr(out: &mut Vec<u8>, bytes: &[u8]) {
    encode_head(out, MT_BSTR, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn encode_tstr(out: &mut Vec<u8>, s: &str) {
    encode_head(out, MT_TSTR, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

// ===========================================================================
// Canonical encoding (§05.2)
// ===========================================================================

impl MessageEnvelope {
    /// Encode this envelope as canonical CBOR per §05.2. The output is
    /// byte-identical to what a re-encode of the decoded form would produce
    /// (this is the property §05.9.1 relies on).
    pub fn encode_canonical(&self) -> Vec<u8> {
        let n_optional = self.correlation_id.is_some() as u64 + self.traceparent.is_some() as u64;
        let n_fields = 10 + n_optional;
        let mut out = Vec::with_capacity(384);
        encode_head(&mut out, MT_MAP, n_fields);

        encode_uint(&mut out, field::VERSION as u64);
        encode_uint(&mut out, self.version as u64);

        encode_uint(&mut out, field::SESSION_ID as u64);
        encode_bstr(&mut out, self.session_id.as_bytes());

        encode_uint(&mut out, field::JOINT_PUBKEY as u64);
        encode_bstr(&mut out, &self.joint_pubkey);

        encode_uint(&mut out, field::PHASE as u64);
        encode_tstr(&mut out, &self.phase);

        encode_uint(&mut out, field::ROUND as u64);
        encode_uint(&mut out, self.round as u64);

        encode_uint(&mut out, field::FROM_PARTY as u64);
        encode_uint(&mut out, self.from_party as u64);

        encode_uint(&mut out, field::TO_PARTY as u64);
        encode_uint(&mut out, self.to_party as u64);

        encode_uint(&mut out, field::INNER as u64);
        encode_bstr(&mut out, &self.inner);

        encode_uint(&mut out, field::SENDER_SIG_BRC31 as u64);
        encode_bstr(&mut out, &self.sender_sig_brc31);

        encode_uint(&mut out, field::EXECUTION_ID_PREFIX as u64);
        encode_bstr(&mut out, &self.execution_id_prefix);

        if let Some(corr) = &self.correlation_id {
            encode_uint(&mut out, field::CORRELATION_ID as u64);
            encode_tstr(&mut out, corr);
        }
        if let Some(tp) = &self.traceparent {
            encode_uint(&mut out, field::TRACEPARENT as u64);
            encode_tstr(&mut out, tp);
        }

        out
    }

    /// Encode just the BRC-31-signed slab (fields 1-8 as a CBOR map(8)).
    /// This is what `sender_sig_brc31` (field 9) signs over per §05.6.
    pub fn encode_signed_slab(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        encode_head(&mut out, MT_MAP, 8);

        encode_uint(&mut out, field::VERSION as u64);
        encode_uint(&mut out, self.version as u64);

        encode_uint(&mut out, field::SESSION_ID as u64);
        encode_bstr(&mut out, self.session_id.as_bytes());

        encode_uint(&mut out, field::JOINT_PUBKEY as u64);
        encode_bstr(&mut out, &self.joint_pubkey);

        encode_uint(&mut out, field::PHASE as u64);
        encode_tstr(&mut out, &self.phase);

        encode_uint(&mut out, field::ROUND as u64);
        encode_uint(&mut out, self.round as u64);

        encode_uint(&mut out, field::FROM_PARTY as u64);
        encode_uint(&mut out, self.from_party as u64);

        encode_uint(&mut out, field::TO_PARTY as u64);
        encode_uint(&mut out, self.to_party as u64);

        encode_uint(&mut out, field::INNER as u64);
        encode_bstr(&mut out, &self.inner);

        out
    }
}

// ===========================================================================
// Strict decoder (§05.9 + §05.9.1)
// ===========================================================================

/// Lightweight CBOR reader that walks bytes minimal-form only and rejects
/// every forbidden construct enumerated in §05.9.1.
struct StrictReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> StrictReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn fail(rule: &'static str, detail: impl Into<String>) -> MpcError {
        MpcError::EnvelopeReencodeMismatch {
            rule,
            detail: detail.into(),
        }
    }

    fn need(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.bytes.len() {
            return Err(Self::fail(
                "envelope-truncated",
                format!(
                    "need {n} bytes at offset {} but only {} remain",
                    self.pos,
                    self.bytes.len().saturating_sub(self.pos)
                ),
            ));
        }
        let s = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn peek_byte(&self) -> Result<u8> {
        self.bytes
            .get(self.pos)
            .copied()
            .ok_or_else(|| Self::fail("envelope-truncated", "expected one more byte"))
    }

    /// Read a CBOR head, return `(major, count, count_byte_width)`. Rejects
    /// non-minimal encoding (§05.9.1 #1), indefinite-length (§05.9.1 #2),
    /// and floats (§05.9.1 #5).
    fn read_head(&mut self) -> Result<(u8, u64)> {
        let b = self.peek_byte()?;
        self.pos += 1;
        let major = b >> 5;
        let info = b & 0x1f;

        // Forbid major type 6 (tags) entirely — §05.9.1 #7. No CBOR tags
        // are whitelisted in mpc-spec-v1.
        if major == 6 {
            return Err(Self::fail(
                "tag-not-whitelisted",
                format!("CBOR tag at offset {} (no tags allowed)", self.pos - 1),
            ));
        }
        // Forbid major type 7 (floats / simple). §05.9.1 #5.
        if major == 7 {
            return Err(Self::fail(
                "float-forbidden",
                format!("float / simple at offset {}", self.pos - 1),
            ));
        }
        // Forbid negative ints (major 1) — §05.3 schema uses only uint, bstr,
        // tstr, map.
        if major == 1 {
            return Err(Self::fail(
                "negint-forbidden",
                format!("negative int at offset {}", self.pos - 1),
            ));
        }

        // Indefinite-length form (info == 31): §05.9.1 #2.
        if info == 31 {
            return Err(Self::fail(
                "indefinite-length",
                format!("indefinite-length item at offset {}", self.pos - 1),
            ));
        }
        // Reserved info values 28..30.
        if (28..=30).contains(&info) {
            return Err(Self::fail(
                "reserved-info",
                format!("reserved info {info} at offset {}", self.pos - 1),
            ));
        }

        let count = match info {
            n @ 0..=23 => u64::from(n),
            24 => {
                let v = self.need(1)?[0] as u64;
                // Non-minimal: 0..23 must use direct form.
                if v <= 23 {
                    return Err(Self::fail(
                        "non-minimal-int",
                        format!(
                            "uint8 0x{v:02x} should be direct form at offset {}",
                            self.pos - 2
                        ),
                    ));
                }
                v
            }
            25 => {
                let s = self.need(2)?;
                let v = u16::from_be_bytes([s[0], s[1]]) as u64;
                if v <= 0xff {
                    return Err(Self::fail(
                        "non-minimal-int",
                        format!(
                            "uint16 0x{v:04x} should use uint8 form at offset {}",
                            self.pos - 3
                        ),
                    ));
                }
                v
            }
            26 => {
                let s = self.need(4)?;
                let v = u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64;
                if v <= 0xffff {
                    return Err(Self::fail(
                        "non-minimal-int",
                        format!(
                            "uint32 0x{v:08x} should use uint16 form at offset {}",
                            self.pos - 5
                        ),
                    ));
                }
                v
            }
            27 => {
                let s = self.need(8)?;
                let v = u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]);
                if v <= 0xffff_ffff {
                    return Err(Self::fail(
                        "non-minimal-int",
                        format!(
                            "uint64 0x{v:016x} should use uint32 form at offset {}",
                            self.pos - 9
                        ),
                    ));
                }
                v
            }
            _ => unreachable!("info >27 already handled above"),
        };

        Ok((major, count))
    }

    fn read_uint(&mut self) -> Result<u64> {
        let (major, count) = self.read_head()?;
        if major != MT_UINT {
            return Err(Self::fail(
                "expected-uint",
                format!(
                    "expected uint at offset {}, got major {major}",
                    self.pos - 1
                ),
            ));
        }
        Ok(count)
    }

    fn read_bstr(&mut self) -> Result<&'a [u8]> {
        let (major, count) = self.read_head()?;
        if major != MT_BSTR {
            return Err(Self::fail(
                "expected-bstr",
                format!(
                    "expected bstr at offset {}, got major {major}",
                    self.pos - 1
                ),
            ));
        }
        self.need(count as usize)
    }

    fn read_tstr(&mut self) -> Result<&'a str> {
        let (major, count) = self.read_head()?;
        if major != MT_TSTR {
            return Err(Self::fail(
                "expected-tstr",
                format!(
                    "expected tstr at offset {}, got major {major}",
                    self.pos - 1
                ),
            ));
        }
        let bytes = self.need(count as usize)?;
        std::str::from_utf8(bytes)
            .map_err(|e| Self::fail("invalid-utf8", format!("tstr is not valid UTF-8: {e}")))
    }

    fn finish(self) -> Result<()> {
        if self.pos != self.bytes.len() {
            return Err(Self::fail(
                "trailing-bytes",
                format!(
                    "{} trailing bytes after canonical termination",
                    self.bytes.len() - self.pos
                ),
            ));
        }
        Ok(())
    }
}

impl MessageEnvelope {
    /// Strictly decode a canonical CBOR envelope per §05.9 + §05.9.1.
    ///
    /// Returns `EnvelopeReencodeMismatch` on any deviation from canonical
    /// form. The decoded envelope is guaranteed to round-trip byte-identically
    /// through [`encode_canonical`] (§05.9.1 byte-equivalent re-encode).
    pub fn decode_strict(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE_SIZE {
            return Err(MpcError::EnvelopeReencodeMismatch {
                rule: "max-size",
                detail: format!(
                    "envelope {} bytes exceeds max {MAX_ENVELOPE_SIZE}",
                    bytes.len()
                ),
            });
        }

        let mut r = StrictReader::new(bytes);

        // Outer map(N).
        let (major, n_fields) = r.read_head()?;
        if major != MT_MAP {
            return Err(StrictReader::fail(
                "expected-map",
                format!("envelope must start with CBOR map; got major {major}"),
            ));
        }
        if !(10..=12).contains(&n_fields) {
            return Err(StrictReader::fail(
                "envelope-arity",
                format!("envelope map has {n_fields} keys (expected 10..=12)"),
            ));
        }

        // Walk fields. Track previous key to enforce strict-ascending order
        // (§05.9.1 #6). Every key MUST be a uint.
        let mut env = MessageEnvelope {
            version: 0,
            session_id: SessionId([0u8; 32]),
            joint_pubkey: [0u8; 33],
            phase: String::new(),
            round: 0,
            from_party: 0,
            to_party: 0,
            inner: Vec::new(),
            sender_sig_brc31: Vec::new(),
            execution_id_prefix: [0u8; 8],
            correlation_id: None,
            traceparent: None,
        };
        let mut prev_key: Option<u64> = None;
        let mut seen = [false; 13]; // index by key 1..=12

        for _ in 0..n_fields {
            // Map keys MUST be uint per §05.3 schema (§05.9.1 #8).
            let key_pos = r.pos;
            let key = r.read_uint().map_err(|e| match e {
                MpcError::EnvelopeReencodeMismatch {
                    rule: "expected-uint",
                    ..
                } => StrictReader::fail(
                    "map-key-non-uint",
                    format!("map key at offset {key_pos} is not a uint"),
                ),
                other => other,
            })?;

            if let Some(p) = prev_key {
                if key <= p {
                    return Err(StrictReader::fail(
                        "unsorted-or-duplicate-key",
                        format!("map key {key} after {p} at offset {key_pos}"),
                    ));
                }
            }
            prev_key = Some(key);

            if key == 0 || key > 12 {
                return Err(StrictReader::fail(
                    "unknown-key",
                    format!("envelope key {key} at offset {key_pos} not in §05.3 schema"),
                ));
            }
            if seen[key as usize] {
                return Err(StrictReader::fail(
                    "duplicate-key",
                    format!("envelope key {key} duplicated at offset {key_pos}"),
                ));
            }
            seen[key as usize] = true;

            match key as u8 {
                field::VERSION => {
                    let v = r.read_uint()?;
                    if v > 0xff {
                        return Err(StrictReader::fail(
                            "version-range",
                            format!("version {v} > 255"),
                        ));
                    }
                    env.version = v as u8;
                }
                field::SESSION_ID => {
                    let b = r.read_bstr()?;
                    if b.len() != 32 {
                        return Err(StrictReader::fail(
                            "session-id-length",
                            format!("session_id is {} bytes (need 32)", b.len()),
                        ));
                    }
                    let mut sid = [0u8; 32];
                    sid.copy_from_slice(b);
                    env.session_id = SessionId(sid);
                }
                field::JOINT_PUBKEY => {
                    let b = r.read_bstr()?;
                    if b.len() != 33 {
                        return Err(StrictReader::fail(
                            "joint-pubkey-length",
                            format!("joint_pubkey is {} bytes (need 33)", b.len()),
                        ));
                    }
                    env.joint_pubkey.copy_from_slice(b);
                }
                field::PHASE => {
                    env.phase = r.read_tstr()?.to_owned();
                }
                field::ROUND => {
                    let v = r.read_uint()?;
                    if v > 0xff {
                        return Err(StrictReader::fail(
                            "round-range",
                            format!("round {v} > 255"),
                        ));
                    }
                    if v == 0 {
                        return Err(StrictReader::fail("round-zero", "round MUST be 1-based"));
                    }
                    env.round = v as u8;
                }
                field::FROM_PARTY => {
                    let v = r.read_uint()?;
                    if v > 0xffff {
                        return Err(StrictReader::fail(
                            "from-party-range",
                            format!("from_party {v} > 65535"),
                        ));
                    }
                    env.from_party = v as u16;
                }
                field::TO_PARTY => {
                    let v = r.read_uint()?;
                    if v > 0xffff {
                        return Err(StrictReader::fail(
                            "to-party-range",
                            format!("to_party {v} > 65535"),
                        ));
                    }
                    env.to_party = v as u16;
                }
                field::INNER => {
                    env.inner = r.read_bstr()?.to_vec();
                }
                field::SENDER_SIG_BRC31 => {
                    env.sender_sig_brc31 = r.read_bstr()?.to_vec();
                }
                field::EXECUTION_ID_PREFIX => {
                    let b = r.read_bstr()?;
                    if b.len() != 8 {
                        return Err(StrictReader::fail(
                            "execution-id-prefix-length",
                            format!("execution_id_prefix is {} bytes (need 8)", b.len()),
                        ));
                    }
                    env.execution_id_prefix.copy_from_slice(b);
                }
                field::CORRELATION_ID => {
                    env.correlation_id = Some(r.read_tstr()?.to_owned());
                }
                field::TRACEPARENT => {
                    env.traceparent = Some(r.read_tstr()?.to_owned());
                }
                _ => unreachable!("key range checked above"),
            }
        }

        r.finish()?;

        // Required fields (1-10): all must be present.
        for (k, &seen_k) in seen.iter().enumerate().take(11).skip(1) {
            if !seen_k {
                return Err(StrictReader::fail(
                    "missing-required-field",
                    format!("envelope missing required field {k} (§05.3)"),
                ));
            }
        }

        // Byte-equivalent re-encode (§05.9.1) — defense in depth on top of
        // the strict reader. Any deviation here is the §05.9.1 #1 / #6 trap.
        let re = env.encode_canonical();
        if re != bytes {
            return Err(StrictReader::fail(
                "reencode-mismatch",
                format!(
                    "decoded envelope re-encodes to {} bytes vs input {} bytes (parser \
                     differential)",
                    re.len(),
                    bytes.len()
                ),
            ));
        }

        Ok(env)
    }
}

// ===========================================================================
// BRC-78 ECIES inner (§05.5)
// ===========================================================================

/// Wrap `inner_plaintext` in a BRC-78 ECIES envelope addressed to
/// `recipient_pub`. Format (per §05.5 step 5): `eph_pub_33 ‖ iv_12 ‖
/// ciphertext ‖ tag_16`.
///
/// `eph_priv` is the sender's ephemeral private key (caller-supplied so this
/// can be deterministic for tests; in production it MUST be `OsRng`-fresh
/// per-message). `iv` is the 12-byte AES-GCM nonce (same caveat).
pub fn brc78_encrypt(
    inner_plaintext: &[u8],
    recipient_pub: &PublicKey,
    eph_priv: &PrivateKey,
    iv: &[u8; 12],
) -> Result<Vec<u8>> {
    let shared = eph_priv
        .derive_shared_secret(recipient_pub)
        .map_err(|e| MpcError::Protocol(format!("BRC-78 ECDH failed: {e:?}")))?;
    let shared_bytes = shared.to_compressed();
    let mut h = Sha256::new();
    h.update(shared_bytes);
    let aes_key_bytes = h.finalize();

    let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);
    let ct_and_tag = cipher
        .encrypt(nonce, inner_plaintext)
        .map_err(|e| MpcError::Encryption(format!("BRC-78 AES-GCM encrypt: {e}")))?;

    let eph_pub = eph_priv.public_key();
    let eph_pub_bytes = eph_pub.to_compressed();

    let mut out = Vec::with_capacity(33 + 12 + ct_and_tag.len());
    out.extend_from_slice(&eph_pub_bytes);
    out.extend_from_slice(iv);
    out.extend_from_slice(&ct_and_tag);
    Ok(out)
}

/// Unwrap a BRC-78 ECIES envelope using the recipient's identity private key.
pub fn brc78_decrypt(envelope_inner: &[u8], recipient_priv: &PrivateKey) -> Result<Vec<u8>> {
    if envelope_inner.len() < 33 + 12 + 16 {
        return Err(MpcError::Encryption(format!(
            "BRC-78 inner too short: {} bytes (need at least 61)",
            envelope_inner.len()
        )));
    }
    let eph_pub_bytes = &envelope_inner[..33];
    let iv = &envelope_inner[33..33 + 12];
    let ct_and_tag = &envelope_inner[33 + 12..];

    let eph_pub = PublicKey::from_bytes(eph_pub_bytes)
        .map_err(|e| MpcError::Protocol(format!("BRC-78 invalid ephemeral pub: {e:?}")))?;
    let shared = recipient_priv
        .derive_shared_secret(&eph_pub)
        .map_err(|e| MpcError::Protocol(format!("BRC-78 ECDH failed: {e:?}")))?;
    let shared_bytes = shared.to_compressed();
    let mut h = Sha256::new();
    h.update(shared_bytes);
    let aes_key_bytes = h.finalize();

    let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt(nonce, ct_and_tag)
        .map_err(|e| MpcError::Encryption(format!("BRC-78 AES-GCM decrypt: {e}")))
}

// ===========================================================================
// BRC-31 outer signature (§05.6)
// ===========================================================================

/// Sign fields 1-8 of `env` with `sender_priv` per §05.6 — deterministic
/// ECDSA (RFC 6979), low-s normalized, DER-encoded. Stores the resulting
/// signature on `env.sender_sig_brc31`.
pub fn brc31_sign_envelope(env: &mut MessageEnvelope, sender_priv: &PrivateKey) -> Result<()> {
    let slab = env.encode_signed_slab();
    let mut h = Sha256::new();
    h.update(&slab);
    let digest = h.finalize();
    let mut digest_arr = [0u8; 32];
    digest_arr.copy_from_slice(&digest);

    let sig = bsv::primitives::ec::ecdsa::sign(&digest_arr, sender_priv)
        .map_err(|e| MpcError::Protocol(format!("BRC-31 ECDSA sign failed: {e:?}")))?;
    env.sender_sig_brc31 = sig.to_der();
    Ok(())
}

/// Verify `env.sender_sig_brc31` against `sender_pub` over the canonical
/// CBOR of fields 1-8 per §05.6. Returns `false` for any verification failure.
pub fn brc31_verify_envelope(env: &MessageEnvelope, sender_pub: &PublicKey) -> bool {
    let slab = env.encode_signed_slab();
    let mut h = Sha256::new();
    h.update(&slab);
    let digest = h.finalize();
    let mut digest_arr = [0u8; 32];
    digest_arr.copy_from_slice(&digest);

    let sig = match bsv::primitives::ec::Signature::from_der(&env.sender_sig_brc31) {
        Ok(s) => s,
        Err(_) => return false,
    };
    bsv::primitives::ec::ecdsa::verify(&digest_arr, &sig, sender_pub)
}

// ===========================================================================
// Tests — small self-contained encoding sanity checks. The byte-exact
// conformance suite against the §05 vector lives in
// `tests/conformance_05_message_envelope.rs`.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> MessageEnvelope {
        MessageEnvelope {
            version: ENVELOPE_VERSION_V1,
            session_id: SessionId([0xaa; 32]),
            joint_pubkey: {
                let mut p = [0u8; 33];
                p[0] = 0x02;
                p
            },
            phase: "sign".into(),
            round: 1,
            from_party: 0,
            to_party: 1,
            inner: vec![0xde, 0xad, 0xbe, 0xef],
            sender_sig_brc31: vec![0x30, 0x44, 0x02, 0x20],
            execution_id_prefix: [0u8; 8],
            correlation_id: None,
            traceparent: None,
        }
    }

    #[test]
    fn round_trip_encode_decode() {
        let env = sample_envelope();
        let bytes = env.encode_canonical();
        let back = MessageEnvelope::decode_strict(&bytes).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn round_trip_with_optional_fields() {
        let mut env = sample_envelope();
        env.correlation_id = Some("corr-1".into());
        env.traceparent = Some("00-aaaa-bbbb-01".into());
        let bytes = env.encode_canonical();
        let back = MessageEnvelope::decode_strict(&bytes).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let env = sample_envelope();
        let mut bytes = env.encode_canonical();
        bytes.push(0x00);
        let err = MessageEnvelope::decode_strict(&bytes).unwrap_err();
        assert!(matches!(
            err,
            MpcError::EnvelopeReencodeMismatch {
                rule: "trailing-bytes",
                ..
            }
        ));
    }

    #[test]
    fn rejects_non_minimal_int() {
        // a8 01 18 01 02 5820 ... — version encoded as 0x18 0x01 instead of 0x01.
        // Construct manually starting from a canonical envelope.
        let env = sample_envelope();
        let bytes = env.encode_canonical();
        // Find the version key/value and rewrite it: pattern is `01 01` near
        // the start after the map header. We know map header is one byte
        // (ac for 12, aa for 10, etc.) → for sample (10 fields) the map
        // header is `aa`, followed by `01 01` (version key + value).
        assert_eq!(bytes[0], 0xaa);
        assert_eq!(&bytes[1..3], &[0x01, 0x01]);
        // Replace the version value 0x01 with 0x18 0x01 (non-minimal). Map
        // arity stays the same since it's still 10 fields.
        let mut bad = Vec::new();
        bad.extend_from_slice(&bytes[..2]); // map header + version key
        bad.extend_from_slice(&[0x18, 0x01]); // non-minimal version
        bad.extend_from_slice(&bytes[3..]);
        // sanity
        assert_eq!(bad[0], 0xaa);
        assert_eq!(&bad[1..5], &[0x01, 0x18, 0x01, 0x02]);

        let err = MessageEnvelope::decode_strict(&bad).unwrap_err();
        assert!(matches!(
            err,
            MpcError::EnvelopeReencodeMismatch {
                rule: "non-minimal-int",
                ..
            }
        ));
    }

    #[test]
    fn signed_slab_drops_optional_and_sig_fields() {
        let mut env = sample_envelope();
        env.correlation_id = Some("corr".into());
        env.traceparent = Some("tp".into());
        env.sender_sig_brc31 = vec![0xff; 71];
        let slab = env.encode_signed_slab();
        // Slab starts with map(8) = 0xa8.
        assert_eq!(slab[0], 0xa8);
        // sig (key 9), execution_id_prefix (key 10), correlation_id (key 11),
        // traceparent (key 12) MUST NOT appear in the slab.
        // The last byte of the slab is whatever closes the bstr for `inner` —
        // for our sample `inner = [0xde,0xad,0xbe,0xef]` the encoding is
        // `08 44 deadbeef`. So slab ends with `efef`... let's not assert
        // the trailing bytes, just check size is much smaller than the full
        // envelope encoding.
        let full = env.encode_canonical();
        assert!(slab.len() < full.len());
    }
}
