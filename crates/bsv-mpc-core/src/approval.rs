//! §09.5.1 / ADR-0044 approval canonicalization — `request_view_hash`.
//!
//! The `request_view_hash` binds a wallet's human-rendered approval prompt to
//! the exact transaction-shaping inputs the cosigner will sign over. It is the
//! SHA-256 of a canonical CBOR **definite-length map** with INTEGER keys 1..8,
//! per ADR-0032 (preimage layout) and ADR-0044 (intent-kind dispatch for the
//! `rendered_text` field):
//!
//! | key | field          | CBOR type                                   |
//! |-----|----------------|---------------------------------------------|
//! | 1   | amount         | unsigned int (satoshis or token amount)     |
//! | 2   | recipient      | text string, OR array of text (kind `multi`)|
//! | 3   | sighash        | hex **text** string (32 bytes → 64 chars)   |
//! | 4   | execution_id   | hex **text** string (32 bytes → 64 chars)   |
//! | 5   | policy_id      | hex **text** string (32 bytes → 64 chars)   |
//! | 6   | manifest_ack   | hex **text** string (64 bytes → 128 chars)  |
//! | 7   | human_locale   | text string (BCP-47 tag, e.g. "en-US")      |
//! | 8   | rendered_text  | text string (canonical per ADR-0044)        |
//!
//! IMPORTANT: keys 3-6 are stored as hex **text** strings (CBOR major type 3),
//! NOT raw byte strings. The encoder below reproduces them as text verbatim.
//!
//! The canonical CBOR rules (RFC 8949 §4.2: definite lengths, minimal integer
//! encoding, integer map keys in ascending order 1..8) are hand-rolled here for
//! this fixed map shape so the bytes are byte-for-byte reproducible against the
//! locked MPC-Spec vectors in `tests/fixtures/09-rendered-text.json`. The map
//! header is `0xA8` (major type 5, 8 pairs); each key `i` encodes to the single
//! byte `0x0i` (minimal uint, value < 24), which is already the canonical
//! bytewise-lexicographic key order.
//!
//! NFC requirement: every text string (recipient, locale, rendered_text) MUST
//! be NFC-normalized UTF-8 before being passed in. The canonical vectors are
//! already NFC, so this module passes the bytes through unchanged — it does NOT
//! perform normalization itself (no normalization dependency is pulled in).
//! Callers feeding non-canonical input are responsible for NFC-normalizing.
//!
//! NOTE (ADR-0044): the `rendered_text` strings are hand-authored per intent
//! kind (and contain literal "..." placeholders in the locked vectors); they
//! are NOT derivable byte-exactly from a generic renderer. `rendered_text` is
//! therefore an **input** to this primitive. The deterministic, lockable part
//! is the CBOR-of-8-fields → SHA-256, which this module owns.

use sha2::{Digest, Sha256};

/// Recipient binding for key 2 of the `request_view_hash` preimage.
///
/// Single-recipient intent kinds (`payment`, `token_transfer`, `script_spend`,
/// `brc100_internalize`) encode a single text string. The `multi` kind encodes
/// a CBOR array of text strings (one per recipient output).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    /// A single recipient address / output descriptor (CBOR text string).
    Single(String),
    /// Multiple recipient addresses (CBOR array of text strings).
    Multi(Vec<String>),
}

/// Result of [`request_view_hash`]: the 32-byte digest plus the exact canonical
/// CBOR preimage bytes that were hashed (returned so callers and conformance
/// harnesses can byte-compare the preimage against the locked vector).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestViewHash {
    /// SHA-256 of [`Self::preimage`].
    pub hash: [u8; 32],
    /// The canonical CBOR definite-length map `{1..8}` that was hashed.
    pub preimage: Vec<u8>,
}

/// CBOR major-type-0 minimal unsigned-integer encoding (RFC 8949 §3, §4.2.1).
fn cbor_uint(n: u64) -> Vec<u8> {
    cbor_head(0, n)
}

/// Encode a CBOR head byte + extended length for `major` carrying value `n`,
/// using the minimal (canonical) representation.
fn cbor_head(major: u8, n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    if n < 24 {
        out.push((major << 5) | (n as u8));
    } else if n < 0x100 {
        out.push((major << 5) | 24);
        out.push(n as u8);
    } else if n < 0x1_0000 {
        out.push((major << 5) | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n < 0x1_0000_0000 {
        out.push((major << 5) | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push((major << 5) | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
    out
}

/// CBOR major-type-3 text string: head(len) ‖ utf-8 bytes. The caller is
/// responsible for NFC normalization (see module docs).
fn cbor_text(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = cbor_head(3, b.len() as u64);
    out.extend_from_slice(b);
    out
}

/// Encode key 2 (recipient): a text string for `Single`, or a major-type-4
/// definite-length array of text strings for `Multi`.
fn cbor_recipient(recipient: &Recipient) -> Vec<u8> {
    match recipient {
        Recipient::Single(s) => cbor_text(s),
        Recipient::Multi(items) => {
            let mut out = cbor_head(4, items.len() as u64);
            for item in items {
                out.extend_from_slice(&cbor_text(item));
            }
            out
        }
    }
}

/// Build the canonical CBOR preimage and compute the `request_view_hash` per
/// §09.5.1 / ADR-0044 / ADR-0032.
///
/// The preimage is a CBOR definite-length map with integer keys 1..8 in
/// ascending order. `sighash_hex`, `execution_id_hex`, `policy_id_hex`, and
/// `manifest_ack_hex` are encoded as hex **text** strings (NOT raw bytes), per
/// the locked vector layout. All text inputs MUST already be NFC-normalized
/// UTF-8 (see module docs).
///
/// Returns the digest and the exact preimage bytes that were hashed.
#[allow(clippy::too_many_arguments)]
pub fn request_view_hash(
    amount: u64,
    recipient: &Recipient,
    sighash_hex: &str,
    execution_id_hex: &str,
    policy_id_hex: &str,
    manifest_ack_hex: &str,
    human_locale: &str,
    rendered_text: &str,
) -> RequestViewHash {
    // Definite-length map header: major type 5, 8 pairs → 0xA8.
    let mut preimage = cbor_head(5, 8);

    // Keys 1..8 in ascending order (single-byte encodings 0x01..0x08 are
    // already the canonical bytewise-lex key order for a CBOR map).
    preimage.extend_from_slice(&cbor_uint(1));
    preimage.extend_from_slice(&cbor_uint(amount));

    preimage.extend_from_slice(&cbor_uint(2));
    preimage.extend_from_slice(&cbor_recipient(recipient));

    preimage.extend_from_slice(&cbor_uint(3));
    preimage.extend_from_slice(&cbor_text(sighash_hex));

    preimage.extend_from_slice(&cbor_uint(4));
    preimage.extend_from_slice(&cbor_text(execution_id_hex));

    preimage.extend_from_slice(&cbor_uint(5));
    preimage.extend_from_slice(&cbor_text(policy_id_hex));

    preimage.extend_from_slice(&cbor_uint(6));
    preimage.extend_from_slice(&cbor_text(manifest_ack_hex));

    preimage.extend_from_slice(&cbor_uint(7));
    preimage.extend_from_slice(&cbor_text(human_locale));

    preimage.extend_from_slice(&cbor_uint(8));
    preimage.extend_from_slice(&cbor_text(rendered_text));

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&Sha256::digest(&preimage));

    RequestViewHash { hash, preimage }
}

// ===========================================================================
// Approval signature + quorum collection (§09.5.1 steps 3-5, issue #43)
// ===========================================================================

use crate::error::{MpcError, Result};
use crate::policy::ApprovalQuorum;
use bsv::primitives::ec::{PrivateKey, PublicKey};

/// Domain-separation tag for the approval-signature preimage (§09.5.1 step 3).
/// **15 bytes** (`b"mpc-approval-v1"`), so the preimage is `32 + 15 + 32 = 79`
/// bytes — built from this literal, never a hardcoded length.
pub const APPROVAL_DOMAIN_TAG: &[u8] = b"mpc-approval-v1";

/// Build the approval-signature preimage (§09.5.1 step 3):
/// `request_view_hash ‖ "mpc-approval-v1" ‖ session_id` — binary concatenation,
/// no separators. The approver signs THIS (via BRC-77), binding their approval
/// to the exact rendered transaction view (`request_view_hash`, see
/// [`request_view_hash`]) AND this ceremony's `session_id` — closing the
/// approve-`policy_id`-alone replay/injection gap.
pub fn approval_preimage(request_view_hash: &[u8; 32], session_id: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + APPROVAL_DOMAIN_TAG.len() + 32);
    m.extend_from_slice(request_view_hash);
    m.extend_from_slice(APPROVAL_DOMAIN_TAG);
    m.extend_from_slice(session_id);
    m
}

/// Sign an approval over the §09.5.1 preimage using **BRC-77** (anyone-verifier
/// mode), with the approver's BRC-31 identity key. A valid signature is an
/// **Allow** vote — signing the view hash == approving the rendered view. Uses
/// `bsv-rs`' BRC-77 `messages::sign` (the same SDK the rest of bsv-mpc uses; NOT
/// rust-mpc's `bsv-sdk`).
pub fn sign_approval(
    request_view_hash: &[u8; 32],
    session_id: &[u8; 32],
    approver: &PrivateKey,
) -> Result<Vec<u8>> {
    let preimage = approval_preimage(request_view_hash, session_id);
    bsv::messages::sign(&preimage, approver, None)
        .map_err(|e| MpcError::Protocol(format!("BRC-77 approval sign: {e}")))
}

/// Verify a BRC-77 approval signature over the §09.5.1 preimage and, on success,
/// return the **signer's** compressed identity pubkey (parsed from the BRC-77
/// wire format `[version:4][sender:33][recipient:1|33][keyID:32][sig:DER]`). A
/// valid signature cryptographically binds that signer to this exact
/// `(request_view_hash, session_id)`. Returns `None` if the signature is invalid
/// or malformed. The caller checks the returned signer against the quorum's
/// `eligible` set ([`ApprovalCollector::record_vote`]).
pub fn verify_approval(
    request_view_hash: &[u8; 32],
    session_id: &[u8; 32],
    sig: &[u8],
) -> Option<Vec<u8>> {
    let preimage = approval_preimage(request_view_hash, session_id);
    // Anyone-verifier mode (signed with verifier=None ⇒ verify with recipient=None).
    match bsv::messages::verify(&preimage, sig, None) {
        Ok(true) => {
            // BRC-77 wire: sender pubkey is the 33 bytes after the 4-byte version.
            if sig.len() < 4 + 33 {
                return None;
            }
            let sender = &sig[4..4 + 33];
            // Sanity: it must parse as a valid compressed point.
            PublicKey::from_bytes(sender).ok()?;
            Some(sender.to_vec())
        }
        _ => None,
    }
}

/// An approver's decision (§09.5.1 step 4). An `Allow` is carried by a valid
/// approval signature; a `Deny` is carried in the BRC-31-authenticated response
/// envelope (the §09.5.1 signed preimage has no decision field — the envelope's
/// outer auth binds the deny to its sender).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// Approve the rendered view.
    Allow,
    /// Reject the rendered view.
    Deny,
}

/// The real-time approval status surfaced to the requester (§09.5.1 step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    /// Still collecting. `collected` Allow votes of `total` (= `k`) required.
    Pending {
        /// Allow votes collected so far.
        collected: u32,
        /// Required Allow votes (`quorum.k`).
        total: u32,
        /// Milliseconds remaining until the deadline.
        deadline_ms_remaining: u64,
        /// Eligible approvers (compressed pubkeys) who have voted (allow or deny).
        eligible_responded: Vec<Vec<u8>>,
    },
    /// `k` Allow votes collected — proceed to sign.
    Approved,
    /// `k` Deny votes collected — abort.
    Denied,
    /// Deadline elapsed before reaching `k` — abort (deny by silence).
    Expired,
}

/// Collects approver votes for a `RequireApproval` verdict until `k`-Allow
/// (Approved), `k`-Deny (Denied), or the deadline (Expired) — §09.5.1 step 4-5.
///
/// Pure state machine: time is supplied as `now_ms` (epoch-ms) by the caller (no
/// wall-clock read inside — deterministic + wasm-safe, same discipline as the
/// policy engine). Votes are deduplicated per signer (the first vote from an
/// eligible approver counts; later votes from the same signer are ignored).
#[derive(Debug, Clone)]
pub struct ApprovalCollector {
    quorum: ApprovalQuorum,
    request_view_hash: [u8; 32],
    session_id: [u8; 32],
    /// Absolute deadline (epoch-ms).
    deadline_ms: u64,
    /// Eligible signers (compressed pubkeys) who voted Allow (deduped).
    allows: Vec<Vec<u8>>,
    /// Eligible signers who voted Deny (deduped).
    denies: Vec<Vec<u8>>,
}

impl ApprovalCollector {
    /// Create a collector for a `RequireApproval` quorum. `deadline_ms` is the
    /// ABSOLUTE epoch-ms deadline (caller computes it from `now + ttl`).
    pub fn new(
        quorum: ApprovalQuorum,
        request_view_hash: [u8; 32],
        session_id: [u8; 32],
        deadline_ms: u64,
    ) -> Self {
        Self {
            quorum,
            request_view_hash,
            session_id,
            deadline_ms,
            allows: Vec::new(),
            denies: Vec::new(),
        }
    }

    /// The exact preimage approvers must sign for this collection.
    pub fn preimage(&self) -> Vec<u8> {
        approval_preimage(&self.request_view_hash, &self.session_id)
    }

    /// Record a vote whose `sig` is a BRC-77 approval signature over this
    /// collection's preimage. Verifies the signature, confirms the signer is in
    /// the quorum's `eligible` set, deduplicates, and tallies per `decision`.
    /// Returns the post-vote [`ApprovalStatus`] (`now_ms` for the deadline view).
    ///
    /// Errors if the signature is invalid/malformed or the signer is not
    /// eligible — a relay-injected or non-approver message is rejected, never
    /// silently counted.
    pub fn record_vote(
        &mut self,
        sig: &[u8],
        decision: ApprovalDecision,
        now_ms: u64,
    ) -> Result<ApprovalStatus> {
        let signer = verify_approval(&self.request_view_hash, &self.session_id, sig)
            .ok_or_else(|| MpcError::Protocol("invalid BRC-77 approval signature".into()))?;
        if !self.quorum.eligible.contains(&signer) {
            return Err(MpcError::Protocol(
                "approval signer is not in the quorum's eligible set".into(),
            ));
        }
        // Dedup: a signer's first vote (allow or deny) is final.
        let already = self.allows.contains(&signer) || self.denies.contains(&signer);
        if !already {
            match decision {
                ApprovalDecision::Allow => self.allows.push(signer),
                ApprovalDecision::Deny => self.denies.push(signer),
            }
        }
        Ok(self.status(now_ms))
    }

    /// Current status (§09.5.1 step 5). `k`-Allow → Approved; `k`-Deny → Denied;
    /// else past-deadline → Expired, otherwise Pending.
    pub fn status(&self, now_ms: u64) -> ApprovalStatus {
        let k = self.quorum.k;
        if self.allows.len() as u32 >= k {
            return ApprovalStatus::Approved;
        }
        if self.denies.len() as u32 >= k {
            return ApprovalStatus::Denied;
        }
        if now_ms >= self.deadline_ms {
            return ApprovalStatus::Expired;
        }
        let mut eligible_responded: Vec<Vec<u8>> = self.allows.clone();
        eligible_responded.extend(self.denies.iter().cloned());
        ApprovalStatus::Pending {
            collected: self.allows.len() as u32,
            total: k,
            deadline_ms_remaining: self.deadline_ms.saturating_sub(now_ms),
            eligible_responded,
        }
    }

    /// Whether the quorum is satisfied (`k` Allow votes) — proceed-to-sign gate.
    pub fn is_approved(&self) -> bool {
        self.allows.len() as u32 >= self.quorum.k
    }
}

/// **WebAuthn binding verification (§08.11, issue #43).** A WebAuthn-bound
/// approver MUST bind the passkey assertion to the rendered transaction view:
/// the `clientDataJSON.challenge` MUST equal the `request_view_hash`, AND the
/// assertion MUST have been made with `userVerification=required` (the UV flag in
/// `authenticatorData`). This closes the gap where a passkey gesture is harvested
/// for a DIFFERENT transaction than the one rendered.
///
/// This verifies the BINDING (challenge == view hash + UV flag set); the WebAuthn
/// assertion *signature* itself is verified by the platform passkey stack at the
/// client (full ceremony wiring lands with the #41 native shells). Given the raw
/// `clientDataJSON` bytes and the 37+-byte `authenticator_data`:
/// 1. parse `clientDataJSON`, require `type == "webauthn.get"`,
/// 2. base64url-decode (no padding) its `challenge` and require it to equal
///    `request_view_hash` (32 bytes),
/// 3. require the UV bit (0x04) set in `authenticator_data[32]` (flags).
pub fn verify_webauthn_approval(
    client_data_json: &[u8],
    authenticator_data: &[u8],
    request_view_hash: &[u8; 32],
) -> Result<()> {
    use base64::Engine;

    let cd: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|e| MpcError::Protocol(format!("clientDataJSON parse: {e}")))?;
    if cd.get("type").and_then(|t| t.as_str()) != Some("webauthn.get") {
        return Err(MpcError::Protocol(
            "WebAuthn clientDataJSON.type must be \"webauthn.get\"".into(),
        ));
    }
    let challenge_b64 = cd
        .get("challenge")
        .and_then(|c| c.as_str())
        .ok_or_else(|| MpcError::Protocol("WebAuthn clientDataJSON.challenge missing".into()))?;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(challenge_b64)
        .map_err(|e| MpcError::Protocol(format!("WebAuthn challenge base64url: {e}")))?;
    if challenge != request_view_hash {
        return Err(MpcError::Protocol(
            "WebAuthn challenge does not equal request_view_hash (§08.11 binding)".into(),
        ));
    }
    // authenticatorData: [0..32]=rpIdHash, [32]=flags. UV is bit 2 (0x04).
    let flags = authenticator_data
        .get(32)
        .ok_or_else(|| MpcError::Protocol("authenticatorData too short (no flags byte)".into()))?;
    if flags & 0x04 == 0 {
        return Err(MpcError::Protocol(
            "WebAuthn userVerification not performed (UV flag clear; §08.11 requires it)".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A reduced, self-contained vector to exercise the encoder shape without
    // depending on the full conformance fixture (that lives in
    // tests/conformance_09_rendered_text.rs).
    fn sample() -> RequestViewHash {
        request_view_hash(
            100,
            &Recipient::Single("1Bexample".into()),
            &"de".repeat(32),
            &"f2".repeat(32),
            &"00".repeat(32),
            &"00".repeat(64),
            "en-US",
            "Send 100 sats to 1Bexample.",
        )
    }

    #[test]
    fn map_header_and_first_key_are_canonical() {
        let r = sample();
        // 0xA8 = major type 5 (map), 8 pairs.
        assert_eq!(r.preimage[0], 0xA8);
        // First key is the single byte 0x01 (minimal uint 1).
        assert_eq!(r.preimage[1], 0x01);
    }

    #[test]
    fn changing_rendered_text_changes_the_hash() {
        let a = sample();
        let b = request_view_hash(
            100,
            &Recipient::Single("1Bexample".into()),
            &"de".repeat(32),
            &"f2".repeat(32),
            &"00".repeat(32),
            &"00".repeat(64),
            "en-US",
            "Send 100 sats to 1Bexample!", // one char differs
        );
        assert_ne!(a.hash, b.hash);
        assert_ne!(a.preimage, b.preimage);
    }

    #[test]
    fn single_vs_multi_recipient_differ() {
        let single = request_view_hash(
            75_000_000,
            &Recipient::Single("1A...".into()),
            &"de".repeat(32),
            &"f2".repeat(32),
            &"00".repeat(32),
            &"00".repeat(64),
            "en-US",
            "rendered",
        );
        let multi = request_view_hash(
            75_000_000,
            &Recipient::Multi(vec!["1A...".into(), "1B...".into()]),
            &"de".repeat(32),
            &"f2".repeat(32),
            &"00".repeat(32),
            &"00".repeat(64),
            "en-US",
            "rendered",
        );
        assert_ne!(single.hash, multi.hash);
        // Locate key 2 (byte 0x02) and inspect its value head. For `Single`
        // it's a text-string head (major type 3 → 0x60..0x7F); for `Multi` it's
        // an array head (major type 4 → 0x80..0x9F). amount 75000000 encodes as
        // 0x1a ‖ 4 bytes, so the key-2 byte sits at a fixed offset; we find it
        // structurally rather than hard-coding the index.
        let single_k2 = single.preimage.iter().position(|&b| b == 0x02).unwrap();
        let multi_k2 = multi.preimage.iter().position(|&b| b == 0x02).unwrap();
        // "1A..." is 5 bytes → text head 0x65.
        assert_eq!(single.preimage[single_k2 + 1], 0x65);
        // 2-element array → 0x82.
        assert_eq!(multi.preimage[multi_k2 + 1], 0x82);
    }

    #[test]
    fn hash_is_sha256_of_preimage() {
        let r = sample();
        let mut expect = [0u8; 32];
        expect.copy_from_slice(&Sha256::digest(&r.preimage));
        assert_eq!(r.hash, expect);
    }

    #[test]
    fn amount_uses_minimal_integer_encoding() {
        // amount 0 → single byte 0x00 as key-1's value (preimage[2]).
        let zero = request_view_hash(
            0,
            &Recipient::Single("x".into()),
            &"de".repeat(32),
            &"f2".repeat(32),
            &"00".repeat(32),
            &"00".repeat(64),
            "en-US",
            "r",
        );
        assert_eq!(zero.preimage[2], 0x00);
    }

    // ── Approval signature + quorum collector (§09.5.1) ──────────────────────

    use bsv::primitives::ec::PrivateKey;

    fn quorum(k: u32, eligible: &[&PrivateKey]) -> ApprovalQuorum {
        ApprovalQuorum {
            k,
            eligible: eligible
                .iter()
                .map(|p| p.public_key().to_compressed().to_vec())
                .collect(),
            deadline_secs: None,
        }
    }

    #[test]
    fn approval_preimage_is_79_bytes_view_tag_session() {
        let vh = [0x11u8; 32];
        let sid = [0x22u8; 32];
        let m = approval_preimage(&vh, &sid);
        // 32 (view hash) + 15 ("mpc-approval-v1") + 32 (session_id) = 79.
        assert_eq!(APPROVAL_DOMAIN_TAG.len(), 15);
        assert_eq!(m.len(), 79);
        assert_eq!(&m[0..32], &vh);
        assert_eq!(&m[32..47], b"mpc-approval-v1");
        assert_eq!(&m[47..79], &sid);
    }

    #[test]
    fn sign_then_verify_returns_signer() {
        let approver = PrivateKey::random();
        let vh = [0x42u8; 32];
        let sid = [0x07u8; 32];
        let sig = sign_approval(&vh, &sid, &approver).expect("sign");
        let signer = verify_approval(&vh, &sid, &sig).expect("verify returns signer");
        assert_eq!(signer, approver.public_key().to_compressed().to_vec());
    }

    #[test]
    fn verify_rejects_wrong_view_hash_or_session() {
        let approver = PrivateKey::random();
        let sig = sign_approval(&[0x42u8; 32], &[0x07u8; 32], &approver).expect("sign");
        // Different view hash → no signer.
        assert!(verify_approval(&[0x43u8; 32], &[0x07u8; 32], &sig).is_none());
        // Different session id → no signer.
        assert!(verify_approval(&[0x42u8; 32], &[0x08u8; 32], &sig).is_none());
    }

    #[test]
    fn collector_k_allow_approves() {
        let (a, b) = (PrivateKey::random(), PrivateKey::random());
        let vh = [0x42u8; 32];
        let sid = [0x07u8; 32];
        let mut c = ApprovalCollector::new(quorum(2, &[&a, &b]), vh, sid, 10_000);
        let sig_a = sign_approval(&vh, &sid, &a).unwrap();
        let sig_b = sign_approval(&vh, &sid, &b).unwrap();
        // One allow → still pending.
        let st = c.record_vote(&sig_a, ApprovalDecision::Allow, 0).unwrap();
        assert!(matches!(
            st,
            ApprovalStatus::Pending {
                collected: 1,
                total: 2,
                ..
            }
        ));
        assert!(!c.is_approved());
        // Second allow → approved.
        let st = c.record_vote(&sig_b, ApprovalDecision::Allow, 1).unwrap();
        assert_eq!(st, ApprovalStatus::Approved);
        assert!(c.is_approved());
    }

    #[test]
    fn collector_dedups_same_signer() {
        let a = PrivateKey::random();
        let vh = [0x42u8; 32];
        let sid = [0x07u8; 32];
        let mut c = ApprovalCollector::new(quorum(2, &[&a]), vh, sid, 10_000);
        let sig_a = sign_approval(&vh, &sid, &a).unwrap();
        c.record_vote(&sig_a, ApprovalDecision::Allow, 0).unwrap();
        // Same signer again — must NOT count twice toward k=2.
        let st = c.record_vote(&sig_a, ApprovalDecision::Allow, 1).unwrap();
        assert!(matches!(st, ApprovalStatus::Pending { collected: 1, .. }));
    }

    #[test]
    fn collector_rejects_non_eligible_signer() {
        let (eligible, outsider) = (PrivateKey::random(), PrivateKey::random());
        let vh = [0x42u8; 32];
        let sid = [0x07u8; 32];
        let mut c = ApprovalCollector::new(quorum(1, &[&eligible]), vh, sid, 10_000);
        let sig_out = sign_approval(&vh, &sid, &outsider).unwrap();
        let err = c
            .record_vote(&sig_out, ApprovalDecision::Allow, 0)
            .unwrap_err();
        assert!(format!("{err}").contains("not in the quorum"));
    }

    #[test]
    fn collector_k_deny_denies_and_deadline_expires() {
        let (a, b) = (PrivateKey::random(), PrivateKey::random());
        let vh = [0x42u8; 32];
        let sid = [0x07u8; 32];
        // k-deny → Denied.
        let mut c = ApprovalCollector::new(quorum(2, &[&a, &b]), vh, sid, 10_000);
        c.record_vote(
            &sign_approval(&vh, &sid, &a).unwrap(),
            ApprovalDecision::Deny,
            0,
        )
        .unwrap();
        let st = c
            .record_vote(
                &sign_approval(&vh, &sid, &b).unwrap(),
                ApprovalDecision::Deny,
                1,
            )
            .unwrap();
        assert_eq!(st, ApprovalStatus::Denied);
        // deadline → Expired (fresh collector, one allow, past the deadline).
        let mut c2 = ApprovalCollector::new(quorum(2, &[&a, &b]), vh, sid, 5_000);
        c2.record_vote(
            &sign_approval(&vh, &sid, &a).unwrap(),
            ApprovalDecision::Allow,
            0,
        )
        .unwrap();
        assert_eq!(c2.status(6_000), ApprovalStatus::Expired);
    }

    // ── WebAuthn binding (§08.11) ────────────────────────────────────────────

    use base64::Engine;

    /// Build a `clientDataJSON` for `webauthn.get` with `challenge` = base64url of
    /// `view_hash`, and `authenticator_data` with the UV flag set/clear.
    fn webauthn_inputs(view_hash: &[u8; 32], uv: bool) -> (Vec<u8>, Vec<u8>) {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(view_hash);
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://wallet.example"}}"#
        );
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = if uv { 0x05 } else { 0x01 }; // UP always; UV (0x04) iff uv
        (cdj.into_bytes(), auth_data)
    }

    #[test]
    fn webauthn_binding_accepts_matching_challenge_with_uv() {
        let vh = [0x42u8; 32];
        let (cdj, ad) = webauthn_inputs(&vh, true);
        assert!(verify_webauthn_approval(&cdj, &ad, &vh).is_ok());
    }

    #[test]
    fn webauthn_binding_rejects_wrong_challenge() {
        let vh = [0x42u8; 32];
        let (cdj, ad) = webauthn_inputs(&[0x99u8; 32], true); // challenge ≠ vh
        let err = verify_webauthn_approval(&cdj, &ad, &vh).unwrap_err();
        assert!(format!("{err}").contains("request_view_hash"));
    }

    #[test]
    fn webauthn_binding_rejects_missing_user_verification() {
        let vh = [0x42u8; 32];
        let (cdj, ad) = webauthn_inputs(&vh, false); // UV flag clear
        let err = verify_webauthn_approval(&cdj, &ad, &vh).unwrap_err();
        assert!(format!("{err}").contains("userVerification"));
    }

    #[test]
    fn webauthn_binding_rejects_wrong_type() {
        let vh = [0x42u8; 32];
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vh);
        let cdj = format!(r#"{{"type":"webauthn.create","challenge":"{challenge}"}}"#).into_bytes();
        let ad = {
            let mut a = vec![0u8; 37];
            a[32] = 0x05;
            a
        };
        assert!(verify_webauthn_approval(&cdj, &ad, &vh).is_err());
    }
}
