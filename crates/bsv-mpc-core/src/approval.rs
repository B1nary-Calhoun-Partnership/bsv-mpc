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
}
