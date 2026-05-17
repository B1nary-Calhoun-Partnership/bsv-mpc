//! CHIP token creation and parsing for MPC node advertisement.
//!
//! **Path A (canonical-compatible).** A CHIP token in this codebase is
//! exactly a canonical 5-field signed SHIP admin token per
//! `@bsv/overlay-discovery-services` (TS reference) and verified against
//! `bsv-overlay-discovery` (Rust port of the TS validator):
//!
//! ```text
//! Field[0] = "SHIP"                                  (4 bytes UTF-8)
//! Field[1] = identity_key.to_compressed()           (33 bytes)
//! Field[2] = domain URI                              (variable UTF-8)
//! Field[3] = topic name "tm_mpc_signing"             (variable UTF-8)
//! Field[4] = ECDSA-DER signature                     (71-73 bytes)
//!            over sha256(concat(fields[0..3])),
//!            signed with BRC-42 child of identity_key
//!            (protocol=[2,"service host interconnect"], keyID="1",
//!             counterparty=Anyone, forSelf=true)
//! locking_key = same BRC-42 child as the signing key
//! ```
//!
//! MPC-specific node capabilities (supported curves, threshold configs,
//! fee_sats, version, etc.) are **NOT** in this token. They're served
//! by each cosigner at `GET https://{domain}/capabilities` and fetched
//! by `discovery.rs` after a SHIP token is validated. This keeps the
//! overlay surface conformant with canonical validators (which check
//! `fields.length === 5` strictly) — see `MPC-Spec/decisions/00XX-chip-token-architecture.md`.
//!
//! **Why not embed capabilities in field[4] or field[5]?**
//! Canonical TS validators (`SHIPTopicManager.ts:30`,
//! `SLAPTopicManager.ts:33`) reject any field count other than 5.
//! Embedding capabilities anywhere in the script makes the token
//! invisible to every overlay running the reference validators. The
//! pre-Path-A `create_chip_token` produced exactly this rejected shape
//! and was the silent reason MPC node discovery never worked on
//! mainnet despite all local tests passing — see the dep-bump unblock
//! commit `f1a567d` for the version skew that hid this and the
//! survey under `feedback_god_tier_full_stack.md` for the full path.

use crate::error::OverlayError;
use crate::types::MPC_TOPIC;
use bsv::overlay::create_signed_overlay_admin_token;
use bsv::overlay::Protocol;
use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv::script::templates::PushDrop;
use bsv::script::LockingScript;
use serde::{Deserialize, Serialize};

/// Identity + domain extracted from a validated CHIP token.
///
/// This is everything the canonical 5-field signed SHIP token actually
/// carries. Full node capabilities (curves, fee_sats, threshold_configs,
/// version, etc.) are NOT in the token; they're fetched by
/// [`crate::discovery`] from `GET https://{domain}/capabilities` and
/// merged with this struct to produce a full [`crate::types::MpcNodeInfo`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChipTokenInfo {
    /// BRC-31 identity public key as hex (33-byte compressed secp256k1).
    pub identity_key: String,

    /// HTTPS domain of the cosigner's Key Share Service. The capabilities
    /// side-channel lives at `https://{domain}/capabilities`.
    pub domain: String,
}

/// Create a CHIP token — canonical 5-field signed SHIP admin token.
///
/// Wraps `bsv::overlay::create_signed_overlay_admin_token` with the
/// MPC topic baked in. Output bytes are byte-exact to `@bsv/sdk 1.10.1`'s
/// `pushdrop.lock(fields, [2, "service host interconnect"], "1", "anyone", true, true, "before")`
/// path — see `~/bsv/bsv-rs/tests/overlay_admin_token_ts_parity_tests.rs`
/// for the byte-locked fixtures.
///
/// # Arguments
///
/// * `identity_priv` — the cosigner's BRC-31 identity private key.
///   Used to BRC-42-derive the locking key AND sign field[4].
/// * `domain` — HTTPS URI of the Key Share Service.
///   Must be non-empty; otherwise `OverlayError::InvalidChipToken`.
///
/// # Errors
///
/// `OverlayError::InvalidChipToken` if `domain` is empty.
pub fn create_chip_token(
    identity_priv: &PrivateKey,
    domain: &str,
) -> Result<Vec<u8>, OverlayError> {
    if domain.is_empty() {
        return Err(OverlayError::InvalidChipToken(
            "domain must not be empty".into(),
        ));
    }

    let script = create_signed_overlay_admin_token(
        identity_priv,
        Protocol::Ship,
        domain,
        MPC_TOPIC,
    );

    Ok(script.to_binary())
}

/// Parse + validate a CHIP token. Strict canonical 5-field signed format.
///
/// Performs three checks in order — any failure returns
/// `OverlayError::InvalidChipToken`:
///
/// 1. PushDrop decodes successfully with exactly 5 fields.
/// 2. Static fields match: field[0] == "SHIP", field[3] == "tm_mpc_signing",
///    field[1] is a valid 33-byte compressed pubkey.
/// 3. **Signature linkage holds**: field[4] is a valid ECDSA-DER signature
///    over sha256(concat(field[0..3])) by the BRC-42 child of the identity
///    in field[1], AND the script's locking key equals that same BRC-42
///    child. Delegated to `bsv_overlay_discovery::validation::is_token_signature_correctly_linked`
///    so we share validation bytes with the canonical Rust + TS validators.
///
/// 4-field tokens (the pre-Path-A legacy format) are rejected — they cannot
/// pass canonical validators and accepting them would mask drift. If you
/// need to inspect a legacy token for diagnostics, decode it manually via
/// `bsv::overlay::decode_overlay_admin_token`.
pub fn parse_chip_token(script_bytes: &[u8]) -> Result<ChipTokenInfo, OverlayError> {
    let script = LockingScript::from_binary(script_bytes)
        .map_err(|e| OverlayError::InvalidChipToken(format!("invalid script: {}", e)))?;

    let pushdrop = PushDrop::decode(&script)
        .map_err(|e| OverlayError::InvalidChipToken(format!("not a valid PushDrop: {}", e)))?;

    let fields = &pushdrop.fields;
    if fields.len() != 5 {
        return Err(OverlayError::InvalidChipToken(format!(
            "canonical signed CHIP token must have exactly 5 fields (got {}); \
             4-field tokens are the pre-Path-A legacy shape and are rejected \
             by mainnet validators",
            fields.len()
        )));
    }

    let protocol_str = std::str::from_utf8(&fields[0])
        .map_err(|_| OverlayError::InvalidChipToken("protocol field is not valid UTF-8".into()))?;
    if protocol_str != "SHIP" {
        return Err(OverlayError::InvalidChipToken(format!(
            "expected protocol SHIP, got {}",
            protocol_str
        )));
    }

    let identity_key_bytes = &fields[1];
    if identity_key_bytes.len() != 33 {
        return Err(OverlayError::InvalidChipToken(format!(
            "identity key must be 33 bytes (got {})",
            identity_key_bytes.len()
        )));
    }
    let identity_pubkey = PublicKey::from_bytes(identity_key_bytes)
        .map_err(|e| OverlayError::InvalidChipToken(format!("invalid identity key: {}", e)))?;

    let domain = std::str::from_utf8(&fields[2])
        .map_err(|_| OverlayError::InvalidChipToken("domain field is not valid UTF-8".into()))?
        .to_string();
    if domain.is_empty() {
        return Err(OverlayError::InvalidChipToken(
            "domain must not be empty".into(),
        ));
    }

    let topic = std::str::from_utf8(&fields[3])
        .map_err(|_| OverlayError::InvalidChipToken("topic field is not valid UTF-8".into()))?;
    if topic != MPC_TOPIC {
        return Err(OverlayError::InvalidChipToken(format!(
            "expected topic {}, got {}",
            MPC_TOPIC, topic
        )));
    }

    // Signature linkage: delegate to canonical Rust port of the TS validator.
    // Returns Ok(true) iff (1) signature over concat(fields[0..3]) is valid for
    // the BRC-42 child of identity field, AND (2) the script's locking pubkey
    // equals that same BRC-42 child.
    let linkage_ok = bsv_overlay_discovery::validation::is_token_signature_correctly_linked(
        &pushdrop.locking_public_key,
        identity_key_bytes,
        fields,
        "SHIP",
    )
    .map_err(|e| OverlayError::InvalidChipToken(format!("signature linkage check failed: {}", e)))?;

    if !linkage_ok {
        return Err(OverlayError::InvalidChipToken(
            "signature does not link to identity key per canonical BRC-42 validator \
             (either field[4] sig doesn't verify, or locking key isn't the BRC-42 child)"
                .into(),
        ));
    }

    Ok(ChipTokenInfo {
        identity_key: identity_pubkey.to_hex(),
        domain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // Deprecated import is intentional: one negative test below crafts a
    // 4-field legacy token via this function to prove parse_chip_token
    // REJECTS that exact shape.
    #[allow(deprecated)]
    use bsv::overlay::create_overlay_admin_token;

    /// A deterministic test private key — same shape used by bsv-rs's parity
    /// tests so we can cross-reference behavior if drift ever appears.
    fn test_priv_key(seed_byte: u8) -> PrivateKey {
        let mut bytes = [0u8; 32];
        bytes[31] = seed_byte;
        // 0x01 is a valid scalar; using small-byte seeds for determinism.
        PrivateKey::from_bytes(&bytes).expect("valid test private key")
    }

    // ── create_chip_token ──────────────────────────────────────────────────

    #[test]
    fn create_chip_token_produces_canonical_5_field_token() {
        let key = test_priv_key(0x01);
        let bytes = create_chip_token(&key, "https://mpc.example.com").unwrap();
        let script = LockingScript::from_binary(&bytes).unwrap();
        let pushdrop = PushDrop::decode(&script).unwrap();

        assert_eq!(
            pushdrop.fields.len(),
            5,
            "CHIP token MUST have exactly 5 fields to be admitted by canonical validators"
        );
        assert_eq!(&pushdrop.fields[0], b"SHIP");
        assert_eq!(pushdrop.fields[1].len(), 33, "identity_key must be 33-byte compressed pubkey");
        assert_eq!(&pushdrop.fields[1][..], &key.public_key().to_compressed()[..]);
        assert_eq!(&pushdrop.fields[2], b"https://mpc.example.com");
        assert_eq!(&pushdrop.fields[3], MPC_TOPIC.as_bytes());
        assert!(
            pushdrop.fields[4].len() >= 70 && pushdrop.fields[4].len() <= 73,
            "field[4] must be DER ECDSA signature (~71-73 bytes); got {}",
            pushdrop.fields[4].len()
        );
    }

    #[test]
    fn create_chip_token_byte_matches_bsv_rs_create_signed_overlay_admin_token() {
        // We delegate to bsv::overlay::create_signed_overlay_admin_token, so
        // the bytes MUST be byte-identical. This guards against accidental
        // wrapper drift (e.g. a future maintainer adding a side effect).
        let key = test_priv_key(0x02);
        let domain = "https://mpc-eu-1.example.com";

        let ours = create_chip_token(&key, domain).unwrap();
        let theirs = create_signed_overlay_admin_token(
            &key,
            Protocol::Ship,
            domain,
            MPC_TOPIC,
        )
        .to_binary();

        assert_eq!(ours, theirs, "create_chip_token must be byte-identical to bsv-rs::create_signed_overlay_admin_token for the same inputs");
    }

    #[test]
    fn create_chip_token_is_deterministic() {
        // bsv-rs uses RFC 6979 deterministic ECDSA — same inputs MUST produce
        // byte-identical output. If this ever flips to fresh randomness, byte
        // comparisons across runs (and against TS parity fixtures) break.
        let key = test_priv_key(0x03);
        let a = create_chip_token(&key, "https://x.example.com").unwrap();
        let b = create_chip_token(&key, "https://x.example.com").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn create_chip_token_rejects_empty_domain() {
        let key = test_priv_key(0x04);
        let err = create_chip_token(&key, "").unwrap_err();
        assert!(err.to_string().contains("domain must not be empty"));
    }

    // ── parse_chip_token: positive cases ───────────────────────────────────

    #[test]
    fn create_and_parse_roundtrip() {
        let key = test_priv_key(0x05);
        let domain = "https://mpc-us-1.example.com";
        let bytes = create_chip_token(&key, domain).unwrap();
        let parsed = parse_chip_token(&bytes).unwrap();

        assert_eq!(parsed.identity_key, key.public_key().to_hex());
        assert_eq!(parsed.domain, domain);
    }

    #[test]
    fn parse_chip_token_returns_only_identity_and_domain() {
        // ChipTokenInfo is intentionally minimal — the token only carries
        // identity + domain. Capabilities (curves, fees, etc.) live behind
        // the /capabilities side-channel per Path A.
        let key = test_priv_key(0x06);
        let bytes = create_chip_token(&key, "https://node.example.com").unwrap();
        let parsed = parse_chip_token(&bytes).unwrap();

        // Confirm shape: only these two fields, no Capability defaults
        // sneaking back in.
        let _: ChipTokenInfo = ChipTokenInfo {
            identity_key: parsed.identity_key.clone(),
            domain: parsed.domain.clone(),
        };
    }

    // ── parse_chip_token: negative cases (each must REJECT) ────────────────

    #[test]
    fn parse_rejects_garbage_bytes() {
        let err = parse_chip_token(&[0x01, 0x02, 0x03]).unwrap_err();
        assert!(err.to_string().contains("invalid script") || err.to_string().contains("PushDrop"));
    }

    #[test]
    fn parse_rejects_4_field_legacy_token() {
        // The deprecated `create_overlay_admin_token` produces 4-field
        // identity-key-locked tokens — exactly the shape canonical mainnet
        // validators silently reject. Our parser MUST also reject so we
        // don't silently admit something the network won't admit.
        let key = test_priv_key(0x07);
        #[allow(deprecated)]
        let script = create_overlay_admin_token(
            Protocol::Ship,
            &key.public_key(),
            "https://legacy.example.com",
            MPC_TOPIC,
        );

        let err = parse_chip_token(&script.to_binary()).unwrap_err();
        assert!(
            err.to_string().contains("exactly 5 fields"),
            "expected 5-field error, got: {}",
            err
        );
    }

    #[test]
    fn parse_rejects_wrong_protocol_slap() {
        // A SLAP token has the same 5-field shape but field[0] = "SLAP".
        // Must reject — SLAP tokens advertise lookup services, not signing.
        let key = test_priv_key(0x08);
        let script = create_signed_overlay_admin_token(
            &key,
            Protocol::Slap,
            "https://slap.example.com",
            "ls_mpc_signing",
        );

        let err = parse_chip_token(&script.to_binary()).unwrap_err();
        assert!(err.to_string().contains("expected protocol SHIP"), "got: {}", err);
    }

    #[test]
    fn parse_rejects_wrong_topic() {
        let key = test_priv_key(0x09);
        let script = create_signed_overlay_admin_token(
            &key,
            Protocol::Ship,
            "https://x.example.com",
            "tm_other_topic",
        );

        let err = parse_chip_token(&script.to_binary()).unwrap_err();
        assert!(err.to_string().contains("expected topic tm_mpc_signing"), "got: {}", err);
    }

    #[test]
    fn parse_rejects_tampered_signature() {
        // Flip a byte inside the signature field. The signature linkage
        // check MUST detect this.
        let key = test_priv_key(0x0a);
        let mut bytes = create_chip_token(&key, "https://tamper.example.com").unwrap();

        // Find the script's locking pubkey + signature region by re-decoding.
        let script = LockingScript::from_binary(&bytes).unwrap();
        let pushdrop = PushDrop::decode(&script).unwrap();
        let sig = &pushdrop.fields[4];
        let sig_bit = sig[sig.len() - 1];

        // The DER signature lives somewhere near the tail of the script
        // bytes. Find and flip its last byte in the serialized bytes.
        let pos = bytes
            .windows(sig.len())
            .position(|w| w == &sig[..])
            .expect("signature bytes must appear in serialized script");
        bytes[pos + sig.len() - 1] ^= 0x01;
        assert_ne!(bytes[pos + sig.len() - 1], sig_bit, "tamper must change a byte");

        let err = parse_chip_token(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("signature") || err.to_string().contains("PushDrop"),
            "expected signature-linkage rejection, got: {}",
            err
        );
    }

    #[test]
    fn parse_rejects_5_field_token_with_wrong_locking_key() {
        // Build a hand-crafted token: 5 fields, valid signature shape,
        // but lock with identity_key directly (the pre-Path-A pattern)
        // instead of the BRC-42 child. Canonical validator MUST detect
        // the locking-key mismatch.
        let key = test_priv_key(0x0b);
        let pubkey = key.public_key();
        let domain = "https://wrong-lock.example.com";

        // Borrow a valid signature from a real signed token so field[4]
        // shape is plausible — the validator's locking-key check should
        // still fail.
        let real = create_signed_overlay_admin_token(&key, Protocol::Ship, domain, MPC_TOPIC);
        let real_decoded = PushDrop::decode(&real).unwrap();
        let real_sig = real_decoded.fields[4].clone();

        let fields = vec![
            b"SHIP".to_vec(),
            pubkey.to_compressed().to_vec(),
            domain.as_bytes().to_vec(),
            MPC_TOPIC.as_bytes().to_vec(),
            real_sig,
        ];
        // Lock with identity_key directly (WRONG — canonical wants BRC-42 child)
        let pushdrop = PushDrop::new(pubkey, fields);
        let script = pushdrop.lock();

        let err = parse_chip_token(&script.to_binary()).unwrap_err();
        assert!(
            err.to_string().contains("signature does not link") || err.to_string().contains("signature"),
            "expected linkage rejection (locking-key mismatch), got: {}",
            err
        );
    }

    #[test]
    fn parse_rejects_wrong_identity_key_length() {
        // Hand-craft a 5-field token where field[1] is not 33 bytes.
        // Should be caught before we even reach signature validation.
        let key = test_priv_key(0x0c);
        let pubkey = key.public_key();
        let fields = vec![
            b"SHIP".to_vec(),
            vec![0u8; 32], // 32 bytes — too short for compressed pubkey
            b"https://x.example.com".to_vec(),
            MPC_TOPIC.as_bytes().to_vec(),
            vec![0u8; 71], // placeholder
        ];
        let pushdrop = PushDrop::new(pubkey, fields);
        let script = pushdrop.lock();

        let err = parse_chip_token(&script.to_binary()).unwrap_err();
        assert!(err.to_string().contains("identity key must be 33 bytes"), "got: {}", err);
    }
}
