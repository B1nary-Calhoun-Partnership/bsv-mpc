//! BRC-42 key derivation for MPC shares.
//!
//! BSV wallets use BRC-42 key derivation (not BIP-32). BRC-42 derives child keys
//! using ECDH shared secrets and invoice numbers:
//!
//! ```text
//! shared_secret = ECDH(counterparty_pub, root_priv)
//! hmac = HMAC-SHA256(key=compressed(shared_secret), data=invoice_bytes)
//! child_pub = root_pub + G * hmac
//! child_priv = root_priv + hmac   (scalar addition mod n)
//! ```
//!
//! Invoice format: `"{security_level}-{protocol_name}-{key_id}"`
//!
//! ## Counterparty Types (proven in POC 3)
//!
//! | Counterparty | Shared Secret          | MPC Round-Trips |
//! |-------------|------------------------|-----------------|
//! | Anyone      | = root_pubkey          | 0 (local)       |
//! | Self_       | ECDH(root_pub, root_priv) | 1 (partial ECDH) |
//! | Other(key)  | ECDH(other_pub, root_priv) | 1 (partial ECDH) |
//!
//! For "Anyone", the counterparty private key is scalar 1, so:
//!   `ECDH(anyone_pub, root_priv) = G * root_priv = root_pubkey`
//!
//! For "Self_" and "Other", the proxy needs MPC cooperation (partial ECDH
//! with Lagrange interpolation) to compute the shared secret without
//! reconstructing the private key. See POC 3 and POC 8.
//!
//! ## BRC-42 Spec
//!
//! Full specification: ~/bsv/BRCs/key-derivation/0042.md
//! BSV SDK implementation: `bsv::wallet::KeyDeriver`

use crate::error::{MpcError, Result};
use crate::types::JointPublicKey;

use bsv::primitives::ec::PublicKey;
use bsv::primitives::hash::sha256_hmac;
use bsv::Address;

/// Derive a BRC-42 child public key from a shared secret and invoice number.
///
/// This is the core BRC-42 derivation math:
///   `child_pub = root_pub + G * HMAC-SHA256(compressed(shared_secret), invoice)`
///
/// The shared secret depends on the counterparty type:
/// - Anyone: `shared_secret = root_pubkey` (no private key needed)
/// - Self_: `shared_secret = ECDH(root_pub, root_priv)` (needs partial ECDH via MPC)
/// - Other(key): `shared_secret = ECDH(other_pub, root_priv)` (needs partial ECDH via MPC)
///
/// Proven in POC 3 (`derive_child_pubkey_manual`), POC 8, and POC 9.
///
/// # Arguments
///
/// * `root_pub` - The joint MPC public key (33 bytes compressed).
/// * `shared_secret` - The ECDH shared secret as a compressed public key (33 bytes).
/// * `invoice_number` - The BRC-42 invoice string, e.g. `"2-worm memory-block-42"`.
///
/// # Returns
///
/// The derived child public key.
pub fn derive_child_pubkey(
    root_pub: &PublicKey,
    shared_secret: &PublicKey,
    invoice_number: &str,
) -> Result<PublicKey> {
    // HMAC-SHA256(key=compressed(shared_secret), data=invoice_bytes)
    let hmac = sha256_hmac(&shared_secret.to_compressed(), invoice_number.as_bytes());

    // G * hmac — compute the offset point
    let offset_pub = PublicKey::from_scalar_mul_generator(&hmac)
        .map_err(|e| MpcError::Protocol(format!("BRC-42: failed to compute G * hmac: {}", e)))?;

    // child_pub = root_pub + offset_pub (point addition)
    let child_pub = root_pub
        .add(&offset_pub)
        .map_err(|e| MpcError::Protocol(format!("BRC-42: point addition failed: {}", e)))?;

    Ok(child_pub)
}

/// Compute the BRC-42 HMAC scalar (the "tweak") for share offset addition.
///
/// In MPC, each party adds this scalar to their private key share locally:
///   `child_share_i = share_i + hmac`
///
/// This is the additive share offset property proven in POC 8.
///
/// # Arguments
///
/// * `shared_secret` - The ECDH shared secret (33 bytes compressed pubkey).
/// * `invoice_number` - The BRC-42 invoice string.
///
/// # Returns
///
/// The 32-byte HMAC scalar that each MPC party adds to their share.
pub fn compute_brc42_hmac(shared_secret: &PublicKey, invoice_number: &str) -> [u8; 32] {
    sha256_hmac(&shared_secret.to_compressed(), invoice_number.as_bytes())
}

/// Build a BRC-42 invoice number string in canonical form.
///
/// Per BRC-42 §03.9 (and the cross-impl conformance gate at
/// `MPC-Spec/conformance/test-vectors/03-brc42-invoice.json`), the invoice
/// MUST be built from a CANONICALIZED protocol name and a VALIDATED key id —
/// otherwise two implementations given inputs differing only in case or
/// whitespace will derive DIFFERENT keys for what should be the same logical
/// derivation. Pre-2026-05-17 this function was a raw `format!` that skipped
/// validation entirely; every downstream caller was silently emitting
/// non-canonical invoices.
///
/// This function delegates to `bsv::wallet::types::validate_protocol_name` and
/// `bsv::wallet::types::validate_key_id` — the same canonical path that
/// `bsv-rs::wallet::KeyDeriver::compute_invoice_number` and every conformant
/// BSV SDK use. Output is byte-identical to those paths for any input they
/// accept. This is the cross-impl wire-compat floor for BRC-42 derivation
/// across the partnership.
///
/// Format: `"{security_level}-{canonical_protocol_name}-{key_id}"` where
/// `canonical_protocol_name = protocol_name.trim().to_lowercase()` with
/// format validation (5-400 chars, lowercase + digits + spaces only, no
/// consecutive spaces, no trailing " protocol").
///
/// Security levels (from BRC-42):
/// - 0 = No security
/// - 1 = App-level
/// - 2 = Counterparty-level (most common — used by bsv-worm)
///
/// Examples (post-canonicalization):
/// - `compute_invoice(2, "worm memory", "block-42")?` → `"2-worm memory-block-42"`
/// - `compute_invoice(2, "  WORM Memory  ", "block-42")?` → `"2-worm memory-block-42"` (canonicalized)
/// - `compute_invoice(2, "auth message signature", "request-nonce-abc123")?`
///   → `"2-auth message signature-request-nonce-abc123"`
///
/// # Errors
///
/// `MpcError::Protocol` if `security_level > 2`, `protocol_name` fails
/// `validate_protocol_name`, or `key_id` fails `validate_key_id`. The
/// error message includes the underlying bsv-rs validation detail.
///
/// Resolves [`MPC-Spec` issue #1] / [ADR-0002] (canonical BRC-42 invoice).
pub fn compute_invoice(security_level: u8, protocol_name: &str, key_id: &str) -> Result<String> {
    if security_level > 2 {
        return Err(MpcError::Protocol(format!(
            "BRC-42: security_level must be 0, 1, or 2 (got {})",
            security_level
        )));
    }
    bsv::wallet::types::validate_key_id(key_id)
        .map_err(|e| MpcError::Protocol(format!("BRC-42: invalid key_id: {}", e)))?;
    let canonical_name = bsv::wallet::types::validate_protocol_name(protocol_name)
        .map_err(|e| MpcError::Protocol(format!("BRC-42: invalid protocol_name: {}", e)))?;
    Ok(format!("{}-{}-{}", security_level, canonical_name, key_id))
}

/// Derive a child public key for the "Anyone" counterparty (0 MPC round-trips).
///
/// For "Anyone", the counterparty private key is scalar 1 (the "anyone key"),
/// so `ECDH(anyone_pub, root_priv) = G * root_priv = root_pubkey`.
/// The shared secret IS the root public key — no private key or MPC needed.
///
/// This is proven in POC 3, Test 1 (`test_anyone_counterparty_local_derivation`).
///
/// # Arguments
///
/// * `root_pub` - The joint MPC public key.
/// * `protocol_name` - BRC-42 protocol name (e.g., "worm memory").
/// * `key_id` - BRC-42 key ID (e.g., "block-42").
/// * `security_level` - BRC-42 security level (usually 2 for counterparty-level).
pub fn derive_anyone_pubkey(
    root_pub: &PublicKey,
    protocol_name: &str,
    key_id: &str,
    security_level: u8,
) -> Result<PublicKey> {
    // For "anyone": shared_secret = root_pubkey
    let invoice = compute_invoice(security_level, protocol_name, key_id)?;
    derive_child_pubkey(root_pub, root_pub, &invoice)
}

/// Derive a child JointPublicKey for the "Anyone" counterparty.
///
/// Convenience wrapper that returns a full `JointPublicKey` with BSV address.
pub fn derive_anyone_joint_key(
    joint_key: &JointPublicKey,
    protocol_name: &str,
    key_id: &str,
    security_level: u8,
) -> Result<JointPublicKey> {
    let root_pub = PublicKey::from_bytes(&joint_key.compressed)
        .map_err(|e| MpcError::InvalidShare(format!("invalid joint public key: {}", e)))?;

    let child_pub = derive_anyone_pubkey(&root_pub, protocol_name, key_id, security_level)?;
    pubkey_to_joint_key(&child_pub)
}

/// Derive a child JointPublicKey given a pre-computed shared secret.
///
/// Used after MPC partial ECDH has produced the shared secret for
/// Self_ or Other(key) counterparty types.
pub fn derive_joint_key_with_secret(
    joint_key: &JointPublicKey,
    shared_secret: &PublicKey,
    protocol_name: &str,
    key_id: &str,
    security_level: u8,
) -> Result<JointPublicKey> {
    let root_pub = PublicKey::from_bytes(&joint_key.compressed)
        .map_err(|e| MpcError::InvalidShare(format!("invalid joint public key: {}", e)))?;

    let invoice = compute_invoice(security_level, protocol_name, key_id)?;
    let child_pub = derive_child_pubkey(&root_pub, shared_secret, &invoice)?;
    pubkey_to_joint_key(&child_pub)
}

/// Convert a PublicKey to a JointPublicKey with BSV address.
fn pubkey_to_joint_key(pubkey: &PublicKey) -> Result<JointPublicKey> {
    let compressed = pubkey.to_compressed().to_vec();
    let address = Address::new_from_public_key(pubkey, true)
        .map_err(|e| MpcError::InvalidShare(format!("failed to derive BSV address: {}", e)))?
        .to_string();
    Ok(JointPublicKey {
        compressed,
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::primitives::ec::PrivateKey;

    /// Known test key (same as POC 3 for consistency).
    fn test_root_key() -> (PrivateKey, PublicKey) {
        let privkey = PrivateKey::from_bytes(&[
            0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1,
            0xe2, 0xf3, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
            0xd0, 0xe1, 0xf2, 0x03,
        ])
        .expect("valid test private key");
        let pubkey = privkey.public_key();
        (privkey, pubkey)
    }

    fn test_joint_key() -> JointPublicKey {
        let (_, pubkey) = test_root_key();
        pubkey_to_joint_key(&pubkey).unwrap()
    }

    // -------------------------------------------------------------------
    // compute_invoice tests
    // -------------------------------------------------------------------

    #[test]
    fn test_invoice_format() {
        assert_eq!(
            compute_invoice(2, "worm memory", "block-42").unwrap(),
            "2-worm memory-block-42"
        );
    }

    // ── BRC-42 invoice canonicalization regression (M1 spec #1) ────────────
    //
    // Pre-fix `compute_invoice` was `format!("{}-{}-{}", ...)` with zero
    // input validation — uppercase, leading/trailing whitespace, double
    // spaces, and ` protocol` suffixes all passed through verbatim. The
    // canonical BRC-42 path (`bsv::wallet::types::validate_protocol_name`,
    // exercised by `bsv-rs::wallet::KeyDeriver::compute_invoice_number` and
    // every conformant SDK) applies `.trim().to_lowercase()` + format
    // validation BEFORE the format!. The pre-fix bug meant bsv-mpc derived
    // DIFFERENT keys than every other conformant SDK for inputs differing
    // only in case or whitespace — silent cross-impl drift, exactly the
    // class the partnership conformance gate is supposed to catch.
    //
    // These tests are the gate. They FAIL on pre-fix code; they PASS after
    // routing through `bsv::wallet::types::validate_protocol_name` and
    // `validate_key_id`. Both invariants — canonicalization AND rejection —
    // are asserted.

    #[test]
    fn compute_invoice_canonicalizes_uppercase_protocol_name() {
        // Pre-fix: returns "2-WORM MEMORY-block-42"
        // Post-fix: returns "2-worm memory-block-42" (matches bsv-rs canonical)
        assert_eq!(
            compute_invoice(2, "WORM MEMORY", "block-42").unwrap(),
            "2-worm memory-block-42",
            "BRC-42 §03.9: protocol_name MUST be lowercased before invoice format"
        );
    }

    #[test]
    fn compute_invoice_trims_protocol_name_whitespace() {
        assert_eq!(
            compute_invoice(2, "  worm memory  ", "block-42").unwrap(),
            "2-worm memory-block-42",
            "BRC-42 §03.9: protocol_name MUST be trimmed before invoice format"
        );
    }

    #[test]
    fn compute_invoice_canonicalizes_uppercase_and_whitespace_together() {
        assert_eq!(
            compute_invoice(2, "  WORM Memory  ", "block-42").unwrap(),
            "2-worm memory-block-42"
        );
    }

    #[test]
    fn compute_invoice_rejects_protocol_name_with_double_space() {
        // validate_protocol_name rejects this — bsv-rs canonical behavior.
        let err = compute_invoice(2, "worm  memory", "block-42").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("consecutive spaces") || msg.contains("protocol_name"),
            "expected double-space rejection, got: {msg}"
        );
    }

    #[test]
    fn compute_invoice_rejects_protocol_name_too_short() {
        // validate_protocol_name minimum: 5 chars.
        let err = compute_invoice(2, "wm", "block-42").unwrap_err();
        assert!(
            err.to_string().contains("5 characters") || err.to_string().contains("protocol_name"),
            "expected min-length rejection, got: {err}"
        );
    }

    #[test]
    fn compute_invoice_rejects_protocol_name_with_hyphen() {
        // validate_protocol_name: only lowercase + digits + spaces.
        let err = compute_invoice(2, "worm-memory", "block-42").unwrap_err();
        assert!(
            err.to_string().contains("lowercase letters")
                || err.to_string().contains("protocol_name"),
            "expected invalid-char rejection, got: {err}"
        );
    }

    #[test]
    fn compute_invoice_rejects_empty_key_id() {
        // validate_key_id minimum: 1 char.
        let err = compute_invoice(2, "worm memory", "").unwrap_err();
        assert!(
            err.to_string().contains("at least 1 character") || err.to_string().contains("key_id"),
            "expected empty-key_id rejection, got: {err}"
        );
    }

    #[test]
    fn compute_invoice_rejects_security_level_above_2() {
        let err = compute_invoice(3, "worm memory", "block-42").unwrap_err();
        assert!(
            err.to_string().contains("security_level"),
            "expected security-level rejection, got: {err}"
        );
    }

    #[test]
    fn compute_invoice_matches_bsv_rs_canonical_path() {
        // The canonical invoice format is what bsv-rs's KeyDeriver computes
        // internally. Our compute_invoice MUST produce byte-identical output
        // for any input that bsv-rs's path accepts. This locks cross-impl
        // wire-compat for BRC-42 derivation across the partnership.
        use bsv::wallet::types::{validate_key_id, validate_protocol_name};

        let cases = [
            (2u8, "worm memory", "block-42"),
            (2, "auth message signature", "request-nonce-abc123"),
            (2, "3241645161d8", "test-prefix test-suffix"),
            (0, "proto", "key"),
            (1, "proto", "key"),
        ];

        for (level, proto, key) in cases {
            // bsv-rs canonical path (what KeyDeriver::compute_invoice_number does)
            let canonical_proto = validate_protocol_name(proto).unwrap();
            validate_key_id(key).unwrap();
            let canonical_invoice = format!("{}-{}-{}", level, canonical_proto, key);

            let ours = compute_invoice(level, proto, key).unwrap();
            assert_eq!(
                ours, canonical_invoice,
                "bsv-mpc::compute_invoice MUST be byte-identical to the bsv-rs canonical \
                 path for input ({level}, {proto:?}, {key:?})"
            );
        }
    }

    #[test]
    fn test_invoice_auth_protocol() {
        assert_eq!(
            compute_invoice(2, "auth message signature", "request-nonce-abc123").unwrap(),
            "2-auth message signature-request-nonce-abc123"
        );
    }

    #[test]
    fn test_invoice_different_security_levels() {
        let inv0 = compute_invoice(0, "proto", "key").unwrap();
        let inv1 = compute_invoice(1, "proto", "key").unwrap();
        let inv2 = compute_invoice(2, "proto", "key").unwrap();
        assert_ne!(inv0, inv1);
        assert_ne!(inv1, inv2);
        assert_eq!(inv0, "0-proto-key");
    }

    // -------------------------------------------------------------------
    // compute_brc42_hmac tests
    // -------------------------------------------------------------------

    #[test]
    fn test_hmac_deterministic() {
        let (_, pubkey) = test_root_key();
        let h1 = compute_brc42_hmac(&pubkey, "2-test-key1");
        let h2 = compute_brc42_hmac(&pubkey, "2-test-key1");
        assert_eq!(h1, h2, "same inputs must produce same HMAC");
    }

    #[test]
    fn test_hmac_different_invoices() {
        let (_, pubkey) = test_root_key();
        let h1 = compute_brc42_hmac(&pubkey, "2-test-key1");
        let h2 = compute_brc42_hmac(&pubkey, "2-test-key2");
        assert_ne!(h1, h2, "different invoices must produce different HMACs");
    }

    #[test]
    fn test_hmac_different_secrets() {
        let (_, pubkey) = test_root_key();
        let other_priv = PrivateKey::from_bytes(&[0xaa; 32]).expect("valid key");
        let other_pub = other_priv.public_key();
        let h1 = compute_brc42_hmac(&pubkey, "2-test-key1");
        let h2 = compute_brc42_hmac(&other_pub, "2-test-key1");
        assert_ne!(
            h1, h2,
            "different shared secrets must produce different HMACs"
        );
    }

    // -------------------------------------------------------------------
    // derive_child_pubkey tests
    // -------------------------------------------------------------------

    #[test]
    fn test_derive_child_produces_different_key() {
        let (_, pubkey) = test_root_key();
        let child = derive_child_pubkey(&pubkey, &pubkey, "2-test-key1").unwrap();
        assert_ne!(
            pubkey.to_compressed(),
            child.to_compressed(),
            "child must differ from parent"
        );
    }

    #[test]
    fn test_derive_child_deterministic() {
        let (_, pubkey) = test_root_key();
        let c1 = derive_child_pubkey(&pubkey, &pubkey, "2-test-key1").unwrap();
        let c2 = derive_child_pubkey(&pubkey, &pubkey, "2-test-key1").unwrap();
        assert_eq!(
            c1.to_compressed(),
            c2.to_compressed(),
            "same inputs must produce same child"
        );
    }

    #[test]
    fn test_derive_child_different_invoices_differ() {
        let (_, pubkey) = test_root_key();
        let c1 = derive_child_pubkey(&pubkey, &pubkey, "2-test-key1").unwrap();
        let c2 = derive_child_pubkey(&pubkey, &pubkey, "2-test-key2").unwrap();
        assert_ne!(
            c1.to_compressed(),
            c2.to_compressed(),
            "different invoices must produce different children"
        );
    }

    #[test]
    fn test_derive_child_is_valid_pubkey() {
        let (_, pubkey) = test_root_key();
        let child = derive_child_pubkey(&pubkey, &pubkey, "2-test-key1").unwrap();
        // If it's a valid compressed pubkey, prefix must be 0x02 or 0x03
        let compressed = child.to_compressed();
        assert!(
            compressed[0] == 0x02 || compressed[0] == 0x03,
            "derived key must be valid compressed secp256k1 point"
        );
        assert_eq!(compressed.len(), 33);
    }

    // -------------------------------------------------------------------
    // derive_anyone — POC 3 Test 1 pattern
    // -------------------------------------------------------------------

    #[test]
    fn test_anyone_matches_bsv_sdk_key_deriver() {
        // This replicates POC 3 Test 1: "Anyone" counterparty local derivation.
        // The MPC proxy can derive this WITHOUT any private key.
        use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

        let (root_priv, root_pub) = test_root_key();

        // BSV SDK derivation (the "normal wallet" path)
        let deriver = KeyDeriver::new(Some(root_priv));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");
        let key_id = "test-prefix test-suffix";
        let wallet_derived = deriver
            .derive_public_key(&protocol, key_id, &Counterparty::Anyone, true)
            .expect("wallet derivation should work");

        // Our BRC-42 derivation (MPC proxy path — no private key!)
        let mpc_derived = derive_anyone_pubkey(&root_pub, "3241645161d8", key_id, 2).unwrap();

        assert_eq!(
            wallet_derived.to_compressed(),
            mpc_derived.to_compressed(),
            "MPC BRC-42 derivation must match BSV SDK KeyDeriver for Anyone"
        );
    }

    #[test]
    fn test_anyone_joint_key_has_address() {
        let jk = test_joint_key();
        let child = derive_anyone_joint_key(&jk, "worm memory", "block-42", 2).unwrap();
        assert!(!child.address.is_empty());
        assert_ne!(jk.address, child.address);
    }

    // -------------------------------------------------------------------
    // Self_ / Other — shared secret path (POC 3 Tests 2-5)
    // -------------------------------------------------------------------

    #[test]
    fn test_self_counterparty_with_known_secret() {
        // POC 3 Test 2: Self_ counterparty needs ECDH.
        // Here we simulate having already computed the shared secret.
        use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

        let (root_priv, root_pub) = test_root_key();

        // Normal wallet derivation
        let deriver = KeyDeriver::new(Some(root_priv.clone()));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");
        let key_id = "test-prefix test-suffix";
        let wallet_derived = deriver
            .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
            .expect("wallet derivation");

        // Compute the shared secret (in production, this comes from MPC partial ECDH)
        let shared_secret = root_priv
            .derive_shared_secret(&root_pub)
            .expect("ECDH self");

        // Our BRC-42 derivation with the pre-computed shared secret
        let invoice = compute_invoice(2, "3241645161d8", key_id).unwrap();
        let mpc_derived = derive_child_pubkey(&root_pub, &shared_secret, &invoice).unwrap();

        assert_eq!(
            wallet_derived.to_compressed(),
            mpc_derived.to_compressed(),
            "MPC BRC-42 derivation must match BSV SDK for Self_ when given correct shared secret"
        );
    }

    #[test]
    fn test_other_counterparty_with_known_secret() {
        // POC 3 Test 3: Other(server_pub) counterparty.
        use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

        let (root_priv, root_pub) = test_root_key();
        let server_priv = PrivateKey::from_bytes(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0x00, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x13,
            0x57, 0x9b, 0xdf, 0x02,
        ])
        .expect("valid server key");
        let server_pub = server_priv.public_key();

        // Normal wallet derivation
        let deriver = KeyDeriver::new(Some(root_priv.clone()));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");
        let key_id = "test-prefix test-suffix";
        let wallet_derived = deriver
            .derive_public_key(
                &protocol,
                key_id,
                &Counterparty::Other(server_pub.clone()),
                true,
            )
            .expect("wallet derivation");

        // Compute shared secret (in production, this comes from MPC partial ECDH)
        let shared_secret = root_priv
            .derive_shared_secret(&server_pub)
            .expect("ECDH other");

        // Our BRC-42 derivation
        let invoice = compute_invoice(2, "3241645161d8", key_id).unwrap();
        let mpc_derived = derive_child_pubkey(&root_pub, &shared_secret, &invoice).unwrap();

        assert_eq!(
            wallet_derived.to_compressed(),
            mpc_derived.to_compressed(),
            "MPC BRC-42 derivation must match BSV SDK for Other counterparty"
        );
    }

    #[test]
    fn test_worm_memory_protocol_self() {
        // POC 3 Test 4: worm memory protocol [2, "worm memory"] with Self_ counterparty
        use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

        let (root_priv, root_pub) = test_root_key();

        let deriver = KeyDeriver::new(Some(root_priv.clone()));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "worm memory");
        let key_id = "memory-block-42";
        let wallet_derived = deriver
            .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
            .expect("wallet derivation");

        let shared_secret = root_priv.derive_shared_secret(&root_pub).expect("ECDH");
        let invoice = compute_invoice(2, "worm memory", key_id).unwrap();
        let mpc_derived = derive_child_pubkey(&root_pub, &shared_secret, &invoice).unwrap();

        assert_eq!(
            wallet_derived.to_compressed(),
            mpc_derived.to_compressed(),
            "worm memory protocol must match"
        );
    }

    #[test]
    fn test_auth_message_signature_protocol() {
        // POC 3 Test 5: auth message signature with Other counterparty
        use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

        let (root_priv, root_pub) = test_root_key();
        let server_priv = PrivateKey::from_bytes(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0x00, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x13,
            0x57, 0x9b, 0xdf, 0x02,
        ])
        .expect("valid server key");
        let server_pub = server_priv.public_key();

        let deriver = KeyDeriver::new(Some(root_priv.clone()));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "auth message signature");
        let key_id = "request-nonce-abc123";
        let wallet_derived = deriver
            .derive_public_key(
                &protocol,
                key_id,
                &Counterparty::Other(server_pub.clone()),
                true,
            )
            .expect("wallet derivation");

        let shared_secret = root_priv.derive_shared_secret(&server_pub).expect("ECDH");
        let invoice = compute_invoice(2, "auth message signature", key_id).unwrap();
        let mpc_derived = derive_child_pubkey(&root_pub, &shared_secret, &invoice).unwrap();

        assert_eq!(
            wallet_derived.to_compressed(),
            mpc_derived.to_compressed(),
            "auth message signature must match"
        );
    }

    // -------------------------------------------------------------------
    // BRC-42 spec test vector (from POC 3 Test 6)
    // -------------------------------------------------------------------

    #[test]
    fn test_brc42_spec_vector_1() {
        // From BRC-42 specification test vectors.
        let sender_priv = PrivateKey::from_hex(
            "583755110a8c059de5cd81b8a04e1be884c46083ade3f779c1e022f6f89da94c",
        )
        .expect("valid sender key");
        let recipient_pub = PublicKey::from_hex(
            "02c0c1e1a1f7d247827d1bcf399f0ef2deef7695c322fd91a01a91378f101b6ffc",
        )
        .expect("valid recipient pubkey");
        let invoice_number = "IBioA4D/OaE=";
        let expected = PublicKey::from_hex(
            "03c1bf5baadee39721ae8c9882b3cf324f0bf3b9eb3fc1b8af8089ca7a7c2e669f",
        )
        .expect("valid expected pubkey");

        // Compute shared secret (sender_priv * recipient_pub)
        let shared_secret = sender_priv
            .derive_shared_secret(&recipient_pub)
            .expect("ECDH");

        // Our BRC-42 derivation
        let derived = derive_child_pubkey(&recipient_pub, &shared_secret, invoice_number).unwrap();

        assert_eq!(
            derived.to_compressed(),
            expected.to_compressed(),
            "must match BRC-42 spec test vector"
        );
    }

    // -------------------------------------------------------------------
    // derive_joint_key_with_secret tests
    // -------------------------------------------------------------------

    #[test]
    fn test_derive_joint_key_with_secret_has_valid_address() {
        let (root_priv, _) = test_root_key();
        let jk = test_joint_key();
        let root_pub = PublicKey::from_bytes(&jk.compressed).unwrap();
        let shared_secret = root_priv.derive_shared_secret(&root_pub).unwrap();

        // protocol_name was "test" (4 chars) — now rejected by canonical
        // validate_protocol_name which requires ≥ 5 chars. Use a valid
        // protocol_name that exercises the same path.
        let child = derive_joint_key_with_secret(&jk, &shared_secret, "tests", "key1", 2).unwrap();
        assert!(!child.address.is_empty());
        assert_eq!(child.compressed.len(), 33);
        assert_ne!(jk.address, child.address);
    }

    // -------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------

    #[test]
    fn test_invalid_joint_key_rejected() {
        let bad_jk = JointPublicKey {
            compressed: vec![0x04, 0x00], // invalid: wrong length and prefix
            address: "bad".to_string(),
        };
        let result = derive_anyone_joint_key(&bad_jk, "test", "key", 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_invoice_works() {
        // BRC-42 doesn't forbid empty invoices, though they're unusual
        let (_, pubkey) = test_root_key();
        let child = derive_child_pubkey(&pubkey, &pubkey, "").unwrap();
        assert_ne!(pubkey.to_compressed(), child.to_compressed());
    }

    #[test]
    fn test_long_invoice_works() {
        let (_, pubkey) = test_root_key();
        let long_invoice = "a".repeat(10000);
        let child = derive_child_pubkey(&pubkey, &pubkey, &long_invoice).unwrap();
        assert_ne!(pubkey.to_compressed(), child.to_compressed());
    }
}
