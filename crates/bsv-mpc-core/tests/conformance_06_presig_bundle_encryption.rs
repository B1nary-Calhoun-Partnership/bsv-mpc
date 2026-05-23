//! Conformance suite for MPC-Spec §06.16 / §06.21.1 + ADR-0030 (presig-share
//! BRC-2 self-encryption byte-lock).
//!
//! Drives the vector at `tests/fixtures/06-presig-bundle-encryption.json`.
//!
//! Two tiers, per the vector's `status`:
//!
//! 1. **Intermediate byte-lock (LOCKED — runs now).** For each vector, the
//!    deterministic BRC-42 derivation intermediates — wallet pubkey, canonical
//!    invoice string, `Self_` ECDH shared secret, and HMAC offset — MUST
//!    reproduce byte-for-byte through bsv-mpc-core's own `hd` path. A divergence
//!    here means bsv-mpc derives a DIFFERENT BRC-2 key than the canonical @bsv
//!    SDK / rust-mpc for the same presig, so no cross-impl decrypt would work.
//!
//! 2. **Ciphertext byte-lock (LOCKED — runs now).** For each vector, BRC-2
//!    self-encrypt under the pinned 32-byte IV via the deterministic
//!    `encrypt_presig_share_with_iv` seam (bsv-rs ≥ 0.3.12) and assert the
//!    `IV(32) ‖ ct ‖ tag` output matches byte-for-byte. The locked ciphertexts
//!    are canonical — reproduced identically by @bsv/sdk (TS), go-sdk, and
//!    OpenSSL with the same wallet-derived key + IV — so this is a true
//!    cross-impl lock, not a single-impl echo.
//!
//! Negative tests (§06.21.1) and the round-trip path run now via
//! `bsv_mpc_core::presig_encryption`.

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::hd::{compute_brc42_hmac, compute_invoice};
use bsv_mpc_core::presig_encryption::{
    decrypt_presig_share, encrypt_presig_share, encrypt_presig_share_with_iv, wallet_from_identity,
};
use serde_json::Value;

const VECTORS: &str = include_str!("fixtures/06-presig-bundle-encryption.json");

fn root() -> Value {
    let r: Value = serde_json::from_str(VECTORS).expect("vector json parses");
    assert_eq!(r["spec_section"], "06.16", "vector file is §06.16");
    assert_eq!(
        r["iv_convention"]["iv_size_bytes"], 32,
        "canonical BSV SymmetricKey IV is 32 bytes (all ecosystem SDKs)"
    );
    r
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("missing string field {key}"))
}

/// Tier 1 — the locked intermediates reproduce through bsv-mpc-core's `hd` path.
#[test]
fn intermediate_values_reproduce_byte_for_byte() {
    let r = root();
    let vectors = r["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 3, "§06 has 3 presig-bundle vectors");

    for v in vectors {
        let name = s(v, "name");
        let inp = &v["inputs"];
        let locked = &v["intermediate_byte_locked"];

        let priv_hex = s(inp, "wallet_identity_priv_hex");
        let presig_id = s(inp, "presig_id");
        // vector-3 omits protocol fields; canonical defaults are level 2 / "mpcpresig".
        let sec_level = inp["protocol_security_level"].as_u64().unwrap_or(2) as u8;
        let protocol_name = inp["protocol_name"].as_str().unwrap_or("mpcpresig");

        let priv_key = PrivateKey::from_hex(priv_hex).expect("priv from hex");
        let pub_key = priv_key.public_key();

        // (a) wallet pubkey (compressed).
        assert_eq!(
            pub_key.to_hex(),
            s(locked, "wallet_pub_compressed_hex"),
            "{name}: wallet pubkey diverges"
        );

        // (b) canonical BRC-42 invoice string (§03; canonicalizes "  MPCPresig  ").
        let invoice = compute_invoice(sec_level, protocol_name, presig_id)
            .unwrap_or_else(|e| panic!("{name}: compute_invoice failed: {e}"));
        assert_eq!(
            invoice,
            s(locked, "brc42_invoice_string"),
            "{name}: invoice string diverges"
        );
        // and its UTF-8 bytes (the HMAC data argument).
        assert_eq!(
            hex::encode(invoice.as_bytes()),
            s(locked, "brc42_invoice_bytes_hex"),
            "{name}: invoice bytes diverge"
        );

        // (c) Self_ ECDH shared secret = root_priv * root_pub (§03.6), compressed.
        let shared_secret = priv_key
            .derive_shared_secret(&pub_key)
            .expect("self ECDH");
        assert_eq!(
            shared_secret.to_hex(),
            s(locked, "shared_secret_compressed_hex"),
            "{name}: Self_ shared secret diverges"
        );

        // (d) HMAC offset = HMAC-SHA256(shared_secret_33B, invoice_bytes).
        let offset = compute_brc42_hmac(&shared_secret, &invoice);
        assert_eq!(
            hex::encode(offset),
            s(locked, "hmac_offset_hex"),
            "{name}: BRC-42 HMAC offset diverges"
        );
    }
}

/// §06.21.1 negative: wrong-presig_id-fails-decrypt.
#[test]
fn negative_wrong_presig_id_fails() {
    let w = wallet_from_identity(&PrivateKey::from_bytes(&[7u8; 32]).unwrap());
    let ct = encrypt_presig_share(&w, "presig-aaa", b"secret presig share data").unwrap();
    assert!(decrypt_presig_share(&w, "presig-bbb", &ct).is_err());
}

/// §06.21.1 negative: wrong-wallet-fails-decrypt.
#[test]
fn negative_wrong_wallet_fails() {
    let wa = wallet_from_identity(&PrivateKey::from_bytes(&[7u8; 32]).unwrap());
    let wb = wallet_from_identity(&PrivateKey::from_bytes(&[8u8; 32]).unwrap());
    let ct = encrypt_presig_share(&wa, "presig-x", b"secret presig share data").unwrap();
    assert!(decrypt_presig_share(&wb, "presig-x", &ct).is_err());
}

/// §06.21.1 negative: tampered-ciphertext-fails-decrypt.
#[test]
fn negative_tampered_ciphertext_fails() {
    let w = wallet_from_identity(&PrivateKey::from_bytes(&[7u8; 32]).unwrap());
    let mut ct = encrypt_presig_share(&w, "presig-x", b"secret presig share data").unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    assert!(decrypt_presig_share(&w, "presig-x", &ct).is_err());
}

/// §06.21.1 negative: different-presig_id-different-ciphertext.
#[test]
fn negative_different_presig_id_different_ciphertext() {
    let w = wallet_from_identity(&PrivateKey::from_bytes(&[7u8; 32]).unwrap());
    let data = b"identical plaintext across two ids";
    let a = encrypt_presig_share(&w, "presig-aaa", data).unwrap();
    let b = encrypt_presig_share(&w, "presig-bbb", data).unwrap();
    assert_ne!(a, b);
}

/// Vector-3 `roundtrip_decrypt_plaintext_hex`: encrypt→decrypt recovers the
/// exact plaintext through the canonical wallet primitive.
#[test]
fn vector3_roundtrip_decrypt() {
    let r = root();
    let v = r["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "presig-bundle-vector-3-roundtrip-decrypt")
        .expect("vector-3 present");
    let priv_key = PrivateKey::from_hex(s(&v["inputs"], "wallet_identity_priv_hex")).unwrap();
    let presig_id = s(&v["inputs"], "presig_id");
    let plaintext = hex::decode(s(&v["inputs"], "presig_share_plaintext_hex")).unwrap();
    let expected = hex::decode(s(&v["expected"], "roundtrip_decrypt_plaintext_hex")).unwrap();

    let w = wallet_from_identity(&priv_key);
    let ct = encrypt_presig_share(&w, presig_id, &plaintext).unwrap();
    let pt = decrypt_presig_share(&w, presig_id, &ct).unwrap();
    assert_eq!(pt, expected, "vector-3 round-trip plaintext mismatch");
}

/// Tier 2 — full ciphertext byte-lock (§06.16). For each vector, BRC-2
/// self-encrypt the plaintext under the pinned 32-byte IV via the deterministic
/// `encrypt_presig_share_with_iv` seam (bsv-rs ≥ 0.3.12) and assert the
/// `IV(32) ‖ ct ‖ tag` output matches the locked vector byte-for-byte. The locked
/// ciphertexts are canonical: reproduced byte-for-byte by @bsv/sdk (TS), go-sdk,
/// and OpenSSL with the same wallet-derived key + IV. Also re-asserts the
/// round-trip through the canonical (random-IV-path) `decrypt_presig_share`,
/// proving the seam used the same key as the production wallet path.
#[test]
fn ciphertext_byte_lock() {
    let r = root();
    let vectors = r["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 3, "§06 has 3 presig-bundle vectors");
    for v in vectors {
        let name = s(v, "name");
        let inp = &v["inputs"];
        let priv_key =
            PrivateKey::from_bytes(&hex::decode(s(inp, "wallet_identity_priv_hex")).unwrap())
                .unwrap();
        let presig_id = s(inp, "presig_id");
        let plaintext = hex::decode(s(inp, "presig_share_plaintext_hex")).unwrap();
        let iv_vec = hex::decode(s(inp, "aes_gcm_iv_hex")).unwrap();
        assert_eq!(iv_vec.len(), 32, "{name}: canonical 32-byte IV");
        let mut iv = [0u8; 32];
        iv.copy_from_slice(&iv_vec);
        let expected = s(&v["expected"], "ciphertext_with_tag_hex");

        let wallet = wallet_from_identity(&priv_key);
        let ct = encrypt_presig_share_with_iv(&wallet, presig_id, &iv, &plaintext).unwrap();
        assert_eq!(hex::encode(&ct), expected, "{name}: ciphertext byte-lock");

        // Round-trip through the canonical decrypt path — proves the deterministic
        // seam derived the SAME BRC-2 key the production wallet path uses.
        let pt = decrypt_presig_share(&wallet, presig_id, &ct).unwrap();
        assert_eq!(pt, plaintext, "{name}: round-trip decrypt under canonical path");
    }
}
