//! Conformance suite for MPC-Spec §03 + ADR-0002 (canonical BRC-42 invoice +
//! HMAC + key derivation).
//!
//! Drives the byte-locked vectors at `tests/fixtures/03-brc42-invoice.json`
//! (cross-validated Python `ecdsa` ⊕ Rust `k256` in the spec repo) and asserts
//! every vector reproduces byte-for-byte through bsv-mpc-core's BRC-42 path:
//!
//! - **private_derivation_vectors** — `recipient_priv.derive_child(sender_pub,
//!   invoiceNumber)` → `childPrivateKey`, plus the ECDH shared secret + HMAC
//!   offset intermediates.
//! - **public_derivation_vectors** — `derive_child_pubkey(recipient_pub,
//!   ECDH(sender_priv, recipient_pub), invoiceNumber)` → `childPublicKey`.
//! - **stress_vectors** — `compute_invoice` against the canonical @bsv SDK
//!   `computeInvoiceNumber` validation: 1 valid ASCII case (must reproduce) +
//!   5 rejection cases (Unicode protocol, empty key_id, protocol < 5 chars,
//!   consecutive spaces, trailing " protocol") that the SDK refuses.
//!
//! This is the cross-impl wire-compat floor: any divergence here means
//! bsv-mpc derives DIFFERENT keys than rust-mpc / the BSV SDK / bsv-worm for
//! the same logical derivation. It locks the 2026-05-17 canonicalization fix
//! against regression (previously bsv-mpc had the §03.4 bug and no vector).

use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv_mpc_core::hd::{compute_brc42_hmac, compute_invoice, derive_child_pubkey};
use serde_json::Value;

const VECTORS: &str = include_str!("fixtures/03-brc42-invoice.json");

fn root() -> Value {
    let r: Value = serde_json::from_str(VECTORS).expect("vector json parses");
    assert_eq!(r["spec_section"], "03", "vector file is §03");
    r
}

#[test]
fn private_derivation_vectors_reproduce_byte_for_byte() {
    let r = root();
    let vectors = r["private_derivation_vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 5, "§03 has 5 private derivation vectors");

    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let inp = &v["inputs"];
        let sender_pub = PublicKey::from_hex(inp["senderPublicKey"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("{name}: senderPublicKey: {e}"));
        let recipient_priv = PrivateKey::from_hex(inp["recipientPrivateKey"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("{name}: recipientPrivateKey: {e:?}"));
        let invoice = inp["invoiceNumber"].as_str().unwrap();

        // Intermediate: ECDH shared secret (recipient_priv * sender_pub).
        let shared = recipient_priv
            .derive_shared_secret(&sender_pub)
            .unwrap_or_else(|e| panic!("{name}: ECDH: {e}"));
        assert_eq!(
            hex::encode(shared.to_compressed()),
            v["intermediate"]["shared_secret_compressed_hex"]
                .as_str()
                .unwrap(),
            "{name}: ECDH shared secret diverges"
        );

        // Intermediate: HMAC offset.
        assert_eq!(
            hex::encode(compute_brc42_hmac(&shared, invoice)),
            v["intermediate"]["hmac_offset_hex"].as_str().unwrap(),
            "{name}: BRC-42 HMAC offset diverges"
        );

        // Output: child private key = recipient_priv + HMAC offset (mod n).
        let child = recipient_priv
            .derive_child(&sender_pub, invoice)
            .unwrap_or_else(|e| panic!("{name}: derive_child: {e}"));
        assert_eq!(
            child.to_hex(),
            v["expected"]["childPrivateKey_hex"].as_str().unwrap(),
            "{name}: childPrivateKey diverges from canonical vector"
        );
    }
}

#[test]
fn public_derivation_vectors_reproduce_byte_for_byte() {
    let r = root();
    let vectors = r["public_derivation_vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 5, "§03 has 5 public derivation vectors");

    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let inp = &v["inputs"];
        let sender_priv = PrivateKey::from_hex(inp["senderPrivateKey"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("{name}: senderPrivateKey: {e:?}"));
        let recipient_pub = PublicKey::from_hex(inp["recipientPublicKey"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("{name}: recipientPublicKey: {e}"));
        let invoice = inp["invoiceNumber"].as_str().unwrap();

        // ECDH shared secret (sender_priv * recipient_pub) — equals the private
        // side's secret by commutativity.
        let shared = sender_priv
            .derive_shared_secret(&recipient_pub)
            .unwrap_or_else(|e| panic!("{name}: ECDH: {e}"));
        assert_eq!(
            hex::encode(shared.to_compressed()),
            v["intermediate"]["shared_secret_compressed_hex"]
                .as_str()
                .unwrap(),
            "{name}: ECDH shared secret diverges"
        );
        assert_eq!(
            hex::encode(compute_brc42_hmac(&shared, invoice)),
            v["intermediate"]["hmac_offset_hex"].as_str().unwrap(),
            "{name}: BRC-42 HMAC offset diverges"
        );

        // Output: child public key = recipient_pub + G*HMAC.
        let child_pub = derive_child_pubkey(&recipient_pub, &shared, invoice)
            .unwrap_or_else(|e| panic!("{name}: derive_child_pubkey: {e}"));
        assert_eq!(
            hex::encode(child_pub.to_compressed()),
            v["expected"]["childPublicKey_hex"].as_str().unwrap(),
            "{name}: childPublicKey diverges from canonical vector"
        );
    }
}

/// Stress vectors lock the §03.2.1 invoice validation against the **canonical
/// @bsv SDK** `KeyDeriver.computeInvoiceNumber`. Vector 1 is a valid ASCII
/// mixed-case/whitespace case that MUST reproduce byte-for-byte; vectors 2-6
/// are REJECTION cases (`expected.rejected == true`) the SDK refuses (Unicode
/// protocol name; empty key_id; protocol < 5 chars; consecutive spaces;
/// trailing " protocol"). bsv-mpc's `compute_invoice` delegates to bsv-rs
/// `validate_protocol_name` / `validate_key_id`, which mirror the SDK, so it
/// must accept vector 1 and reject 2-6. (These were corrected in MPC-Spec §03
/// on 2026-05-21 after this harness surfaced that the prior §03.5.2/§03.5.3
/// vectors were over-permissive vs the SDK; rust-mpc's `build_invoice_number`
/// still needs the same validation — tracked for Binary.)
#[test]
fn stress_vectors_match_canonical_sdk_validation() {
    let r = root();
    let vectors = r["stress_vectors"].as_array().unwrap();
    assert!(vectors.len() >= 3, "§03 stress vectors present");

    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let inp = &v["inputs"];
        let res = compute_invoice(
            inp["security_level"].as_u64().unwrap() as u8,
            inp["protocol_id_raw"].as_str().unwrap(),
            inp["key_id_raw"].as_str().unwrap(),
        );

        if v["expected"]["rejected"].as_bool().unwrap_or(false) {
            // REJECTION case — the canonical SDK refuses this input.
            assert!(
                res.is_err(),
                "{name}: bsv-mpc MUST reject this input (canonical @bsv SDK \
                 computeInvoiceNumber rejects it: {}). Got Ok({:?})",
                v["expected"]["reason"].as_str().unwrap_or(""),
                res.ok()
            );
        } else {
            // VALID case — must reproduce the canonical invoice + HMAC.
            let invoice = res.unwrap_or_else(|e| panic!("{name}: must canonicalize: {e}"));
            assert_eq!(
                invoice,
                v["intermediate"]["invoice_string"].as_str().unwrap(),
                "{name}: canonical invoice string diverges"
            );
            let shared = PublicKey::from_hex(inp["shared_secret_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                hex::encode(compute_brc42_hmac(&shared, &invoice)),
                v["expected"]["hmac_offset_hex"].as_str().unwrap(),
                "{name}: HMAC offset diverges"
            );
        }
    }
}
