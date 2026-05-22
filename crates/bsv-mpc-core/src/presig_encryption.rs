//! BRC-2 self-encryption for presignature shares (MPC-Spec §06.16, ADR-0030).
//!
//! After the 3-round presign (§06.16), each cosigner encrypts its secret presig
//! share **to itself** via the canonical BRC-2 wallet primitive
//! ([`ProtoWallet::encrypt`]) and ships the opaque ciphertext to the coordinator
//! (§06.17.2). The coordinator stores it in the [`crate::types::PresigBundle`]
//! and cannot read it at rest; only the originating cosigner can decrypt it at
//! sign-time (§06.20).
//!
//! Canonical parameters (§06.16 table / ADR-0030 §37):
//!
//! | Parameter | Value |
//! |---|---|
//! | `counterparty` | [`Counterparty::Self_`] |
//! | `protocol_id.security_level` | `2` ([`SecurityLevel::Counterparty`], discriminant `2`) |
//! | `protocol_id.protocol` | `"mpcpresig"` (BRC-43: lowercase, no hyphens) |
//! | `key_id` | the `presig_id` (unique per presig; canonical = the presign session_id) |
//!
//! The wallet computes the BRC-42 invoice `2-mpcpresig-{presig_id}` (§03),
//! derives the ECDH-self shared secret, derives the AES-256-GCM key (the
//! x-coordinate of the derived child-key self-ECDH point), and emits the
//! ciphertext (`IV(32) ‖ ciphertext ‖ authTag(16)`, the canonical 32-byte-IV
//! `SymmetricKey` convention). We MUST NOT hand-roll AES — using the wallet
//! primitive guarantees `bsv-mpc` and `rust-mpc` derive the same canonical key.
//!
//! Mirrors the reference impl `rust-mpc/crates/brc42/src/presig_encryption.rs`.
//! The cross-impl byte-lock lives in
//! `tests/conformance_06_presig_bundle_encryption.rs`.

use bsv::primitives::ec::PrivateKey;
use bsv::wallet::{Counterparty, DecryptArgs, EncryptArgs, ProtoWallet, Protocol, SecurityLevel};

use crate::error::{MpcError, Result};

/// BRC-43 protocol name for presig-share self-encryption. Lowercase, no hyphens
/// (§06.16). 9 chars — within the §03.2.1 `[a-z0-9 ]{5,400}` charset.
pub const PRESIG_PROTOCOL_NAME: &str = "mpcpresig";

/// The canonical BRC-2 protocol_id for presig-share encryption: security level 2
/// with protocol name `"mpcpresig"`. `SecurityLevel::Counterparty` is the
/// discriminant-2 variant, so the BRC-42 invoice prefix is `"2"`
/// (`2-mpcpresig-{presig_id}`).
fn presig_protocol() -> Protocol {
    Protocol::new(SecurityLevel::Counterparty, PRESIG_PROTOCOL_NAME)
}

/// Construct a [`ProtoWallet`] from a 32-byte identity private key.
///
/// The cosigner's BRC-2 self-encryption key derives deterministically from this
/// identity key, so both encrypt (generation) and decrypt (sign-time) MUST use
/// the same wallet.
pub fn wallet_from_identity(identity_priv: &PrivateKey) -> ProtoWallet {
    ProtoWallet::new(Some(identity_priv.clone()))
}

/// BRC-2 self-encrypt a presig share (§06.16 step 2).
///
/// `share_bytes` is the already-serialized secret presig material the cosigner
/// must retain (e.g. its `tilde_chi_i`). Returns the opaque ciphertext
/// (`IV(32) ‖ ct ‖ tag`) to ship to the coordinator. The caller MUST zeroize
/// `share_bytes` once the coordinator acknowledges receipt (§06.16 step 3).
pub fn encrypt_presig_share(
    wallet: &ProtoWallet,
    presig_id: &str,
    share_bytes: &[u8],
) -> Result<Vec<u8>> {
    let result = wallet
        .encrypt(EncryptArgs {
            plaintext: share_bytes.to_vec(),
            protocol_id: presig_protocol(),
            key_id: presig_id.to_string(),
            counterparty: Some(Counterparty::Self_),
        })
        .map_err(|e| MpcError::Encryption(format!("presig share encrypt: {e}")))?;
    Ok(result.ciphertext)
}

/// Inverse of [`encrypt_presig_share`] — BRC-2 self-decrypt at sign-time (§06.20).
///
/// Re-derives the same key from `(wallet identity, presig_id)` and decrypts.
/// Fails (AES-GCM tag mismatch) on a wrong `presig_id`, a wrong wallet, or a
/// tampered ciphertext — the negative paths the §06.21.1 conformance vector pins.
pub fn decrypt_presig_share(
    wallet: &ProtoWallet,
    presig_id: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let result = wallet
        .decrypt(DecryptArgs {
            ciphertext: ciphertext.to_vec(),
            protocol_id: presig_protocol(),
            key_id: presig_id.to_string(),
            counterparty: Some(Counterparty::Self_),
        })
        .map_err(|e| MpcError::Encryption(format!("presig share decrypt: {e}")))?;
    Ok(result.plaintext)
}

/// The §06.20 cosigner consume path: decrypt the coordinator-shipped BRC-2
/// ciphertext, then issue this party's partial signature (optionally applying a
/// BRC-42 offset for HD-derived signing).
///
/// At sign-time the coordinator ships the cosigner its stored
/// `cosigner_encrypted_share` + the message-to-sign (+ a BRC-42 offset for the
/// HD path). The cosigner re-derives its wallet key, decrypts (same protocol_id
/// + key_id=presig_id), deserializes the `cggmp24::Presignature`, applies the
/// offset if present, and emits its serialized `PartialSignature` for the
/// coordinator to combine. Single-use is enforced by the coordinator removing
/// the bundle from the pool (§06.17.3).
pub fn decrypt_and_issue_partial(
    wallet: &ProtoWallet,
    presig_id: &str,
    encrypted_share: &[u8],
    message_hash: &[u8; 32],
    brc42_offset: Option<[u8; 32]>,
) -> Result<Vec<u8>> {
    let presig_json = decrypt_presig_share(wallet, presig_id, encrypted_share)?;
    crate::signing::issue_partial_signature_json_with_offset(
        &presig_json,
        message_hash,
        brc42_offset,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet(seed: u8) -> ProtoWallet {
        let priv_key = PrivateKey::from_bytes(&[seed; 32]).unwrap();
        wallet_from_identity(&priv_key)
    }

    #[test]
    fn roundtrip_recovers_plaintext() {
        let w = wallet(1);
        let presig_id = "presig-roundtrip-001";
        let plaintext = b"presig share plaintext 32 bytesx";
        let ct = encrypt_presig_share(&w, presig_id, plaintext).unwrap();
        // Ciphertext is not the plaintext, and carries the 32-byte IV + 16-byte tag.
        assert_ne!(ct.as_slice(), plaintext.as_slice());
        assert_eq!(ct.len(), 32 + plaintext.len() + 16, "IV(32) || ct || tag(16)");
        let pt = decrypt_presig_share(&w, presig_id, &ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext.as_slice());
    }

    // §06.21.1 negative test: wrong-presig_id-fails-decrypt.
    #[test]
    fn wrong_presig_id_fails_decrypt() {
        let w = wallet(1);
        let ct = encrypt_presig_share(&w, "presig-aaa", b"some secret share").unwrap();
        assert!(
            decrypt_presig_share(&w, "presig-bbb", &ct).is_err(),
            "decrypt under a different presig_id must fail (different derived key)"
        );
    }

    // §06.21.1 negative test: wrong-wallet-fails-decrypt.
    #[test]
    fn wrong_wallet_fails_decrypt() {
        let wa = wallet(1);
        let wb = wallet(2);
        let ct = encrypt_presig_share(&wa, "presig-x", b"some secret share").unwrap();
        assert!(
            decrypt_presig_share(&wb, "presig-x", &ct).is_err(),
            "decrypt under a different wallet must fail"
        );
    }

    // §06.21.1 negative test: tampered-ciphertext-fails-decrypt.
    #[test]
    fn tampered_ciphertext_fails_decrypt() {
        let w = wallet(1);
        let mut ct = encrypt_presig_share(&w, "presig-x", b"some secret share").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01; // flip a tag byte
        assert!(
            decrypt_presig_share(&w, "presig-x", &ct).is_err(),
            "AES-GCM tag must reject a tampered ciphertext"
        );
    }

    // §06.21.1 negative test: different-presig_id-different-ciphertext
    // (per-presig_id key uniqueness — the §06.16 "unique encryption key per
    // presig" guarantee). NOTE: each encrypt also uses a fresh random IV, so
    // ciphertexts differ regardless; to isolate the KEY-uniqueness property we
    // also assert the cross-decrypt fails (covered above) — here we assert the
    // bytes differ as the spec's stated vector requires.
    #[test]
    fn different_presig_id_different_ciphertext() {
        let w = wallet(1);
        let data = b"identical plaintext for both ids";
        let ct_a = encrypt_presig_share(&w, "presig-aaa", data).unwrap();
        let ct_b = encrypt_presig_share(&w, "presig-bbb", data).unwrap();
        assert_ne!(ct_a, ct_b, "same plaintext, different presig_id → ciphertexts differ");
    }
}
