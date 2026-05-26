//! At-rest sealing of the coordinator's own presig share (MPC-Spec §06.17.1).
//!
//! `PresigBundle.presig_bytes` is the coordinator's OWN serialized presig share
//! — equivalent in sensitivity to its DKG key share (§06.17.1) — and MUST be
//! encrypted at rest at the same level. This module mirrors the proven DKG
//! at-rest pattern in [`crate::share`]: AES-256-GCM with a 12-byte random nonce,
//! key derived from the coordinator's at-rest root key via HMAC-SHA256 under a
//! distinct domain. The storage backend (worker DO SQLite) holds only the
//! sealed bytes and never the at-rest key — matching the `mpc_shares` /
//! `mpc_custody` "ciphertext-only at rest" model.
//!
//! `cosigner_encrypted_shares` are already opaque BRC-2 ciphertext
//! ([`crate::presig_encryption`]) and are stored as-is; only `presig_bytes`
//! needs this layer.
//!
//! Sealed layout: `nonce(12) ‖ ciphertext ‖ tag(16)` — self-describing, so
//! [`unseal_presig_bytes`] needs only the key.
//!
//! §06.18 deletion: because the at-rest representation is ciphertext under a
//! key the storage backend never holds, deleting the row (plus the explicit
//! overwrite the worker performs before DELETE) is a conformant best-effort
//! zeroize — a backend without erase semantics "MUST encrypt-at-rest with
//! rotated keys so a key-rotation operation effectively zeroizes the prior
//! generation" (§06.18); this layer is that encryption.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

use crate::error::{MpcError, Result};

/// Domain separator for presig at-rest key derivation. Distinct from
/// [`crate::share`]'s `b"bsv-mpc-share"` so a presig at-rest key can never
/// collide with a DKG-share encryption key derived from the same root.
const PRESIG_AT_REST_DOMAIN: &[u8] = b"bsv-mpc-presig-at-rest";

/// Nonce length for AES-256-GCM (12 bytes), matching [`crate::share`].
const NONCE_LEN: usize = 12;

/// Derive the per-presig at-rest encryption key.
///
/// `key = HMAC-SHA256(root_key, "bsv-mpc-presig-at-rest" ‖ presig_id)`.
/// Keyed on `presig_id` so each bundle seals under a distinct key (defense in
/// depth; mirrors the per-`presig_id` uniqueness of the BRC-2 cosigner layer).
pub fn derive_presig_at_rest_key(root_key: &[u8; 32], presig_id: &str) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(root_key)
        .expect("HMAC-SHA256 accepts any key length; 32 bytes is always valid");
    mac.update(PRESIG_AT_REST_DOMAIN);
    mac.update(presig_id.as_bytes());
    let result = mac.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes());
    key
}

/// Seal the coordinator's plaintext presig share for at-rest storage.
///
/// Returns `nonce(12) ‖ ciphertext ‖ tag(16)`. The caller stores this opaque
/// blob (as `PresigBundle.presig_bytes`); the storage backend never sees the
/// plaintext or the key.
pub fn seal_presig_bytes(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| MpcError::Encryption(format!("seal presig bytes: {e}")))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Inverse of [`seal_presig_bytes`]. Fails (AES-GCM tag) on a wrong key or a
/// tampered blob.
pub fn unseal_presig_bytes(sealed: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + 16 {
        return Err(MpcError::Encryption(format!(
            "sealed presig blob too short: {} bytes (need >= nonce + tag)",
            sealed.len()
        )));
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| MpcError::Encryption(format!("unseal presig bytes: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::derive_share_encryption_key;
    use crate::types::SessionId;

    const ROOT: [u8; 32] = [0x42; 32];
    // 48-byte stand-in for a serialized coordinator presig share.
    const PLAINTEXT: &[u8] = b"coordinator presig share -- 48 bytes of secret!!";

    #[test]
    fn seal_unseal_roundtrip() {
        let key = derive_presig_at_rest_key(&ROOT, "presig-001");
        let sealed = seal_presig_bytes(PLAINTEXT, &key).unwrap();
        assert_eq!(unseal_presig_bytes(&sealed, &key).unwrap(), PLAINTEXT);
    }

    #[test]
    fn sealed_blob_is_not_plaintext_recoverable() {
        // not-plaintext-recoverable (the §06.17.1 at-rest property): the stored
        // bytes must not contain the plaintext as a substring.
        let key = derive_presig_at_rest_key(&ROOT, "presig-001");
        let sealed = seal_presig_bytes(PLAINTEXT, &key).unwrap();
        assert_ne!(sealed, PLAINTEXT);
        assert!(
            !sealed.windows(PLAINTEXT.len()).any(|w| w == PLAINTEXT),
            "sealed blob must not contain the plaintext share"
        );
        // layout: nonce(12) + ct(=pt len) + tag(16)
        assert_eq!(sealed.len(), NONCE_LEN + PLAINTEXT.len() + 16);
    }

    #[test]
    fn wrong_key_fails_unseal() {
        let key = derive_presig_at_rest_key(&ROOT, "presig-001");
        let other = derive_presig_at_rest_key(&ROOT, "presig-002");
        let sealed = seal_presig_bytes(PLAINTEXT, &key).unwrap();
        assert!(
            unseal_presig_bytes(&sealed, &other).is_err(),
            "different presig_id derives a different key → unseal must fail"
        );
    }

    #[test]
    fn tampered_blob_fails_unseal() {
        let key = derive_presig_at_rest_key(&ROOT, "presig-001");
        let mut sealed = seal_presig_bytes(PLAINTEXT, &key).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(unseal_presig_bytes(&sealed, &key).is_err());
    }

    #[test]
    fn key_derivation_is_deterministic_and_domain_separated() {
        // deterministic
        assert_eq!(
            derive_presig_at_rest_key(&ROOT, "presig-001"),
            derive_presig_at_rest_key(&ROOT, "presig-001"),
        );
        // domain-separated from the DKG-share key derivation (different domain
        // tag) even when the variable input collides bytewise. derive_share_*
        // takes a SessionId; use one whose bytes equal the presig_id's bytes is
        // not directly comparable, so we assert the two never coincide for a
        // representative input.
        let sid = SessionId([0x01; 32]);
        let share_key = derive_share_encryption_key(&ROOT, &sid);
        let presig_key = derive_presig_at_rest_key(&ROOT, &"\u{1}".repeat(32));
        assert_ne!(
            *share_key, presig_key,
            "presig at-rest key domain must not collide with DKG-share key domain"
        );
    }
}
