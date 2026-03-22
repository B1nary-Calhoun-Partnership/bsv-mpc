//! Key share encryption, decryption, and storage utilities.
//!
//! MPC key shares must never exist in plaintext at rest. This module provides
//! AES-256-GCM encryption for shares using encryption keys derived via the
//! BRC-42 pattern (HMAC-SHA256 of a root key with the session ID as context).
//!
//! ## Encryption Scheme
//!
//! - **Algorithm**: AES-256-GCM (authenticated encryption with associated data)
//! - **Key derivation**: HMAC-SHA256(root_key, "bsv-mpc-share" || session_id)
//! - **Nonce**: 12 bytes, randomly generated per encryption (never reused)
//! - **Associated data**: None (the session ID and share index are in the
//!   `EncryptedShare` struct alongside the ciphertext)
//!
//! ## BRC-42 Key Derivation
//!
//! The share encryption key is derived from the wallet's root key using the
//! BRC-42 pattern. This ensures:
//!
//! 1. Each session gets a unique encryption key (domain separation via session ID).
//! 2. The root key is never used directly for encryption.
//! 3. The derivation is deterministic — the same root key + session ID always
//!    produces the same encryption key, enabling re-encryption after wallet restore.
//!
//! ## Storage Format
//!
//! The [`EncryptedShare`] struct serializes to JSON and contains all metadata
//! needed to decrypt: nonce, ciphertext, session ID, share index, and threshold
//! config. The encryption key is NOT stored — it must be re-derived from the
//! wallet's root key.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

use crate::error::{MpcError, Result};
use crate::types::{EncryptedShare, SessionId, ShareIndex, ThresholdConfig};

/// Domain separator for share encryption key derivation.
///
/// This string is prepended to the session ID before HMAC to ensure that
/// share encryption keys are isolated from any other key derived from the
/// same root key.
const SHARE_KEY_DOMAIN: &[u8] = b"bsv-mpc-share";

/// Encrypt a raw key share using AES-256-GCM.
///
/// # Arguments
///
/// * `share_bytes` — The plaintext key share (serialized cggmp24 key share data).
/// * `encryption_key` — A 32-byte AES-256 key, typically derived via
///   [`derive_share_encryption_key`].
///
/// # Returns
///
/// An [`EncryptedShare`] containing the nonce and ciphertext. The `session_id`,
/// `share_index`, and `config` fields are set to placeholder values — the caller
/// should fill them in from the DKG result.
///
/// # Security
///
/// A fresh 12-byte nonce is generated from `OsRng` for each call. The GCM
/// authentication tag (16 bytes) is appended to the ciphertext, providing
/// both confidentiality and integrity.
pub fn encrypt_share(share_bytes: &[u8], encryption_key: &[u8; 32]) -> Result<EncryptedShare> {
    // Generate 12-byte random nonce. AES-256-GCM requires a 96-bit nonce.
    // OsRng provides cryptographically secure randomness from the OS.
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create AES-256-GCM cipher from the encryption key.
    let key = Key::<Aes256Gcm>::from_slice(encryption_key);
    let cipher = Aes256Gcm::new(key);

    // Encrypt. The resulting ciphertext includes the 16-byte GCM auth tag
    // appended after the encrypted data.
    let ciphertext = cipher
        .encrypt(nonce, share_bytes)
        .map_err(|e| MpcError::Encryption(e.to_string()))?;

    Ok(EncryptedShare {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
        session_id: SessionId(String::new()), // caller fills in
        share_index: ShareIndex(0),            // caller fills in
        config: ThresholdConfig {
            threshold: 0,
            parties: 0,
        }, // caller fills in
    })
}

/// Decrypt an encrypted key share using AES-256-GCM.
///
/// # Arguments
///
/// * `encrypted` — The encrypted share (nonce + ciphertext from [`encrypt_share`]).
/// * `encryption_key` — The same 32-byte key used for encryption.
///
/// # Returns
///
/// The plaintext key share bytes.
///
/// # Errors
///
/// Returns [`MpcError::Encryption`] if:
/// - The encryption key is wrong (GCM auth tag verification fails).
/// - The ciphertext has been tampered with.
/// - The nonce is not exactly 12 bytes.
pub fn decrypt_share(encrypted: &EncryptedShare, encryption_key: &[u8; 32]) -> Result<Vec<u8>> {
    // Validate the encrypted share structure before attempting decryption.
    // This catches obvious structural issues (wrong nonce length, empty
    // ciphertext, invalid config) before we hit the crypto layer.
    validate_encrypted_share(encrypted)?;

    // Construct the nonce. validate_encrypted_share already confirmed 12 bytes.
    let nonce = Nonce::from_slice(&encrypted.nonce);

    // Create AES-256-GCM cipher from the encryption key.
    let key = Key::<Aes256Gcm>::from_slice(encryption_key);
    let cipher = Aes256Gcm::new(key);

    // Decrypt. GCM authentication tag is verified automatically — if the key
    // is wrong or the ciphertext was tampered with, decrypt() returns an error.
    cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|e| MpcError::Encryption(e.to_string()))
}

/// Derive a share-specific encryption key from a root wallet key.
///
/// Uses the BRC-42 HMAC-SHA256 pattern for deterministic key derivation:
///
/// ```text
/// encryption_key = HMAC-SHA256(root_key, "bsv-mpc-share" || session_id)
/// ```
///
/// # Arguments
///
/// * `root_key` — The wallet's 32-byte root encryption key.
/// * `session_id` — The MPC session ID (used as domain separator).
///
/// # Returns
///
/// A 32-byte AES-256 encryption key unique to this session.
///
/// # Determinism
///
/// The same `(root_key, session_id)` pair always produces the same encryption
/// key. This is essential for wallet backup/restore — a restored wallet can
/// re-derive the encryption key to decrypt its shares.
pub fn derive_share_encryption_key(root_key: &[u8; 32], session_id: &SessionId) -> [u8; 32] {
    // HMAC-SHA256 with root_key as the HMAC key.
    // Message = domain_separator || session_id_bytes
    //
    // The BRC-42 pattern ensures:
    // - Domain separation: the prefix "bsv-mpc-share" isolates these keys
    //   from any other HMAC-derived keys using the same root key.
    // - Session isolation: different MPC sessions produce different keys.
    // - Determinism: same inputs always produce the same output.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(root_key)
        .expect("HMAC-SHA256 accepts any key length; 32 bytes is always valid");
    mac.update(SHARE_KEY_DOMAIN);
    mac.update(session_id.0.as_bytes());
    let result = mac.finalize();

    // HMAC-SHA256 output is exactly 32 bytes, which is exactly what AES-256 needs.
    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes());
    key
}

/// Validate that an encrypted share's metadata is consistent.
///
/// Checks:
/// - Nonce is exactly 12 bytes.
/// - Ciphertext is non-empty.
/// - Share index is within the threshold config bounds.
/// - Threshold config is valid (2 <= t <= n).
pub fn validate_encrypted_share(share: &EncryptedShare) -> Result<()> {
    if share.nonce.len() != 12 {
        return Err(MpcError::InvalidShare(format!(
            "nonce must be 12 bytes, got {}",
            share.nonce.len()
        )));
    }
    if share.ciphertext.is_empty() {
        return Err(MpcError::InvalidShare("ciphertext is empty".to_string()));
    }
    if share.share_index.0 >= share.config.parties {
        return Err(MpcError::InvalidShare(format!(
            "share index {} >= parties {}",
            share.share_index.0, share.config.parties
        )));
    }
    if share.config.threshold < 2 || share.config.threshold > share.config.parties {
        return Err(MpcError::InvalidThreshold {
            t: share.config.threshold,
            n: share.config.parties,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a valid EncryptedShare by encrypting some data with a known key.
    fn make_encrypted_share(
        plaintext: &[u8],
        key: &[u8; 32],
        session_id: &str,
        share_index: u16,
        threshold: u16,
        parties: u16,
    ) -> EncryptedShare {
        let mut share = encrypt_share(plaintext, key).expect("encryption should succeed");
        share.session_id = SessionId(session_id.to_string());
        share.share_index = ShareIndex(share_index);
        share.config = ThresholdConfig { threshold, parties };
        share
    }

    // ----------------------------------------------------------------
    // Round-trip tests
    // ----------------------------------------------------------------

    #[test]
    fn encrypt_then_decrypt_returns_original_bytes() {
        let key = [0xABu8; 32];
        let plaintext = b"this is a secret key share that must survive round-trip";

        let mut encrypted = encrypt_share(plaintext, &key).expect("encrypt should succeed");
        // Fill in valid metadata (encrypt_share returns placeholders).
        encrypted.session_id = SessionId("test-session".to_string());
        encrypted.share_index = ShareIndex(0);
        encrypted.config = ThresholdConfig {
            threshold: 2,
            parties: 2,
        };

        let decrypted = decrypt_share(&encrypted, &key).expect("decrypt should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn round_trip_with_valid_metadata() {
        let key = [0x42u8; 32];
        let plaintext = b"share data";

        let share = make_encrypted_share(plaintext, &key, "session-abc", 0, 2, 3);
        let decrypted = decrypt_share(&share, &key).expect("decrypt should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let key = [0x01u8; 32];
        let plaintext = b"";

        let share = make_encrypted_share(plaintext, &key, "session-empty", 0, 2, 2);
        let decrypted = decrypt_share(&share, &key).expect("decrypt should succeed");

        assert!(decrypted.is_empty());
    }

    #[test]
    fn large_plaintext_round_trips() {
        let key = [0xFFu8; 32];
        // 10KB of data, simulating a serialized cggmp24 KeyShare (~10KB JSON).
        let plaintext: Vec<u8> = (0..10240).map(|i| (i % 256) as u8).collect();

        let share = make_encrypted_share(&plaintext, &key, "session-large", 1, 2, 3);
        let decrypted = decrypt_share(&share, &key).expect("decrypt should succeed");

        assert_eq!(decrypted, plaintext);
    }

    // ----------------------------------------------------------------
    // Nonce tests
    // ----------------------------------------------------------------

    #[test]
    fn nonce_is_always_12_bytes() {
        let key = [0x77u8; 32];
        for _ in 0..100 {
            let encrypted = encrypt_share(b"data", &key).expect("encrypt should succeed");
            assert_eq!(encrypted.nonce.len(), 12);
        }
    }

    #[test]
    fn different_encryptions_produce_different_nonces() {
        let key = [0x88u8; 32];
        let a = encrypt_share(b"same data", &key).expect("encrypt should succeed");
        let b = encrypt_share(b"same data", &key).expect("encrypt should succeed");

        // With 12 bytes of randomness, collision probability is ~2^{-96}.
        // For practical purposes, two calls should never produce the same nonce.
        assert_ne!(a.nonce, b.nonce, "two random nonces should differ");
    }

    // ----------------------------------------------------------------
    // Key mismatch tests
    // ----------------------------------------------------------------

    #[test]
    fn wrong_key_fails_decryption() {
        let key_a = [0xAAu8; 32];
        let key_b = [0xBBu8; 32];
        let plaintext = b"secret share data";

        let share = make_encrypted_share(plaintext, &key_a, "session-x", 0, 2, 2);

        let result = decrypt_share(&share, &key_b);
        assert!(result.is_err(), "wrong key should fail decryption");
        match result.unwrap_err() {
            MpcError::Encryption(_) => {} // expected
            other => panic!("expected MpcError::Encryption, got: {:?}", other),
        }
    }

    #[test]
    fn different_keys_produce_different_ciphertext() {
        let key_a = [0xAAu8; 32];
        let key_b = [0xBBu8; 32];
        let plaintext = b"identical plaintext";

        let enc_a = encrypt_share(plaintext, &key_a).expect("encrypt should succeed");
        let enc_b = encrypt_share(plaintext, &key_b).expect("encrypt should succeed");

        // Ciphertexts should differ due to different keys (and different random nonces).
        assert_ne!(enc_a.ciphertext, enc_b.ciphertext);
    }

    // ----------------------------------------------------------------
    // Tamper detection tests
    // ----------------------------------------------------------------

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let key = [0xCCu8; 32];
        let plaintext = b"do not tamper with me";

        let mut share = make_encrypted_share(plaintext, &key, "session-tamper", 0, 2, 3);

        // Flip one bit in the ciphertext.
        if let Some(byte) = share.ciphertext.first_mut() {
            *byte ^= 0x01;
        }

        let result = decrypt_share(&share, &key);
        assert!(
            result.is_err(),
            "tampered ciphertext should fail GCM auth check"
        );
    }

    #[test]
    fn tampered_nonce_fails_decryption() {
        let key = [0xDDu8; 32];
        let plaintext = b"nonce must match exactly";

        let mut share = make_encrypted_share(plaintext, &key, "session-nonce", 0, 2, 2);

        // Flip one bit in the nonce.
        share.nonce[0] ^= 0x01;

        let result = decrypt_share(&share, &key);
        assert!(
            result.is_err(),
            "tampered nonce should fail GCM auth check"
        );
    }

    // ----------------------------------------------------------------
    // Key derivation tests
    // ----------------------------------------------------------------

    #[test]
    fn derived_keys_are_deterministic() {
        let root_key = [0x11u8; 32];
        let session = SessionId("session-deterministic".to_string());

        let key_1 = derive_share_encryption_key(&root_key, &session);
        let key_2 = derive_share_encryption_key(&root_key, &session);

        assert_eq!(key_1, key_2, "same inputs must produce same key");
    }

    #[test]
    fn derived_keys_change_with_session_id() {
        let root_key = [0x22u8; 32];
        let session_a = SessionId("session-alpha".to_string());
        let session_b = SessionId("session-beta".to_string());

        let key_a = derive_share_encryption_key(&root_key, &session_a);
        let key_b = derive_share_encryption_key(&root_key, &session_b);

        assert_ne!(
            key_a, key_b,
            "different session IDs must produce different keys"
        );
    }

    #[test]
    fn derived_keys_change_with_root_key() {
        let root_a = [0x33u8; 32];
        let root_b = [0x44u8; 32];
        let session = SessionId("session-same".to_string());

        let key_a = derive_share_encryption_key(&root_a, &session);
        let key_b = derive_share_encryption_key(&root_b, &session);

        assert_ne!(
            key_a, key_b,
            "different root keys must produce different derived keys"
        );
    }

    #[test]
    fn derived_key_is_32_bytes() {
        let root_key = [0x55u8; 32];
        let session = SessionId("any-session".to_string());

        let key = derive_share_encryption_key(&root_key, &session);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derived_key_is_not_all_zeros() {
        // Sanity check: HMAC output should not be degenerate.
        let root_key = [0x00u8; 32];
        let session = SessionId("zero-root".to_string());

        let key = derive_share_encryption_key(&root_key, &session);
        assert_ne!(key, [0u8; 32], "derived key should not be all zeros");
    }

    // ----------------------------------------------------------------
    // Full flow: derive key then encrypt/decrypt
    // ----------------------------------------------------------------

    #[test]
    fn derive_encrypt_decrypt_full_flow() {
        let root_key = [0x66u8; 32];
        let session = SessionId("flow-test-session".to_string());
        let plaintext = b"complete flow: derive -> encrypt -> decrypt";

        let enc_key = derive_share_encryption_key(&root_key, &session);
        let share = make_encrypted_share(plaintext, &enc_key, "flow-test-session", 0, 2, 3);
        let decrypted = decrypt_share(&share, &enc_key).expect("full flow decrypt should succeed");

        assert_eq!(decrypted, plaintext);
    }

    // ----------------------------------------------------------------
    // validate_encrypted_share tests
    // ----------------------------------------------------------------

    #[test]
    fn validate_accepts_well_formed_share() {
        let key = [0x99u8; 32];
        let share = make_encrypted_share(b"valid share", &key, "valid-session", 1, 2, 3);
        assert!(validate_encrypted_share(&share).is_ok());
    }

    #[test]
    fn validate_rejects_wrong_nonce_length() {
        let share = EncryptedShare {
            nonce: vec![0u8; 8], // wrong: should be 12
            ciphertext: vec![1, 2, 3],
            session_id: SessionId("s".to_string()),
            share_index: ShareIndex(0),
            config: ThresholdConfig {
                threshold: 2,
                parties: 2,
            },
        };
        assert!(validate_encrypted_share(&share).is_err());
    }

    #[test]
    fn validate_rejects_empty_ciphertext() {
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![], // empty
            session_id: SessionId("s".to_string()),
            share_index: ShareIndex(0),
            config: ThresholdConfig {
                threshold: 2,
                parties: 2,
            },
        };
        assert!(validate_encrypted_share(&share).is_err());
    }

    #[test]
    fn validate_rejects_index_out_of_range() {
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![1],
            session_id: SessionId("s".to_string()),
            share_index: ShareIndex(3), // >= parties (3)
            config: ThresholdConfig {
                threshold: 2,
                parties: 3,
            },
        };
        assert!(validate_encrypted_share(&share).is_err());
    }

    #[test]
    fn validate_rejects_threshold_too_low() {
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![1],
            session_id: SessionId("s".to_string()),
            share_index: ShareIndex(0),
            config: ThresholdConfig {
                threshold: 1, // < 2
                parties: 3,
            },
        };
        assert!(validate_encrypted_share(&share).is_err());
    }

    #[test]
    fn validate_rejects_threshold_exceeds_parties() {
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![1],
            session_id: SessionId("s".to_string()),
            share_index: ShareIndex(0),
            config: ThresholdConfig {
                threshold: 4,
                parties: 3, // threshold > parties
            },
        };
        assert!(validate_encrypted_share(&share).is_err());
    }
}
