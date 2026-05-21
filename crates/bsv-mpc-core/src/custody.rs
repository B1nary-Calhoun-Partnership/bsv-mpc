//! Durable share custody: KEK-wrap an [`EncryptedShare`] for storage on an
//! untrusted durable tier (the CF Worker DO), so the cosigner's `share_A`
//! survives an ephemeral-compute restart **without** the durable store ever
//! holding plaintext share material.
//!
//! ## Why
//!
//! The deployed cosigner (CF Container) holds `share_A` in memory only — and the
//! in-memory `EncryptedShare.ciphertext` is the *raw* cggmp24 share JSON (it is
//! NOT itself AES-encrypted; the in-memory tier is the trust boundary). CF
//! Container disk is ephemeral, so on restart `share_A` is gone → a 2-of-2 joint
//! key can never sign again → permanent **fund-lock**. The fix: persist `share_A`
//! to the durable DO, **wrapped under a KEK** that only the container holds.
//!
//! ## Scheme
//!
//! ```text
//! KEK   = HMAC-SHA256(server_identity_key_bytes, "bsv-mpc share custody kek v1")
//! blob  = AES-256-GCM_KEK( serde_json(EncryptedShare) )   // fresh 96-bit nonce
//! ```
//!
//! - The whole `EncryptedShare` (including its raw `ciphertext`) is serialized
//!   and AEAD-sealed, so the DO sees only ciphertext + a fresh nonce.
//! - The KEK is derived from the container's long-lived `MPC_SERVER_PRIVATE_KEY`
//!   (a durable secret only the container possesses). Neither the DO blob nor a
//!   leaked container secret alone is sufficient: confidentiality rests on the
//!   KEK (held only by the container), and the durable store holds only sealed
//!   bytes. Defense-in-depth over the §07/§08.1 owner-authz on the custody route.
//! - Deterministic KEK derivation ⇒ the same container (same secret) re-derives
//!   the KEK after a restart and unwraps its own share. Lose the secret ⇒ the
//!   blob is unrecoverable (so the operator MUST treat `MPC_SERVER_PRIVATE_KEY`
//!   as the custody root).

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{MpcError, Result};
use crate::share::{decrypt_share, encrypt_share};
use crate::types::EncryptedShare;

/// Domain separator for the custody KEK (isolates it from §03 BRC-42 invoice
/// keys, the `share.rs` per-session keys, and any other HMAC use of the secret).
const CUSTODY_KEK_DOMAIN: &[u8] = b"bsv-mpc share custody kek v1";

/// Derive the 32-byte custody KEK from the cosigner's long-lived identity-key
/// material (`MPC_SERVER_PRIVATE_KEY` raw bytes). Deterministic — the same
/// secret always yields the same KEK, so a restarted container can unwrap the
/// share it sealed before the restart.
pub fn derive_custody_kek(server_key_bytes: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(server_key_bytes)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(CUSTODY_KEK_DOMAIN);
    let out = mac.finalize().into_bytes();
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&out);
    kek
}

/// Seal an `EncryptedShare` (whose `ciphertext` is the raw cggmp24 share) into a
/// custody blob under the KEK. The result is itself an `EncryptedShare` whose
/// `ciphertext` is `AES-256-GCM_KEK(serde_json(input))` — safe to hand to an
/// untrusted durable store. Non-secret metadata (`session_id`, `share_index`,
/// `config`, `joint_pubkey`) is copied through for keying/observability; the
/// secret lives only inside the sealed blob.
pub fn wrap_share_for_custody(share: &EncryptedShare, kek: &[u8; 32]) -> Result<EncryptedShare> {
    let plaintext = serde_json::to_vec(share)
        .map_err(|e| MpcError::Serialization(format!("custody serialize share: {e}")))?;
    let mut blob = encrypt_share(&plaintext, kek)?;
    blob.session_id = share.session_id;
    blob.share_index = share.share_index;
    blob.config = share.config;
    blob.joint_pubkey_compressed = share.joint_pubkey_compressed.clone();
    Ok(blob)
}

/// Unseal a custody blob produced by [`wrap_share_for_custody`] back into the
/// original in-memory `EncryptedShare` (raw `ciphertext` restored). A wrong KEK
/// or a tampered blob fails the GCM tag and returns an error (never plaintext).
pub fn unwrap_custody_share(blob: &EncryptedShare, kek: &[u8; 32]) -> Result<EncryptedShare> {
    let plaintext = decrypt_share(blob, kek)?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| MpcError::Serialization(format!("custody deserialize share: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SessionId, ShareIndex, ThresholdConfig};

    fn raw_share() -> EncryptedShare {
        // Mirrors the in-memory cosigner share: ciphertext = raw cggmp24 JSON.
        EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: br#"{"raw":"cggmp24-key-share-state"}"#.to_vec(),
            session_id: SessionId::from_str_hash("custody-test"),
            share_index: ShareIndex(0),
            config: ThresholdConfig::new(2, 2).unwrap(),
            joint_pubkey_compressed: vec![2u8; 33],
        }
    }

    #[test]
    fn kek_is_deterministic_and_domain_separated() {
        let sk = [7u8; 32];
        assert_eq!(derive_custody_kek(&sk), derive_custody_kek(&sk));
        assert_ne!(derive_custody_kek(&sk), derive_custody_kek(&[8u8; 32]));
        // Domain separation: not equal to the raw HMAC without the domain tag.
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&sk).unwrap();
        mac.update(b"");
        let bare: [u8; 32] = mac.finalize().into_bytes().into();
        assert_ne!(derive_custody_kek(&sk), bare);
    }

    #[test]
    fn wrap_unwrap_round_trips() {
        let kek = derive_custody_kek(&[42u8; 32]);
        let original = raw_share();
        let blob = wrap_share_for_custody(&original, &kek).unwrap();

        // The durable blob is genuinely sealed — its ciphertext is NOT the raw
        // share, and the raw share string does not appear in it.
        assert_ne!(blob.ciphertext, original.ciphertext);
        assert!(!blob
            .ciphertext
            .windows(b"cggmp24".len())
            .any(|w| w == b"cggmp24"));
        // Non-secret metadata copied through for keying.
        assert_eq!(blob.session_id, original.session_id);
        assert_eq!(
            blob.joint_pubkey_compressed,
            original.joint_pubkey_compressed
        );

        let restored = unwrap_custody_share(&blob, &kek).unwrap();
        assert_eq!(restored.ciphertext, original.ciphertext);
        assert_eq!(restored.nonce, original.nonce);
        assert_eq!(restored.session_id, original.session_id);
        assert_eq!(restored.share_index.0, original.share_index.0);
        assert_eq!(restored.config.threshold, original.config.threshold);
    }

    #[test]
    fn wrong_kek_fails_closed() {
        let kek = derive_custody_kek(&[1u8; 32]);
        let blob = wrap_share_for_custody(&raw_share(), &kek).unwrap();
        let wrong = derive_custody_kek(&[2u8; 32]);
        assert!(
            unwrap_custody_share(&blob, &wrong).is_err(),
            "a wrong KEK MUST fail the GCM tag, never return plaintext"
        );
    }

    #[test]
    fn tampered_blob_fails_closed() {
        let kek = derive_custody_kek(&[9u8; 32]);
        let mut blob = wrap_share_for_custody(&raw_share(), &kek).unwrap();
        // Flip a ciphertext byte → GCM tag must reject.
        blob.ciphertext[0] ^= 0xff;
        assert!(unwrap_custody_share(&blob, &kek).is_err());
    }
}
