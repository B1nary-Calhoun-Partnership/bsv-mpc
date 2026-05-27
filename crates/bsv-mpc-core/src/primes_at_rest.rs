//! At-rest sealing of seeded Paillier primes (issue #5).
//!
//! The retained off-hot-path `POST /ceremony/seed-primes` endpoint (DECISIONS.md:
//! "remains for any off-path native DKG use") persists a `PregeneratedPrimes` JSON
//! blob in the worker DO-SQLite `mpc_primes` table so a seed call + a later
//! ceremony survive an eviction in between. That blob is **key-share-sensitive**
//! (Paillier safe primes feed aux-info) and MUST be encrypted at rest — the live
//! container path generates primes ephemerally in-memory (no at-rest exposure), but
//! this durable seed path is the one place primes touch disk.
//!
//! Reuses the proven AES-256-GCM byte sealer from [`crate::presig_at_rest`]
//! (`nonce(12) ‖ ciphertext ‖ tag(16)`) under a **distinct key-derivation domain**,
//! so a primes-at-rest key can never collide with a presig or DKG-share key derived
//! from the same root. The storage backend (DO SQLite) holds only the sealed bytes
//! and never the key — matching the `mpc_shares` / `mpc_custody` "ciphertext-only
//! at rest" model (the KEK derives from the worker's `SERVER_PRIVATE_KEY`).

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::Result;

/// Domain separator for primes at-rest key derivation. Distinct from
/// [`crate::presig_at_rest`]'s `b"bsv-mpc-presig-at-rest"` and [`crate::share`]'s
/// `b"bsv-mpc-share"` so the three at-rest key spaces never collide under one root.
const PRIMES_AT_REST_DOMAIN: &[u8] = b"bsv-mpc-primes-at-rest";

/// Derive the per-session primes at-rest encryption key:
/// `key = HMAC-SHA256(root_key, "bsv-mpc-primes-at-rest" ‖ session_id)`.
/// `root_key` is derived from the worker's `SERVER_PRIVATE_KEY`; keyed on
/// `session_id` so each seeded set seals under a distinct key.
pub fn derive_primes_at_rest_key(root_key: &[u8; 32], session_id: &str) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(root_key)
        .expect("HMAC-SHA256 accepts any key length; 32 bytes is always valid");
    mac.update(PRIMES_AT_REST_DOMAIN);
    mac.update(session_id.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&mac.finalize().into_bytes());
    key
}

/// Seal a primes JSON blob for at-rest storage. Returns the opaque
/// `nonce(12) ‖ ciphertext ‖ tag(16)` (the shared AES-256-GCM byte sealer).
pub fn seal_primes_bytes(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    crate::presig_at_rest::seal_presig_bytes(plaintext, key)
}

/// Inverse of [`seal_primes_bytes`]. Fails (AES-GCM tag) on a wrong key or a
/// tampered blob.
pub fn unseal_primes_bytes(sealed: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    crate::presig_at_rest::unseal_presig_bytes(sealed, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presig_at_rest::derive_presig_at_rest_key;
    use crate::share::derive_share_encryption_key;
    use crate::types::SessionId;

    const ROOT: [u8; 32] = [0x42; 32];
    // Stand-in for a serialized `PregeneratedPrimes` JSON blob.
    const PLAINTEXT: &[u8] = b"{\"p\":\"deadbeef...\",\"q\":\"cafebabe...\"} seeded primes";

    #[test]
    fn seal_unseal_roundtrip() {
        let key = derive_primes_at_rest_key(&ROOT, "sess-001");
        let sealed = seal_primes_bytes(PLAINTEXT, &key).unwrap();
        assert_eq!(unseal_primes_bytes(&sealed, &key).unwrap(), PLAINTEXT);
    }

    #[test]
    fn sealed_blob_is_not_plaintext_recoverable() {
        let key = derive_primes_at_rest_key(&ROOT, "sess-001");
        let sealed = seal_primes_bytes(PLAINTEXT, &key).unwrap();
        assert_ne!(sealed, PLAINTEXT);
        assert!(
            !sealed.windows(PLAINTEXT.len()).any(|w| w == PLAINTEXT),
            "sealed primes blob must not contain the plaintext"
        );
    }

    #[test]
    fn wrong_key_fails_unseal() {
        let key = derive_primes_at_rest_key(&ROOT, "sess-001");
        let other = derive_primes_at_rest_key(&ROOT, "sess-002");
        let sealed = seal_primes_bytes(PLAINTEXT, &key).unwrap();
        assert!(
            unseal_primes_bytes(&sealed, &other).is_err(),
            "a different session_id derives a different key → unseal must fail"
        );
    }

    #[test]
    fn key_domain_is_separated_from_presig_and_share() {
        // Same root + same variable input must derive DISTINCT keys across the three
        // at-rest domains (primes vs presig vs DKG-share).
        let primes = derive_primes_at_rest_key(&ROOT, "x");
        let presig = derive_presig_at_rest_key(&ROOT, "x");
        assert_ne!(
            primes, presig,
            "primes vs presig at-rest key domains must differ"
        );
        let sid = SessionId([0x01; 32]);
        let share = derive_share_encryption_key(&ROOT, &sid);
        assert_ne!(
            *share, primes,
            "primes vs DKG-share key domains must differ"
        );
    }
}
