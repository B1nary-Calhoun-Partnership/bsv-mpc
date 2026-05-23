//! §18.5 / ADR-0038 recovery KDF — Argon2id passphrase → KEK.
//!
//! Catastrophic recovery (MPC-Spec §18.5, case (c): 2 of 3 cosigners
//! simultaneously fail, user holds only share A) collapses the threshold to
//! "user types a recovery passphrase." That passphrase MUST NOT be fed through
//! a memory-cheap KDF (plain HKDF/HMAC/PBKDF2 are GPU-grindable at ~10^8
//! attempts/sec). Per ADR-0038 the passphrase is stretched with **Argon2id**
//! (RFC 9106, version 19 / `0x13`) into a 32-byte key-encryption key (KEK) used
//! directly as the AES-256-GCM key for the encrypted backup blob.
//!
//! Two parameter profiles are normative (ADR-0038 §1):
//!
//! - [`RecoveryProfile::Server`] — desktop / web wallet recovery:
//!   `m = 256 MiB (262144 KiB), t = 3, p = 1`.
//! - [`RecoveryProfile::Mobile`] — mobile flows where 256 MiB is prohibitive:
//!   `m = 64 MiB (65536 KiB), t = 4, p = 1` (lower memory, higher iteration
//!   count to keep grinding cost roughly equivalent).
//!
//! No associated data and no secret key (pepper) are used — the salt is the
//! only non-passphrase input, and it MUST be per-blob random in production
//! (ADR-0038 §2). The conformance vectors use deterministic test-only salts.
//!
//! ## Normalization is the caller's responsibility
//!
//! The passphrase MUST be **NFC-normalized UTF-8 bytes** before it reaches this
//! module. Per MPC-Spec §18.5.1 and the ADR-0038 conformance notes, the
//! implementation **MUST NOT** re-normalize (to NFD / NFKC or otherwise) — it
//! hashes exactly the bytes it is given. Re-normalizing here would silently
//! diverge from `rust-mpc` and break cross-impl backup decrypt.

use crate::error::MpcError;
use argon2::{Algorithm, Argon2, Params, Version};

/// Argon2id KEK output length in bytes (used directly as an AES-256-GCM key).
const KEK_LEN: usize = 32;

/// Normative Argon2id parameter profiles for recovery-passphrase derivation
/// (ADR-0038 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryProfile {
    /// Desktop / web wallet recovery: `m = 256 MiB, t = 3, p = 1`.
    Server,
    /// Mobile recovery (256 MiB infeasible): `m = 64 MiB, t = 4, p = 1`.
    Mobile,
}

impl RecoveryProfile {
    /// Returns `(memory_cost_kib, time_cost, parallelism)` for this profile.
    #[must_use]
    pub fn params(self) -> (u32, u32, u32) {
        match self {
            // 256 MiB = 262144 KiB.
            RecoveryProfile::Server => (262_144, 3, 1),
            // 64 MiB = 65536 KiB.
            RecoveryProfile::Mobile => (65_536, 4, 1),
        }
    }
}

/// Derive the 32-byte recovery KEK from a passphrase + salt using the Argon2id
/// parameters of the given [`RecoveryProfile`].
///
/// `passphrase_nfc_utf8` MUST already be NFC-normalized UTF-8 bytes — see the
/// module docs. The implementation does not re-normalize.
///
/// # Errors
///
/// Returns [`MpcError::Protocol`] if the underlying Argon2id parameters or hash
/// step fail (e.g. an unsupported salt length for the configured params).
pub fn derive_recovery_kek(
    passphrase_nfc_utf8: &[u8],
    salt: &[u8],
    profile: RecoveryProfile,
) -> Result<[u8; KEK_LEN], MpcError> {
    let (m, t, p) = profile.params();
    derive_recovery_kek_raw(passphrase_nfc_utf8, salt, m, t, p)
}

/// Lower-level Argon2id KEK derivation with explicit cost parameters.
///
/// This is the self-describing path used by the conformance harness, which
/// passes the byte-locked `memory_cost_kib` / `time_cost` / `parallelism`
/// straight from the vector. [`derive_recovery_kek`] is a thin wrapper that
/// supplies a [`RecoveryProfile`]'s parameters.
///
/// Always Argon2id, version 19 (`0x13`), 32-byte output, no AAD, no secret.
///
/// # Errors
///
/// Returns [`MpcError::Protocol`] if `Params::new` rejects the inputs or the
/// Argon2id hash step fails.
pub fn derive_recovery_kek_raw(
    passphrase: &[u8],
    salt: &[u8],
    memory_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<[u8; KEK_LEN], MpcError> {
    let params = Params::new(memory_cost_kib, time_cost, parallelism, Some(KEK_LEN))
        .map_err(|e| MpcError::Protocol(format!("argon2 params invalid: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut kek = [0u8; KEK_LEN];
    argon
        .hash_password_into(passphrase, salt, &mut kek)
        .map_err(|e| MpcError::Protocol(format!("argon2id hash failed: {e}")))?;
    Ok(kek)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mobile params keep tests fast (64 MiB vs 256 MiB).
    const SALT_A: &[u8; 32] = &[0x11; 32];
    const SALT_B: &[u8; 32] = &[0x22; 32];

    #[test]
    fn different_salt_yields_different_kek() {
        let pass = b"correct horse battery staple";
        let a = derive_recovery_kek(pass, SALT_A, RecoveryProfile::Mobile).unwrap();
        let b = derive_recovery_kek(pass, SALT_B, RecoveryProfile::Mobile).unwrap();
        assert_ne!(a, b, "per-blob salt must change the KEK (ADR-0038 §2)");
    }

    #[test]
    fn derivation_is_deterministic() {
        let pass = b"alice loves bob";
        let a = derive_recovery_kek(pass, SALT_A, RecoveryProfile::Mobile).unwrap();
        let b = derive_recovery_kek(pass, SALT_A, RecoveryProfile::Mobile).unwrap();
        assert_eq!(a, b, "same passphrase + salt + profile must reproduce");
    }

    #[test]
    fn profile_params_match_adr_0038() {
        assert_eq!(RecoveryProfile::Server.params(), (262_144, 3, 1));
        assert_eq!(RecoveryProfile::Mobile.params(), (65_536, 4, 1));
        assert_ne!(
            RecoveryProfile::Server.params(),
            RecoveryProfile::Mobile.params()
        );
    }

    #[test]
    fn raw_matches_profile_for_mobile_params() {
        let pass = b"alice loves bob";
        let via_profile = derive_recovery_kek(pass, SALT_A, RecoveryProfile::Mobile).unwrap();
        let via_raw = derive_recovery_kek_raw(pass, SALT_A, 65_536, 4, 1).unwrap();
        assert_eq!(via_profile, via_raw);
    }
}
