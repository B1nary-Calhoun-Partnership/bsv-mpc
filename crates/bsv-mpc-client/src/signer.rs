//! The client's secret signing hot path.
//!
//! The device [`KeyStore`](crate::KeyStore) seals the agent's cggmp24 key-share
//! material; [`unseal_signing_scalar`] unseals it under a **fresh biometric
//! prompt** and extracts the secret signing scalar via `bsv_mpc_core::ecdh`,
//! holding it as [`Zeroizing`]`<[u8; 32]>` (wiped on drop) the entire time.
//!
//! This is the security-critical, novel part of the native client. The live
//! 2-party ECDSA ceremony that *consumes* this scalar rides the relay seam
//! ([`ChainServices`](crate::ChainServices), Phase 4); the on-chain signature
//! from a real device is the Phase 5 capstone. Both halves are deliberately
//! separated so the secret-handling boundary is provable on its own.

use zeroize::Zeroizing;

use crate::error::ClientError;
use crate::keystore::KeyStore;

/// Biometric-gated unseal of the agent's share material → the raw signing scalar
/// as `Zeroizing<[u8; 32]>`.
///
/// `reason` is the biometric prompt string. The unsealed share JSON and the
/// extracted scalar are both `Zeroizing`, so they are wiped when this function's
/// scope (and the caller's binding) drop.
pub async fn unseal_signing_scalar(
    keystore: &dyn KeyStore,
    agent_id: &str,
    reason: &str,
) -> Result<Zeroizing<[u8; 32]>, ClientError> {
    // 1. Fresh-biometric unseal → device-decrypted cggmp24 key-share JSON.
    let share_json: Zeroizing<Vec<u8>> = keystore.unseal_share(agent_id, reason).await?;
    // 2. Extract the secret scalar. `parse_share_scalar` already returns
    //    `Zeroizing<[u8; 32]>` (bsv-mpc-core, hardened Finding 4), so the secret
    //    never exists as an un-wiped `[u8; 32]`.
    let scalar = bsv_mpc_core::ecdh::parse_share_scalar(&share_json)?;
    Ok(scalar)
}

// Native-only: builds a REAL cggmp24 share via trusted_dealer. Excluded from the
// wasm build (the lib code above is wasm-clean; only this test needs cggmp24).
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::keystore::InMemoryKeyStore;
    use cggmp24::security_level::SecurityLevel128;
    use cggmp24::supported_curves::Secp256k1;
    use generic_ec::{NonZero, Scalar, SecretScalar};

    // Same fixed key the core ecdh tests use (POC 3 / POC 9).
    const TEST_KEY: [u8; 32] = [
        0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2,
        0xf3, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1,
        0xf2, 0x03,
    ];

    /// A real 2-of-2 cggmp24 share JSON + the scalar `parse_share_scalar` should
    /// recover from it (the golden, computed straight from core).
    fn real_share_and_expected_scalar() -> (Vec<u8>, [u8; 32]) {
        let mut s = Scalar::<Secp256k1>::from_be_bytes(TEST_KEY).expect("valid scalar");
        let sk = NonZero::from_secret_scalar(SecretScalar::new(&mut s)).expect("non-zero");
        let shares = cggmp24::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(2)
            .set_threshold(Some(2))
            .set_shared_secret_key(sk)
            .generate_core_shares(&mut rand::rngs::OsRng)
            .expect("trusted dealer");
        let json = serde_json::to_vec(&shares[0]).expect("serialize share");
        let expected = bsv_mpc_core::ecdh::parse_share_scalar(&json).expect("parse");
        (json, *expected)
    }

    #[tokio::test]
    async fn unseal_recovers_the_real_signing_scalar_as_zeroizing() {
        let (share_json, expected) = real_share_and_expected_scalar();
        let ks = InMemoryKeyStore::new();
        ks.seal_share("agent-1", &share_json).await.unwrap();

        // The device-seal layer is transparent: unseal → parse recovers exactly
        // the share scalar, held as Zeroizing end-to-end.
        let scalar: Zeroizing<[u8; 32]> = unseal_signing_scalar(&ks, "agent-1", "Sign tx")
            .await
            .unwrap();
        assert_eq!(
            *scalar, expected,
            "recovered scalar must match the real share"
        );
    }

    #[tokio::test]
    async fn unseal_garbage_share_rejects_for_the_right_reason() {
        let ks = InMemoryKeyStore::new();
        ks.seal_share("agent-1", b"not a valid cggmp24 key share")
            .await
            .unwrap();
        // Validate-don't-skip: a bad share fails at parse, surfaced as Core.
        let err = unseal_signing_scalar(&ks, "agent-1", "Sign tx")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ClientError::Core(_)),
            "expected Core, got {err:?}"
        );
    }
}
