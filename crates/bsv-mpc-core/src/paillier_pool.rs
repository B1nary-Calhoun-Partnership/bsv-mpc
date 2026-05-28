//! Paillier safe-prime keypair pool — MPC-Spec §06.10.1 / ADR-0041.
//!
//! At-rest-encrypted pool of pre-generated 2048-bit Paillier safe-prime
//! keypairs, consumed by [`crate::dkg::DkgCoordinator`]'s auxinfo phase
//! (and by `key_refresh` ceremonies). Reduces `aux_info_gen` p99 on
//! `profile-edge` / `profile-mobile` from ~33s to ~6s (5-6x speedup,
//! per [ADR-0041 §06.10.1](../../MPC-Spec/decisions/0041-network-profile-latency-budgets.md)).
//!
//! Empirically validated by `poc/poc16-sm-inline/` gates G-3.3 / G-3.4
//! before this production module landed:
//!
//! - **Pool round-trip preserves `PregeneratedPrimes` byte-for-byte.**
//!   `cggmp24::aux_info_gen` is itself non-deterministic on internal
//!   RNG state (ZK proof nonces), so the testable invariant is the
//!   pool's contract (primes go in, the same primes come out) rather
//!   than protocol-output equality. See gate G-3.3.
//! - **At-rest ciphertext is non-plaintext.** AES-256-GCM with a
//!   BRC-42 HMAC-derived key (mirrors [`crate::share`] §16.1
//!   share-encryption pattern). See gate G-3.4.
//!
//! ## Encryption pattern
//!
//! ```text
//! encryption_key = HMAC-SHA256(root_key, "bsv-mpc-paillier-pool" || pool_id)
//! ciphertext     = AES-256-GCM(encryption_key, nonce_random_12B, plaintext)
//! plaintext      = serde_json::to_vec(&PregeneratedPrimes)
//! ```
//!
//! ## Storage abstraction
//!
//! [`PrimePoolStorage`] is a `Send + Sync` trait (default OQ3 from
//! `docs/PHASE-G-AUDIT.md`). Phase G ships [`InMemoryPoolStorage`]
//! for use in `bsv-mpc-service` and tests; Phase I will add a D1-backed
//! impl for the deployed CF Worker.
//!
//! ## Usage
//!
//! ```ignore
//! use bsv_mpc_core::paillier_pool::{InMemoryPoolStorage, PaillierPool};
//!
//! let pool = PaillierPool::new(
//!     InMemoryPoolStorage::new(),
//!     &root_key,
//!     identity_key.as_bytes(),
//!     /* floor = */ 2,
//! );
//! pool.backfill_to_floor(&mut rand::rngs::OsRng)?;
//! // Later, in DKG aux_info phase:
//! let primes = pool.take()?;  // None → caller falls back to inline gen
//! ```

use std::sync::Mutex;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use cggmp24::key_refresh::PregeneratedPrimes;
use cggmp24::security_level::SecurityLevel128;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{MpcError, Result};

/// Domain separator for the BRC-42 HMAC-SHA256 key derivation used by
/// this module. Distinct from [`crate::share::SHARE_KEY_DOMAIN`] so
/// pool-encryption keys and share-encryption keys never collide even
/// if a caller passes the same `root_key` to both.
const POOL_KEY_DOMAIN: &[u8] = b"bsv-mpc-paillier-pool";

/// Recommended pool-size floor per [MPC-Spec §06.10.1](https://...).
/// Two pre-generated keypairs is enough to cover a single ceremony's
/// 2-party auxinfo without falling back to inline generation.
pub const DEFAULT_FLOOR: usize = 2;

/// Process-global serialization gate for 2048-bit Paillier safe-prime
/// generation.
///
/// Each `PregeneratedPrimes::generate` has a multi-GiB transient RSS peak
/// (`num-bigint`, no GMP). On a memory-capped host running N generations
/// concurrently, those peaks SUM — and a Cloudflare Container caps at 12 GiB
/// with **no swap**, so the kernel OOM-kills the instance, wiping the
/// in-memory MPC coordinator state and hanging every in-flight ceremony
/// (the #40 / #58 deployed instability — see
/// `docs/HANDOFF-40-deployed-reshare-fixed.md` §0 "CF CONTAINERS ROOT CAUSE").
///
/// Routing every generation through this gate guarantees only ONE generation's
/// RSS peak is live at a time (never N-parallel). Pair it with
/// `MALLOC_ARENA_MAX=2` in the deployed image so glibc returns the freed arenas
/// to the OS between sequential generations instead of retaining them.
static PRIME_GEN_GATE: Mutex<()> = Mutex::new(());

/// Generate one set of 2048-bit Paillier safe primes while holding the
/// process-global [`PRIME_GEN_GATE`], so no two generations' RSS peaks overlap
/// within this process.
///
/// **Blocking** — `generate` is heavily CPU-bound (1-30s); call it from a
/// blocking context (e.g. `tokio::task::spawn_blocking`) or a dedicated thread,
/// never directly on an async runtime worker. The gate is a plain
/// `std::sync::Mutex`: a second caller blocks until the first finishes, which is
/// exactly the serialization we want (and is wasm-safe — wasm32 is
/// single-threaded so the gate is uncontended there).
pub fn generate_serialized<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> PregeneratedPrimes<SecurityLevel128> {
    let _gate = PRIME_GEN_GATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    PregeneratedPrimes::<SecurityLevel128>::generate(rng)
}

/// At-rest ciphertext blob format.
///
/// `nonce` is the random per-`put` AES-GCM nonce; `ciphertext` is
/// `AES-256-GCM(encryption_key, nonce, serialized_primes)`.
///
/// `#[derive(Zeroize, ZeroizeOnDrop)]` (#80): wipe the blob on drop so neither the
/// nonce nor the encrypted prime bytes linger in freed heap. This also wipes the
/// at-rest blobs held in [`InMemoryPoolStorage`]'s `Vec` transitively when that
/// storage drops (a `Mutex<Vec<_>>` can't itself derive `Zeroize`).
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedPrimes {
    /// AES-GCM 12-byte nonce.
    pub nonce: [u8; 12],
    /// AES-GCM ciphertext + 16-byte authentication tag (appended).
    pub ciphertext: Vec<u8>,
}

/// Storage abstraction. Phase G ships [`InMemoryPoolStorage`]; Phase I
/// will add `D1PoolStorage` for the deployed CF Worker. Implementations
/// must preserve FIFO ordering (the pool drains oldest-first so primes
/// don't sit indefinitely encrypted with a key that may rotate).
pub trait PrimePoolStorage: Send + Sync {
    /// Append an encrypted blob to the end of the queue.
    fn put_encrypted(&self, blob: EncryptedPrimes) -> Result<()>;

    /// Remove and return the oldest encrypted blob, or `None` if empty.
    fn take_encrypted(&self) -> Result<Option<EncryptedPrimes>>;

    /// Number of blobs currently stored.
    fn count(&self) -> Result<usize>;
}

/// In-memory FIFO pool storage. Suitable for `bsv-mpc-service`
/// (in-process daemon) and tests. Not durable across restarts —
/// production CF Worker deployments use `D1PoolStorage` (Phase I).
pub struct InMemoryPoolStorage {
    inner: Mutex<Vec<EncryptedPrimes>>,
}

impl InMemoryPoolStorage {
    /// Construct an empty in-memory pool.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
        }
    }
}

impl Default for InMemoryPoolStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl PrimePoolStorage for InMemoryPoolStorage {
    fn put_encrypted(&self, blob: EncryptedPrimes) -> Result<()> {
        self.inner
            .lock()
            .map_err(|e| MpcError::ShareStorage(format!("pool mutex poisoned: {e}")))?
            .push(blob);
        Ok(())
    }

    fn take_encrypted(&self) -> Result<Option<EncryptedPrimes>> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| MpcError::ShareStorage(format!("pool mutex poisoned: {e}")))?;
        if guard.is_empty() {
            Ok(None)
        } else {
            Ok(Some(guard.remove(0)))
        }
    }

    fn count(&self) -> Result<usize> {
        Ok(self
            .inner
            .lock()
            .map_err(|e| MpcError::ShareStorage(format!("pool mutex poisoned: {e}")))?
            .len())
    }
}

/// Paillier safe-prime keypair pool.
///
/// Wraps a [`PrimePoolStorage`] backend with the AES-256-GCM
/// encryption key and the floor policy. Pool consumers (e.g.
/// [`crate::dkg::DkgCoordinator::with_pool`]) see only the
/// `take` / `put` / `backfill_to_floor` surface.
pub struct PaillierPool<S: PrimePoolStorage> {
    storage: S,
    /// `Zeroizing<[u8; 32]>` (#80 TYPE LOCK): the AES-256-GCM pool key is the one
    /// plaintext secret this struct holds at rest. Wiped on `Drop`, and a refactor
    /// can't copy it out to a raw `[u8; 32]` without breaking the build.
    encryption_key: Zeroizing<[u8; 32]>,
    floor: usize,
}

impl<S: PrimePoolStorage> PaillierPool<S> {
    /// Construct a pool with a BRC-42-HMAC-derived encryption key.
    ///
    /// # Arguments
    ///
    /// * `storage` — backend implementation (e.g. [`InMemoryPoolStorage`]).
    /// * `root_key` — caller's 32-byte root encryption key (typically
    ///   derived from the cosigner's identity private key via the
    ///   wallet's `getPublicKey` / BRC-42 chain). Same shape as
    ///   [`crate::share::derive_share_encryption_key`]'s `root_key`.
    /// * `pool_id` — domain-separation bytes (typically the cosigner's
    ///   identity pubkey bytes). Distinct pools must use distinct
    ///   `pool_id`s or their encryption keys collide.
    /// * `floor` — minimum pool size that backfill triggers should
    ///   maintain. [`DEFAULT_FLOOR`] (=2) per ADR-0041.
    pub fn new(storage: S, root_key: &[u8; 32], pool_id: &[u8], floor: usize) -> Self {
        let encryption_key = derive_pool_key(root_key, pool_id);
        Self {
            storage,
            encryption_key,
            floor,
        }
    }

    /// Pull one pregenerated keypair from the pool. Returns `None` if
    /// the pool is empty — caller's expected fallback is inline
    /// `PregeneratedPrimes::generate(rng)` (cggmp24 internal).
    pub fn take(&self) -> Result<Option<PregeneratedPrimes<SecurityLevel128>>> {
        let Some(blob) = self.storage.take_encrypted()? else {
            return Ok(None);
        };
        let plaintext = decrypt(&self.encryption_key, &blob)?;
        let primes: PregeneratedPrimes<SecurityLevel128> = serde_json::from_slice(&plaintext)
            .map_err(|e| MpcError::Serialization(format!("decode pregenerated primes: {e}")))?;
        Ok(Some(primes))
    }

    /// Put a keypair into the pool, encrypting at rest.
    pub fn put(&self, primes: PregeneratedPrimes<SecurityLevel128>) -> Result<()> {
        // #80: the serialized prime plaintext is the decrypted secret material —
        // hold it in `Zeroizing` so it's wiped once encrypted at rest.
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&primes)
                .map_err(|e| MpcError::Serialization(format!("encode pregenerated primes: {e}")))?,
        );
        let blob = encrypt(&self.encryption_key, &plaintext)?;
        self.storage.put_encrypted(blob)?;
        Ok(())
    }

    /// Run one backfill cycle: while `count < floor`, generate fresh
    /// safe primes and put them in the pool. Synchronous — the caller
    /// owns scheduling (eager at startup for long-lived `bsv-mpc-service`;
    /// DO `alarm()` for the deployed CF Worker in Phase I).
    ///
    /// Returns the number of new keypairs added.
    ///
    /// **Wall-clock**: each `PregeneratedPrimes::generate` produces 4
    /// independent 2048-bit safe primes; each takes 1-3s on desktop,
    /// 5-15s on ARM mobile (per ADR-0041 §06.10.3). With `floor = 2`,
    /// a cold backfill takes ~10-25s desktop, ~40-120s mobile.
    pub fn backfill_to_floor<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<usize> {
        let mut added = 0;
        while self.storage.count()? < self.floor {
            // Serialized so a concurrent ceremony's inline aux-gen and this
            // backfill never spike the process RSS in parallel (OOM guard).
            let primes = generate_serialized(rng);
            self.put(primes)?;
            added += 1;
        }
        Ok(added)
    }

    /// Read-through accessor for the storage layer. Exposed primarily
    /// for tests (which inspect ciphertext to assert encryption is
    /// applied).
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// The configured floor — minimum pool size that `backfill_to_floor`
    /// maintains.
    pub fn floor(&self) -> usize {
        self.floor
    }
}

// ----- crypto helpers (BRC-42 HMAC-SHA256 + AES-256-GCM) -----

fn derive_pool_key(root_key: &[u8; 32], pool_id: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(root_key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(POOL_KEY_DOMAIN);
    mac.update(pool_id);
    let result = mac.finalize();
    // Build straight into `Zeroizing` (#80) so the derived key never sits in an
    // un-wiped raw `[u8; 32]`.
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&result.into_bytes());
    key
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedPrimes> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| MpcError::Encryption(format!("pool put encrypt: {e}")))?;
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce.as_slice());
    Ok(EncryptedPrimes {
        nonce: nonce_arr,
        ciphertext,
    })
}

fn decrypt(key: &[u8; 32], blob: &EncryptedPrimes) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&blob.nonce);
    // #80: the decrypted prime material is wrapped in `Zeroizing` so it's wiped when
    // the caller's `plaintext` goes out of scope (mirrors `share::decrypt_share`).
    cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map(Zeroizing::new)
        .map_err(|e| MpcError::Encryption(format!("pool take decrypt: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cggmp24::backend::Integer;
    use cggmp24::security_level::SecurityLevel;
    use rand::RngCore;

    /// Generate a `PregeneratedPrimes` using Blum primes (`p ≡ 3 mod 4`),
    /// which are faster to generate than safe primes. Acceptable for
    /// CGGMP'24 correctness per `poc/poc2-wasm/src/lib.rs:29-52` and
    /// `crates/bsv-mpc-core/src/dkg.rs:1129` (the same test helper
    /// already used to keep `aux_info_gen` tests tractable).
    fn generate_blum_primes<R: RngCore>(rng: &mut R) -> PregeneratedPrimes<SecurityLevel128> {
        let bitsize = SecurityLevel128::RSA_PRIME_BITLEN;
        let primes = [
            gen_blum(rng, bitsize),
            gen_blum(rng, bitsize),
            gen_blum(rng, bitsize),
            gen_blum(rng, bitsize),
        ];
        PregeneratedPrimes::try_from(primes).expect("Blum primes have correct bit size")
    }

    fn gen_blum<R: RngCore>(rng: &mut R, bitsize: u32) -> Integer {
        loop {
            let n = Integer::generate_prime(rng, bitsize);
            if n.mod_u(4) == 3 {
                break n;
            }
        }
    }

    #[test]
    fn put_then_take_round_trips_primes_byte_for_byte() {
        let mut rng = rand::rngs::OsRng;
        let primes_orig = generate_blum_primes(&mut rng);
        let primes_before = serde_json::to_vec(&primes_orig).unwrap();

        let pool = PaillierPool::new(
            InMemoryPoolStorage::new(),
            &[0x11u8; 32],
            b"test-pool-id",
            DEFAULT_FLOOR,
        );
        pool.put(primes_orig).unwrap();
        let primes_back = pool.take().unwrap().expect("non-empty after put");
        let primes_after = serde_json::to_vec(&primes_back).unwrap();

        assert_eq!(
            primes_before, primes_after,
            "pool round-trip must be byte-identical"
        );
    }

    #[test]
    fn take_on_empty_returns_none() {
        let pool = PaillierPool::new(
            InMemoryPoolStorage::new(),
            &[0u8; 32],
            b"empty-test",
            DEFAULT_FLOOR,
        );
        assert!(pool.take().unwrap().is_none());
    }

    #[test]
    fn at_rest_blob_is_non_plaintext() {
        let mut rng = rand::rngs::OsRng;
        let primes = generate_blum_primes(&mut rng);
        let plaintext = serde_json::to_vec(&primes).unwrap();

        let pool = PaillierPool::new(
            InMemoryPoolStorage::new(),
            &[0x42u8; 32],
            b"ciphertext-check",
            DEFAULT_FLOOR,
        );
        pool.put(primes).unwrap();
        let stored = pool.storage().take_encrypted().unwrap().expect("non-empty");

        assert_ne!(
            stored.ciphertext, plaintext,
            "stored ciphertext must NOT equal plaintext — encryption broken?"
        );
        // AES-GCM appends a 16-byte authentication tag, so ciphertext is
        // exactly plaintext.len() + 16 bytes.
        assert_eq!(
            stored.ciphertext.len(),
            plaintext.len() + 16,
            "AES-256-GCM should add exactly 16 bytes of authentication tag"
        );
        assert_ne!(stored.nonce, [0u8; 12], "nonce must be random, not zero");
    }

    #[test]
    fn backfill_to_floor_uses_real_safe_primes() {
        // Use floor=1 to keep wall-clock tractable (one safe-prime
        // PregeneratedPrimes set takes 5-30s on commodity hardware).
        let pool = PaillierPool::new(
            InMemoryPoolStorage::new(),
            &[0x99u8; 32],
            b"backfill-test",
            1,
        );
        let mut rng = rand::rngs::OsRng;

        assert_eq!(pool.storage().count().unwrap(), 0);
        let added = pool.backfill_to_floor(&mut rng).unwrap();
        assert_eq!(added, 1);
        assert_eq!(pool.storage().count().unwrap(), 1);

        // Re-check: no-op when already at floor.
        let added2 = pool.backfill_to_floor(&mut rng).unwrap();
        assert_eq!(added2, 0);
        assert_eq!(pool.storage().count().unwrap(), 1);
    }

    #[test]
    fn distinct_pool_ids_produce_distinct_encryption_keys() {
        let root_key = [0x55u8; 32];
        let key_a = derive_pool_key(&root_key, b"party-0");
        let key_b = derive_pool_key(&root_key, b"party-1");
        assert_ne!(
            key_a.as_slice(),
            key_b.as_slice(),
            "different pool_ids must derive different encryption keys"
        );
    }

    #[test]
    fn share_domain_and_pool_domain_separate() {
        // Sanity check: the pool's domain prefix is distinct from
        // share.rs SHARE_KEY_DOMAIN. Different domains → different
        // derived keys for the same (root_key, pool_id/session_id).
        let root_key = [0xABu8; 32];
        let pool_key = derive_pool_key(&root_key, b"common-id");

        // Inline a domain-only HMAC to mimic share.rs's compute.
        let mut share_mac = <Hmac<Sha256> as Mac>::new_from_slice(&root_key).unwrap();
        share_mac.update(b"bsv-mpc-share");
        share_mac.update(b"common-id");
        let share_result = share_mac.finalize().into_bytes();

        assert_ne!(
            pool_key.as_slice(),
            share_result.as_slice(),
            "pool and share key derivations must be domain-separated"
        );
    }

    // ----------------------------------------------------------------
    // Zeroize (#80) — mirror of the `share.rs:568` TYPE-LOCK proof plan.
    //
    //   (1) OBSERVABLE: `EncryptedPrimes::zeroize` actually clears the nonce +
    //       ciphertext bytes — the SAME wipe `ZeroizeOnDrop` runs on drop (and
    //       transitively on each blob held in `InMemoryPoolStorage`'s `Vec`).
    //   (2) TYPE LOCK: `PaillierPool::encryption_key` is `Zeroizing<[u8; 32]>`,
    //       `derive_pool_key` returns `Zeroizing<[u8; 32]>`, and the `decrypt` /
    //       `put` plaintext is `Zeroizing<Vec<u8>>`. These compile only while the
    //       wrapper is present, so a refactor cannot silently leak the decrypted
    //       prime material (or the pool key) into a raw, un-wiped buffer.
    // ----------------------------------------------------------------

    #[test]
    fn encrypted_primes_zeroize_clears_nonce_and_ciphertext() {
        let mut blob = EncryptedPrimes {
            nonce: [0xABu8; 12],
            ciphertext: vec![0xCDu8; 64],
        };
        // Precondition: the secret bytes are present.
        assert_ne!(blob.nonce, [0u8; 12]);
        assert!(!blob.ciphertext.is_empty());

        blob.zeroize(); // the same routine `ZeroizeOnDrop` runs on drop

        assert_eq!(blob.nonce, [0u8; 12], "#80: blob nonce MUST be wiped");
        assert!(
            blob.ciphertext.is_empty(),
            "#80: blob ciphertext MUST be wiped (Zeroize clears + truncates the Vec)"
        );
    }
}
