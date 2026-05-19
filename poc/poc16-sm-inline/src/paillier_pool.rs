//! Paillier safe-prime keypair pool — MPC-Spec §06.10.1 / ADR-0041.
//!
//! At-rest-encrypted pool of pre-generated 2048-bit Paillier safe-prime
//! keypairs, consumed by `aux_info_gen` and `key_refresh` ceremonies.
//! Per ADR-0041 § Consequences this targets the production location
//! `crates/bsv-mpc-core/src/paillier_pool.rs`; this POC validates the
//! shape (storage trait, AES-256-GCM at-rest, BRC-42 HMAC-derived key,
//! floor + backfill primitive) before that production module lands.
//!
//! Encryption pattern (default OQ2 — mirrors §16.1 share encryption):
//!
//! ```text
//! encryption_key = HMAC-SHA256(root_key, "bsv-mpc-paillier-pool" || pool_id)
//! ciphertext     = AES-256-GCM(encryption_key, nonce_random_12B, plaintext)
//! ```
//!
//! Plaintext format: `serde_json::to_vec(&PregeneratedPrimes)`.
//!
//! Storage shape (default OQ3 — `Send + Sync`):
//!
//! ```text
//! trait PrimePoolStorage: Send + Sync {
//!     fn put_encrypted(...);  // append a ciphertext blob
//!     fn take_encrypted();    // pop one ciphertext blob (FIFO)
//!     fn count();             // number of blobs currently stored
//! }
//! ```

use std::sync::Mutex;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use cggmp24::key_refresh::PregeneratedPrimes;
use cggmp24::security_level::SecurityLevel128;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

const KEY_DOMAIN: &[u8] = b"bsv-mpc-paillier-pool";

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("prime generation error: {0}")]
    PrimeGen(String),
}

/// At-rest blob format. `nonce` is the AES-GCM nonce (random per-put);
/// `ciphertext` is `AES-256-GCM(encryption_key, nonce, serialized_primes)`.
#[derive(Clone, Debug)]
pub struct EncryptedPrimes {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Storage abstraction. Phase G ships an in-memory impl (this module);
/// Phase I will add a `D1PoolStorage` for the deployed CF Worker.
pub trait PrimePoolStorage: Send + Sync {
    fn put_encrypted(&self, blob: EncryptedPrimes) -> Result<(), PoolError>;
    fn take_encrypted(&self) -> Result<Option<EncryptedPrimes>, PoolError>;
    fn count(&self) -> Result<usize, PoolError>;
}

/// In-memory pool storage (FIFO `Vec<EncryptedPrimes>` behind a mutex).
/// Suitable for `bsv-mpc-service` (in-process daemon) and for tests.
pub struct InMemoryPoolStorage {
    inner: Mutex<Vec<EncryptedPrimes>>,
}

impl InMemoryPoolStorage {
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
    fn put_encrypted(&self, blob: EncryptedPrimes) -> Result<(), PoolError> {
        self.inner
            .lock()
            .map_err(|e| PoolError::Storage(e.to_string()))?
            .push(blob);
        Ok(())
    }

    fn take_encrypted(&self) -> Result<Option<EncryptedPrimes>, PoolError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| PoolError::Storage(e.to_string()))?;
        if guard.is_empty() {
            Ok(None)
        } else {
            Ok(Some(guard.remove(0))) // FIFO
        }
    }

    fn count(&self) -> Result<usize, PoolError> {
        Ok(self
            .inner
            .lock()
            .map_err(|e| PoolError::Storage(e.to_string()))?
            .len())
    }
}

/// The pool itself. Wraps a storage backend with the encryption key and
/// the floor policy. Pool consumers (e.g., a `DkgCoordinator` calling
/// `.with_pool(&pool)`) only see the `take()` / `put()` /
/// `backfill_to_floor()` surface.
pub struct PaillierPool<S: PrimePoolStorage> {
    storage: S,
    encryption_key: [u8; 32],
    floor: usize,
}

impl<S: PrimePoolStorage> PaillierPool<S> {
    /// Construct a pool with a BRC-42-HMAC-derived encryption key.
    ///
    /// `root_key` — caller's 32-byte root (mirrors the share.rs entry).
    /// `pool_id`  — domain separator (e.g., wallet identity key bytes).
    /// `floor`    — minimum pool size before backfill triggers; per
    ///              ADR-0041 the recommended default is 2.
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
    /// `PregeneratedPrimes::generate(rng)`.
    pub fn take(&self) -> Result<Option<PregeneratedPrimes<SecurityLevel128>>, PoolError> {
        let Some(blob) = self.storage.take_encrypted()? else {
            return Ok(None);
        };
        let plaintext = decrypt(&self.encryption_key, &blob)?;
        let primes: PregeneratedPrimes<SecurityLevel128> = serde_json::from_slice(&plaintext)
            .map_err(|e| PoolError::Serialization(e.to_string()))?;
        Ok(Some(primes))
    }

    /// Put a freshly-generated keypair into the pool, encrypted at rest.
    pub fn put(&self, primes: PregeneratedPrimes<SecurityLevel128>) -> Result<(), PoolError> {
        let plaintext =
            serde_json::to_vec(&primes).map_err(|e| PoolError::Serialization(e.to_string()))?;
        let blob = encrypt(&self.encryption_key, &plaintext)?;
        self.storage.put_encrypted(blob)?;
        Ok(())
    }

    /// One backfill cycle: while count < floor, generate + put.
    /// Synchronous — caller schedules (eager at startup OR DO alarm in
    /// CF Worker context). Returns the number of new keypairs added.
    pub fn backfill_to_floor<R: RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<usize, PoolError> {
        let mut added = 0;
        while self.storage.count()? < self.floor {
            let primes = PregeneratedPrimes::<SecurityLevel128>::generate(rng);
            self.put(primes)?;
            added += 1;
        }
        Ok(added)
    }

    /// Read-through accessor for the storage layer (exposed so tests
    /// can confirm the at-rest blob is non-plaintext).
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Read-through accessor for the configured floor.
    pub fn floor(&self) -> usize {
        self.floor
    }
}

// ----- crypto helpers (BRC-42 HMAC-SHA256 + AES-256-GCM) -----

fn derive_pool_key(root_key: &[u8; 32], pool_id: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(root_key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(KEY_DOMAIN);
    mac.update(pool_id);
    let result = mac.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes());
    key
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedPrimes, PoolError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| PoolError::Encryption(e.to_string()))?;
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce.as_slice());
    Ok(EncryptedPrimes {
        nonce: nonce_arr,
        ciphertext,
    })
}

fn decrypt(key: &[u8; 32], blob: &EncryptedPrimes) -> Result<Vec<u8>, PoolError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&blob.nonce);
    cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|e| PoolError::Encryption(e.to_string()))
}
