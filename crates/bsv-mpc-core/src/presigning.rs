//! Background presignature stockpiling for low-latency online signing.
//!
//! Presignatures are the key optimization in CGGMP'24. By running the expensive
//! nonce generation and proof exchange *before* the message to sign is known,
//! the actual online signing phase reduces to a single round of communication.
//!
//! ## Presigning Protocol (3 rounds)
//!
//! The offline presigning protocol generates a presignature `(k, R)` where:
//! - `k` is a secret nonce shared across the signing group (no party knows the full `k`)
//! - `R = k * G` is the corresponding public nonce point
//!
//! The 3 rounds are:
//!
//! 1. **Round 1**: Each party generates a random nonce share `k_i` and a
//!    random masking value `gamma_i`. Broadcasts commitments to both.
//!
//! 2. **Round 2**: Decommit values. Each pair of parties runs a multiplicative-
//!    to-additive (MtA) sub-protocol to convert their multiplicative shares
//!    `k_i * gamma_j` into additive shares. This is the most computationally
//!    expensive step (Paillier-based MtA).
//!
//! 3. **Round 3**: Each party broadcasts `delta_i = k_i * gamma_i + sum(MtA shares)`.
//!    The joint `delta = sum(delta_i)` allows computing `R = delta^-1 * Gamma`
//!    where `Gamma = sum(gamma_i * G)`.
//!
//! ## Stockpiling Strategy
//!
//! The `PresigningManager` maintains a pool of ready-to-use presignatures.
//! When the pool drops below half capacity, new presignatures should be
//! generated in the background. This ensures signing requests are never
//! blocked waiting for the 3-round offline phase.
//!
//! Typical pool sizes:
//! - Single agent: 5-10 presignatures
//! - High-throughput wallet: 50-100 presignatures
//! - Each presignature is ~500 bytes serialized

use crate::error::Result;
use crate::types::{Presignature, SessionId};

/// Manages a pool of presignatures for a single MPC session.
///
/// The manager tracks available presignatures and provides methods to generate
/// new ones and consume them for signing. Presignatures are consumed in FIFO
/// order (oldest first).
///
/// # Example (pseudocode)
///
/// ```ignore
/// let mut mgr = PresigningManager::new(session_id, 10);
///
/// // Background: keep the pool topped up
/// while mgr.should_replenish() {
///     mgr.generate().await?;
/// }
///
/// // Foreground: consume for signing
/// if let Some(presig) = mgr.take() {
///     let result = coordinator.sign(&sighash, Some(presig)).await?;
/// }
/// ```
pub struct PresigningManager {
    /// Pool of ready-to-use presignatures (FIFO order).
    pool: Vec<Presignature>,
    /// Maximum number of presignatures to maintain in the pool.
    max_pool_size: usize,
    /// The MPC session these presignatures belong to.
    session_id: SessionId,
    // TODO: Add cggmp24 presigning state fields:
    // - `share: EncryptedShare` — this party's key share (needed for presigning)
    // - `config: ThresholdConfig` — threshold config
    // - `my_index: ShareIndex` — this party's index
}

impl PresigningManager {
    /// Create a new presigning manager with an empty pool.
    ///
    /// # Arguments
    ///
    /// * `session_id` — The MPC session to generate presignatures for.
    /// * `max_pool_size` — Maximum number of presignatures to stockpile.
    pub fn new(session_id: SessionId, max_pool_size: usize) -> Self {
        Self {
            pool: Vec::with_capacity(max_pool_size),
            max_pool_size,
            session_id,
        }
    }

    /// Run the 3-round presigning protocol and add the result to the pool.
    ///
    /// This is a cooperative protocol — it requires communication with `t-1`
    /// other parties. The caller is responsible for routing `RoundMessage`s
    /// between parties (via the transport layer in `bsv-mpc-worker`).
    ///
    /// # Protocol Steps
    ///
    /// 1. Generate nonce share `k_i` and masking value `gamma_i`
    /// 2. Run MtA sub-protocol with each other party
    /// 3. Broadcast delta share and compute joint nonce point
    /// 4. Serialize the resulting presignature state
    ///
    /// # Errors
    ///
    /// Returns [`MpcError::Protocol`] if the presigning protocol fails
    /// (e.g., a party provides invalid proofs).
    pub async fn generate(&mut self) -> Result<()> {
        todo!(
            "cggmp24 integration: \
             1. Decrypt this party's key share from self.share \
             2. Initialize cggmp24 presigning state machine for session {} \
             3. Round 1: generate k_i, gamma_i, broadcast commitments \
             4. Round 2: run MtA sub-protocol (Paillier-based) with each co-signer \
                - This converts multiplicative shares k_i * gamma_j into additive shares \
                - Most computationally expensive step (~100ms per party pair) \
             5. Round 3: compute delta_i = k_i * gamma_i + sum(MtA additive shares) \
                - Broadcast delta_i \
                - Compute joint delta = sum(delta_i) \
                - Compute R = delta^-1 * Gamma where Gamma = sum(gamma_i * G) \
             6. Serialize presigning state (k_i share, R, proofs) into opaque bytes \
             7. Create Presignature {{ id: uuid, session_id, data: serialized, created_at: now }} \
             8. Push to self.pool \
             9. Zeroize intermediate values (k_i, gamma_i, MtA shares) \
             \
             Session: {}, pool: {}/{}",
            self.session_id,
            self.session_id,
            self.pool.len(),
            self.max_pool_size
        )
    }

    /// Take one presignature from the pool for use in online signing.
    ///
    /// Presignatures are consumed in FIFO order (oldest first). Each
    /// presignature can only be used once — reusing a presignature would
    /// leak the private key (nonce reuse attack).
    ///
    /// Returns `None` if the pool is empty. In that case, the caller should
    /// either wait for [`generate`](Self::generate) to complete or fall back
    /// to the 4-round interactive signing protocol.
    pub fn take(&mut self) -> Option<Presignature> {
        if self.pool.is_empty() {
            None
        } else {
            // Remove from the front (FIFO — oldest first).
            Some(self.pool.remove(0))
        }
    }

    /// Get the current number of available presignatures.
    pub fn pool_size(&self) -> usize {
        self.pool.len()
    }

    /// Check whether the pool should be replenished.
    ///
    /// Returns `true` if the pool has fewer than half its maximum capacity.
    /// The caller should trigger background presigning when this returns `true`.
    pub fn should_replenish(&self) -> bool {
        self.pool.len() < self.max_pool_size / 2
    }

    /// Get the maximum pool size.
    pub fn max_pool_size(&self) -> usize {
        self.max_pool_size
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}
