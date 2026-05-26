//! Presignature pool management with background replenishment.
//!
//! The presignature pool is the key to low-latency MPC signing. The CGGMP'24
//! protocol splits signing into two phases:
//!
//! 1. **Presigning (offline, 3 rounds)**: Generate a reusable presignature
//!    during idle time. This is the expensive part (~200-300ms with KSS).
//!
//! 2. **Online signing (1 round)**: Given a presignature and a message hash,
//!    produce a full ECDSA signature in a single round (~50-100ms).
//!
//! By maintaining a pool of presignatures, the proxy can serve signing
//! requests at online-signing latency most of the time. The background
//! replenishment task refills the pool during idle periods.
//!
//! ## Pool sizing
//!
//! The pool size (`max_presignatures`) should be tuned based on expected
//! signing throughput:
//!
//! - **Low traffic** (1-2 signs/min): 5-10 presignatures
//! - **Medium traffic** (5-10 signs/min): 15-20 presignatures
//! - **High traffic** (>10 signs/min): 30+ presignatures
//!
//! The replenishment task triggers when the pool falls below 50% capacity.
//! Each replenishment generates one presignature per 5-second cycle.
//!
//! ## Thread safety
//!
//! The `PresignManager` is wrapped in `Arc<RwLock<...>>` in `AppState`.
//! Multiple handler tasks can concurrently read the pool size, but only
//! one can take/add presignatures at a time.

use std::any::Any;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bsv_mpc_core::types::Presignature;

use crate::burn_rate::{BurnRateRegulator, InvalidationReason};
use crate::server::AppState;

/// A pooled presignature plus its non-serializable raw output.
///
/// The relay **combiner** (the proxy) needs the full
/// `(Presignature, PresignaturePublicData)` from
/// [`bsv_mpc_core::presigning::PresigningManager::take_raw`] — the public data
/// is not `Serialize` and never crosses the proxy↔cosigner boundary (handoff
/// §1 / ADR-018). The serializable `presig` is retained for the legacy 1-round
/// HTTP sign path and for metadata/logging.
///
/// The raw output is `Box<dyn Any + Send>` (cggmp24's type-erased presig data),
/// which is `Send` but not `Sync`. The pool lives behind `AppState`'s
/// `Arc<RwLock<…>>`, which axum requires to be `Sync`, so the box is wrapped in
/// a `Mutex` purely as a `Sync` shim — it is never actually contended (the
/// entry is owned by the caller once removed from the pool, and the box is
/// moved out with `into_inner`).
pub struct PooledPresignature {
    /// The serializable presignature (legacy HTTP sign path; metadata).
    pub presig: Presignature,
    /// Type-erased `(Presignature, PresignaturePublicData)` for the relay
    /// combiner ([`crate::relay_sign::combine_sign_over_relay`]).
    raw: Mutex<Box<dyn Any + Send>>,
}

/// **§1 device-holds-(t−1) presig SET pool (issue #38).**
///
/// A FIFO pool where each entry is a correlated *set* of presignatures — one per
/// share THIS device holds, tagged `(party_index, raw box)` — all produced by a
/// SINGLE presign ceremony (so they share one `PresignaturePublicData`). The
/// device-holds relay combiner issues one local partial per entry and folds in
/// the external cosigner's partial over the relay
/// ([`crate::bridge::MpcBridge::sign_over_relay_device_holds`]).
///
/// Like [`PresignManager`], FIFO order MUST stay in lockstep with the external
/// cosigner's own presignature pool (both consume oldest-first) so each device
/// set is combined against its correlated cosigner presignature. The single-box
/// `PresignManager` is the `t−1 == 1` special case; this pool generalizes it to
/// the device-holds-many topology.
/// One pooled device presig: `(party_index, raw box behind a Sync shim)`. The
/// box is `Box<dyn Any + Send>` (Send, not Sync); the `Mutex` is purely a `Sync`
/// shim so the pool can live behind `AppState`'s `RwLock` (axum requires `Sync`)
/// — it is never actually contended.
type PooledDeviceEntry = (u16, Mutex<Box<dyn Any + Send>>);
/// A correlated set of device presigs — one entry per share the device holds.
type PooledDeviceSet = Vec<PooledDeviceEntry>;

pub struct DevicePresigSetPool {
    /// FIFO of correlated presig sets (one entry per device share).
    pool: std::collections::VecDeque<PooledDeviceSet>,
    /// Maximum number of SETS to retain.
    max_size: usize,
    /// Total sets added since startup (metrics).
    total_added: u64,
    /// Total sets consumed since startup (metrics).
    total_consumed: u64,
}

impl DevicePresigSetPool {
    /// Create a new device presig-set pool with the given maximum number of sets.
    pub fn new(max_size: usize) -> Self {
        Self {
            pool: std::collections::VecDeque::with_capacity(max_size),
            max_size,
            total_added: 0,
            total_consumed: 0,
        }
    }

    /// Add a correlated presig set (one entry per device share) to the back.
    /// Silently dropped if the pool is at capacity.
    pub fn add_set(&mut self, set: Vec<(u16, Box<dyn Any + Send>)>) {
        if self.pool.len() < self.max_size {
            self.pool.push_back(
                set.into_iter()
                    .map(|(idx, raw)| (idx, Mutex::new(raw)))
                    .collect(),
            );
            self.total_added += 1;
        } else {
            tracing::trace!(
                pool_size = self.pool.len(),
                max = self.max_size,
                "device presig-set pool full — dropping generated set"
            );
        }
    }

    /// Take the oldest presig set (FIFO), returning `(party_index, raw box)` per
    /// device share. `None` if empty.
    pub fn take_set(&mut self) -> Option<Vec<(u16, Box<dyn Any + Send>)>> {
        let set = self.pool.pop_front()?;
        self.total_consumed += 1;
        Some(
            set.into_iter()
                .map(|(idx, raw)| {
                    // We own the entry now; unwrap the Sync shim. `into_inner`
                    // only fails on a poisoned mutex, impossible here (never locked).
                    (
                        idx,
                        raw.into_inner()
                            .expect("device presig mutex never poisoned"),
                    )
                })
                .collect(),
        )
    }

    /// Number of sets currently available.
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }

    /// Maximum pool capacity (sets).
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Total sets consumed since startup.
    pub fn total_consumed(&self) -> u64 {
        self.total_consumed
    }
}

/// Manages a FIFO pool of pre-computed presignatures.
///
/// Presignatures are generated by the background replenishment task and
/// consumed by signing requests. The pool provides amortized single-round
/// signing latency.
pub struct PresignManager {
    /// FIFO pool of ready presignatures.
    ///
    /// New presignatures are pushed to the back; signing requests take
    /// from the front. This ensures older presignatures are used first,
    /// which is important because presignatures have a limited lifetime
    /// (though in practice they last indefinitely in the CGGMP'24 protocol).
    ///
    /// In **relay mode** this pool's FIFO order MUST stay in lockstep with the
    /// cosigner DO's presignature pool (both consume oldest-first), so the
    /// proxy's `Presignature_B` is combined against the correlated
    /// `Presignature_A` the DO consumes.
    pool: Vec<PooledPresignature>,

    /// Maximum pool capacity.
    ///
    /// The background task stops generating presignatures when the pool
    /// reaches this size. Excess presignatures are silently dropped.
    max_size: usize,

    /// Total presignatures generated since startup (for metrics).
    total_generated: u64,

    /// Total presignatures consumed by signing requests (for metrics).
    total_consumed: u64,

    /// §06.19 burn-rate regulator: drives target/low-water/cap + the
    /// consumed/invalidated counters. Time is sourced from [`Self::start`].
    regulator: BurnRateRegulator,

    /// Monotonic clock origin; `start.elapsed()` feeds the regulator's EWMA.
    start: Instant,

    /// `mpc.presig.regen_in_flight` — regen sessions currently running. Set by
    /// the background replenish task around each parallel launch batch.
    regen_in_flight: usize,
}

impl PresignManager {
    /// Create a new presignature manager with the given maximum pool size.
    pub fn new(max_size: usize) -> Self {
        Self {
            pool: Vec::with_capacity(max_size),
            max_size,
            total_generated: 0,
            total_consumed: 0,
            regulator: BurnRateRegulator::new(),
            start: Instant::now(),
            regen_in_flight: 0,
        }
    }

    /// Monotonic seconds since construction — the regulator's clock.
    fn now_secs(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    /// Take one presignature from the front of the pool (FIFO), discarding its
    /// raw output — the **legacy 1-round HTTP sign path**.
    ///
    /// Returns `None` if the pool is empty. The caller should fall back to
    /// the full 4-round signing protocol when no presignature is available.
    pub fn take(&mut self) -> Option<Presignature> {
        if self.pool.is_empty() {
            None
        } else {
            self.total_consumed += 1;
            self.regulator.record_consumption(self.now_secs());
            Some(self.pool.remove(0).presig)
        }
    }

    /// Take one presignature's **raw** output from the front of the pool (FIFO)
    /// — the box `(Presignature, PresignaturePublicData)` the **relay combiner**
    /// feeds to `SigningCoordinator::sign_with_presignature`.
    ///
    /// Returns `None` if the pool is empty.
    pub fn take_raw(&mut self) -> Option<Box<dyn Any + Send>> {
        if self.pool.is_empty() {
            None
        } else {
            self.total_consumed += 1;
            self.regulator.record_consumption(self.now_secs());
            // We own the entry now; unwrap the Sync shim. `into_inner` only
            // fails on a poisoned mutex, which is impossible here (never locked).
            Some(
                self.pool
                    .remove(0)
                    .raw
                    .into_inner()
                    .expect("presig raw mutex never poisoned"),
            )
        }
    }

    /// Add a presignature (with its raw output) to the back of the pool.
    ///
    /// If the pool is at capacity, the presignature is silently dropped.
    /// This can happen if signing traffic drops while replenishment is active.
    pub fn add(&mut self, presig: Presignature, raw: Box<dyn Any + Send>) {
        if self.pool.len() < self.max_size {
            self.pool.push(PooledPresignature {
                presig,
                raw: Mutex::new(raw),
            });
            self.total_generated += 1;
        } else {
            tracing::trace!(
                pool_size = self.pool.len(),
                max = self.max_size,
                "Presignature pool full — dropping generated presignature"
            );
        }
    }

    /// Current number of presignatures available in the pool.
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }

    /// Whether the pool should be replenished — the §06.19 trigger: available
    /// below the burn-rate-derived `low_water`. (Supersedes the old fixed
    /// 50%-of-capacity heuristic; `max_size` now only bounds storage.)
    pub fn should_replenish(&self) -> bool {
        self.pool.len() < self.low_water_mark()
    }

    /// §06.19 `burn_rate` (consumptions/sec) — `mpc.presig.burn_rate`.
    pub fn burn_rate(&self) -> f64 {
        self.regulator.burn_rate(self.now_secs())
    }

    /// §06.19 `target_pool_size = max(8, ceil(burn_rate * 30))`.
    pub fn target_pool_size(&self) -> usize {
        self.regulator.target_pool_size(self.now_secs())
    }

    /// §06.19 `low_water = ceil(target * 0.5)`.
    pub fn low_water_mark(&self) -> usize {
        self.regulator.low_water(self.now_secs())
    }

    /// §06.19 `high_water_cap = target * 2` — storage bound. Also clamped by
    /// `max_size` (the hard storage ceiling).
    pub fn high_water_cap(&self) -> usize {
        self.regulator
            .high_water_cap(self.now_secs())
            .min(self.max_size)
    }

    /// How many presign sessions to launch now (§06.19), given regens already
    /// in flight. Also clamped so the pool + in-flight never exceeds `max_size`.
    pub fn regen_count(&self) -> usize {
        let by_rate =
            self.regulator
                .regen_count(self.now_secs(), self.pool.len(), self.regen_in_flight);
        let hard_room = self
            .max_size
            .saturating_sub(self.pool.len() + self.regen_in_flight);
        by_rate.min(hard_room)
    }

    /// `mpc.presig.regen_in_flight` (gauge).
    pub fn regen_in_flight(&self) -> usize {
        self.regen_in_flight
    }

    /// Set the in-flight regen gauge (the background task brackets each launch).
    pub fn set_regen_in_flight(&mut self, n: usize) {
        self.regen_in_flight = n;
    }

    /// Record a §06.18 invalidation event (`bundles_invalidated_total{reason}`).
    pub fn record_invalidation(&mut self, reason: InvalidationReason, count: u64) {
        self.regulator.record_invalidation(reason, count);
    }

    /// `mpc.presig.bundles_invalidated_total{reason}` (counter).
    pub fn bundles_invalidated(&self, reason: InvalidationReason) -> u64 {
        self.regulator.bundles_invalidated_total(reason)
    }

    /// Maximum pool capacity.
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Total presignatures generated since startup.
    pub fn total_generated(&self) -> u64 {
        self.total_generated
    }

    /// Total presignatures consumed by signing requests since startup.
    pub fn total_consumed(&self) -> u64 {
        self.total_consumed
    }

    /// Pool utilization as a percentage (0.0 to 1.0).
    pub fn utilization(&self) -> f64 {
        if self.max_size == 0 {
            return 0.0;
        }
        self.pool.len() as f64 / self.max_size as f64
    }
}

/// Background task that replenishes the presignature pool during idle time.
///
/// This task runs forever, checking every 5 seconds whether the pool needs
/// replenishment. When the pool drops below 50% capacity, it generates one
/// presignature per cycle by running the 3-round presigning protocol with
/// the KSS.
///
/// ## Error handling
///
/// Presigning failures (network errors, KSS errors, protocol errors) are
/// logged as warnings but do not crash the task. The next cycle will retry.
/// This is appropriate because presigning is a best-effort optimization —
/// the proxy can always fall back to full 4-round signing.
///
/// ## Backoff
///
/// On consecutive failures, the task increases its sleep interval to avoid
/// hammering a struggling KSS. The interval resets on success.
pub async fn background_replenish(state: Arc<AppState>) {
    /// Base interval between replenishment attempts.
    const BASE_INTERVAL_SECS: u64 = 5;
    /// Maximum backoff interval on consecutive failures.
    const MAX_BACKOFF_SECS: u64 = 60;

    let mut consecutive_failures: u32 = 0;

    loop {
        // Adaptive sleep: back off on failures, reset on success.
        let sleep_secs = if consecutive_failures == 0 {
            BASE_INTERVAL_SECS
        } else {
            (BASE_INTERVAL_SECS * 2u64.saturating_pow(consecutive_failures)).min(MAX_BACKOFF_SECS)
        };

        tokio::time::sleep(tokio::time::Duration::from_secs(sleep_secs)).await;

        // §06.19: launch `regen_count` sessions this cycle (0 when the pool is
        // at/above low_water, or when in-flight + available already covers the
        // target). The count brings the pool to `target` bounded by the cap.
        let count = {
            let mgr = state.presign_manager.read().await;
            mgr.regen_count()
        };
        if count == 0 {
            consecutive_failures = 0;
            continue;
        }

        // Publish the in-flight gauge for the duration of the batch (§06.19
        // metric + feeds the next cycle's cap arithmetic).
        {
            let mut mgr = state.presign_manager.write().await;
            mgr.set_regen_in_flight(count);
        }

        // Launch the `count` presign sessions in PARALLEL (§06.19). Each
        // `presign_raw` runs an independent 3-round session (independent
        // SessionId + mailbox pair) and the awaits overlap.
        let results =
            futures::future::join_all((0..count).map(|_| state.bridge.presign_raw())).await;

        let (mut added, mut last_err) = (0usize, None::<String>);
        {
            let mut mgr = state.presign_manager.write().await;
            for r in results {
                match r {
                    Ok((presig, raw)) => {
                        mgr.add(presig, raw);
                        added += 1;
                    }
                    Err(e) => last_err = Some(e.to_string()),
                }
            }
            mgr.set_regen_in_flight(0);
            tracing::debug!(
                launched = count,
                added,
                pool_size = mgr.len(),
                target = mgr.target_pool_size(),
                burn_rate = mgr.burn_rate(),
                "burn-rate regen batch complete"
            );
        }

        if added > 0 {
            consecutive_failures = 0;
        } else {
            consecutive_failures = consecutive_failures.saturating_add(1);
            tracing::warn!(
                error = last_err.unwrap_or_default(),
                consecutive_failures,
                next_retry_secs = (BASE_INTERVAL_SECS * 2u64.saturating_pow(consecutive_failures))
                    .min(MAX_BACKOFF_SECS),
                "burn-rate regen batch produced no presignatures"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_pool_is_empty() {
        let mgr = PresignManager::new(10);
        assert!(mgr.is_empty());
        assert_eq!(mgr.len(), 0);
        assert_eq!(mgr.max_size(), 10);
    }

    #[test]
    fn take_from_empty_returns_none() {
        let mut mgr = PresignManager::new(10);
        assert!(mgr.take().is_none());
    }

    #[test]
    fn should_replenish_when_below_half() {
        let mgr = PresignManager::new(10);
        // 0 out of 10 — well below 50%
        assert!(mgr.should_replenish());
    }

    #[test]
    fn utilization_empty() {
        let mgr = PresignManager::new(10);
        assert!((mgr.utilization() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn utilization_zero_max() {
        let mgr = PresignManager::new(0);
        assert!((mgr.utilization() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn metrics_track_correctly() {
        let mgr = PresignManager::new(10);
        assert_eq!(mgr.total_generated(), 0);
        assert_eq!(mgr.total_consumed(), 0);
    }

    fn dummy_presig(id: &str) -> Presignature {
        Presignature {
            id: id.to_string(),
            session_id: bsv_mpc_core::types::SessionId::from_str_hash("pool-test"),
            data: vec![],
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn add_then_take_raw_returns_the_box() {
        // The relay combiner consumes the raw `(Presignature, PublicData)` box;
        // verify the pool stores and hands it back intact through the Sync shim.
        let mut mgr = PresignManager::new(4);
        let raw: Box<dyn Any + Send> = Box::new(0xC0FFEEu64);
        mgr.add(dummy_presig("a"), raw);
        assert_eq!(mgr.len(), 1);
        let got = mgr.take_raw().expect("raw present");
        assert_eq!(*got.downcast::<u64>().expect("downcast"), 0xC0FFEE);
        assert_eq!(mgr.len(), 0);
        assert_eq!(mgr.total_consumed(), 1);
    }

    #[test]
    fn take_returns_presig_and_is_fifo() {
        // Legacy HTTP path still gets the serializable Presignature, oldest-first.
        let mut mgr = PresignManager::new(4);
        mgr.add(dummy_presig("first"), Box::new(1u8));
        mgr.add(dummy_presig("second"), Box::new(2u8));
        assert_eq!(mgr.take().expect("first").id, "first");
        assert_eq!(mgr.take().expect("second").id, "second");
        assert!(mgr.take().is_none());
    }
}
