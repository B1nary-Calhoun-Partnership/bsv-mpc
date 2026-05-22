//! Burn-rate-driven presig pool regulation (MPC-Spec §06.19, ADR-0030 §11).
//!
//! The coordinator maintains a regeneration loop per `(joint_pubkey,
//! cosigner_subset)` pair. The normative baseline algorithm:
//!
//! ```text
//! burn_rate(t)        = EWMA over the last 60s of presig consumptions per second
//! target_pool_size(t) = max(8, ceil(burn_rate(t) * 30))    // 30s runway, floor 8
//! low_water           = ceil(target_pool_size(t) * 0.5)
//! high_water_cap      = target_pool_size(t) * 2
//! ```
//!
//! On each consumption (or 1s tick), if `available < low_water`, launch
//! `target - available` presign sessions in parallel, bounded so storage never
//! exceeds `high_water_cap` (counting in-flight regens).
//!
//! This module is the pure decision core: time is an injected `now_secs`
//! (monotonic), so the §06.19 formula is unit-tested deterministically with a
//! synthetic clock. [`crate::presign_manager`] drives it with a real
//! `Instant`-based clock and owns the pool + parallel-launch wiring.
//!
//! ## EWMA of an event rate
//!
//! A continuous-time EWMA with time constant `τ = 60s`: on each consumption the
//! rate is decayed by `exp(-Δt/τ)` and incremented by `1/τ`. Steady-state under
//! a constant arrival rate `r` converges to `r` (each event contributes `1/τ`;
//! `1/τ · r · τ = r`). Reading the rate at time `t` decays to `t` without
//! incrementing.

/// EWMA time constant — the "last 60s" window (§06.19).
const EWMA_WINDOW_SECS: f64 = 60.0;
/// Runway: target covers 30s of burn (§06.19).
const RUNWAY_SECS: f64 = 30.0;
/// Pool floor — never target below 8 (§06.19).
const POOL_FLOOR: usize = 8;

/// §06.18 invalidation reasons (the `reason` metric label, ∈ refresh|subset|policy|rekey).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidationReason {
    Refresh,
    Subset,
    Policy,
    Rekey,
}

/// Pure §06.19 burn-rate regulator. Holds the EWMA + lifetime counters; all
/// time-dependent reads take an injected monotonic `now_secs`.
#[derive(Debug, Clone)]
pub struct BurnRateRegulator {
    /// EWMA of consumptions/sec.
    ewma_rate: f64,
    /// Monotonic seconds of the last EWMA update; `None` until first consumption.
    last_update_secs: Option<f64>,
    /// `mpc.presig.bundles_consumed_total`.
    consumed_total: u64,
    /// `mpc.presig.bundles_invalidated_total{reason}` split by reason.
    invalidated_refresh: u64,
    invalidated_subset: u64,
    invalidated_policy: u64,
    invalidated_rekey: u64,
}

impl Default for BurnRateRegulator {
    fn default() -> Self {
        Self::new()
    }
}

impl BurnRateRegulator {
    pub fn new() -> Self {
        Self {
            ewma_rate: 0.0,
            last_update_secs: None,
            consumed_total: 0,
            invalidated_refresh: 0,
            invalidated_subset: 0,
            invalidated_policy: 0,
            invalidated_rekey: 0,
        }
    }

    /// The EWMA rate decayed forward to `now_secs` (read-only; no increment).
    fn decayed_rate(&self, now_secs: f64) -> f64 {
        match self.last_update_secs {
            None => 0.0,
            Some(last) => {
                let elapsed = (now_secs - last).max(0.0);
                self.ewma_rate * (-elapsed / EWMA_WINDOW_SECS).exp()
            }
        }
    }

    /// Record one presig consumption at `now_secs`: decay to now, then add the
    /// `1/τ` event contribution. Bumps `bundles_consumed_total`.
    pub fn record_consumption(&mut self, now_secs: f64) {
        self.ewma_rate = self.decayed_rate(now_secs) + 1.0 / EWMA_WINDOW_SECS;
        self.last_update_secs = Some(now_secs);
        self.consumed_total += 1;
    }

    /// `mpc.presig.burn_rate` (consumptions/sec) at `now_secs`.
    pub fn burn_rate(&self, now_secs: f64) -> f64 {
        self.decayed_rate(now_secs)
    }

    /// `target_pool_size(t) = max(8, ceil(burn_rate * 30))`.
    pub fn target_pool_size(&self, now_secs: f64) -> usize {
        let by_rate = (self.burn_rate(now_secs) * RUNWAY_SECS).ceil() as usize;
        POOL_FLOOR.max(by_rate)
    }

    /// `low_water = ceil(target * 0.5)`.
    pub fn low_water(&self, now_secs: f64) -> usize {
        let target = self.target_pool_size(now_secs);
        target.div_ceil(2)
    }

    /// `high_water_cap = target * 2`.
    pub fn high_water_cap(&self, now_secs: f64) -> usize {
        self.target_pool_size(now_secs) * 2
    }

    /// How many presign sessions to launch right now.
    ///
    /// Returns `0` unless `available < low_water` (the §06.19 trigger). When
    /// triggered, returns `target - available`, bounded so `available + in_flight
    /// + launch <= high_water_cap` (storage cost bound, counting regens already
    /// running). `in_flight` is the number of regen sessions in progress.
    pub fn regen_count(&self, now_secs: f64, available: usize, in_flight: usize) -> usize {
        if available >= self.low_water(now_secs) {
            return 0;
        }
        let target = self.target_pool_size(now_secs);
        let cap = self.high_water_cap(now_secs);
        let want = target.saturating_sub(available);
        let storage_room = cap.saturating_sub(available + in_flight);
        want.min(storage_room)
    }

    /// Record a §06.18 invalidation (for the `bundles_invalidated_total{reason}`
    /// counter). `count` bundles were purged for `reason`.
    pub fn record_invalidation(&mut self, reason: InvalidationReason, count: u64) {
        match reason {
            InvalidationReason::Refresh => self.invalidated_refresh += count,
            InvalidationReason::Subset => self.invalidated_subset += count,
            InvalidationReason::Policy => self.invalidated_policy += count,
            InvalidationReason::Rekey => self.invalidated_rekey += count,
        }
    }

    /// `mpc.presig.bundles_consumed_total`.
    pub fn bundles_consumed_total(&self) -> u64 {
        self.consumed_total
    }

    /// `mpc.presig.bundles_invalidated_total` for a reason label.
    pub fn bundles_invalidated_total(&self, reason: InvalidationReason) -> u64 {
        match reason {
            InvalidationReason::Refresh => self.invalidated_refresh,
            InvalidationReason::Subset => self.invalidated_subset,
            InvalidationReason::Policy => self.invalidated_policy,
            InvalidationReason::Rekey => self.invalidated_rekey,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_pool_targets_the_floor() {
        // No consumption → burn_rate 0 → target = floor 8, low_water 4, cap 16.
        let r = BurnRateRegulator::new();
        assert_eq!(r.burn_rate(0.0), 0.0);
        assert_eq!(r.target_pool_size(0.0), 8);
        assert_eq!(r.low_water(0.0), 4);
        assert_eq!(r.high_water_cap(0.0), 16);
    }

    #[test]
    fn steady_consumption_converges_ewma_to_rate() {
        // Consume at exactly 1/sec for 20 minutes (≫ τ) → fully converged.
        // Sample the rate mid-interval (t+0.5): that's the time-averaged rate
        // ~1.0/sec, not the post-event instantaneous peak (which sits a hair
        // above 1.0 because each event adds 1/τ before decaying). target =
        // max(8, ceil(1.0*30)) = 30.
        let mut r = BurnRateRegulator::new();
        let mut t = 0.0;
        for _ in 0..1200 {
            t += 1.0;
            r.record_consumption(t);
        }
        let sample = t + 0.5;
        let br = r.burn_rate(sample);
        assert!((br - 1.0).abs() < 0.02, "burn_rate {br} should converge to ~1.0/sec");
        assert_eq!(r.target_pool_size(sample), 30);
        assert_eq!(r.low_water(sample), 15);
        assert_eq!(r.high_water_cap(sample), 60);
        assert_eq!(r.bundles_consumed_total(), 1200);
    }

    #[test]
    fn burn_rate_decays_toward_zero_when_idle() {
        // Sustain 2/sec for 300s (5 windows → converged to ~2.0), then go idle.
        let mut r = BurnRateRegulator::new();
        let mut t = 0.0;
        for _ in 0..600 {
            t += 0.5; // 2/sec
            r.record_consumption(t);
        }
        assert!(r.burn_rate(t + 0.25) > 1.8, "should be elevated (~2/sec) after the burst");
        // 5 windows of silence (300s): exp(-5) ≈ 0.0067 → effectively zero.
        let later = t + 5.0 * 60.0;
        assert!(r.burn_rate(later) < 0.05, "rate should decay to ~0 when idle");
        assert_eq!(r.target_pool_size(later), 8, "target falls back to the floor");
    }

    #[test]
    fn regen_triggers_only_below_low_water_and_fills_to_target() {
        let r = BurnRateRegulator::new(); // idle → target 8, low_water 4, cap 16
        // At or above low_water → no regen.
        assert_eq!(r.regen_count(0.0, 4, 0), 0);
        assert_eq!(r.regen_count(0.0, 8, 0), 0);
        // Below low_water → fill to target (8 - available).
        assert_eq!(r.regen_count(0.0, 3, 0), 5);
        assert_eq!(r.regen_count(0.0, 0, 0), 8);
    }

    #[test]
    fn regen_is_bounded_by_cap_counting_in_flight() {
        let r = BurnRateRegulator::new(); // target 8, cap 16
        // available 0, but 14 already in flight → only room for 2 more (cap 16).
        assert_eq!(r.regen_count(0.0, 0, 14), 2);
        // in_flight already at/over cap → launch nothing.
        assert_eq!(r.regen_count(0.0, 0, 16), 0);
        assert_eq!(r.regen_count(0.0, 0, 20), 0);
    }

    #[test]
    fn invalidation_counters_split_by_reason() {
        let mut r = BurnRateRegulator::new();
        r.record_invalidation(InvalidationReason::Refresh, 3);
        r.record_invalidation(InvalidationReason::Policy, 5);
        r.record_invalidation(InvalidationReason::Policy, 2);
        assert_eq!(r.bundles_invalidated_total(InvalidationReason::Refresh), 3);
        assert_eq!(r.bundles_invalidated_total(InvalidationReason::Policy), 7);
        assert_eq!(r.bundles_invalidated_total(InvalidationReason::Subset), 0);
        assert_eq!(r.bundles_invalidated_total(InvalidationReason::Rekey), 0);
    }
}
