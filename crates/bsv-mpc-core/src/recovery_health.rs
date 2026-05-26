//! §18.4a recovery-health indicator + the #40 recovery safety rails.
//!
//! Companion to [`recovery`](crate::recovery) (the §18.5 Argon2id backup KDF).
//! Three guards around the §18.2 reshare-based device-loss recovery ceremony
//! ([`reshar_coordinator`](crate::reshar_coordinator)):
//!
//!  - [`RecoveryHealth`] — the normative §18.4a indicator (passkey / backup
//!    freshness / trustees reachable / refresh recency → healthy | degraded |
//!    critical), per ADR-0034.
//!  - [`survivor_quorum_ok`] — the precondition a recovery reshare MUST satisfy:
//!    enough surviving shares both to *reconstruct* the secret (≥ `t`) AND to keep
//!    the *lost* set below the security threshold (≥ `n − t + 1`, i.e. at most
//!    `t − 1` lost — so no adversary holding the lost shares can reconstruct K).
//!  - [`RecoveryCooldown`] — anti-hot-swap: refuse a second recovery within a
//!    cooldown window (a stolen-device attacker who triggers one recovery cannot
//!    immediately trigger another to churn the sharing).

use serde::{Deserialize, Serialize};

/// §18.4a `trustees_reachable` sub-field: how many of the user's escrows/trustees
/// (§18.5.2 / §18.6) are currently pingable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrusteesReachable {
    pub current: u8,
    pub total: u8,
}

/// §18.4a `overall_status` — surfaced as a persistent green/yellow/red indicator.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecoveryStatus {
    Healthy,
    Degraded,
    Critical,
}

impl RecoveryStatus {
    /// The on-the-wire `tstr` value (§18.4a).
    pub fn as_str(&self) -> &'static str {
        match self {
            RecoveryStatus::Healthy => "healthy",
            RecoveryStatus::Degraded => "degraded",
            RecoveryStatus::Critical => "critical",
        }
    }
}

/// §18.4a recovery-health indicator. The field set is normative; the freshness
/// thresholds in [`RecoveryHealth::overall_status`] are the RECOMMENDED defaults
/// (an operator MAY tighten them).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryHealth {
    /// §18.5.1 Path 1 — encrypted-backup KEK derivability (passkey present).
    pub passkey_present: bool,
    /// Freshness of the user's BRC-100 wallet backup sync.
    pub backup_synced_age_secs: u64,
    /// §18.5.2 escrows / §18.6 trustees currently reachable.
    pub trustees_reachable: TrusteesReachable,
    /// §16.5.1 routine-refresh recency.
    pub last_refresh_age_days: u32,
}

/// `ceil(total/2) + 1` — the §18.4a "healthy" trustee-reachability floor.
fn healthy_trustee_floor(total: u8) -> u8 {
    // ceil(total / 2) + 1.
    ((total as u16).div_ceil(2) + 1).min(u8::MAX as u16) as u8
}

impl RecoveryHealth {
    /// §18.4a `overall_status` per the RECOMMENDED default thresholds:
    /// - `critical`: `passkey_present=false` OR `trustees_reachable.current < 2`
    ///   (recovery quorum at risk) OR `last_refresh_age_days > 60`.
    /// - `healthy`: `passkey_present` AND `backup_synced_age_secs < 3600` AND
    ///   `trustees_reachable.current ≥ ceil(total/2)+1` AND `last_refresh_age_days < 35`.
    /// - `degraded`: anything in between (any one healthy threshold breached).
    pub fn overall_status(&self) -> RecoveryStatus {
        let tr = &self.trustees_reachable;
        // Critical is evaluated first (strongest): any of these → red.
        if !self.passkey_present || tr.current < 2 || self.last_refresh_age_days > 60 {
            return RecoveryStatus::Critical;
        }
        if self.passkey_present
            && self.backup_synced_age_secs < 3600
            && tr.current >= healthy_trustee_floor(tr.total)
            && self.last_refresh_age_days < 35
        {
            return RecoveryStatus::Healthy;
        }
        RecoveryStatus::Degraded
    }

    /// Convenience: the §18.4a `tstr` status.
    pub fn overall_status_str(&self) -> &'static str {
        self.overall_status().as_str()
    }
}

/// The minimum surviving shares a `t`-of-`n` sharing needs before a recovery
/// reshare is permitted: `max(t, n − t + 1)`.
///
/// - `≥ t` — functionality: the PSS reshare must reconstruct the secret, which
///   needs at least `t` shares.
/// - `≥ n − t + 1` — security: at most `t − 1` shares were lost, so the lost set
///   alone CANNOT reconstruct K.
///
/// (For a `2`-of-`3`, both terms equal `2`. They diverge for e.g. `3`-of-`4`,
/// where functionality binds at `3` while `n − t + 1 = 2`.)
pub fn min_survivors_to_recover(t: u16, n: u16) -> u16 {
    let security = n.saturating_sub(t).saturating_add(1); // n − t + 1
    t.max(security)
}

/// True iff `surviving_shares` is enough to safely perform a recovery reshare of a
/// `t`-of-`n` sharing (see [`min_survivors_to_recover`]).
pub fn survivor_quorum_ok(surviving_shares: u16, t: u16, n: u16) -> bool {
    if t == 0 || n < t {
        return false; // degenerate config
    }
    surviving_shares >= min_survivors_to_recover(t, n)
}

/// Why a recovery was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryGuardError {
    /// Too few surviving shares (see [`survivor_quorum_ok`]).
    SurvivorQuorum {
        survivors: u16,
        required: u16,
        t: u16,
        n: u16,
    },
    /// A recovery was attempted within the post-recovery cooldown window.
    CooldownActive { remaining_secs: u64 },
}

impl std::fmt::Display for RecoveryGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoveryGuardError::SurvivorQuorum {
                survivors,
                required,
                t,
                n,
            } => write!(
                f,
                "recovery refused: {survivors} surviving share(s) < required {required} for {t}-of-{n} (need ≥ t AND ≥ n−t+1)"
            ),
            RecoveryGuardError::CooldownActive { remaining_secs } => write!(
                f,
                "recovery refused: post-recovery cooldown active ({remaining_secs}s remaining) — anti hot-swap"
            ),
        }
    }
}
impl std::error::Error for RecoveryGuardError {}

/// Anti-hot-swap guard: refuses a second recovery within `window_secs` of the
/// last committed one. Time is supplied by the caller (unix epoch seconds) so the
/// guard is pure + wasm-safe (no `std::time::Instant`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCooldown {
    window_secs: u64,
    last_recovery_at: Option<u64>,
}

impl RecoveryCooldown {
    /// A guard with the given cooldown window and no prior recovery.
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            last_recovery_at: None,
        }
    }

    /// Whether a recovery is permitted at `now_secs` (does NOT record it).
    pub fn permitted(&self, now_secs: u64) -> bool {
        match self.last_recovery_at {
            None => true,
            Some(last) => now_secs.saturating_sub(last) >= self.window_secs,
        }
    }

    /// Seconds remaining in the cooldown at `now_secs` (`0` if permitted).
    pub fn remaining_secs(&self, now_secs: u64) -> u64 {
        match self.last_recovery_at {
            None => 0,
            Some(last) => self
                .window_secs
                .saturating_sub(now_secs.saturating_sub(last)),
        }
    }

    /// Record a recovery at `now_secs`, or refuse if still within the window.
    pub fn try_record(&mut self, now_secs: u64) -> Result<(), RecoveryGuardError> {
        if self.permitted(now_secs) {
            self.last_recovery_at = Some(now_secs);
            Ok(())
        } else {
            Err(RecoveryGuardError::CooldownActive {
                remaining_secs: self.remaining_secs(now_secs),
            })
        }
    }

    /// The unix-epoch second of the last recorded recovery, if any.
    pub fn last_recovery_at(&self) -> Option<u64> {
        self.last_recovery_at
    }
}

/// Pre-flight a recovery reshare: enforce BOTH the survivor quorum and the
/// post-recovery cooldown, recording the recovery on success.
///
/// Returns `Ok(())` and records `now_secs` iff `surviving_shares` clears
/// [`survivor_quorum_ok`] for `t`-of-`n` AND the [`RecoveryCooldown`] permits a
/// recovery at `now_secs`. The quorum is checked first, so a sub-quorum attempt
/// never consumes the cooldown slot.
pub fn authorize_recovery(
    surviving_shares: u16,
    t: u16,
    n: u16,
    cooldown: &mut RecoveryCooldown,
    now_secs: u64,
) -> Result<(), RecoveryGuardError> {
    if !survivor_quorum_ok(surviving_shares, t, n) {
        return Err(RecoveryGuardError::SurvivorQuorum {
            survivors: surviving_shares,
            required: min_survivors_to_recover(t, n),
            t,
            n,
        });
    }
    cooldown.try_record(now_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── survivor quorum ──────────────────────────────────────────────────────
    #[test]
    fn quorum_2of3_needs_2_survivors() {
        // 2-of-3: max(t=2, n−t+1=2) = 2.
        assert_eq!(min_survivors_to_recover(2, 3), 2);
        assert!(survivor_quorum_ok(3, 2, 3)); // none lost
        assert!(survivor_quorum_ok(2, 2, 3)); // lost the phone → exactly the gate case
        assert!(!survivor_quorum_ok(1, 2, 3)); // lost 2 → cannot recover
        assert!(!survivor_quorum_ok(0, 2, 3));
    }

    #[test]
    fn quorum_3of4_binds_on_functionality() {
        // 3-of-4: max(t=3, n−t+1=2) = 3 (functionality binds, stricter than n−t+1).
        assert_eq!(min_survivors_to_recover(3, 4), 3);
        assert!(survivor_quorum_ok(3, 3, 4));
        assert!(!survivor_quorum_ok(2, 3, 4)); // 2 < t=3: cannot reshare even though ≥ n−t+1
    }

    #[test]
    fn quorum_4of6_security_vs_functionality() {
        // 4-of-6: max(t=4, n−t+1=3) = 4.
        assert_eq!(min_survivors_to_recover(4, 6), 4);
        assert!(survivor_quorum_ok(4, 4, 6));
        assert!(!survivor_quorum_ok(3, 4, 6));
    }

    #[test]
    fn quorum_rejects_degenerate_config() {
        assert!(!survivor_quorum_ok(5, 0, 3)); // t=0
        assert!(!survivor_quorum_ok(5, 3, 2)); // n < t
    }

    // ── recovery health (§18.4a) ──────────────────────────────────────────────
    fn health(
        passkey: bool,
        backup_age: u64,
        cur: u8,
        total: u8,
        refresh_days: u32,
    ) -> RecoveryHealth {
        RecoveryHealth {
            passkey_present: passkey,
            backup_synced_age_secs: backup_age,
            trustees_reachable: TrusteesReachable {
                current: cur,
                total,
            },
            last_refresh_age_days: refresh_days,
        }
    }

    #[test]
    fn health_healthy_when_all_thresholds_met() {
        // total=3 → floor = ceil(3/2)+1 = 3, so current must be 3.
        assert_eq!(healthy_trustee_floor(3), 3);
        let h = health(true, 100, 3, 3, 10);
        assert_eq!(h.overall_status(), RecoveryStatus::Healthy);
        assert_eq!(h.overall_status_str(), "healthy");
    }

    #[test]
    fn health_critical_when_passkey_absent() {
        let h = health(false, 100, 3, 3, 10);
        assert_eq!(h.overall_status(), RecoveryStatus::Critical);
    }

    #[test]
    fn health_critical_when_quorum_at_risk() {
        // current < 2 → recovery quorum at risk → critical.
        let h = health(true, 100, 1, 3, 10);
        assert_eq!(h.overall_status(), RecoveryStatus::Critical);
    }

    #[test]
    fn health_critical_when_refresh_too_stale() {
        let h = health(true, 100, 3, 3, 61);
        assert_eq!(h.overall_status(), RecoveryStatus::Critical);
    }

    #[test]
    fn health_degraded_when_one_threshold_breached() {
        // Backup stale (>3600s) but not critical → degraded.
        let h = health(true, 7200, 3, 3, 10);
        assert_eq!(h.overall_status(), RecoveryStatus::Degraded);
        // Refresh in (35, 60] → degraded (not yet critical).
        let h2 = health(true, 100, 3, 3, 40);
        assert_eq!(h2.overall_status(), RecoveryStatus::Degraded);
        // current=2 of 5: ≥2 (not critical) but < floor(=ceil(5/2)+1=4) → degraded.
        assert_eq!(healthy_trustee_floor(5), 4);
        let h3 = health(true, 100, 2, 5, 10);
        assert_eq!(h3.overall_status(), RecoveryStatus::Degraded);
    }

    // ── cooldown (anti hot-swap) ──────────────────────────────────────────────
    #[test]
    fn cooldown_first_recovery_permitted() {
        let mut cd = RecoveryCooldown::new(3600);
        assert!(cd.permitted(1_000));
        assert!(cd.try_record(1_000).is_ok());
        assert_eq!(cd.last_recovery_at(), Some(1_000));
    }

    #[test]
    fn cooldown_second_recovery_within_window_refused() {
        let mut cd = RecoveryCooldown::new(3600);
        cd.try_record(1_000).unwrap();
        assert!(!cd.permitted(2_000));
        match cd.try_record(2_000) {
            Err(RecoveryGuardError::CooldownActive { remaining_secs }) => {
                assert_eq!(remaining_secs, 3600 - 1000);
            }
            other => panic!("expected cooldown refusal, got {other:?}"),
        }
        // The refused attempt did NOT overwrite the last-recovery timestamp.
        assert_eq!(cd.last_recovery_at(), Some(1_000));
    }

    #[test]
    fn cooldown_recovery_after_window_permitted() {
        let mut cd = RecoveryCooldown::new(3600);
        cd.try_record(1_000).unwrap();
        assert!(cd.permitted(1_000 + 3600));
        assert!(cd.try_record(1_000 + 3600).is_ok());
        assert_eq!(cd.last_recovery_at(), Some(4_600));
    }

    // ── authorize_recovery (integration of both rails) ────────────────────────
    #[test]
    fn authorize_recovery_happy_path_2of3() {
        let mut cd = RecoveryCooldown::new(3600);
        // Lost the phone → 2 survivors of 2-of-3 at t=now.
        assert!(authorize_recovery(2, 2, 3, &mut cd, 5_000).is_ok());
        assert_eq!(cd.last_recovery_at(), Some(5_000));
    }

    #[test]
    fn authorize_recovery_sub_quorum_does_not_consume_cooldown() {
        let mut cd = RecoveryCooldown::new(3600);
        // Only 1 survivor of 2-of-3: quorum fails BEFORE the cooldown is touched.
        match authorize_recovery(1, 2, 3, &mut cd, 5_000) {
            Err(RecoveryGuardError::SurvivorQuorum { required, .. }) => assert_eq!(required, 2),
            other => panic!("expected survivor-quorum refusal, got {other:?}"),
        }
        assert_eq!(
            cd.last_recovery_at(),
            None,
            "failed quorum must NOT record a recovery"
        );
        // A subsequent valid recovery is therefore still permitted immediately.
        assert!(authorize_recovery(2, 2, 3, &mut cd, 5_001).is_ok());
    }

    #[test]
    fn authorize_recovery_blocks_immediate_second() {
        let mut cd = RecoveryCooldown::new(86_400);
        assert!(authorize_recovery(2, 2, 3, &mut cd, 10_000).is_ok());
        // A second recovery one hour later is blocked (anti hot-swap).
        assert!(matches!(
            authorize_recovery(2, 2, 3, &mut cd, 10_000 + 3600),
            Err(RecoveryGuardError::CooldownActive { .. })
        ));
    }
}
