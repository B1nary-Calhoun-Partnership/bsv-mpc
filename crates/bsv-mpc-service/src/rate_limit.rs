//! Per-identity token-bucket rate limiting for the KSS/ceremony endpoints (issue
//! #5). The container is the live heavy-MPC surface (DKG/presign/sign-relay), so an
//! authenticated caller that spams expensive ceremonies is the real DoS vector.
//!
//! Keyed by the **verified** BRC-31 identity (enforced inside
//! [`crate::auth::verify_or_allow`] AFTER signature verification) — not by IP or the
//! claimed identity header, so an attacker cannot rotate a spoofed key to escape the
//! bucket (in the CF Container topology the source IP is the edge anyway). Pure +
//! deterministic-clock-testable; no async, no I/O.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A classic token bucket: `capacity` tokens (the burst), refilled at
/// `refill_per_sec`; each admitted request consumes one token.
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    /// `capacity` = max burst; `refill_per_sec` = sustained rate. `capacity == 0`
    /// disables limiting (always-allow) — the escape hatch for dev/tests.
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity: capacity as f64,
            refill_per_sec,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Build from env: `MPC_RATE_LIMIT_CAPACITY` (default 60) +
    /// `MPC_RATE_LIMIT_REFILL_PER_SEC` (default 1.0). Generous by design — the goal
    /// is to cap abuse, not throttle legitimate ceremonies.
    pub fn from_env() -> Self {
        let capacity = std::env::var("MPC_RATE_LIMIT_CAPACITY")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(60);
        let refill = std::env::var("MPC_RATE_LIMIT_REFILL_PER_SEC")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(1.0);
        Self::new(capacity, refill)
    }

    /// Whether limiting is active (`false` when disabled via `capacity == 0`).
    pub fn is_enabled(&self) -> bool {
        self.capacity > 0.0
    }

    /// Try to admit one request for `key`. `true` = allowed (a token consumed);
    /// `false` = over the limit (caller should return 429).
    pub fn check(&self, key: &str) -> bool {
        self.check_at(key, Instant::now())
    }

    /// [`check`](Self::check) with an explicit clock — the deterministic test seam.
    fn check_at(&self, key: &str, now: Instant) -> bool {
        if self.capacity <= 0.0 {
            return true; // disabled
        }
        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: self.capacity,
            last: now,
        });
        // Refill for the elapsed wall-time, capped at capacity.
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop buckets idle longer than `older_than` (housekeeping so the map can't grow
    /// unbounded across distinct identities). A full bucket is indistinguishable from
    /// a fresh one, so evicting an idle (refilled-to-capacity) entry is lossless.
    pub fn prune_idle(&self, older_than: Duration) {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        buckets.retain(|_, b| now.saturating_duration_since(b.last) < older_than);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_admits_then_rejects() {
        let rl = RateLimiter::new(3, 0.0); // no refill — pure burst budget
        let t0 = Instant::now();
        assert!(rl.check_at("id", t0));
        assert!(rl.check_at("id", t0));
        assert!(rl.check_at("id", t0));
        assert!(
            !rl.check_at("id", t0),
            "the (capacity+1)th request must be rejected"
        );
    }

    #[test]
    fn refills_over_time() {
        let rl = RateLimiter::new(1, 10.0); // 10 tokens/sec
        let t0 = Instant::now();
        assert!(
            rl.check_at("id", t0),
            "first request consumes the single token"
        );
        assert!(!rl.check_at("id", t0), "immediately over the limit");
        // 0.1s later → +1 token refilled → admitted again.
        assert!(rl.check_at("id", t0 + Duration::from_millis(100)));
        // Refill is capped at capacity (can't bank > 1 token here).
        assert!(!rl.check_at("id", t0 + Duration::from_millis(100)));
    }

    #[test]
    fn per_identity_isolation() {
        let rl = RateLimiter::new(1, 0.0);
        let t0 = Instant::now();
        assert!(rl.check_at("alice", t0));
        assert!(!rl.check_at("alice", t0), "alice is exhausted");
        // bob has his own bucket — alice's exhaustion does not affect him.
        assert!(rl.check_at("bob", t0), "bob's bucket is independent");
    }

    #[test]
    fn capacity_zero_disables() {
        let rl = RateLimiter::new(0, 0.0);
        let t0 = Instant::now();
        for _ in 0..1000 {
            assert!(
                rl.check_at("id", t0),
                "capacity 0 = always allow (disabled)"
            );
        }
        assert!(!rl.is_enabled());
    }
}
