//! Diagnostic stage timing for the n-party presig-over-relay ceremony (#96 → #98).
//!
//! ## Why this exists
//!
//! #96 was filed on the hypothesis that the device's slow 4-of-6 presig
//! (~88 s macOS-native vs >1000 s on-device, "pure CPU peg" >17 min) was the
//! rustls HTTP handshake on Apple. Dependency analysis disproved that: bsv-rs
//! forces reqwest's `default-tls`, so the entire Apple HTTP path *already* runs
//! native-tls (Security.framework) — the TLS backend is NOT the lever. Rather
//! than guess at the next bottleneck, this module **measures** where the
//! ceremony's wall-clock actually goes so the next on-device run returns a
//! breakdown instead of a binary "still slow".
//!
//! ## Design
//!
//! A process-global accumulator, **scoped to one ceremony** by [`arm`]/[`disarm`]
//! (the device runs a single presig at a time). It is a strict no-op unless the
//! device coordinator [`arm`]s it, so the deployed Linux cosigner — which runs
//! `PresignHandler` tasks but never the device-side coordinator — records
//! nothing and pays zero overhead (its behavior is unchanged).
//!
//! The summary surfaces through two channels that already exist, so **no FFI
//! signature changes and no new exports** are needed (a binary XCFramework
//! rebuild suffices, never a binding regen):
//!   - folded into the `timed out awaiting PresigBundle assembly` error string,
//!     which already crosses the FFI on the failing path (visible on sim + device);
//!   - emitted via `tracing::info!(target: "presig.timing", …)` for any context
//!     that installs a subscriber (the native test harness, `--nocapture`).
//!
//! ## Reading the breakdown
//!
//! The decisive comparison is `presig.coord.assembly_wait` (wall of the bundle
//! gate) vs the summed `presig.handler.round*.exec` (pure CPU spent in the cggmp24
//! Paillier/bignum round math during that gate). When `exec ≈ assembly_wait` the
//! ceremony is genuinely CPU-bound (the #98 multi-thread runtime is the right
//! lever; investigate worker / blocking-pool sizing). When `exec ≪ assembly_wait`
//! it is network/relay-wait-bound (look at per-round-trip relay latency / cosigner
//! responsiveness, not local CPU).
//!
//! Separately, `round*.await − round*.exec` exposes blocking-pool starvation: if
//! the `await` (queue + run) dwarfs the in-closure `exec`, the runtime is
//! serializing the device's `w = t−1` parties instead of overlapping them.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Recording is active only between [`arm`] and [`disarm`]. Checked first on
/// every hot-path call so a disarmed cosigner pays a single relaxed atomic load.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// `None` until the first [`arm`]; holds the current ceremony's accumulator.
static STATE: Mutex<Option<State>> = Mutex::new(None);

struct State {
    /// Ceremony start, for the `wall=` total.
    t0: Instant,
    /// stage name → accumulated (sum, max, count).
    stages: BTreeMap<&'static str, Acc>,
}

#[derive(Default, Clone, Copy)]
struct Acc {
    total: Duration,
    max: Duration,
    count: u64,
}

/// Begin a fresh ceremony measurement: reset accumulators and enable recording.
/// Called by the device-side presig coordinator at ceremony start.
pub fn arm() {
    if let Ok(mut g) = STATE.lock() {
        *g = Some(State {
            t0: Instant::now(),
            stages: BTreeMap::new(),
        });
    }
    ENABLED.store(true, Ordering::Relaxed);
}

/// Stop recording. The accumulated state is retained so [`summary`] can still be
/// read once after the ceremony ends (or times out).
pub fn disarm() {
    ENABLED.store(false, Ordering::Relaxed);
}

/// Whether recording is currently armed (cheap relaxed load).
#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Accumulate one observation of `stage`. No-op (one atomic load) when disarmed.
pub fn record(stage: &'static str, dur: Duration) {
    if !enabled() {
        return;
    }
    if let Ok(mut g) = STATE.lock() {
        if let Some(s) = g.as_mut() {
            let a = s.stages.entry(stage).or_default();
            a.total = a.total.saturating_add(dur);
            a.count += 1;
            if dur > a.max {
                a.max = dur;
            }
        }
    }
}

/// Time a **synchronous** block (e.g. the CPU-bound body inside a
/// `spawn_blocking`) and record its elapsed under `stage`. When disarmed, calls
/// `f` directly with no `Instant` overhead.
pub fn time<T>(stage: &'static str, f: impl FnOnce() -> T) -> T {
    if !enabled() {
        return f();
    }
    let start = Instant::now();
    let out = f();
    record(stage, start.elapsed());
    out
}

/// RAII guard for an **async** scope (held across `.await`s): records the elapsed
/// from creation to drop under `stage`. When disarmed it captures no `Instant`.
#[must_use = "the guard records on drop; bind it to a name held for the scope"]
pub struct Guard {
    stage: &'static str,
    start: Option<Instant>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(start) = self.start {
            record(self.stage, start.elapsed());
        }
    }
}

/// Start an async-scope [`Guard`] for `stage`.
pub fn guard(stage: &'static str) -> Guard {
    Guard {
        stage,
        start: enabled().then(Instant::now),
    }
}

/// Compact, single-line, greppable breakdown of the current ceremony, stages
/// ordered by total cost descending. Safe to call after [`disarm`].
pub fn summary() -> String {
    let Ok(g) = STATE.lock() else {
        return "presig.timing: <poisoned>".to_string();
    };
    let Some(s) = g.as_ref() else {
        return "presig.timing: <not armed>".to_string();
    };
    let mut rows: Vec<(&&'static str, &Acc)> = s.stages.iter().collect();
    rows.sort_by_key(|(_, a)| std::cmp::Reverse(a.total));
    let mut out = format!("presig.timing wall={:.1}s", s.t0.elapsed().as_secs_f64());
    for (name, a) in rows {
        out.push_str(&format!(
            " | {name}={:.1}s/{}x(max={:.1}s)",
            a.total.as_secs_f64(),
            a.count,
            a.max.as_secs_f64(),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // The global is process-wide; this test owns it for its duration. Other
    // crates' tests do not touch `presig_timing`, so there is no cross-test race.
    #[test]
    fn disarmed_is_a_noop_and_armed_accumulates() {
        // Disarmed: record/time/guard must not panic and must not accumulate.
        disarm();
        record("x", Duration::from_millis(5));
        assert_eq!(time("x", || 42), 42);
        {
            let _g = guard("x");
        }
        assert!(summary().contains("not armed") || !summary().contains("x="));

        // Armed: observations accumulate (sum, count, max) and `time` returns the value.
        arm();
        record("net", Duration::from_millis(10));
        record("net", Duration::from_millis(30));
        let r = time("cpu", || {
            // Busy enough to register a nonzero sample without sleeping.
            (0..10_000u64).sum::<u64>()
        });
        assert_eq!(r, 49_995_000);
        {
            let _g = guard("scope");
        }
        let s = summary();
        assert!(s.contains("presig.timing wall="), "summary: {s}");
        assert!(s.contains("net=0.0s/2x"), "two net samples summed: {s}");
        assert!(s.contains("cpu="), "cpu time recorded: {s}");
        assert!(s.contains("scope="), "guard recorded: {s}");

        // Disarm leaves the summary readable but stops new recording.
        disarm();
        record("net", Duration::from_secs(100));
        assert!(
            summary().contains("net=0.0s/2x"),
            "no recording while disarmed"
        );
    }
}
