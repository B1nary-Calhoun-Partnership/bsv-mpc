//! **Phase-A throwaway-DKG diagnostic — party 0 joins LATE** (issue: deployed
//! cross-(t,n) reshare `reshare: party 1 timed out awaiting throwaway DKG aux`).
//!
//! This mirrors PHASE A of `reshar_full_2of2_to_2of3_via_messagebox_e2e` (a
//! throwaway 2-of-3 DKG via `DkgHandler` over the LIVE relay), but reproduces the
//! deployed split's timing: parties 1 & 2 subscribe + initiate + ship round-1
//! FIRST, then — after a configurable delay (default ~90s, the container's
//! observed Paillier-prime-gen latency) — party 0 subscribes + initiates + ships
//! its round-1.
//!
//! ## Diagnosis (REPRODUCED)
//!
//! With the ORIGINAL ordering — party 0 generates its ~60-90s Paillier primes
//! BEFORE subscribing to `mpc-dkg` + initiating + shipping round-1 — party 0
//! joined the relay ~90s late and the joint DKG NEVER converged (relay backfill
//! did NOT recover the late join). A 90s-delayed party-0 timed out after 450s.
//! That is the deployed root cause.
//!
//! ## The fix (what this test now guards)
//!
//! Primes are only consumed at the keygen→auxinfo transition, NOT at init. So
//! every party now SUBSCRIBES + initiates + ships keygen round-1 IMMEDIATELY
//! (no late relay join), then late-seeds primes via `DkgHandler::seed_primes_late`
//! once generation finishes. This test models that: all 3 parties arm promptly,
//! but party 0's primes are seeded `PARTY0_DELAY_SECS` (default 90s) LATE —
//! exactly the real-world bottleneck. With the fix the DKG must still complete.
//!
//! - PASS → the fix works: a slow-prime party no longer breaks the ceremony,
//!   because it joins the relay on time and primes catch up before auxinfo.
//! - TIMEOUT → the fix is insufficient.
//!
//! ```bash
//! MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-service --test reshar_phaseA_delayed_party0_e2e \
//!     -- --nocapture --test-threads=1
//! ```
//! Override the delay: `PARTY0_DELAY_SECS=120 ...`

use std::sync::Arc;
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::types::{SessionId, ThresholdConfig};
use bsv_mpc_messagebox::types::BOX_DKG;
use bsv_mpc_messagebox::MessageBoxClient;
use bsv_mpc_service::storage::SqliteShareStorage;
use bsv_mpc_service::{DkgHandler, MessageBoxListener};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::PregeneratedPrimes;
use rand::RngCore;

fn relay_url() -> Option<String> {
    std::env::var("MESSAGEBOX_RELAY_URL").ok()
}
fn party0_delay() -> Duration {
    let secs = std::env::var("PARTY0_DELAY_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(90);
    Duration::from_secs(secs)
}
fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("priv")
}
fn fresh_storage() -> Arc<std::sync::RwLock<SqliteShareStorage>> {
    let dir = tempfile::tempdir().expect("tempdir");
    let s = SqliteShareStorage::open(dir.path().to_str().unwrap()).expect("open");
    std::mem::forget(dir);
    Arc::new(std::sync::RwLock::new(s))
}

#[tokio::test]
#[allow(non_snake_case)]
async fn phaseA_dkg_with_delayed_party0_over_messagebox() {
    let Some(relay_url) = relay_url() else {
        eprintln!("MESSAGEBOX_RELAY_URL not set — skipping delayed-party0 phase-A diagnostic.");
        return;
    };
    let _ = tracing_subscriber::fmt::try_init();
    let t0 = std::time::Instant::now();
    let delay = party0_delay();
    eprintln!(
        "⏱  party 0 will join phase A ~{:?} late (override via PARTY0_DELAY_SECS)",
        delay
    );

    let new_cfg = ThresholdConfig::new(2, 3).expect("2-of-3");
    let n_new: u16 = 3;

    // ── 3 agents on the relay ──
    let mut privs = Vec::new();
    let mut clients = Vec::new();
    let mut pubs = Vec::new();
    for _ in 0..n_new {
        let p = fresh_priv();
        let c = MessageBoxClient::new(&relay_url, p.clone()).expect("client");
        let ph = c.identity_hex().await.expect("id");
        privs.push(p);
        clients.push(c);
        pubs.push(ph);
    }
    eprintln!("✔ 3 agents on the relay");

    let dkg_session = {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        SessionId(b)
    };
    // Generous: covers the injected prime-seed delay + the full multi-round DKG
    // (keygen + auxinfo) thereafter.
    let timeout = Duration::from_secs(delay.as_secs() + 360);

    let dkg_handlers: Vec<DkgHandler> = (0..n_new)
        .map(|i| DkgHandler::new(new_cfg, i, fresh_storage()))
        .collect();

    // helper to subscribe + initiate + ship round-1 for a single party — WITHOUT
    // primes (the fixed ordering: never block the relay join on prime gen).
    async fn arm_party(
        idx: u16,
        n_new: u16,
        dkg_session: SessionId,
        handler: &DkgHandler,
        client: &MessageBoxClient,
        pubs: &[String],
    ) -> (
        tokio::sync::oneshot::Receiver<bsv_mpc_core::types::DkgResult>,
        MessageBoxListener,
    ) {
        let listener = MessageBoxListener::start(client.clone(), BOX_DKG, handler.handler_fn())
            .await
            .expect("dkg listener");
        let peers: Vec<(u16, String)> = (0..n_new)
            .filter(|&k| k != idx)
            .map(|k| (k, pubs[k as usize].clone()))
            .collect();
        let (rx, out) = handler
            .initiate(dkg_session, peers)
            .await
            .expect("dkg initiate");
        for o in out {
            client
                .send_round_message(&o.recipient_pub_hex, &o.message_box, &o.round_msg, o.params)
                .await
                .expect("ship dkg round-1");
        }
        (rx, listener)
    }

    // ════ ALL 3 parties arm PROMPTLY (subscribe + initiate + ship round-1) ════
    // No party joins the relay late — the §06.17 ordering fix.
    let (rx0, l0) = arm_party(0, n_new, dkg_session, &dkg_handlers[0], &clients[0], &pubs).await;
    let (rx1, l1) = arm_party(1, n_new, dkg_session, &dkg_handlers[1], &clients[1], &pubs).await;
    let (rx2, l2) = arm_party(2, n_new, dkg_session, &dkg_handlers[2], &clients[2], &pubs).await;
    eprintln!(
        "✔ all 3 parties armed + round-1 shipped at +{:?}",
        t0.elapsed()
    );

    // ── Generate primes for parties 1 & 2 and seed immediately; generate +
    //    seed party 0's primes `delay` LATE (models its slow safe-prime gen). ──
    eprintln!(
        "(generating Paillier primes — parties 1,2 seeded now; party 0 seeded {delay:?} late)"
    );
    let mut primes = tokio::task::spawn_blocking(|| {
        (0..3)
            .map(|_| {
                std::thread::spawn(|| {
                    PregeneratedPrimes::<SecurityLevel128>::generate(&mut rand::rngs::OsRng)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    })
    .await
    .expect("prime gen");
    let primes0 = primes.remove(0);
    dkg_handlers[1].seed_primes_late(dkg_session, primes.remove(0));
    dkg_handlers[2].seed_primes_late(dkg_session, primes.remove(0));
    eprintln!(
        "✔ parties 1 & 2 primes seeded at +{:?}; party 0 seeding in {delay:?}",
        t0.elapsed()
    );

    // INJECTED LATENESS: party 0's primes arrive `delay` after init (the real
    // bottleneck) — but party 0 ALREADY subscribed + shipped round-1, so it is
    // NOT late on the relay.
    let h0 = dkg_handlers[0].clone();
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        h0.seed_primes_late(dkg_session, primes0);
    });
    eprintln!(
        "✔ awaiting all 3 aux (party 0's primes seeded late at ~+{:?})",
        delay
    );

    // ── Await all 3 DKGs ──
    let mut rxs = vec![(0usize, rx0), (1, rx1), (2, rx2)];
    let mut completed = 0;
    let mut results: Vec<Option<bsv_mpc_core::types::DkgResult>> = vec![None, None, None];
    for (j, rx) in rxs.drain(..) {
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(r)) => {
                eprintln!("✔ party {j} DKG complete at +{:?}", t0.elapsed());
                results[j] = Some(r);
                completed += 1;
            }
            Ok(Err(e)) => panic!("party {j} DKG channel dropped: {e}"),
            Err(_) => {
                eprintln!(
                    "✗ party {j} DKG TIMED OUT after {:?} (total +{:?}) — REPRODUCES the deployed bug",
                    timeout,
                    t0.elapsed()
                );
                panic!(
                    "party {j} timed out awaiting throwaway DKG aux (delayed-party0 reproduction)"
                );
            }
        }
    }
    for l in [l0, l1, l2] {
        let _ = tokio::time::timeout(Duration::from_secs(10), l.shutdown()).await;
    }

    assert_eq!(
        completed, 3,
        "all 3 parties must complete the throwaway DKG"
    );

    // Sanity: all 3 agree on the joint pubkey of the throwaway key.
    let jpk0 = &results[0].as_ref().unwrap().joint_key.compressed;
    for (j, r) in results.iter().enumerate() {
        assert_eq!(
            &r.as_ref().unwrap().joint_key.compressed,
            jpk0,
            "party {j} disagrees on throwaway joint pubkey"
        );
    }
    eprintln!(
        "✔✔ PASS: late-joining party 0 STILL completed the throwaway 2-of-3 DKG (backfill works). \
         total {:?}",
        t0.elapsed()
    );
}
