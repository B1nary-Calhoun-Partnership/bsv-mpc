//! **Online-sign latency benchmark** (#5 speed item) — measures the wall-clock
//! of the ADR-018 relay online-sign hot path against the DEPLOYED cosigner DO +
//! live MessageBox relay, plus the pure wasm DO `issue_partial` round-trip.
//!
//! Pool is pre-stocked (K correlated pairs from one DKG), then K online signs
//! are timed. Reports per-sign + min/median/mean/max. No sats. Gated on
//! `RELAY_BENCH_E2E=1`.
//!
//! ```bash
//! RELAY_BENCH_E2E=1 cargo test -p bsv-mpc-proxy \
//!   --test relay_sign_bench_e2e --release -- --nocapture --test-threads=1
//! ```

use std::time::{Duration, Instant};

use bsv::primitives::ec::{PublicKey, Signature};
use bsv_mpc_core::dkg::{generate_test_primes, DkgCoordinator, DkgRoundResult};
use bsv_mpc_core::presigning::{
    serialize_party_presignature, PresigningManager, PresigningRoundResult,
};
use bsv_mpc_core::types::{
    DkgResult, EncryptedShare, JointPublicKey, SessionId, ShareIndex, SigningResult,
    ThresholdConfig,
};
use bsv_mpc_proxy::bridge::MpcBridge;
use bsv_mpc_proxy::config::ProxyConfig;
use bsv_mpc_proxy::relay_sign::DoTrigger;

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";

type PresignBox = Box<dyn std::any::Any + Send>;

fn opt_in() -> bool {
    std::env::var("RELAY_BENCH_E2E").ok().as_deref() == Some("1")
}

fn run_dkg_2of2() -> (JointPublicKey, EncryptedShare, EncryptedShare, SessionId) {
    let config = ThresholdConfig::new(2, 2).unwrap();
    let session = SessionId::from_str_hash("bench-dkg");
    let mut c0 = DkgCoordinator::new(session, config, ShareIndex(0));
    let mut c1 = DkgCoordinator::new(session, config, ShareIndex(1));
    let mut rng = rand::rngs::OsRng;
    c0.set_pregenerated_primes(generate_test_primes(&mut rng));
    c1.set_pregenerated_primes(generate_test_primes(&mut rng));
    let mut out0 = c0.init().unwrap();
    let mut out1 = c1.init().unwrap();
    for _ in 0..40 {
        let r0 = c0.process_round(out1.clone()).unwrap();
        let r1 = c1.process_round(out0.clone()).unwrap();
        match (r0, r1) {
            (DkgRoundResult::Complete(a), DkgRoundResult::Complete(b)) => {
                assert_eq!(a.joint_key.compressed, b.joint_key.compressed);
                return (a.joint_key, a.share, b.share, session);
            }
            (DkgRoundResult::NextRound(n0), DkgRoundResult::NextRound(n1)) => {
                out0 = n0;
                out1 = n1;
            }
            _ => panic!("DKG desync"),
        }
    }
    panic!("DKG did not complete");
}

fn gen_presig_pair(share0: EncryptedShare, share1: EncryptedShare) -> (Vec<u8>, PresignBox) {
    let session = SessionId::from_str_hash("bench-presig");
    let participants = vec![0u16, 1u16];
    let mut m0 = PresigningManager::new(session, share0, participants.clone(), 2);
    let mut m1 = PresigningManager::new(session, share1, participants, 2);
    let mut o0 = m0.init_generate().unwrap();
    let mut o1 = m1.init_generate().unwrap();
    let (mut d0, mut d1) = (false, false);
    for _ in 0..40 {
        if d0 && d1 {
            break;
        }
        let r0 = m0.process_generate_round(o1.clone()).unwrap();
        let r1 = m1.process_generate_round(o0.clone()).unwrap();
        o0 = match r0 {
            PresigningRoundResult::NextRound(m) => m,
            PresigningRoundResult::Complete => {
                d0 = true;
                vec![]
            }
        };
        o1 = match r1 {
            PresigningRoundResult::NextRound(m) => m,
            PresigningRoundResult::Complete => {
                d1 = true;
                vec![]
            }
        };
    }
    let (_w0, box0) = m0.take_raw().unwrap();
    let presig_a_json = serialize_party_presignature(box0).unwrap();
    let (_w1, box1) = m1.take_raw().unwrap();
    (presig_a_json, box1)
}

fn assert_bsv_valid(joint: &JointPublicKey, sighash: &[u8; 32], sig: &SigningResult) {
    let mut a = [0u8; 33];
    a.copy_from_slice(&joint.compressed);
    let joint_pub = PublicKey::from_bytes(&a).unwrap();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.r);
    s.copy_from_slice(&sig.s);
    assert!(joint_pub.verify(sighash, &Signature::new(r, s)));
}

fn stats(label: &str, mut xs: Vec<u128>) {
    xs.sort_unstable();
    let n = xs.len();
    let sum: u128 = xs.iter().sum();
    let median = xs[n / 2];
    eprintln!(
        "  {label}: n={n} min={}ms median={}ms mean={}ms max={}ms",
        xs[0],
        median,
        sum / n as u128,
        xs[n - 1]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_online_sign_latency() {
    if !opt_in() {
        eprintln!("RELAY_BENCH_E2E=1 not set — skipping online-sign latency benchmark.");
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let worker_url =
        std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.to_string());
    let relay_url =
        std::env::var("MESSAGEBOX_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string());
    let k: usize = std::env::var("BENCH_K")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    // One DKG, K correlated presig pairs (pair 0's A drives the repeatable
    // issue-partial probe; all K drive K sequential end-to-end relay signs).
    let (joint, share0, share1, dkg_session) = run_dkg_2of2();
    let joint_hex = hex::encode(&joint.compressed);
    eprintln!("✔ joint {joint_hex}; generating {k} presig pairs…");
    let mut pairs: Vec<(Vec<u8>, PresignBox)> = Vec::new();
    for _ in 0..k {
        pairs.push(gen_presig_pair(share0.clone(), share1.clone()));
    }
    let presig_a_json = pairs[0].0.clone();

    // ── A. Pure DO partial-issue latency (the wasm online-sign compute) via the
    //    direct `/poc/issue-partial` HTTP route (no relay; repeatable — the
    //    issue is deterministic and does not consume the presig). ──
    let http = reqwest::Client::new();
    let mut issue_ms = Vec::new();
    for i in 0..k {
        let sighash = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(format!("bench-issue-{i}").as_bytes());
            let mut o = [0u8; 32];
            o.copy_from_slice(&h.finalize());
            o
        };
        let t = Instant::now();
        let resp = http
            .post(format!("{worker_url}/poc/issue-partial"))
            .json(&serde_json::json!({
                "presignature_hex": hex::encode(&presig_a_json),
                "sighash_hex": hex::encode(sighash),
            }))
            .send()
            .await
            .expect("issue-partial");
        assert!(resp.status().is_success(), "issue-partial status");
        let _: serde_json::Value = resp.json().await.expect("issue-partial json");
        issue_ms.push(t.elapsed().as_millis());
    }
    eprintln!("✔ measured {k} DO issue-partial round-trips");

    // Real proxy bridge (authed to the deployed DO).
    let dkg_result = DkgResult {
        joint_key: joint.clone(),
        share: share1,
        session_id: dkg_session,
    };
    let dir = std::env::temp_dir();
    let share_path = dir.join(format!("bench_share_{}.json", std::process::id()));
    tokio::fs::write(&share_path, serde_json::to_vec(&dkg_result).unwrap())
        .await
        .unwrap();
    let config = ProxyConfig {
        port: 3322,
        kss_url: worker_url.clone(),
        share_path: share_path.to_string_lossy().to_string(),
        fee_per_signing: 0,
        fee_addresses: vec![],
        fee_threshold: None,
        max_presignatures: 10,
        encryption_key: None,
        arc_api_key: "unused".into(),
        threshold_configs: vec!["2-of-2".to_string()],
        min_balance_sats: None,
        relay_url,
        relay_sign: true,
        presign_url: None,
    };
    let bridge = MpcBridge::new(&config).await.expect("bridge handshake");

    // ── B. K SEQUENTIAL end-to-end relay co-signs. Provision K presigs (FIFO
    //    pool: the DO consumes oldest-first, matching our box order), then sign K
    //    times. This exercises the per-sign-session relay filter (the root-cause
    //    fix for stale-backlog cross-contamination) — each co-sign MUST be
    //    BSV-valid, proving sequential signing is robust. ──
    let mut provision_ms = Vec::new();
    let mut boxes: Vec<PresignBox> = Vec::new();
    for (i, (presig_a_json, box_b)) in pairs.into_iter().enumerate() {
        let t = Instant::now();
        bridge
            .provision_presig_to_do(&joint_hex, &presig_a_json, "bench", &format!("bench-{i}"))
            .await
            .expect("provision");
        provision_ms.push(t.elapsed().as_millis());
        boxes.push(box_b);
    }
    eprintln!("✔ provisioned {k} presigs to the deployed DO pool");

    let mut sign_ms = Vec::new();
    for (i, box_b) in boxes.into_iter().enumerate() {
        let sighash = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(format!("bench-relay-sign-{i}").as_bytes());
            let mut o = [0u8; 32];
            o.copy_from_slice(&h.finalize());
            o
        };
        let trigger = DoTrigger {
            url: format!("{worker_url}/sign-relay"),
            presig_a_json: vec![],
            do_index: 0,
            agent_id: Some(joint_hex.clone()),
            auth_headers: vec![],
            cosigner_encrypted_share: None,
            brc42_offset: None,
        };
        let t = Instant::now();
        let sig = bridge
            .sign_over_relay(&sighash, box_b, None, trigger, Duration::from_secs(60))
            .await
            .expect("relay sign");
        let ms = t.elapsed().as_millis();
        assert_bsv_valid(&joint, &sighash, &sig);
        eprintln!("  relay sign {i}: {ms}ms (BSV-valid)");
        sign_ms.push(ms);
    }

    let _ = tokio::fs::remove_file(&share_path).await;

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  ONLINE-SIGN LATENCY — deployed cosigner DO + live relay       ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    stats(
        "DO issue-partial RTT (wasm online-sign compute + HTTPS, no relay)",
        issue_ms,
    );
    stats(
        "end-to-end relay co-sign (subscribe+BRC-103 handshake+trigger+relay+combine)",
        sign_ms,
    );
    stats(
        "presig provision (authed POST /ceremony/ingest-presig)",
        provision_ms,
    );
    eprintln!("  NOTE: each relay co-sign opens a FRESH relay session (BRC-103 handshake)");
    eprintln!("        per call — a warm/pooled relay connection removes that one-time cost,");
    eprintln!("        leaving ~the DO issue-partial RTT + one relay round-trip as the floor.");
}
