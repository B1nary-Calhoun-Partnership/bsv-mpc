//! **#4c gate** — the native cosigner/container's provisioning path stocks the
//! deployed DO pool, and the proxy combiner consumes it over the authed relay.
//!
//! Proves `bsv_mpc_service::ProvisionConfig::ship_presignature` (the code the CF
//! Container runs after each presig gen): it BRC-31-authenticates to the
//! deployed worker and POSTs `Presignature_A` into the DO's pool. Then a real
//! `MpcBridge` (share_B) triggers the authed `/sign-relay`, the DO consumes the
//! service-provisioned presig, and the proxy combines → BSV-valid 2-of-2
//! signature. No sats. This is the self-stocking loop minus the live DKG/presig
//! transport (4e adds the deployed container driving it end to end).
//!
//! Gated on `PROVISION_SVC_E2E=1`.
//!
//! ```bash
//! PROVISION_SVC_E2E=1 cargo test -p bsv-mpc-proxy \
//!   --test provision_via_service_deployed_e2e --release -- --nocapture --test-threads=1
//! ```

use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv_mpc_core::brc31_client::Brc31Client;
use bsv_mpc_core::dkg::{generate_test_primes, DkgCoordinator, DkgRoundResult};
use bsv_mpc_core::presigning::{PresigningManager, PresigningRoundResult};
use bsv_mpc_core::types::{
    DkgResult, EncryptedShare, JointPublicKey, SessionId, ShareIndex, SigningResult,
    ThresholdConfig,
};
use bsv_mpc_proxy::bridge::MpcBridge;
use bsv_mpc_proxy::config::ProxyConfig;
use bsv_mpc_proxy::relay_sign::DoTrigger;
use bsv_mpc_service::ProvisionConfig;
use rand::RngCore;

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";

type PresignBox = Box<dyn std::any::Any + Send>;

fn opt_in() -> bool {
    std::env::var("PROVISION_SVC_E2E").ok().as_deref() == Some("1")
}

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("fresh priv")
}

fn deterministic_sighash(tag: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(tag);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn run_dkg_2of2() -> (JointPublicKey, EncryptedShare, EncryptedShare, SessionId) {
    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let session = SessionId::from_str_hash("prov-svc-dkg");
    let mut c0 = DkgCoordinator::new(session, config, ShareIndex(0));
    let mut c1 = DkgCoordinator::new(session, config, ShareIndex(1));
    let mut rng = rand::rngs::OsRng;
    c0.set_pregenerated_primes(generate_test_primes(&mut rng));
    c1.set_pregenerated_primes(generate_test_primes(&mut rng));
    let mut out0 = c0.init().expect("c0 init");
    let mut out1 = c1.init().expect("c1 init");
    for round in 0..40 {
        let r0 = c0.process_round(out1.clone()).expect("c0 round");
        let r1 = c1.process_round(out0.clone()).expect("c1 round");
        match (r0, r1) {
            (DkgRoundResult::Complete(a), DkgRoundResult::Complete(b)) => {
                assert_eq!(a.joint_key.compressed, b.joint_key.compressed);
                return (a.joint_key, a.share, b.share, session);
            }
            (DkgRoundResult::NextRound(n0), DkgRoundResult::NextRound(n1)) => {
                out0 = n0;
                out1 = n1;
            }
            _ => panic!("DKG desync at round {round}"),
        }
    }
    panic!("DKG did not complete");
}

fn gen_presig_pair(share0: EncryptedShare, share1: EncryptedShare) -> (Vec<u8>, PresignBox) {
    let session = SessionId::from_str_hash("prov-svc-presig");
    let participants = vec![0u16, 1u16];
    let mut m0 = PresigningManager::new(session, share0, participants.clone(), 2);
    let mut m1 = PresigningManager::new(session, share1, participants, 2);
    let mut o0 = m0.init_generate().expect("m0 init");
    let mut o1 = m1.init_generate().expect("m1 init");
    let (mut d0, mut d1) = (false, false);
    for _ in 0..40 {
        if d0 && d1 {
            break;
        }
        let r0 = m0.process_generate_round(o1.clone()).expect("m0 round");
        let r1 = m1.process_generate_round(o0.clone()).expect("m1 round");
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
    assert_eq!(m0.pool_size(), 1);
    assert_eq!(m1.pool_size(), 1);
    let (_w0, box0) = m0.take_raw().expect("m0 take_raw");
    let presig_a_json = bsv_mpc_core::presigning::serialize_party_presignature(box0)
        .expect("serialize Presignature_A");
    let (_w1, box1) = m1.take_raw().expect("m1 take_raw");
    (presig_a_json, box1)
}

fn assert_bsv_valid(joint: &JointPublicKey, sighash: &[u8; 32], sig: &SigningResult) {
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&joint.compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey");
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.r);
    s.copy_from_slice(&sig.s);
    let bsv_sig = Signature::new(r, s);
    assert!(bsv_sig.is_low_s(), "MPC signature MUST be low-s");
    assert!(
        joint_pub.verify(sighash, &bsv_sig),
        "combined signature MUST verify under the joint pubkey"
    );
}

#[tokio::test]
async fn service_provisions_do_pool_proxy_combines() {
    if !opt_in() {
        eprintln!("PROVISION_SVC_E2E=1 not set — skipping #4c service-provisioning gate.");
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let worker_url =
        std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.to_string());
    let relay_url =
        std::env::var("MESSAGEBOX_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string());

    // 1. DKG + correlated pair (share0 = cosigner/container, share1 = proxy).
    let (joint, share0, share1, dkg_session) = run_dkg_2of2();
    let joint_hex = hex::encode(&joint.compressed);
    eprintln!("✔ joint pubkey = {joint_hex}");
    let (presig_a_json, box_b) = gen_presig_pair(share0, share1.clone());

    // 2. The native cosigner/container ships Presignature_A → DO pool, using the
    //    SERVICE's ProvisionConfig (the exact code path the CF Container runs).
    let prov = ProvisionConfig {
        worker_url: worker_url.clone(),
        auth: tokio::sync::Mutex::new(Brc31Client::new(fresh_priv())),
        http: reqwest::Client::new(),
    };
    prov.ship_presignature(&joint_hex, &presig_a_json, "prov-svc", "prov-svc-1")
        .await
        .expect("service ships Presignature_A to the deployed DO pool");
    eprintln!("✔ service provisioned Presignature_A → DO pool (authed /ceremony/ingest-presig)");

    // 3. Proxy combiner (share_B): real bridge, authed /sign-relay consumes the
    //    service-provisioned presig from the DO pool, combine → BSV-valid.
    let dkg_result = DkgResult {
        joint_key: joint.clone(),
        share: share1,
        session_id: dkg_session,
    };
    let dir = std::env::temp_dir();
    let share_path = dir.join(format!("prov_svc_share_{}.json", std::process::id()));
    tokio::fs::write(&share_path, serde_json::to_vec(&dkg_result).unwrap())
        .await
        .expect("write share");
    let config = ProxyConfig {
        port: 3322,
        kss_url: worker_url.clone(),
        share_path: share_path.to_string_lossy().to_string(),
        fee_per_signing: 0,
        fee_addresses: vec![],
        fee_threshold: None,
        max_presignatures: 5,
        encryption_key: None,
        arc_api_key: "unused".into(),
        threshold_configs: vec!["2-of-2".to_string()],
        min_balance_sats: None,
        relay_url,
        relay_sign: true,
        presign_url: None,
    };
    let bridge = MpcBridge::new(&config).await.expect("bridge handshake");

    let sighash = deterministic_sighash(b"provision via service v1");
    let trigger = DoTrigger {
        url: format!("{worker_url}/sign-relay"),
        presig_a_json: vec![],
        do_index: 0,
        agent_id: Some(joint_hex.clone()),
        auth_headers: vec![],
        cosigner_encrypted_share: None,
        brc42_offset: None,
    };
    let sig: SigningResult = bridge
        .sign_over_relay(&sighash, box_b, None, trigger, Duration::from_secs(60))
        .await
        .expect("proxy combines the service-provisioned presig over the relay");
    assert_bsv_valid(&joint, &sighash, &sig);
    let _ = tokio::fs::remove_file(&share_path).await;

    eprintln!(
        "✔ BSV-valid 2-of-2 sig from a SERVICE-provisioned presig (DER {} bytes)",
        sig.signature.len()
    );
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #4c GATE PASS — service provisions DO pool, proxy combines    ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
}
