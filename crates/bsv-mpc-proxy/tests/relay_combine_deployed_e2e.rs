//! **#12 (I-4c) gate** — the proxy's production relay combiner co-signs with the
//! DEPLOYED DO over the live MessageBox relay → BSV-valid 2-of-2 signature.
//!
//! This drives `bsv_mpc_proxy::relay_sign::combine_sign_over_relay` — the same
//! function `MpcBridge::sign_over_relay` delegates to — with a real generated
//! `share_B` + correlated `(Presignature_B, PresignaturePublicData_B)`. Party
//! 0's `Presignature_A` is shipped to the deployed `/poc/sign-relay`; the DO
//! issues + relays party-0's partial; the proxy combines into a final ECDSA
//! signature and verifies it under the joint pubkey. No sats (I-5/#16 adds the
//! broadcast).
//!
//! Gated on `RELAY_COMBINE_E2E=1`; `DEPLOYED_WORKER_URL` / `MESSAGEBOX_RELAY_URL`
//! default to the Calhoun `dev-a3e` deployments.
//!
//! ```bash
//! RELAY_COMBINE_E2E=1 cargo test -p bsv-mpc-proxy \
//!   --test relay_combine_deployed_e2e --release -- --nocapture --test-threads=1
//! ```

use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv_mpc_core::dkg::{generate_test_primes, DkgCoordinator, DkgRoundResult};
use bsv_mpc_core::presigning::{PresigningManager, PresigningRoundResult};
use bsv_mpc_core::types::{
    EncryptedShare, JointPublicKey, SessionId, ShareIndex, SigningResult, ThresholdConfig,
};
use bsv_mpc_proxy::relay_sign::{combine_sign_over_relay, DoTrigger};
use rand::RngCore;

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";

type PresignBox = Box<dyn std::any::Any + Send>;

fn opt_in() -> bool {
    std::env::var("RELAY_COMBINE_E2E").ok().as_deref() == Some("1")
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

fn run_dkg_2of2() -> (JointPublicKey, EncryptedShare, EncryptedShare) {
    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let session = SessionId::from_str_hash("i4c-dkg");
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
                return (a.joint_key, a.share, b.share);
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

/// Party 0's serialized `Presignature_A` (for the DO) + party 1's boxed
/// `PresignOutput` (for the proxy combiner).
fn gen_presig_pair(share0: EncryptedShare, share1: EncryptedShare) -> (Vec<u8>, PresignBox) {
    let session = SessionId::from_str_hash("i4c-presig");
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
        "proxy-combined signature MUST verify under the joint pubkey"
    );
}

#[tokio::test]
async fn proxy_combines_deployed_do_over_relay() {
    if !opt_in() {
        eprintln!(
            "RELAY_COMBINE_E2E=1 not set — skipping #12 proxy relay-combiner gate.
To run: RELAY_COMBINE_E2E=1 cargo test -p bsv-mpc-proxy \\
  --test relay_combine_deployed_e2e --release -- --nocapture --test-threads=1"
        );
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let worker_url =
        std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.to_string());
    let relay_url =
        std::env::var("MESSAGEBOX_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string());

    // Real DKG + correlated presig pair. share1 = the proxy's share_B.
    let (joint, share0, share1) = run_dkg_2of2();
    let (presig_a_json, box_b) = gen_presig_pair(share0, share1.clone());
    let sighash = deterministic_sighash(b"i4c proxy relay-combine v1");
    let sign_session = SessionId::from_str_hash("i4c-sign");
    eprintln!("✔ joint pubkey = {}", hex::encode(&joint.compressed));

    // Drive the PRODUCTION proxy combiner (what MpcBridge::sign_over_relay calls).
    let sig = combine_sign_over_relay(
        &relay_url,
        fresh_priv(), // proxy's relay identity (analogous to BridgeAuth.auth_key)
        share1,
        vec![0, 1],
        ThresholdConfig::new(2, 2).unwrap(),
        sign_session,
        &sighash,
        box_b,
        &joint,
        DoTrigger {
            url: format!("{worker_url}/poc/sign-relay"),
            presig_a_json,
            do_index: 0,
            agent_id: None,
            auth_headers: vec![],
        },
        None, // unauthed POC route — no canonical signer
        Duration::from_secs(40),
    )
    .await
    .expect("proxy combines the deployed DO's partial over the relay");

    assert_bsv_valid(&joint, &sighash, &sig);

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #12 I-4c — PROXY COMBINES DEPLOYED DO'S PARTIAL OVER RELAY   ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("  joint_pubkey: {}", hex::encode(&joint.compressed));
    eprintln!("  joint_address: {}", joint.address);
    eprintln!("  sighash: {}", hex::encode(sighash));
    eprintln!(
        "  DER sig ({} bytes): {}",
        sig.signature.len(),
        hex::encode(&sig.signature)
    );
    eprintln!("  → BSV-valid under the joint pubkey (NO sats spent).");
}
