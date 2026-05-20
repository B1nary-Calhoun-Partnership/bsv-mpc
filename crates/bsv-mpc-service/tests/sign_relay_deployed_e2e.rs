//! **#15 (I-4b.2) gate** — the DEPLOYED CF Worker DO co-signs over the live relay.
//!
//! End-to-end, NO sats: a real 2-of-2 CGGMP'24 key + a correlated pair of
//! presignatures are generated locally via the `bsv-mpc-core` public API. This
//! party (the combiner, party 1) holds `share_B` + `(Presignature_B,
//! PresignaturePublicData_B)`. Party 0's serialized `Presignature_A` is shipped
//! to the **deployed** `bsv-mpc-worker` DO (`/poc/sign-relay`), which custodies
//! it in its pool, issues party 0's partial signature, wraps it as a canonical
//! §05 `MessageEnvelope`, and sends it to this combiner over the **live
//! MessageBox relay**. The combiner receives the partial, combines it with its
//! own, and asserts the resulting ECDSA signature is **BSV-valid** under the
//! joint public key.
//!
//! This is the ADR-018 hybrid in full: the wasm DO is the light online signer
//! (issue partial), the native party is the combiner (holds the
//! non-serializable `PresignaturePublicData`). The DO's transport identity is
//! independent of the MPC math — it merely custodies + issues `Presignature_A`.
//!
//! ## Gating
//!
//! - `local_hybrid_combine_via_public_api` — pure-crypto control (no network);
//!   proves the hybrid issue/combine plumbing with `PresigningManager` +
//!   `DkgCoordinator` outputs. Runs only under `SIGN_RELAY_E2E=1`.
//! - `deployed_do_cosigns_over_relay` — the live gate. Runs only under
//!   `SIGN_RELAY_E2E=1`; uses `DEPLOYED_WORKER_URL` / `MESSAGEBOX_RELAY_URL`
//!   (defaults to the Calhoun `dev-a3e` deployments).
//!
//! ```bash
//! SIGN_RELAY_E2E=1 cargo test -p bsv-mpc-service \
//!   --test sign_relay_deployed_e2e --release -- --nocapture --test-threads=1
//! ```

use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv_mpc_core::dkg::{generate_test_primes, DkgCoordinator, DkgRoundResult};
use bsv_mpc_core::presigning::{PresigningManager, PresigningRoundResult};
use bsv_mpc_core::signing::{issue_partial_signature_json, SigningCoordinator, SigningRoundResult};
use bsv_mpc_core::types::{
    EncryptedShare, JointPublicKey, RoundMessage, SessionId, ShareIndex, SigningResult,
    ThresholdConfig,
};
use bsv_mpc_messagebox::types::BOX_SIGN;
use bsv_mpc_messagebox::MessageBoxClient;
use cggmp24::signing::PresignaturePublicData;
use cggmp24::supported_curves::Secp256k1;
use rand::RngCore;

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";

fn opt_in() -> bool {
    std::env::var("SIGN_RELAY_E2E").ok().as_deref() == Some("1")
}

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("fresh priv must be valid")
}

fn deterministic_sighash(tag: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(tag);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Boxed PresignOutput as `sign_with_presignature` expects it.
type PresignBox = Box<dyn std::any::Any + Send>;

/// Run a real 2-of-2 DKG via two in-process `DkgCoordinator`s (Blum test
/// primes), returning the joint key + both parties' plaintext-KeyShare-bearing
/// `EncryptedShare`s.
fn run_dkg_2of2() -> (JointPublicKey, EncryptedShare, EncryptedShare) {
    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let session = SessionId::from_str_hash("i4b2-dkg");
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
                assert_eq!(
                    a.joint_key.compressed, b.joint_key.compressed,
                    "DKG must agree on joint pubkey"
                );
                return (a.joint_key, a.share, b.share);
            }
            (DkgRoundResult::NextRound(n0), DkgRoundResult::NextRound(n1)) => {
                out0 = n0;
                out1 = n1;
            }
            _ => panic!("DKG desynchronized at round {round}"),
        }
    }
    panic!("DKG did not complete within 40 rounds");
}

/// Generate one correlated presignature pair via two `PresigningManager`s.
/// Returns party 0's serialized `cggmp24::Presignature` (for the DO) + party
/// 1's boxed `PresignOutput` (for the combiner's `sign_with_presignature`).
fn gen_presig_pair(share0: EncryptedShare, share1: EncryptedShare) -> (Vec<u8>, PresignBox) {
    let session = SessionId::from_str_hash("i4b2-presig");
    let participants = vec![0u16, 1u16];
    let mut m0 = PresigningManager::new(session, share0, participants.clone(), 2);
    let mut m1 = PresigningManager::new(session, share1, participants, 2);

    let mut o0 = m0.init_generate().expect("m0 init_generate");
    let mut o1 = m1.init_generate().expect("m1 init_generate");
    let mut done0 = false;
    let mut done1 = false;
    for _ in 0..40 {
        if done0 && done1 {
            break;
        }
        let r0 = m0.process_generate_round(o1.clone()).expect("m0 round");
        let r1 = m1.process_generate_round(o0.clone()).expect("m1 round");
        o0 = match r0 {
            PresigningRoundResult::NextRound(m) => m,
            PresigningRoundResult::Complete => {
                done0 = true;
                vec![]
            }
        };
        o1 = match r1 {
            PresigningRoundResult::NextRound(m) => m,
            PresigningRoundResult::Complete => {
                done1 = true;
                vec![]
            }
        };
    }
    assert_eq!(m0.pool_size(), 1, "m0 must hold a presignature");
    assert_eq!(m1.pool_size(), 1, "m1 must hold a presignature");

    // Party 0 → serialized cggmp24 Presignature for the DO (the only data the
    // light wasm cosigner needs; PresignaturePublicData stays native).
    let (_w0, box0) = m0.take_raw().expect("m0 take_raw");
    let (presig_a, _public_a) = *box0
        .downcast::<(
            cggmp24::Presignature<Secp256k1>,
            PresignaturePublicData<Secp256k1>,
        )>()
        .expect("box0 is the cggmp24 presignature output");
    let presig_a_json = serde_json::to_vec(&presig_a).expect("serialize Presignature_A");

    // Party 1 → boxed PresignOutput for the combiner.
    let (_w1, box1) = m1.take_raw().expect("m1 take_raw");
    (presig_a_json, box1)
}

/// Combine party 0's partial (issued from `Presignature_A`) with this party's
/// (`share1` + boxed `PresignOutput`) and return the final ECDSA signature.
fn combine_to_signature(
    share1: EncryptedShare,
    presig_box_b: PresignBox,
    sighash: &[u8; 32],
    partial_a: RoundMessage,
) -> SigningResult {
    let session = SessionId::from_str_hash("i4b2-sign");
    let mut coord = SigningCoordinator::new(
        session,
        share1,
        ThresholdConfig::new(2, 2).unwrap(),
        vec![0, 1],
    );
    coord
        .sign_with_presignature(sighash, presig_box_b)
        .expect("combiner issues its own partial");
    match coord
        .process_round(vec![partial_a])
        .expect("combiner combines the DO's partial + its own")
    {
        SigningRoundResult::Complete(sig) => sig,
        SigningRoundResult::NextRound(_) => panic!("combiner did not complete after one partial"),
    }
}

/// BSV-verify a `SigningResult` against the joint pubkey; assert low-s + valid.
fn assert_bsv_valid(joint: &JointPublicKey, sighash: &[u8; 32], sig: &SigningResult) {
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&joint.compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey");
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.r);
    s.copy_from_slice(&sig.s);
    let bsv_sig = Signature::new(r, s);
    assert!(bsv_sig.is_low_s(), "MPC signature MUST be low-s (BIP-62)");
    assert!(
        joint_pub.verify(sighash, &bsv_sig),
        "hybrid signature MUST verify under the joint pubkey"
    );
}

/// Pure-crypto control (no network): prove the hybrid issue/combine path using
/// `PresigningManager` + `DkgCoordinator` public-API outputs. De-risks the
/// relay test — if this passes, the relay only adds transport (proven byte-
/// identical in #15 Part A).
#[tokio::test]
async fn local_hybrid_combine_via_public_api() {
    if !opt_in() {
        eprintln!("SIGN_RELAY_E2E=1 not set — skipping local hybrid control.");
        return;
    }
    let (joint, share0, share1) = run_dkg_2of2();
    let (presig_a_json, box_b) = gen_presig_pair(share0, share1.clone());
    let sighash = deterministic_sighash(b"i4b2 local hybrid control v1");

    // DO-side op (run locally here): issue party 0's partial.
    let partial_a_json =
        issue_partial_signature_json(&presig_a_json, &sighash).expect("issue partial A");
    let partial_a = RoundMessage {
        session_id: SessionId::from_str_hash("i4b2-sign"),
        round: 1,
        from: ShareIndex(0),
        to: None,
        payload: partial_a_json,
    };

    let sig = combine_to_signature(share1, box_b, &sighash, partial_a);
    assert_bsv_valid(&joint, &sighash, &sig);
    eprintln!(
        "✔ local hybrid control: BSV-valid sig, DER {} bytes, joint={}",
        sig.signature.len(),
        hex::encode(&joint.compressed)
    );
}

/// The live #15 gate: the DEPLOYED DO issues party 0's partial over the live
/// relay; this combiner combines it into a BSV-valid 2-of-2 signature.
#[tokio::test]
async fn deployed_do_cosigns_over_relay() {
    if !opt_in() {
        eprintln!(
            "SIGN_RELAY_E2E=1 not set — skipping deployed DO co-sign gate.
To run: SIGN_RELAY_E2E=1 cargo test -p bsv-mpc-service \\
  --test sign_relay_deployed_e2e --release -- --nocapture --test-threads=1"
        );
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let worker_url =
        std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.to_string());
    let relay_url =
        std::env::var("MESSAGEBOX_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string());

    // 1. Local DKG + correlated presig pair.
    let (joint, share0, share1) = run_dkg_2of2();
    let (presig_a_json, box_b) = gen_presig_pair(share0, share1.clone());
    let sighash = deterministic_sighash(b"i4b2 deployed relay co-sign v1");
    let sign_session = SessionId::from_str_hash("i4b2-sign");
    eprintln!("✔ joint pubkey = {}", hex::encode(&joint.compressed));

    // 2. Combiner identity + subscription (BEFORE we trigger the DO send).
    let combiner = MessageBoxClient::new(&relay_url, fresh_priv()).expect("combiner client");
    let combiner_pub = combiner.identity_hex().await.expect("combiner identity");
    eprintln!("✔ combiner identity = {combiner_pub}");
    let mut sub = combiner
        .subscribe_round_messages(BOX_SIGN)
        .await
        .expect("combiner subscribes to mpc-sign");

    // 3. Prime the combiner coordinator (issues its own partial; holds public data).
    let mut coord = SigningCoordinator::new(
        sign_session,
        share1,
        ThresholdConfig::new(2, 2).unwrap(),
        vec![0, 1],
    );
    coord
        .sign_with_presignature(&sighash, box_b)
        .expect("combiner issues its partial");

    // 4. Ship Presignature_A to the deployed DO; it issues + relays party 0's partial.
    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{worker_url}/poc/sign-relay"))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "presignature_hex": hex::encode(&presig_a_json),
            "sighash_hex": hex::encode(sighash),
            "recipient_pub_hex": combiner_pub,
            "from_index": 0,
            "to_index": 1,
            "joint_pubkey_hex": hex::encode(&joint.compressed),
            "session_id_hex": sign_session.hex(),
        }))
        .send()
        .await
        .expect("deployed /poc/sign-relay reachable");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("sign-relay JSON");
    eprintln!("✔ DO /poc/sign-relay ({status}): {body}");
    assert!(status.is_success(), "sign-relay HTTP {status}");
    assert_eq!(
        body["sent"],
        serde_json::json!(true),
        "DO must send the partial"
    );
    assert_eq!(
        body["pool_round_trip_matches"],
        serde_json::json!(true),
        "DO pool round-trip must be byte-identical"
    );

    // 5. Receive the DO's partial over the relay.
    let decoded = tokio::time::timeout(Duration::from_secs(40), sub.next())
        .await
        .expect("partial must arrive within 40s")
        .expect("subscription stream open")
        .expect("partial decodes cleanly (BRC-78 + BRC-31 + §05.9.1)");
    eprintln!(
        "✔ received DO partial: from party {}, sender={}",
        decoded.round_msg.from.0,
        decoded.sender_pub.to_hex()
    );
    assert_eq!(
        decoded.round_msg.from,
        ShareIndex(0),
        "the DO emits party 0's partial"
    );

    // 6. Combine → BSV-valid 2-of-2 signature.
    let sig = match coord
        .process_round(vec![decoded.round_msg])
        .expect("combine the DO's partial + our own")
    {
        SigningRoundResult::Complete(s) => s,
        SigningRoundResult::NextRound(_) => panic!("did not complete after the DO's partial"),
    };
    assert_bsv_valid(&joint, &sighash, &sig);
    sub.shutdown().await;

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #15 I-4b.2 — DEPLOYED DO CO-SIGNED OVER THE LIVE RELAY       ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("  joint_pubkey: {}", hex::encode(&joint.compressed));
    eprintln!("  joint_address: {}", joint.address);
    eprintln!("  sighash: {}", hex::encode(sighash));
    eprintln!(
        "  DER sig ({} bytes): {}",
        sig.signature.len(),
        hex::encode(&sig.signature)
    );
    eprintln!("  r: {}", hex::encode(&sig.r));
    eprintln!("  s: {}", hex::encode(&sig.s));
    eprintln!("  → BSV-valid under the joint pubkey (NO sats spent).");
}
