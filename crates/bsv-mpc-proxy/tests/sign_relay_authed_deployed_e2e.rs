//! **#6 / #5 step 4 gate** — the proxy co-signs with the DEPLOYED DO over the
//! live relay through the **production, BRC-31-authed `/sign-relay`** route
//! (not the unauthed `/poc/sign-relay`), driven by a real [`MpcBridge`] with
//! its stable owner identity (§07.4 / §08.1).
//!
//! Flow (the real production path):
//! 1. Real 2-of-2 DKG → joint key + correlated presignature pair.
//! 2. Build an `MpcBridge` from `share_B` pointed at the deployed worker — it
//!    derives the proxy's stable identity from the share and performs the BRC-31
//!    handshake (durable DO-SQLite session, #5 step 3).
//! 3. `provision_presig_to_do` ships `Presignature_A` into the DO pool over the
//!    **authed** `/ceremony/ingest-presig`.
//! 4. `sign_over_relay` triggers the **authed** `/sign-relay`: the DO consumes
//!    the pooled presig, issues its partial, relays it; the proxy combines into
//!    a BSV-valid 2-of-2 signature. No sats (the #6 gate adds the broadcast).
//! 5. Negative control: an **unauthed** `/sign-relay` POST → **401** (§07.6 —
//!    no endpoint trusted by location).
//!
//! Gated on `SIGN_RELAY_AUTHED_E2E=1`.
//!
//! ```bash
//! SIGN_RELAY_AUTHED_E2E=1 cargo test -p bsv-mpc-proxy \
//!   --test sign_relay_authed_deployed_e2e --release -- --nocapture --test-threads=1
//! ```

use std::time::Duration;

use bsv::primitives::ec::{PublicKey, Signature};
use bsv_mpc_core::dkg::{generate_test_primes, DkgCoordinator, DkgRoundResult};
use bsv_mpc_core::presigning::{PresigningManager, PresigningRoundResult};
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
    std::env::var("SIGN_RELAY_AUTHED_E2E").ok().as_deref() == Some("1")
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
    let session = SessionId::from_str_hash("authed-dkg");
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

fn gen_presig_pair(
    share0: EncryptedShare,
    share1: EncryptedShare,
) -> (Vec<u8>, bsv_mpc_core::types::Presignature, PresignBox) {
    let session = SessionId::from_str_hash("authed-presig");
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
    let (presig_b, box1) = m1.take_raw().expect("m1 take_raw");
    (presig_a_json, presig_b, box1)
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

fn proxy_config(
    share_path: String,
    worker_url: &str,
    relay_url: &str,
    relay_sign: bool,
) -> ProxyConfig {
    ProxyConfig {
        port: 3322,
        kss_url: worker_url.to_string(),
        share_path,
        fee_per_signing: 0,
        fee_addresses: vec![],
        fee_threshold: None,
        max_presignatures: 5,
        encryption_key: None,
        arc_api_key: "test_key".into(),
        threshold_configs: vec!["2-of-2".to_string()],
        min_balance_sats: None,
        relay_url: relay_url.to_string(),
        relay_sign,
        presign_url: None,
        approval_recv_timeout_secs: 60,
        network: None,
        policy_manifest_path: None,
    }
}

#[tokio::test]
async fn proxy_cosigns_through_authed_sign_relay() {
    if !opt_in() {
        eprintln!(
            "SIGN_RELAY_AUTHED_E2E=1 not set — skipping #6/#5-step-4 authed sign-relay gate."
        );
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let worker_url =
        std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.to_string());
    let relay_url =
        std::env::var("MESSAGEBOX_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string());

    // ── 1. Real DKG + correlated presig pair. share1 = the proxy's share_B. ──
    let (joint, share0, share1, dkg_session) = run_dkg_2of2();
    let joint_hex = hex::encode(&joint.compressed);
    eprintln!("✔ joint pubkey = {joint_hex}");
    let (presig_a_json, _presig_b, box_b) = gen_presig_pair(share0, share1.clone());

    // ── 2. Real MpcBridge from share_B → stable identity + BRC-31 handshake. ──
    let dkg_result = DkgResult {
        joint_key: joint.clone(),
        share: share1,
        session_id: dkg_session,
    };
    let dir = std::env::temp_dir();
    let share_path = dir.join(format!("authed_relay_share_{}.json", std::process::id()));
    tokio::fs::write(&share_path, serde_json::to_vec(&dkg_result).unwrap())
        .await
        .expect("write share file");
    let config = proxy_config(
        share_path.to_string_lossy().to_string(),
        &worker_url,
        &relay_url,
        false,
    );
    let bridge = MpcBridge::new(&config)
        .await
        .expect("MpcBridge::new (handshake with deployed worker)");
    eprintln!("✔ proxy stable identity authed with KSS");

    // ── 3. Provision Presignature_A into the DO pool over authed ingest. ──
    bridge
        .provision_presig_to_do(
            &joint_hex,
            &presig_a_json,
            "authed-relay",
            "authed-presig-1",
        )
        .await
        .expect("provision presig to DO pool (authed)");
    eprintln!("✔ Presignature_A provisioned to DO pool (authed /ceremony/ingest-presig)");

    // ── 4. Authed /sign-relay → DO consumes pooled presig → combine. ──
    let sighash = deterministic_sighash(b"authed sign-relay v1");
    let trigger = DoTrigger {
        url: format!("{worker_url}/sign-relay"),
        presig_a_json: vec![], // production: DO consumes from its pool, not the body
        do_index: 0,
        agent_id: Some(joint_hex.clone()),
        auth_headers: vec![], // filled by sign_over_relay from the bridge session
        cosigner_encrypted_share: None,
        brc42_offset: None,
    };
    let sig: SigningResult = bridge
        .sign_over_relay(&sighash, box_b, None, trigger, Duration::from_secs(60))
        .await
        .expect("proxy + deployed DO co-sign over the AUTHED relay route");
    assert_bsv_valid(&joint, &sighash, &sig);
    eprintln!(
        "✔ BSV-valid 2-of-2 signature via authed /sign-relay (DER {} bytes)",
        sig.signature.len()
    );

    // ── 5. Negative control: unauthed /sign-relay → 401 (§07.6). ──
    let unauth = reqwest::Client::new()
        .post(format!("{worker_url}/sign-relay"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "agent_id": joint_hex,
            "recipient_pub_hex": joint_hex,
            "sighash_hex": hex::encode(sighash),
        }))
        .send()
        .await
        .expect("unauthed /sign-relay request");
    assert_eq!(
        unauth.status().as_u16(),
        401,
        "unauthed /sign-relay MUST be rejected (§07.6 — no endpoint trusted by location)"
    );
    eprintln!("✔ unauthed /sign-relay → 401 (gate enforced)");

    let _ = tokio::fs::remove_file(&share_path).await;

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #6/#5-step-4 GATE PASS — authed /sign-relay co-sign + 401     ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
}

/// **#3 gate** — `createSignature` (the wallet_api BRC-100 entry) routes through
/// the relay combiner when `relay_sign` is on. Enters `create_signature_impl`
/// with a base-key request (no `protocolID` → `hmac_offset = None`), so the
/// signature is over the **root joint key** — exactly what the relay path
/// produces. Proves the dispatch + pool `take_raw` + trigger construction wiring
/// end-to-end against the deployed cosigner. No sats.
///
/// ```bash
/// SIGN_RELAY_AUTHED_E2E=1 cargo test -p bsv-mpc-proxy \
///   --test sign_relay_authed_deployed_e2e create_signature_routes_through_relay \
///   --release -- --nocapture --test-threads=1
/// ```
#[tokio::test]
async fn create_signature_routes_through_relay() {
    use bsv::primitives::ec::Signature as BsvSignature;
    use bsv_mpc_proxy::presign_manager::PresignManager;
    use bsv_mpc_proxy::server::ProxyBuilder;

    if !opt_in() {
        eprintln!("SIGN_RELAY_AUTHED_E2E=1 not set — skipping #3 createSignature-over-relay gate.");
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let worker_url =
        std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.to_string());
    let relay_url =
        std::env::var("MESSAGEBOX_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string());

    // 1. DKG + correlated pair; seed proxy pool with box_B + Presignature_B.
    let (joint, share0, share1, dkg_session) = run_dkg_2of2();
    let joint_arr = {
        let mut a = [0u8; 33];
        a.copy_from_slice(&joint.compressed);
        a
    };
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey");
    let (presig_a_json, presig_b, box_b) = gen_presig_pair(share0, share1.clone());

    // 2. Real bridge from share_B (stable identity + BRC-31 handshake), relay on.
    let dkg_result = DkgResult {
        joint_key: joint.clone(),
        share: share1,
        session_id: dkg_session,
    };
    let dir = std::env::temp_dir();
    let share_path = dir.join(format!("relay_csig_share_{}.json", std::process::id()));
    tokio::fs::write(&share_path, serde_json::to_vec(&dkg_result).unwrap())
        .await
        .expect("write share file");
    let config = proxy_config(
        share_path.to_string_lossy().to_string(),
        &worker_url,
        &relay_url,
        true, // relay_sign ON — route createSignature through the combiner
    );
    let bridge = MpcBridge::new(&config)
        .await
        .expect("MpcBridge::new (handshake)");

    // 3. Provision Presignature_A → DO pool; seed the proxy pool with box_B.
    bridge
        .provision_presig_to_do(
            &hex::encode(&joint.compressed),
            &presig_a_json,
            "relay-csig",
            "relay-csig-1",
        )
        .await
        .expect("provision presig to DO pool");
    let mut mgr = PresignManager::new(4);
    mgr.add(presig_b, box_b);

    let state = ProxyBuilder::new(config)
        .with_bridge(bridge)
        .with_presign_manager(mgr)
        .build()
        .await
        .expect("build AppState");

    // 4. Drive the BRC-100 entry. No protocolID → base (root) key; hashToDirectlySign.
    let sighash = deterministic_sighash(b"createSignature over relay v1");
    let resp = bsv_mpc_proxy::wallet_api::create_signature_impl(
        &state,
        serde_json::json!({
            "data": hex::encode(sighash),
            "hashToDirectlySign": true,
        }),
    )
    .await;
    let sig_hex = resp
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("createSignature returned no signature: {resp}"));
    let der = hex::decode(sig_hex).expect("sig hex");
    let sig = BsvSignature::from_der(&der).expect("DER signature");
    assert!(
        joint_pub.verify(&sighash, &sig),
        "createSignature-over-relay signature MUST verify under the joint root key"
    );
    eprintln!(
        "✔ createSignature routed through relay → root-key sig verifies (DER {} bytes)",
        der.len()
    );

    let _ = tokio::fs::remove_file(&share_path).await;
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #3 GATE PASS — createSignature dispatches through the relay   ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
}
