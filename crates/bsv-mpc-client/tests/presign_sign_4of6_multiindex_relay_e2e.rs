//! **#69 PR-2 step 7a — genuine n-party presign GENERATION + device-holds sign,
//! 4-of-6, over the live relay (#86).**
//!
//! The piece nothing in the repo covered: a REAL multi-index presignature set
//! produced by a genuine n-party presign-over-relay ceremony (not the test-only
//! `gen_presig_set` that holds all 6 shares). The device drives its `w = t−1 = 3`
//! co-located parties `{0,1,2}` while ONE external container cosigner completes the
//! `t=4` quorum at index `3`, all over the LIVE MessageBox relay. Then the device
//! folds its three correlated presigs locally + triggers the cosigner once →
//! a BSV-valid 4-of-6 signature under the joint key.
//!
//! Pipeline (all over the live relay, against an IN-PROCESS `bsv-mpc-service`
//! container):
//!   1. genuine 4-of-6 DKG over the relay → device shares `{0,1,2}`, container
//!      composite shares `{joint}#{3,4,5}` (reuses step-5b `coordinate_dkg_over_relay`);
//!   2. `coordinate_presign_over_relay_nparty` → THREE correlated raw device presig
//!      boxes (reconstructed from the assembled bundle) + the cosigner's sealed ct;
//!   3. `combine_sign_over_relay_nparty` (primary `{0}` + extras `{1,2}` folded
//!      locally + ONE cosigner `{3}` trigger shipping the ct back) → `SigningResult`;
//!   4. the signature verifies under the agreed joint pubkey.
//!
//! Merge gate: the signature is BSV-valid under the joint key — i.e. the GENERATION
//! side (step 7a) feeds the proven CONSUME side (#83 `device_holds_combine`) and
//! produces a real threshold signature, with the cosigner generating its OWN presig
//! as a genuine protocol party (no process ever held > t−1 shares).
//!
//! Gated on `MESSAGEBOX_RELAY_URL` (no sats — DKG + presign + sign, no broadcast):
//! ```bash
//! MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-client --test presign_sign_4of6_multiindex_relay_e2e \
//!     -- --nocapture --test-threads=1
//! ```
//! Wall-clock ~5-9 min (six DKG auxinfo prime-sets + the four-party presign MtA).
#![cfg(not(target_arch = "wasm32"))]

use std::any::Any;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::types::{EncryptedShare, JointPublicKey, PolicyId, ShareIndex, ThresholdConfig};
use bsv_mpc_relay::provision_dkg::{coordinate_dkg_over_relay, CosignerEndpoint, DkgOverRelay};
use bsv_mpc_relay::provision_presign::{
    coordinate_presign_over_relay_nparty, PresignCosignerArm, PresignOverRelay,
};
use bsv_mpc_relay::reshare::ArmRequestSigner;
use bsv_mpc_relay::DoTrigger;
use bsv_mpc_service::{build_router, AppState, AuthState, SqliteShareStorage};

const T: u16 = 4;
const N: u16 = 6;
const DEVICE_INDICES: [u16; 3] = [0, 1, 2];
const CONTAINER_INDICES: [u16; 3] = [3, 4, 5];
/// The signing-subset cosigner index (device {0,1,2} + this one = t=4).
const COSIGNER_SIGN_INDEX: u16 = 3;
const SERVER_KEY_HEX: &str = "3333333333333333333333333333333333333333333333333333333333333333";

fn relay_url() -> Option<String> {
    std::env::var("MESSAGEBOX_RELAY_URL").ok()
}

fn noop_signer() -> ArmRequestSigner {
    Arc::new(
        |_: &str, _: &str, _: &[u8]| -> bsv_mpc_core::error::Result<Vec<(String, String)>> {
            Ok(Vec::new())
        },
    )
}

async fn spawn_container() -> (
    String,
    Arc<RwLock<SqliteShareStorage>>,
    tokio::task::JoinHandle<()>,
) {
    std::env::set_var("MPC_SERVER_PRIVATE_KEY", SERVER_KEY_HEX);
    let data_dir = std::env::temp_dir().join(format!("presign_sign_4of6_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage = Arc::new(RwLock::new(
        SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap(),
    ));
    let state = Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage: storage.clone(),
        started_at: chrono::Utc::now(),
        provision: None,
        auth: AuthState::dev(),
        custody: None,
    });
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    (url, storage, server)
}

/// 12 workers: three device + one container presign party each run CPU-heavy
/// Paillier MtA proceeds in-process here (plus six DKG auxinfo parties earlier);
/// too few workers starves the WS receive loops. In production each side hosts one
/// party — this density is a test artifact.
#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
async fn presign_then_sign_4of6_device_holds_over_relay() {
    let Some(relay_url) = relay_url() else {
        eprintln!(
            "MESSAGEBOX_RELAY_URL not set — skipping #69 PR-2 step-7a presign+sign e2e. To run: \
             MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
             cargo test -p bsv-mpc-client --test presign_sign_4of6_multiindex_relay_e2e \
             -- --nocapture --test-threads=1"
        );
        return;
    };
    let _ = tracing_subscriber::fmt::try_init();
    let t0 = std::time::Instant::now();

    assert_eq!(DEVICE_INDICES.len() as u16, T - 1, "device holds w = t−1");

    let (container_url, storage, _server) = spawn_container().await;
    eprintln!("✔ in-process container at {container_url} (holds {CONTAINER_INDICES:?})");

    // ── 1. Genuine 4-of-6 DKG over the relay. ──
    let dkg = coordinate_dkg_over_relay(
        DkgOverRelay {
            relay_url: relay_url.clone(),
            threshold: T,
            parties: N,
            local_indices: DEVICE_INDICES.to_vec(),
            cosigners: vec![CosignerEndpoint {
                init_url: format!("{container_url}/dkg-relay/init"),
                indices: CONTAINER_INDICES.to_vec(),
                arm_signer: noop_signer(),
                // #85: PIN the container's master out-of-band so the DKG verifies
                // every per-index attestation + the post-DKG liveness challenge.
                expected_master_pub: Some(
                    PrivateKey::from_hex(SERVER_KEY_HEX)
                        .unwrap()
                        .public_key()
                        .to_hex(),
                ),
            }],
            provisional_agent_id: "step7a-presign-sign".into(),
        },
        Duration::from_secs(600),
    )
    .await
    .expect("genuine 4-of-6 DKG over the live relay MUST agree");
    let joint = dkg.joint_key.compressed.clone();
    let agent_id = hex::encode(&joint);
    let joint_key = JointPublicKey {
        compressed: joint.clone(),
        address: dkg.joint_key.address.clone(),
    };
    eprintln!(
        "✔ 4-of-6 DKG agreed — joint_pubkey={agent_id} addr={} in {:?}",
        dkg.joint_key.address,
        t0.elapsed()
    );

    // DETERMINISTIC readiness wait: the container persists its {3,4,5} composite
    // shares on its DKG listener pump, which can lag the device's return (the device
    // returns on its own quorum agreement). In production, provisioning and presign
    // are separate user actions (no race); here we poll the in-process storage until
    // the cosigner's share is durable before arming the presign — removing the race
    // entirely for the e2e (the server-side load also retries, as a prod fallback).
    {
        let mut ready = false;
        for _ in 0..150 {
            let present = storage
                .read()
                .ok()
                .and_then(|s| {
                    s.get_share_at_index(&agent_id, COSIGNER_SIGN_INDEX)
                        .ok()
                        .flatten()
                })
                .is_some();
            if present {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            ready,
            "container MUST persist its cosigner share {{joint}}#{COSIGNER_SIGN_INDEX} after DKG"
        );
        eprintln!("✔ container persisted cosigner share #{COSIGNER_SIGN_INDEX} (presign-ready)");
    }

    // Build the device's signable EncryptedShares for {0,1,2} (the DKG output's
    // per-index value is the plaintext cggmp24 KeyShare JSON; pair it with the
    // agreed joint pubkey, exactly what `PresigningManager` consumes).
    let config = ThresholdConfig::new(T, N).unwrap();
    let local_shares: Vec<(u16, EncryptedShare)> = dkg
        .local_shares
        .iter()
        .map(|(idx, keyshare_json)| {
            (
                *idx,
                EncryptedShare {
                    nonce: vec![0u8; 12],
                    ciphertext: keyshare_json.clone(),
                    session_id: dkg.session_id,
                    share_index: ShareIndex(*idx),
                    config,
                    joint_pubkey_compressed: joint.clone(),
                },
            )
        })
        .collect();

    // ── 2. Genuine n-party presign over the relay: device {0,1,2} + cosigner {3}. ──
    let presign = coordinate_presign_over_relay_nparty(
        PresignOverRelay {
            relay_url: relay_url.clone(),
            config,
            local_shares,
            cosigner: PresignCosignerArm {
                init_url: format!("{container_url}/presign-relay/init"),
                index: COSIGNER_SIGN_INDEX,
                arm_signer: noop_signer(),
                // #85: pin the container master so the presign verifies the cosigner
                // identity == pin and routes to the pinned master.
                expected_master_pub: Some(
                    PrivateKey::from_hex(SERVER_KEY_HEX)
                        .unwrap()
                        .public_key()
                        .to_hex(),
                ),
            },
            agent_id: agent_id.clone(),
            policy_id: PolicyId([0u8; 32]),
            at_rest_root: [7u8; 32],
        },
        Duration::from_secs(300),
    )
    .await
    .unwrap_or_else(|e| panic!("n-party presign over the live relay MUST produce a set: {e}"));

    assert_eq!(
        presign.participants,
        vec![0, 1, 2, 3],
        "signing subset = device {{0,1,2}} + cosigner {{3}}"
    );
    assert_eq!(
        presign.device_presigs.len(),
        3,
        "three correlated device presigs"
    );
    assert_eq!(presign.primary_index, 0, "primary = lowest device index");
    assert!(
        !presign.cosigner_encrypted_share.is_empty(),
        "external cosigner ciphertext present"
    );
    eprintln!(
        "✔ n-party presign agreed — 3 device presigs + cosigner ct ({} bytes) in {:?}",
        presign.cosigner_encrypted_share.len(),
        t0.elapsed()
    );

    // ── 3. Device-holds sign: fold {0,1,2} locally + trigger cosigner {3}. ──
    let participants = presign.participants.clone();
    let primary_index = presign.primary_index;
    let presig_id = presign.session_id.hex();

    // Split the device presig set into the primary's box + the extras (re-keyed
    // from PARTY index to SIGNING index = position within `participants`).
    let mut my_presig_box: Option<Box<dyn Any + Send>> = None;
    let mut extra_local_presigs: Vec<(u16, Box<dyn Any + Send>)> = Vec::new();
    for (party, raw) in presign.device_presigs {
        if party == primary_index {
            my_presig_box = Some(raw);
        } else {
            let sig_idx = participants.iter().position(|&p| p == party).unwrap() as u16;
            extra_local_presigs.push((sig_idx, raw));
        }
    }
    let my_presig_box = my_presig_box.expect("primary presig box present");

    let primary_share = local_shares_lookup(&dkg, primary_index, &joint, config);

    let sighash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"#69 step-7a device-holds 4-of-6 sign over the relay");
        let mut b = [0u8; 32];
        b.copy_from_slice(&h.finalize());
        b
    };

    // Per-sign relay identity + session, UNIQUE PER RUN (derived from the fresh
    // joint key, which differs every DKG). The shared `mpc-sign` relay box persists
    // partials across runs, and `combine_sign_over_relay_nparty` filters by
    // session_id; a FIXED session would let a prior run's stale partial be combined
    // against this run's (different) presig → "malformed or cheating party". Keying
    // both off `agent_id` guarantees no cross-run collision.
    let sign_session =
        bsv_mpc_core::types::SessionId::from_str_hash(&format!("step7a-sign-{agent_id}"));
    let combiner_priv = {
        let h =
            bsv_mpc_core::types::SessionId::from_str_hash(&format!("step7a-combiner-{agent_id}"));
        PrivateKey::from_bytes(&h.0).unwrap()
    };

    let do_index = participants
        .iter()
        .position(|&p| p == COSIGNER_SIGN_INDEX)
        .unwrap() as u16;

    let result = bsv_mpc_relay::combine_sign_over_relay_nparty(
        &relay_url,
        combiner_priv,
        primary_share,
        extra_local_presigs,
        participants.clone(),
        config,
        sign_session,
        &sighash,
        my_presig_box,
        &joint_key,
        None, // base-key sign (no BRC-42 offset)
        DoTrigger {
            url: format!("{container_url}/sign-relay"),
            presig_a_json: Vec::new(),
            do_index,
            agent_id: Some(agent_id.clone()),
            auth_headers: Vec::new(), // dev-auth container
            cosigner_encrypted_share: Some(presign.cosigner_encrypted_share),
            brc42_offset: None,
            presig_id: Some(presig_id), // §06.17.1 key_id = PRESIGN session hex
        },
        None, // dev auth — no canonical BRC-31 request signer
        Duration::from_secs(120),
    )
    .await
    .unwrap_or_else(|e| panic!("device-holds 4-of-6 combine over the relay MUST sign: {e}"));

    // ── 4. The signature is BSV-valid under the agreed joint key. ──
    let pubkey = bsv::PublicKey::from_bytes(&joint).expect("joint pubkey");
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&result.r);
    sig_bytes[32..].copy_from_slice(&result.s);
    let bsv_sig = bsv::Signature::from_compact(&sig_bytes).expect("compact sig");
    assert!(
        pubkey.verify(&sighash, &bsv_sig),
        "the device-holds 4-of-6 signature MUST verify under the joint pubkey"
    );

    eprintln!(
        "✔✔ STEP 7a PROVEN — genuine n-party presign + device-holds 4-of-6 sign over the live \
         relay → BSV-valid signature under joint key {agent_id}. Total {:?}.",
        t0.elapsed()
    );
}

/// Rebuild the device's `EncryptedShare` at `index` from the DKG output (the
/// per-index value is the plaintext cggmp24 KeyShare JSON).
fn local_shares_lookup(
    dkg: &bsv_mpc_relay::provision_dkg::DkgOverRelayOutput,
    index: u16,
    joint: &[u8],
    config: ThresholdConfig,
) -> EncryptedShare {
    let (_idx, keyshare_json) = dkg
        .local_shares
        .iter()
        .find(|(i, _)| *i == index)
        .expect("primary share present");
    EncryptedShare {
        nonce: vec![0u8; 12],
        ciphertext: keyshare_json.clone(),
        session_id: dkg.session_id,
        share_index: ShareIndex(index),
        config,
        joint_pubkey_compressed: joint.to_vec(),
    }
}
