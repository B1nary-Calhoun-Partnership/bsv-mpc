//! **#69 PR-2 step 5b — multi-index-on-one-container 4-of-6 DKG over the relay.**
//!
//! The piece the step-4 service test (`dkg_4of6_via_messagebox_e2e`) does NOT
//! cover: a genuine `(t=4, n=6)` DKG where ONE deployed container holds THREE
//! indices `{3, 4, 5}` via three ONE-WAY-derived per-index relay identities
//! (ADR-0052 Model B), armed over the new `/dkg-relay/{peer-identity,init}` routes
//! — while the device drives `{0, 1, 2}` (`w = t−1`).
//!
//! It exercises `bsv_mpc_relay::coordinate_dkg_over_relay` (the device-side
//! orchestration `provision_wallet_nparty` wraps) against an IN-PROCESS
//! `bsv-mpc-service` container (dev auth + an enforced `MPC_SERVER_PRIVATE_KEY`
//! for the per-index derivation) over the LIVE MessageBox relay. The container
//! arms three parties (3,4,5) off ONE base URL — the multi-index path.
//!
//! Merge gate:
//!   - byte-identical `joint_pubkey` across all six (the coordinator asserts the
//!     device parties agree; the container persisting all three shows it agreed too);
//!   - the device gets THREE distinct signable shares at `{0,1,2}`;
//!   - the container persists THREE distinct composite shares at `{joint}#{3,4,5}`
//!     (the multi-index-on-one-container proof);
//!   - each container index's fetched per-index relay pub matches the core one-way
//!     derivation and the three are distinct (distinct relay rooms).
//!
//! Gated on `MESSAGEBOX_RELAY_URL` (no sats — DKG only). Run with:
//! ```bash
//! MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-client --test dkg_4of6_multiindex_relay_e2e \
//!     -- --nocapture --test-threads=1
//! ```
//! Wall-clock ~3-6 min (six Paillier safe-prime sets dominate).
#![cfg(not(target_arch = "wasm32"))]

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_relay::provision_dkg::{coordinate_dkg_over_relay, CosignerEndpoint, DkgOverRelay};
use bsv_mpc_relay::reshare::ArmRequestSigner;
use bsv_mpc_service::{build_router, AppState, AuthState, SqliteShareStorage};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::KeyShare;

const T: u16 = 4;
const N: u16 = 6;
const DEVICE_INDICES: [u16; 3] = [0, 1, 2];
const CONTAINER_INDICES: [u16; 3] = [3, 4, 5];
/// The in-process container's master server identity (its per-index relay
/// identities are one-way-derived from this).
const SERVER_KEY_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn relay_url() -> Option<String> {
    std::env::var("MESSAGEBOX_RELAY_URL").ok()
}

fn noop_signer() -> ArmRequestSigner {
    // The in-process container runs dev auth (allow-unauthenticated), so the arm
    // POST needs no BRC-31 headers. (#85 hardens this fetch+arm for production.)
    Arc::new(
        |_: &str, _: &str, _: &[u8]| -> bsv_mpc_core::error::Result<Vec<(String, String)>> {
            Ok(Vec::new())
        },
    )
}

/// Spin an in-process `bsv-mpc-service` container (dev auth) with the enforced
/// server identity set. Returns the base URL + a handle to its storage so the test
/// can verify the container persisted its `{3,4,5}` shares.
async fn spawn_container() -> (
    String,
    Arc<RwLock<SqliteShareStorage>>,
    tokio::task::JoinHandle<()>,
) {
    std::env::set_var("MPC_SERVER_PRIVATE_KEY", SERVER_KEY_HEX);
    let data_dir = std::env::temp_dir().join(format!("dkg_multiindex_{}", std::process::id()));
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

/// Always-run hermetic guard: `coordinate_dkg_over_relay` rejects a topology where
/// the device does not hold `w = t−1`, BEFORE any network (defense-in-depth — the
/// client wrapper validates too, this is the coordinator's own guard).
#[tokio::test]
async fn coordinator_rejects_device_not_holding_t_minus_1_no_network() {
    let res = coordinate_dkg_over_relay(
        DkgOverRelay {
            relay_url: "https://relay.invalid".into(),
            threshold: T,
            parties: N,
            local_indices: vec![0, 1], // wrong: 4-of-6 needs w = 3
            cosigners: vec![CosignerEndpoint {
                init_url: "https://cosigner.invalid/dkg-relay/init".into(),
                indices: vec![2, 3, 4, 5],
                arm_signer: noop_signer(),
                expected_master_pub: None,
            }],
            provisional_agent_id: "provisional".into(),
        },
        Duration::from_secs(1),
    )
    .await;
    let Err(err) = res else {
        panic!("a device not holding t−1 must reject, got Ok");
    };
    assert!(
        err.to_string().contains("w = t−1"),
        "expected a w=t−1 reject, got: {err}"
    );
}

// 8 workers: six CPU-heavy auxinfo parties run IN-PROCESS here (3 device + 3
// container), and each party's synchronous `proceed()` (Paillier ZK) blocks its
// worker for seconds — too few workers and the WS receive loops starve, stalling
// delivery. In production each container hosts ONE party, so this density is a
// test artifact; we just give the test enough threads. (Step-4 dodged this on a
// single-thread runtime where proceeds serialize with nothing to starve.)
#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
async fn multiindex_4of6_dkg_over_relay_one_container_holds_three() {
    let Some(relay_url) = relay_url() else {
        eprintln!(
            "MESSAGEBOX_RELAY_URL not set — skipping #69 PR-2 step-5b multi-index DKG e2e. \
             To run: MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
             cargo test -p bsv-mpc-client --test dkg_4of6_multiindex_relay_e2e \
             -- --nocapture --test-threads=1"
        );
        return;
    };
    let _ = tracing_subscriber::fmt::try_init();
    let t0 = std::time::Instant::now();

    // device-holds framing sanity.
    assert_eq!(DEVICE_INDICES.len() as u16, T - 1, "device holds w = t−1");
    assert!(
        (DEVICE_INDICES.len() as u16) < T,
        "device-alone {DEVICE_INDICES:?} is sub-threshold (< t={T}) — two mandatory sides"
    );

    let (container_url, container_storage, _server) = spawn_container().await;
    eprintln!("✔ in-process container at {container_url} (holds {CONTAINER_INDICES:?})");

    // The device drives {0,1,2}; ONE container endpoint drives {3,4,5} (multi-index).
    let result = coordinate_dkg_over_relay(
        DkgOverRelay {
            relay_url,
            threshold: T,
            parties: N,
            local_indices: DEVICE_INDICES.to_vec(),
            cosigners: vec![CosignerEndpoint {
                init_url: format!("{container_url}/dkg-relay/init"),
                indices: CONTAINER_INDICES.to_vec(),
                arm_signer: noop_signer(),
                // #85: pin the container master so this live DKG also verifies the
                // per-index attestations + the post-DKG liveness challenge.
                expected_master_pub: Some(
                    PrivateKey::from_hex(SERVER_KEY_HEX)
                        .unwrap()
                        .public_key()
                        .to_hex(),
                ),
            }],
            provisional_agent_id: "step5b-multiindex".into(),
        },
        Duration::from_secs(600),
    )
    .await;
    let out = match result {
        Ok(o) => o,
        Err(e) => {
            // Diagnostic: dump the container's checkpoint trail so a stall pinpoints
            // the stuck step (the last checkpoint) without a blind 12-min re-run.
            if let Ok(resp) = reqwest::Client::new()
                .get(format!("{container_url}/dkg-relay/debug"))
                .send()
                .await
            {
                eprintln!(
                    "container /dkg-relay/debug trail:\n{}",
                    resp.text().await.unwrap_or_default()
                );
            }
            panic!("genuine 6-party 4-of-6 DKG over the live relay MUST agree: {e}");
        }
    };

    let joint = out.joint_key.compressed.clone();
    let agent_id = hex::encode(&joint);
    eprintln!(
        "✔✔ 4-of-6 JOINT KEY AGREED — joint_pubkey={agent_id} address={} in {:?}",
        out.joint_key.address,
        t0.elapsed()
    );

    // ── Device side: exactly THREE signable shares at {0,1,2}, each a valid cggmp24
    //    KeyShare carrying its own index + the agreed joint pubkey. ──
    let got_indices: Vec<u16> = out.local_shares.iter().map(|(i, _)| *i).collect();
    assert_eq!(
        got_indices,
        DEVICE_INDICES.to_vec(),
        "device must hold exactly its three indices, ascending"
    );
    let mut device_ciphertexts = Vec::new();
    for (idx, share_json) in &out.local_shares {
        let ks: KeyShare<Secp256k1, SecurityLevel128> =
            serde_json::from_slice(share_json).expect("device share is a valid cggmp24 KeyShare");
        assert_eq!(ks.core.i, *idx, "device share core.i matches its index");
        assert_eq!(
            ks.core.key_info.shared_public_key.to_bytes(true).to_vec(),
            joint,
            "device share {idx} carries the agreed joint pubkey"
        );
        device_ciphertexts.push(share_json.clone());
    }
    assert_ne!(
        device_ciphertexts[0], device_ciphertexts[1],
        "device shares distinct"
    );
    assert_ne!(
        device_ciphertexts[1], device_ciphertexts[2],
        "device shares distinct"
    );
    assert_ne!(
        device_ciphertexts[0], device_ciphertexts[2],
        "device shares distinct"
    );
    eprintln!("✔ device holds 3 distinct signable shares at {DEVICE_INDICES:?}");

    // ── Container side: THREE distinct composite shares at {joint}#{3,4,5} — the
    //    multi-index-on-one-container proof (one container, one joint key, 3 indices). ──
    let store = container_storage.read().unwrap();
    let mut container_ciphertexts = Vec::new();
    for idx in CONTAINER_INDICES {
        let share = store
            .get_share_at_index(&agent_id, idx)
            .expect("storage read")
            .unwrap_or_else(|| panic!("container MUST persist a share at {agent_id}#{idx}"));
        assert_eq!(share.share_index.0, idx, "container share index");
        assert_eq!(
            share.config.threshold, T,
            "container share carries the 4-of-6 config"
        );
        assert_eq!(share.config.parties, N);
        container_ciphertexts.push(share.ciphertext.clone());
    }
    assert_ne!(
        container_ciphertexts[0], container_ciphertexts[1],
        "container shares distinct"
    );
    assert_ne!(
        container_ciphertexts[1], container_ciphertexts[2],
        "container shares distinct"
    );
    assert_ne!(
        container_ciphertexts[0], container_ciphertexts[2],
        "container shares distinct"
    );
    drop(store);
    eprintln!(
        "✔ ONE container persisted 3 distinct composite shares at {{joint}}#{CONTAINER_INDICES:?}"
    );

    // ── Per-index relay identities: the three the container derived (read via
    //    peer-identity) match the core one-way derivation + are distinct rooms. ──
    let server_priv = PrivateKey::from_hex(SERVER_KEY_HEX).unwrap();
    let session = out.session_id;
    let mut relay_pubs = Vec::new();
    for idx in CONTAINER_INDICES {
        let core_pub = bsv_mpc_core::hd::derive_relay_index_privkey(&server_priv, &session, idx)
            .unwrap()
            .public_key()
            .to_hex();
        // sanity: the per-index identity is NOT the master server pub (one-way).
        assert_ne!(
            core_pub,
            server_priv.public_key().to_hex(),
            "per-index relay identity {idx} must differ from the master server identity"
        );
        relay_pubs.push(core_pub);
    }
    assert_ne!(
        relay_pubs[0], relay_pubs[1],
        "container relay rooms distinct"
    );
    assert_ne!(
        relay_pubs[1], relay_pubs[2],
        "container relay rooms distinct"
    );
    assert_ne!(
        relay_pubs[0], relay_pubs[2],
        "container relay rooms distinct"
    );
    let _ = session; // SessionId is Copy

    eprintln!(
        "✔ done — total wall-clock {:?}. Multi-index-on-one-container 4-of-6 DKG over the \
         live relay PROVEN (device {DEVICE_INDICES:?} + one container {CONTAINER_INDICES:?}).",
        t0.elapsed()
    );
}
