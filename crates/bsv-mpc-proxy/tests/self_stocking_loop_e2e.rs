//! **#4 self-stocking loop gate** — the ENTIRE provisioning mechanism end to
//! end, in-process service + deployed DO, no harness hand-stitching:
//!
//! 1. **DKG over HTTP** — proxy (party 1) ↔ local `bsv-mpc-service` (party 0):
//!    real distributed DKG → proxy `share_B`, service `share_A` (keyed by joint
//!    key). No trusted dealer.
//! 2. **Presig over HTTP** — proxy drives `presign_raw` against the service
//!    (`presign_url`); the service generates the correlated pair and, on
//!    completion, **ships `Presignature_A` to the deployed DO pool** itself
//!    (`ProvisionConfig`, authed `/ceremony/ingest-presig`). The proxy keeps
//!    `box_B`. Nothing hand-stitches the pools.
//! 3. **Online sign over the relay** — proxy triggers the authed `/sign-relay`
//!    on the DEPLOYED worker; the DO consumes the service-provisioned presig and
//!    relays its partial; the proxy combines → **BSV-valid 2-of-2** signature.
//!
//! The only thing not deployed here is the CF Container itself (the service runs
//! in-process); 4e redeploys it. No sats. Gated on `SELF_STOCKING_E2E=1` (DKG
//! generates primes inline → ~2 min).
//!
//! ```bash
//! SELF_STOCKING_E2E=1 cargo test -p bsv-mpc-proxy \
//!   --test self_stocking_loop_e2e --release -- --nocapture --test-threads=1
//! ```

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv_mpc_core::brc31_client::Brc31Client;
use bsv_mpc_core::types::{JointPublicKey, SigningResult, ThresholdConfig};
use bsv_mpc_proxy::bridge::{run_dkg_over_http, MpcBridge};
use bsv_mpc_proxy::config::ProxyConfig;
use bsv_mpc_proxy::relay_sign::DoTrigger;
use bsv_mpc_service::{build_router, AppState, ProvisionConfig, SqliteShareStorage};
use rand::RngCore;

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";

fn opt_in() -> bool {
    std::env::var("SELF_STOCKING_E2E").ok().as_deref() == Some("1")
}

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).unwrap()
}

fn deterministic_sighash(tag: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(tag);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn assert_bsv_valid(joint: &JointPublicKey, sighash: &[u8; 32], sig: &SigningResult) {
    let mut a = [0u8; 33];
    a.copy_from_slice(&joint.compressed);
    let joint_pub = PublicKey::from_bytes(&a).unwrap();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.r);
    s.copy_from_slice(&sig.s);
    let bsv_sig = Signature::new(r, s);
    assert!(bsv_sig.is_low_s(), "MPC signature MUST be low-s");
    assert!(
        joint_pub.verify(sighash, &bsv_sig),
        "self-stocking signature MUST verify under the joint pubkey"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_self_stocking_loop() {
    if !opt_in() {
        eprintln!("SELF_STOCKING_E2E=1 not set — skipping #4 self-stocking loop gate.");
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let worker_url =
        std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.to_string());
    let relay_url =
        std::env::var("MESSAGEBOX_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string());

    // The cosigner (party 0, share_A): either the DEPLOYED CF Container
    // (`DEPLOYED_CONTAINER_URL` — the 4e fully-deployed proof) or an in-process
    // instance (local proof). The deployed container has `MPC_WORKER_URL` baked,
    // so it self-ships `Presignature_A` to the deployed DO.
    let data_dir = std::env::temp_dir().join(format!("selfstock_svc_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let (svc_url, server) = match std::env::var("DEPLOYED_CONTAINER_URL") {
        Ok(url) => {
            eprintln!("✔ using DEPLOYED CF Container cosigner: {url}");
            (url, None)
        }
        Err(_) => {
            let storage = SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap();
            let state = Arc::new(AppState {
                data_dir: data_dir.to_string_lossy().to_string(),
                storage: RwLock::new(storage),
                started_at: chrono::Utc::now(),
                provision: Some(ProvisionConfig {
                    worker_url: worker_url.clone(),
                    auth: tokio::sync::Mutex::new(Brc31Client::new(fresh_priv())),
                    http: reqwest::Client::new(),
                }),
                auth: bsv_mpc_service::AuthState::dev(),
            });
            let app = build_router(state);
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let handle = tokio::spawn(async move {
                axum::serve(listener, app.into_make_service())
                    .await
                    .unwrap();
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
            (url, Some(handle))
        }
    };

    // ── 1. Distributed DKG over HTTP (proxy party 1 ↔ service party 0). ──
    let config = ThresholdConfig::new(2, 2).unwrap();
    let dkg = run_dkg_over_http(&svc_url, config)
        .await
        .expect("distributed DKG");
    let joint_hex = hex::encode(&dkg.joint_key.compressed);
    eprintln!("✔ DKG complete — joint {joint_hex}");

    // Persist share_B; build the proxy bridge (sign-relay→DO, presig→service).
    let share_path = data_dir.join("share_b.json");
    tokio::fs::write(&share_path, serde_json::to_vec(&dkg).unwrap())
        .await
        .unwrap();
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
        presign_url: Some(svc_url.clone()), // presig + DKG go to the native cosigner
    };
    let bridge = MpcBridge::new(&config)
        .await
        .expect("bridge handshake with DO");

    // ── 2. Presig over HTTP: proxy↔service; service auto-ships A → deployed DO. ──
    let (_presig_b, box_b) = bridge.presign_raw().await.expect("presig + auto-provision");
    eprintln!("✔ presig generated; service auto-provisioned Presignature_A → deployed DO");

    // ── 3. Online sign over the relay using the self-provisioned presig. ──
    let sighash = deterministic_sighash(b"self-stocking loop v1");
    let trigger = DoTrigger {
        url: format!("{worker_url}/sign-relay"),
        presig_a_json: vec![],
        do_index: 0,
        agent_id: Some(joint_hex.clone()),
        auth_headers: vec![],
    };
    let sig: SigningResult = bridge
        .sign_over_relay(&sighash, box_b, trigger, Duration::from_secs(60))
        .await
        .expect("proxy combines the self-provisioned presig over the relay");
    assert_bsv_valid(&dkg.joint_key, &sighash, &sig);

    if let Some(s) = server {
        s.abort();
    }
    let _ = std::fs::remove_dir_all(&data_dir);

    eprintln!(
        "✔ BSV-valid 2-of-2 sig from the SELF-STOCKED pool (DER {} bytes)",
        sig.signature.len()
    );
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #4 GATE PASS — full self-stocking loop (DKG→presig→ship→sign) ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
}
