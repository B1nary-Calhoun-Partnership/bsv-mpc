//! **#104 aux-REUSE — the full setup→reuse WIRE proof over the live relay.**
//!
//! The piece the in-process Stage-2 crypto test (`aux_reuse_capture_load_and_sign_
//! two_distinct_wallets`) does NOT cover: the genuine over-the-relay ceremony.
//! Two phases against ONE in-process `bsv-mpc-service` container holding `{3,4,5}`
//! (the device drives `{0,1,2}`):
//!
//!   PHASE 1 — PRODUCER: `coordinate_aux_setup_over_relay` runs the one-time n=6
//!   aux-info ceremony in capture mode. The device captures its `{0,1,2}` aux blobs;
//!   the container captures + KEK-seals its `{3,4,5}` aux to durable custody; the
//!   device then runs the **#2 aux-bound liveness challenge** against the container's
//!   `/aux-setup/challenge` (extract the Notary's captured moduli → the live master
//!   signs over exactly those → the device verifies). A successful return means the
//!   producer + the deployed challenge wire + the binding envelope all held.
//!
//!   PHASE 2 — CONSUMER: `coordinate_dkg_over_relay` with `device_aux` = the captured
//!   blobs + `group_id`/`aux_epoch`. The device REUSES its sealed aux (no aux SM); the
//!   container's `/dkg-relay/init` load branch reuses ITS sealed aux. A 4-of-6 joint
//!   key is agreed and the device gets 3 signable shares.
//!
//! THE REUSE PROOF (deterministic, not timing): the reused wallet's share at index 0
//! carries the **same Paillier modulus `N[0]`** as the setup blob — a fresh-aux
//! fallback would carry a different random safe-prime modulus, so an equal modulus
//! PROVES the aux was reused, not regenerated.
//!
//! Gated on `MESSAGEBOX_RELAY_URL` (the live relay) + the deployed worker custody DO
//! (the container KEK-seals its aux there, like `composite_custody_restart_e2e`). No
//! sats — DKG/aux only. Run:
//! ```bash
//! MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-client --test aux_reuse_4of6_relay_e2e \
//!     -- --nocapture --test-threads=1
//! ```
//! Wall-clock ~4-8 min (PHASE 1 grinds six safe-prime aux sets; PHASE 2 reuses ⇒ fast).
#![cfg(not(target_arch = "wasm32"))]

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::aux_binding::{derive_binding_mac_key, verify_aux_binding_mac};
use bsv_mpc_core::brc31_client::Brc31Client;
use bsv_mpc_core::canonical::{aux_group_id, AuxGroupDescriptor};
use bsv_mpc_relay::provision_aux::{
    coordinate_aux_setup_over_relay, AuxCosignerEndpoint, AuxSetupOverRelay,
};
use bsv_mpc_relay::provision_dkg::{coordinate_dkg_over_relay, CosignerEndpoint, DkgOverRelay};
use bsv_mpc_relay::reshare::ArmRequestSigner;
use bsv_mpc_service::{build_router, AppState, AuthState, CustodyConfig, SqliteShareStorage};
use cggmp24::key_share::AuxInfo;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::KeyShare;

const T: u16 = 4;
const N: u16 = 6;
const DEVICE_INDICES: [u16; 3] = [0, 1, 2];
const CONTAINER_INDICES: [u16; 3] = [3, 4, 5];
/// The in-process container's master server identity (its per-index relay identities
/// + its `/aux-setup/challenge` signature derive from this).
const SERVER_KEY_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";
const AUX_EPOCH: u64 = 1;

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

/// Compressed-pubkey 33-byte array from a key (for the group descriptor).
fn compressed_33(pk_hex: &str) -> [u8; 33] {
    hex::decode(pk_hex)
        .unwrap()
        .try_into()
        .expect("compressed pubkey is 33 bytes")
}

/// In-process `bsv-mpc-service` container (dev inbound auth) WITH durable custody
/// pointed at the deployed worker DO (the aux ceremony KEK-seals its aux there) and
/// the enforced server identity (relay-identity derivation + the challenge master).
async fn spawn_container(worker_url: &str) -> (String, tokio::task::JoinHandle<()>) {
    std::env::set_var("MPC_SERVER_PRIVATE_KEY", SERVER_KEY_HEX);
    let data_dir = std::env::temp_dir().join(format!("aux_reuse_e2e_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage = Arc::new(RwLock::new(
        SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap(),
    ));
    let server_priv = PrivateKey::from_hex(SERVER_KEY_HEX).unwrap();
    let server_bytes: [u8; 32] = hex::decode(SERVER_KEY_HEX).unwrap().try_into().unwrap();
    let kek = bsv_mpc_core::custody::derive_custody_kek(&server_bytes);
    let state = Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage,
        started_at: chrono::Utc::now(),
        provision: None,
        auth: AuthState::dev(),
        custody: Some(CustodyConfig {
            worker_url: worker_url.to_string(),
            kek,
            auth: tokio::sync::Mutex::new(Brc31Client::new(server_priv)),
            http: reqwest::Client::new(),
        }),
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
    (url, server)
}

// 12 workers: six CPU-heavy auxinfo parties run IN-PROCESS in PHASE 1 (3 device + 3
// container); each party's synchronous Paillier `proceed()` blocks its worker, so too
// few workers starve the WS receive loops. (Production = one party per container.)
#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
async fn aux_reuse_4of6_setup_then_reuse_over_relay() {
    let Some(relay_url) = relay_url() else {
        eprintln!(
            "MESSAGEBOX_RELAY_URL not set — skipping #104 aux-reuse setup→reuse wire e2e. To run: \
             MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
             cargo test -p bsv-mpc-client --test aux_reuse_4of6_relay_e2e -- --nocapture --test-threads=1"
        );
        return;
    };
    let worker = std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.to_string());
    let _ = tracing_subscriber::fmt::try_init();

    // device-holds framing sanity.
    assert_eq!(DEVICE_INDICES.len() as u16, T - 1, "device holds w = t−1");

    // Fresh random device identity → a FRESH group_id (no DO-record collision with a
    // prior run; the aux is reusable, so a stable id would re-load stale records).
    let device_id = {
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b[0] |= 1;
        PrivateKey::from_bytes(&b).unwrap()
    };
    let server_priv = PrivateKey::from_hex(SERVER_KEY_HEX).unwrap();
    let server_master_hex = server_priv.public_key().to_hex();
    let device_master = compressed_33(&device_id.public_key().to_hex());
    let server_master = compressed_33(&server_master_hex);

    // The FROZEN group descriptor: device{0,1,2}=device master; container{3,4,5}=server.
    let mut index_masters = vec![[0u8; 33]; N as usize];
    for &i in &DEVICE_INDICES {
        index_masters[i as usize] = device_master;
    }
    for &i in &CONTAINER_INDICES {
        index_masters[i as usize] = server_master;
    }
    let descriptor = AuxGroupDescriptor {
        index_masters,
        threshold: T,
        security_level_bits: 128,
    };
    let group_id = aux_group_id(&descriptor);
    let at_rest_root = [0x7u8; 32];

    let (container_url, _server) = spawn_container(&worker).await;
    eprintln!("✔ in-process container at {container_url} (holds {CONTAINER_INDICES:?}), custody→{worker}");

    // ── PHASE 1 — PRODUCER: the one-time group aux-setup ceremony. ──
    let t0 = std::time::Instant::now();
    let setup = coordinate_aux_setup_over_relay(
        AuxSetupOverRelay {
            relay_url: relay_url.clone(),
            threshold: T,
            parties: N,
            local_indices: DEVICE_INDICES.to_vec(),
            cosigners: vec![AuxCosignerEndpoint {
                init_url: format!("{container_url}/aux-setup/init"),
                indices: CONTAINER_INDICES.to_vec(),
                arm_signer: noop_signer(),
                expected_master_pub: Some(server_master_hex.clone()),
            }],
            provisional_agent_id: "aux-setup-e2e".into(),
            prime_pool: None,
            at_rest_root,
            pool_id: Vec::new(),
            group_id,
            aux_epoch: AUX_EPOCH,
            descriptor: descriptor.clone(),
        },
        Duration::from_secs(600),
    )
    .await
    .expect("aux-setup ceremony (producer + #2 liveness challenge + binding envelope) MUST succeed");
    let setup_elapsed = t0.elapsed();
    eprintln!(
        "✔✔ PHASE 1 — aux-setup produced {} device blobs in {setup_elapsed:?} (challenge passed)",
        setup.blobs.len()
    );

    // Producer assertions: 3 device blobs at {0,1,2}, each binding the group + MAC OK.
    assert_eq!(setup.blobs.len(), 3, "device produced 3 aux blobs");
    let mac_key = derive_binding_mac_key(&at_rest_root);
    let mut device_aux: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut setup_aux0: Option<AuxInfo<SecurityLevel128>> = None;
    for b in &setup.blobs {
        assert!(DEVICE_INDICES.contains(&b.index), "blob index is a device index");
        assert_eq!(b.record.group_id, group_id, "blob record binds THIS group_id");
        assert_eq!(b.record.aux_epoch, AUX_EPOCH, "blob record carries the epoch");
        assert_eq!(b.record.n, N, "blob record n");
        assert_eq!(b.record.t, T, "blob record t");
        assert!(
            verify_aux_binding_mac(&b.record, &mac_key, &b.mac),
            "blob MAC verifies under the at-rest-derived key (#5)"
        );
        let aux: AuxInfo<SecurityLevel128> =
            serde_json::from_slice(&b.aux_json).expect("blob aux_json is a valid AuxInfo");
        assert_eq!(aux.N.len() as u16, N, "blob aux carries the full n-moduli vector");
        if b.index == 0 {
            setup_aux0 = Some(aux);
        }
        device_aux.push((b.index, b.aux_json.clone()));
    }
    let setup_aux0 = setup_aux0.expect("a blob for index 0");
    eprintln!("✔ 3 blobs bind group_id + MAC-verify; each carries the full n-moduli vector");

    // ── PHASE 2 — CONSUMER: provision a wallet REUSING the group aux. ──
    let t1 = std::time::Instant::now();
    let out = coordinate_dkg_over_relay(
        DkgOverRelay {
            relay_url,
            threshold: T,
            parties: N,
            local_indices: DEVICE_INDICES.to_vec(),
            cosigners: vec![CosignerEndpoint {
                init_url: format!("{container_url}/dkg-relay/init"),
                indices: CONTAINER_INDICES.to_vec(),
                arm_signer: noop_signer(),
                expected_master_pub: Some(server_master_hex.clone()),
            }],
            provisional_agent_id: "aux-reuse-e2e".into(),
            prime_pool: None,
            at_rest_root,
            pool_id: Vec::new(),
            on_keygen: None,
            // REUSE: feed the captured device blobs + the group → skip the aux SM.
            device_aux: Some(device_aux),
            group_id: Some(group_id),
            aux_epoch: Some(AUX_EPOCH),
        },
        Duration::from_secs(600),
    )
    .await
    .expect("reuse provision (device + container both reuse their sealed aux) MUST agree");
    let reuse_elapsed = t1.elapsed();
    eprintln!(
        "✔✔ PHASE 2 — reuse provision agreed 4-of-6 joint key {} in {reuse_elapsed:?}",
        out.joint_key.address
    );

    // The device got exactly its 3 signable shares, each on the agreed joint key.
    let got: Vec<u16> = out.local_shares.iter().map(|(i, _)| *i).collect();
    assert_eq!(got, DEVICE_INDICES.to_vec(), "device holds its three indices");
    let joint = out.joint_key.compressed.clone();
    let mut wallet_aux0: Option<AuxInfo<SecurityLevel128>> = None;
    for (idx, share_json) in &out.local_shares {
        let ks: KeyShare<Secp256k1, SecurityLevel128> =
            serde_json::from_slice(share_json).expect("device share is a valid cggmp24 KeyShare");
        assert_eq!(ks.core.i, *idx, "share core.i == index");
        assert_eq!(
            ks.core.key_info.shared_public_key.to_bytes(true).to_vec(),
            joint,
            "share {idx} carries the agreed joint pubkey"
        );
        if *idx == 0 {
            // The KeyShare embeds its AuxInfo; re-serialize→deserialize to a standalone
            // AuxInfo so we can compare its moduli to the setup blob's (the reuse proof).
            let aux_json = serde_json::to_vec(&ks.aux).expect("serialize wallet aux");
            wallet_aux0 = Some(
                serde_json::from_slice(&aux_json).expect("wallet aux deserializes to AuxInfo"),
            );
        }
    }
    let wallet_aux0 = wallet_aux0.expect("wallet share for index 0");

    // ── THE REUSE PROOF (deterministic): the reused wallet's aux moduli at index 0
    //    are byte-identical to the setup group's — i.e. the SAME Paillier moduli were
    //    fused via `from_parts`, NOT freshly generated. A fresh-aux fallback would
    //    carry different random safe-primes, so equality PROVES reuse. ──
    assert_eq!(
        wallet_aux0.N, setup_aux0.N,
        "REUSE PROOF: the reused wallet's Paillier modulus vector MUST equal the setup \
         group's — a fresh-aux fallback would differ"
    );
    eprintln!(
        "✔✔✔ REUSE PROVEN — wallet aux moduli == setup group moduli (the aux was reused, not \
         regenerated). PHASE 1 setup {setup_elapsed:?} vs PHASE 2 reuse {reuse_elapsed:?}. \
         Total {:?}. #104 setup→reuse WIRE proven over the live relay.",
        t0.elapsed()
    );
}
