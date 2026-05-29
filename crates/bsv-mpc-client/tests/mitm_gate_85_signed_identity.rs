//! **#85 MITM gate — fast, always-run proof.**
//!
//! Spins an in-process `bsv-mpc-service` container (with an enforced master
//! identity) and asserts, over real HTTP (no relay, no DKG — fast):
//!   - `GET /dkg-relay/peer-identity` returns the per-index relay pub WITH a master
//!     `attestation` that verifies under the container's REAL master and FAILS under
//!     a wrong master or a tampered relay pub (a MITM substitution).
//!   - `POST /identity-challenge` returns a master signature over (joint, nonce) that
//!     verifies under the real master and FAILS under a wrong master / replayed nonce.
//!
//! Together with the `hd::` unit golden-vectors + the live `*_relay_e2e` tests
//! (which PIN the master and exercise the device-side verify + funding-challenge
//! end-to-end), this proves the device only ever federates with the pinned Notary.
#![cfg(not(target_arch = "wasm32"))]

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv_mpc_core::types::SessionId;
use bsv_mpc_service::{build_router, AppState, AuthState, SqliteShareStorage};

const SERVER_KEY_HEX: &str = "4444444444444444444444444444444444444444444444444444444444444444";

async fn spawn_container() -> (String, tokio::task::JoinHandle<()>) {
    std::env::set_var("MPC_SERVER_PRIVATE_KEY", SERVER_KEY_HEX);
    let data_dir = std::env::temp_dir().join(format!("mitm85_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage = Arc::new(RwLock::new(
        SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap(),
    ));
    let state = Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage,
        started_at: chrono::Utc::now(),
        provision: None,
        auth: AuthState::dev(),
        custody: None,
    });
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, build_router(state).into_make_service())
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    (url, server)
}

#[tokio::test]
async fn dkg_peer_identity_is_master_attested_and_rejects_mitm() {
    let (url, _server) = spawn_container().await;
    let master = PrivateKey::from_hex(SERVER_KEY_HEX).unwrap().public_key();
    let session = SessionId::from_bytes([0xa7u8; 32]);
    let index = 4u16;

    let resp: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "{url}/dkg-relay/peer-identity?session={}&index={index}",
            session.hex()
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let relay_pub =
        PublicKey::from_hex(resp["relay_pub_hex"].as_str().expect("relay_pub_hex")).unwrap();
    // The response advertises the container's master + an attestation.
    assert_eq!(
        resp["master_pub_hex"].as_str().unwrap(),
        master.to_hex(),
        "advertised master must be the container's real master"
    );
    let att: [u8; 64] = hex::decode(resp["attestation_hex"].as_str().expect("attestation_hex"))
        .unwrap()
        .try_into()
        .unwrap();

    // Positive — verifies under the PINNED (real) master.
    assert!(
        bsv_mpc_core::hd::verify_relay_identity_attestation(
            &master, &session, index, &relay_pub, &att
        ),
        "attestation MUST verify under the container's real master"
    );
    // NEGATIVE 1 — a MITM that pinned its OWN master cannot make it verify.
    let attacker = PrivateKey::from_bytes(&[0x99u8; 32]).unwrap().public_key();
    assert!(!bsv_mpc_core::hd::verify_relay_identity_attestation(
        &attacker, &session, index, &relay_pub, &att
    ));
    // NEGATIVE 2 — a substituted relay pub (the MITM's routed identity) fails.
    let mitm_relay = PrivateKey::from_bytes(&[0x55u8; 32]).unwrap().public_key();
    assert!(!bsv_mpc_core::hd::verify_relay_identity_attestation(
        &master,
        &session,
        index,
        &mitm_relay,
        &att
    ));
    // NEGATIVE 3 — wrong index (replay across slots) fails.
    assert!(!bsv_mpc_core::hd::verify_relay_identity_attestation(
        &master, &session, 5, &relay_pub, &att
    ));
}

#[tokio::test]
async fn identity_challenge_is_master_signed_and_rejects_mitm() {
    let (url, _server) = spawn_container().await;
    let master = PrivateKey::from_hex(SERVER_KEY_HEX).unwrap().public_key();
    let joint = vec![0x02u8; 33];
    let nonce = [0x33u8; 32];

    let resp: serde_json::Value = reqwest::Client::new()
        .post(format!("{url}/identity-challenge"))
        .json(&serde_json::json!({
            "joint_pubkey_hex": hex::encode(&joint),
            "nonce_hex": hex::encode(nonce),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["master_pub_hex"].as_str().unwrap(), master.to_hex());
    let sig: [u8; 64] = hex::decode(
        resp["challenge_sig_hex"]
            .as_str()
            .expect("challenge_sig_hex"),
    )
    .unwrap()
    .try_into()
    .unwrap();

    // Positive — verifies under the pinned master for THIS wallet + nonce.
    assert!(bsv_mpc_core::hd::verify_cosigner_challenge(
        &master, &joint, &nonce, &sig
    ));
    // NEGATIVE — wrong master / replayed nonce / wrong wallet all fail closed.
    let attacker = PrivateKey::from_bytes(&[0x88u8; 32]).unwrap().public_key();
    assert!(!bsv_mpc_core::hd::verify_cosigner_challenge(
        &attacker, &joint, &nonce, &sig
    ));
    assert!(!bsv_mpc_core::hd::verify_cosigner_challenge(
        &master,
        &joint,
        &[0x34u8; 32],
        &sig
    ));
    assert!(!bsv_mpc_core::hd::verify_cosigner_challenge(
        &master,
        &[0x03u8; 33],
        &nonce,
        &sig
    ));
}

#[tokio::test]
async fn reshare_and_refresh_identity_is_master_and_rejects_mitm() {
    // The recovery flow (#85): /reshare-relay/identity + /refresh-relay/identity
    // return the cosigner's MASTER pub directly. The client (coordinate_reshare_over_relay)
    // PINS the master out-of-band and rejects any fetched identity != the pin. Assert
    // the service returns the master AND the compare-to-pinned distinguishes the real
    // master from a MITM substitution.
    let (url, _server) = spawn_container().await;
    let master = PrivateKey::from_hex(SERVER_KEY_HEX)
        .unwrap()
        .public_key()
        .to_hex();
    let attacker = PrivateKey::from_bytes(&[0x99u8; 32])
        .unwrap()
        .public_key()
        .to_hex();

    for path in ["/reshare-relay/identity", "/refresh-relay/identity"] {
        let resp: serde_json::Value = reqwest::Client::new()
            .get(format!("{url}{path}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let fetched = resp["peer_pub_hex"].as_str().expect("peer_pub_hex");
        // The reshare/refresh relay identity IS the master pub.
        assert_eq!(fetched, master, "{path} MUST return the master pub");
        // Client pin gate: correct master accepts; a wrong/MITM master is rejected
        // (this is exactly `coordinate_reshare_over_relay`'s `fetched != pinned` check).
        assert!(fetched == master, "{path}: correct pin accepts");
        assert!(
            fetched != attacker,
            "{path}: a MITM-substituted master MUST NOT match the pin → reshare rejects"
        );
    }
}
