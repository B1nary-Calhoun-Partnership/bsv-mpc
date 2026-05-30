//! **#90 distributed-ECDH partial round — hermetic conformance + round-trip.**
//!
//! The keystone correctness gate: the cosigner's `/ecdh-relay` partial(s),
//! Lagrange-combined with the device's own `w = t−1` local partials, reconstruct
//! the EXACT full ECDH shared secret (`root_priv.derive_shared_secret`) — for both
//! `Self_` (counterparty = joint pubkey) and `Other` — WITHOUT reconstructing the
//! key. Then the FULL device→cosigner round-trip over an in-process `bsv-mpc-service`
//! (`coordinate_ecdh_over_relay` → `POST /ecdh-relay`) proves the wire contract +
//! the #85 master-pin: a correct pin combines to the right secret; a wrong pin fails
//! closed.
//!
//! ECDH is response-direct (no MessageBox relay), so these run hermetically with NO
//! `MESSAGEBOX_RELAY_URL` / no sats — always on, fast (`trusted_dealer` shares).
#![cfg(not(target_arch = "wasm32"))]

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv_mpc_core::ecdh::{
    combine_partials_lagrange, compute_partial_ecdh_point, parse_share_scalar,
    parse_share_vss_points,
};
use bsv_mpc_core::types::{EncryptedShare, SessionId, ShareIndex, ThresholdConfig};
use bsv_mpc_relay::{coordinate_ecdh_over_relay, EcdhCosignerArm};
use bsv_mpc_service::ecdh_relay_handler::issue_ecdh_partials;
use bsv_mpc_service::{build_router, AppState, AuthState, SqliteShareStorage};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::IncompleteKeyShare;
use generic_ec::{NonZero, Scalar, SecretScalar};

/// The in-process cosigner's master server identity (its #85 attestation key).
const SERVER_KEY_HEX: &str = "3333333333333333333333333333333333333333333333333333333333333333";

/// Same fixed root key as the core `ecdh.rs` / `hd.rs` tests (cross-referenceable).
const ROOT_PRIV: [u8; 32] = [
    0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2, 0xf3,
    0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03,
];

fn bsv_privkey_to_scalar(privkey: &PrivateKey) -> NonZero<SecretScalar<Secp256k1>> {
    let mut scalar = Scalar::<Secp256k1>::from_be_bytes(privkey.to_bytes()).expect("valid scalar");
    let secret = SecretScalar::new(&mut scalar);
    NonZero::from_secret_scalar(secret).expect("non-zero scalar")
}

/// Real `(t, n)` core shares for a known root key (fast — trusted dealer, no DKG).
fn gen_shares(root: &PrivateKey, t: u16, n: u16) -> Vec<IncompleteKeyShare<Secp256k1>> {
    cggmp24::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(n)
        .set_threshold(Some(t))
        .set_shared_secret_key(bsv_privkey_to_scalar(root))
        .generate_core_shares(&mut rand::rngs::OsRng)
        .expect("trusted dealer")
}

fn share_json(share: &IncompleteKeyShare<Secp256k1>) -> Vec<u8> {
    serde_json::to_vec(share).expect("serialize share")
}

/// Build a minimal `EncryptedShare` wrapping a raw core share JSON (the ECDH path
/// reads only `.ciphertext`).
fn wrap_share(share: &IncompleteKeyShare<Secp256k1>, t: u16, n: u16, idx: u16) -> EncryptedShare {
    EncryptedShare {
        nonce: vec![0u8; 12],
        ciphertext: share_json(share),
        session_id: SessionId::from_bytes([0x42u8; 32]),
        share_index: ShareIndex(idx),
        config: ThresholdConfig::new(t, n).unwrap(),
        joint_pubkey_compressed: vec![],
    }
}

/// Device-local partial for party `i`: `counterparty_pub * f(I_i)` paired with `I_i`.
fn local_partial(
    share: &IncompleteKeyShare<Secp256k1>,
    counterparty_pub: &PublicKey,
    i: u16,
) -> (PublicKey, [u8; 32]) {
    let json = share_json(share);
    let scalar = parse_share_scalar(&json).unwrap();
    let vss = parse_share_vss_points(&json).unwrap();
    let partial = compute_partial_ecdh_point(counterparty_pub, &scalar).unwrap();
    (partial, vss[i as usize])
}

// ── (1) Pure conformance: cosigner partial + device-local partials == full ECDH ──

#[test]
fn ecdh_partials_combine_matches_full_ecdh_2of2() {
    let root = PrivateKey::from_bytes(&ROOT_PRIV).unwrap();
    let root_pub = root.public_key();
    let shares = gen_shares(&root, 2, 2);
    let master = PrivateKey::from_bytes(&[0x11u8; 32]).unwrap();
    let agent_id = hex::encode(root_pub.to_compressed());
    let nonce = [0x5au8; 32];

    // Self_ (counterparty = joint pubkey) AND Other (an external server pubkey).
    let server = PrivateKey::from_bytes(&[0xabu8; 32]).unwrap().public_key();
    for counterparty in [&root_pub, &server] {
        // Cosigner (party 1) issues its partial over the executor.
        let outcome = issue_ecdh_partials(
            &master,
            &agent_id,
            counterparty,
            &nonce,
            &[(1, share_json(&shares[1]))],
        )
        .unwrap();
        assert_eq!(outcome.partials.len(), 1);
        let cp = &outcome.partials[0];
        assert_eq!(cp.index, 1);

        // The cosigner's partial MUST equal the direct core computation.
        let scalar1 = parse_share_scalar(&share_json(&shares[1])).unwrap();
        assert_eq!(
            cp.partial.to_compressed(),
            compute_partial_ecdh_point(counterparty, &scalar1)
                .unwrap()
                .to_compressed(),
            "cosigner partial != core compute_partial_ecdh_point"
        );

        // Device computes party 0's partial; combine the two == full ECDH.
        let (p0, vss0) = local_partial(&shares[0], counterparty, 0);
        let combined =
            combine_partials_lagrange(&[(p0, vss0), (cp.partial.clone(), cp.vss_point)]).unwrap();
        let full = root.derive_shared_secret(counterparty).unwrap();
        assert_eq!(
            combined.to_compressed(),
            full.to_compressed(),
            "relay-round ECDH partial set MUST Lagrange-combine to the full ECDH secret"
        );

        // The #85 attestation over the returned set verifies under the master.
        let digest =
            bsv_mpc_core::hd::ecdh_partials_digest(&[(cp.index, cp.partial.clone(), cp.vss_point)]);
        let sig: [u8; 64] = hex::decode(&outcome.attestation_sig_hex)
            .unwrap()
            .try_into()
            .unwrap();
        assert!(
            bsv_mpc_core::hd::verify_ecdh_partials_attestation(
                &master.public_key(),
                &agent_id,
                counterparty,
                &nonce,
                &digest,
                &sig
            ),
            "the cosigner's #85 attestation MUST verify under its master"
        );
    }
}

// ── In-process cosigner over HTTP (no relay — ECDH is response-direct) ───────────

async fn spawn_cosigner(
    shares_to_store: Vec<(String, u16, EncryptedShare)>,
) -> (String, tokio::task::JoinHandle<()>) {
    std::env::set_var("MPC_SERVER_PRIVATE_KEY", SERVER_KEY_HEX);
    let data_dir = std::env::temp_dir().join(format!("ecdh_relay_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage = SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap();
    let storage = Arc::new(RwLock::new(storage));
    {
        let mut s = storage.write().unwrap();
        for (agent_id, idx, share) in &shares_to_store {
            // Empty owner ⇒ dev-auth (AuthState::dev) lets the request through with
            // no per-identity owner check, so no BRC-31 signer is needed in-process.
            s.store_share_at_index(agent_id, *idx, share, "").unwrap();
        }
    }
    let state = Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage,
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
    tokio::time::sleep(Duration::from_millis(150)).await;
    (url, server)
}

fn server_master_pub_hex() -> String {
    let bytes: [u8; 32] = hex::decode(SERVER_KEY_HEX).unwrap().try_into().unwrap();
    let master = PrivateKey::from_bytes(&bytes).unwrap();
    hex::encode(master.public_key().to_compressed())
}

// ── (2) Full round-trip, 3-of-4 multi-index device {0,1} + cosigner {2}, #85 pin ──

#[tokio::test]
async fn ecdh_relay_roundtrip_3of4_combines_and_pins_85() {
    let root = PrivateKey::from_bytes(&ROOT_PRIV).unwrap();
    let root_pub = root.public_key();
    let agent_id = hex::encode(root_pub.to_compressed());
    let shares = gen_shares(&root, 3, 4);

    // Cosigner holds {2,3}; the device drives {0,1} (w = t−1 = 2). Store both
    // composite cosigner shares; the device requests just index 2 (enough to reach t).
    let (url, _server) = spawn_cosigner(vec![
        (agent_id.clone(), 2, wrap_share(&shares[2], 3, 4, 2)),
        (agent_id.clone(), 3, wrap_share(&shares[3], 3, 4, 3)),
    ])
    .await;

    let counterparty = PrivateKey::from_bytes(&[0xcdu8; 32]).unwrap().public_key();
    let nonce = [0x77u8; 32];
    let arm = EcdhCosignerArm {
        url: format!("{url}/ecdh-relay"),
        agent_id: agent_id.clone(),
        indices: vec![2],
        expected_master_pub: Some(server_master_pub_hex()), // #85 pinned to the real master
    };

    let cosigner_partials =
        coordinate_ecdh_over_relay(&counterparty, &nonce, &arm, None, Duration::from_secs(20))
            .await
            .expect("ecdh round-trip");
    assert_eq!(cosigner_partials.len(), 1);
    assert_eq!(cosigner_partials[0].index, 2);

    // Device-local partials {0,1} + the cosigner's {2} → combine == full ECDH.
    let (p0, v0) = local_partial(&shares[0], &counterparty, 0);
    let (p1, v1) = local_partial(&shares[1], &counterparty, 1);
    let cp = &cosigner_partials[0];
    let combined =
        combine_partials_lagrange(&[(p0, v0), (p1, v1), (cp.partial.clone(), cp.vss_point)])
            .unwrap();
    let full = root.derive_shared_secret(&counterparty).unwrap();
    assert_eq!(
        combined.to_compressed(),
        full.to_compressed(),
        "3-of-4 relay-round ECDH MUST combine to the full ECDH secret"
    );
}

// ── (3) NEGATIVE — a wrong #85 master pin fails closed ──────────────────────────

#[tokio::test]
async fn ecdh_relay_rejects_wrong_master_pin() {
    let root = PrivateKey::from_bytes(&ROOT_PRIV).unwrap();
    let agent_id = hex::encode(root.public_key().to_compressed());
    let shares = gen_shares(&root, 2, 2);

    let (url, _server) =
        spawn_cosigner(vec![(agent_id.clone(), 1, wrap_share(&shares[1], 2, 2, 1))]).await;

    let counterparty = PrivateKey::from_bytes(&[0xcdu8; 32]).unwrap().public_key();
    // Pin to an ATTACKER master (not the in-process server's) → must fail closed.
    let attacker_pub = hex::encode(
        PrivateKey::from_bytes(&[0x99u8; 32])
            .unwrap()
            .public_key()
            .to_compressed(),
    );
    let arm = EcdhCosignerArm {
        url: format!("{url}/ecdh-relay"),
        agent_id,
        indices: vec![1],
        expected_master_pub: Some(attacker_pub),
    };
    let err = coordinate_ecdh_over_relay(
        &counterparty,
        &[0u8; 32],
        &arm,
        None,
        Duration::from_secs(20),
    )
    .await
    .expect_err("a wrong #85 master pin MUST fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("pinned master") || msg.contains("#85"),
        "expected a #85 pin rejection, got: {msg}"
    );
}

// ── (4) Server-side input validation — the route 400s on bad input ──────────────

#[tokio::test]
async fn ecdh_relay_route_rejects_bad_input() {
    let (url, _server) = spawn_cosigner(vec![]).await;
    let endpoint = format!("{url}/ecdh-relay");
    let http = reqwest::Client::new();

    // Empty indices → 400.
    let resp = http
        .post(&endpoint)
        .json(&serde_json::json!({
            "agent_id": "02abcd",
            "counterparty_pub_hex": "02".to_string() + &"11".repeat(32),
            "indices": [],
            "nonce_hex": "00".repeat(32),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "empty indices must 400");
    assert!(resp.text().await.unwrap().contains("indices"));

    // Malformed counterparty pubkey → 400.
    let resp = http
        .post(&endpoint)
        .json(&serde_json::json!({
            "agent_id": "02abcd",
            "counterparty_pub_hex": "not-a-pubkey",
            "indices": [1],
            "nonce_hex": "00".repeat(32),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "bad counterparty_pub must 400");
    assert!(resp.text().await.unwrap().contains("counterparty_pub"));

    // Bad nonce length → 400 (counterparty = the secp256k1 generator G, definitely
    // a valid point, so the request reaches the nonce check).
    let gen_g = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let resp = http
        .post(&endpoint)
        .json(&serde_json::json!({
            "agent_id": "02abcd",
            "counterparty_pub_hex": gen_g,
            "indices": [1],
            "nonce_hex": "00",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "bad nonce must 400");
    assert!(resp.text().await.unwrap().contains("nonce"));
}
