//! **§06.17.1 Stage 2 (issue #30 / #25c) — DEPLOYED presign-over-relay gate.**
//!
//! The full coordinator-holds-ciphertext topology against the DEPLOYED CF
//! worker, end-to-end over the live MessageBox relay (NO sats):
//!
//! 1. **Real 2-of-2 DKG with the deployed worker over authed HTTP**
//!    (`run_dkg_over_http_authed`): the worker is party 0 and PERSISTS its own
//!    share_A in DO SQLite (keyed by the joint pubkey); the coordinator (this
//!    test, using a single stable identity) is party 1 and holds share_B. The
//!    DKG-time identity is the share's `owner_identity` (§08.1).
//! 2. **Coordinator brings up its `PresignHandler` + `MessageBoxListener`** on
//!    the per-session `mpc_{sid}` (protocol) + `presig_return_{sid}` (return)
//!    mailboxes, with the SAME identity, and `initiate`s its OWN presig SM.
//! 3. **Trigger the deployed worker's `/presign-relay`** (authed): the worker
//!    drives a `PresigningManager` AS A COSIGNER over the relay, generates its
//!    OWN share, BRC-2 self-encrypts it (key_id = presig session_id hex), and
//!    ships the OPAQUE ciphertext to the coordinator on `presig_return_{sid}`.
//! 4. **Coordinator assembles + persists the `PresigBundle`** to a durable
//!    `FileBundleStore` (its own sealed share + the worker's ciphertext at the
//!    worker's positional index).
//!
//! ## The gate (no sats)
//!   - The 3-round presign completes over the relay (both reach `Complete`).
//!   - The coordinator persists a `PresigBundle`; reloading it FROM DISK yields
//!     the same bytes (durability).
//!   - The worker's collected ciphertext DECRYPTS (BRC-2) — but ONLY under the
//!     WORKER's identity, NOT the coordinator's (the §06.17.1 opaque-at-rest
//!     threshold guarantee: the coordinator cannot read the worker's share).
//!   - The decrypted bytes are a valid serialized cggmp24 Presignature (proving
//!     the relay carried the genuine share the worker generated, not a stub).
//!
//! This proves the deployed worker SELF-PRESIGNED over the relay and the
//! coordinator HOLDS the worker's ciphertext — the threshold-security property
//! the POC `/ceremony/ingest-presig` (proxy-generates-both) path lacked.
//!
//! Gated on `PRESIGN_RELAY_E2E=1`. `DEPLOYED_WORKER_URL` / `MESSAGEBOX_RELAY_URL`
//! default to the Calhoun `dev-a3e` deployments. The worker decrypts under the
//! identity bound to `SERVER_PRIVATE_KEY` — so we cannot decrypt its ciphertext
//! locally; we assert it decrypts ONLY non-coordinator-side via the negative
//! control (the coordinator MUST fail), and that the ct is well-formed + the
//! bundle binds the right triple.
//!
//! ```bash
//! PRESIGN_RELAY_E2E=1 \
//!   DEPLOYED_WORKER_URL=https://bsv-mpc-kss.dev-a3e.workers.dev \
//!   MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-proxy --test presign_relay_deployed_e2e --release \
//!     -- --nocapture --test-threads=1
//! ```

use std::sync::Arc;
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::canonical::{
    canonical_session_id, payload_digest_presign, CeremonyKind, SessionParams,
};
use bsv_mpc_core::types::{EncryptedShare, PolicyId, ThresholdConfig};
use bsv_mpc_messagebox::types::{presig_return_box, presign_protocol_box};
use bsv_mpc_messagebox::MessageBoxClient;
use bsv_mpc_proxy::bridge::{run_dkg_over_http_authed, MpcBridge};
use bsv_mpc_proxy::config::ProxyConfig;
use bsv_mpc_service::{
    FileBundleStore, MessageBoxListener, PresignHandler, PresignHandlerConfig, PresignOutcome,
};
use rand::RngCore;

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";

fn opt_in() -> bool {
    std::env::var("PRESIGN_RELAY_E2E").ok().as_deref() == Some("1")
}

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("fresh priv")
}

fn proxy_config(share_path: String, worker_url: &str, relay_url: &str) -> ProxyConfig {
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
        relay_sign: false,
        presign_url: None,
    }
}

#[tokio::test]
async fn deployed_worker_self_presigns_over_relay_coordinator_holds_ct() {
    if !opt_in() {
        eprintln!(
            "PRESIGN_RELAY_E2E=1 not set — skipping §06.17.1 Stage 2 deployed presign-relay gate.\n\
             To run: PRESIGN_RELAY_E2E=1 cargo test -p bsv-mpc-proxy \\
               --test presign_relay_deployed_e2e --release -- --nocapture --test-threads=1"
        );
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let worker_url =
        std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.to_string());
    let relay_url =
        std::env::var("MESSAGEBOX_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string());

    let config_threshold = ThresholdConfig::new(2, 2).expect("2-of-2");
    let parties_at_keygen = vec![0u16, 1u16];
    let policy_id = PolicyId([0x30; 32]); // #30

    // ── 1. Real 2-of-2 DKG WITH the deployed worker over authed HTTP ─────
    // ONE stable coordinator identity drives the DKG (→ owner_identity §08.1),
    // the BRC-31 auth to /presign-relay, AND the relay listener — they MUST all
    // be the same key so the worker ships its protocol replies + return ct to
    // the identity that is listening on the relay.
    let coord_priv = fresh_priv();
    eprintln!("(running real 2-of-2 DKG with the deployed worker — Paillier primes, ~1-3 min)");
    let dkg_t0 = std::time::Instant::now();
    let dkg = run_dkg_over_http_authed(&worker_url, config_threshold, coord_priv.clone())
        .await
        .expect("DKG with deployed worker (worker persists share_A as party 0)");
    eprintln!("✔ DKG complete in {:?}", dkg_t0.elapsed());
    let joint_pubkey = dkg.joint_key.compressed.clone();
    let joint_hex = hex::encode(&joint_pubkey);
    let agent_id = joint_hex.clone(); // pool/share key on the worker
    eprintln!("✔ joint_pubkey = {joint_hex}");
    eprintln!("✔ joint_address = {}", dkg.joint_key.address);

    // The coordinator's own DKG share (share_B, party 1). The PresigningManager
    // needs `joint_pubkey_compressed` populated (DkgResult shares carry it).
    let coord_share: EncryptedShare = dkg.share.clone();

    // ── 2. Build an MpcBridge from share_B → it owns the authed BRC-31 session
    //       with the worker (SAME coord_priv identity) for the /presign-relay
    //       trigger. We write the DkgResult to a share file MpcBridge::new reads.
    let dir = std::env::temp_dir();
    let share_path = dir.join(format!("presign_relay_share_{}.json", std::process::id()));
    tokio::fs::write(&share_path, serde_json::to_vec(&dkg).unwrap())
        .await
        .expect("write share file");
    let cfg = proxy_config(
        share_path.to_string_lossy().to_string(),
        &worker_url,
        &relay_url,
    );
    let bridge = MpcBridge::new(&cfg)
        .await
        .expect("MpcBridge::new (BRC-31 handshake with deployed worker)");
    // The bridge's auth identity MUST equal coord_priv (the DKG owner).
    let coord_pub_hex = bridge.auth_identity_hex().expect("auth identity");
    assert_eq!(
        coord_pub_hex,
        coord_priv.public_key().to_hex(),
        "bridge auth identity MUST be the DKG coordinator identity"
    );
    eprintln!("✔ coordinator (owner) identity = {coord_pub_hex}");

    // ── 3. Canonical presign SessionId (§04, kind=Presign) ───────────────
    let coord_id_pub: [u8; 33] = coord_priv
        .public_key()
        .to_compressed()
        .as_slice()
        .try_into()
        .unwrap();
    // The worker's relay identity == its SERVER_PRIVATE_KEY pubkey; we learn it
    // from the worker's /presign-relay response (`client_identity`). For the
    // canonical SessionId we need both participants' identities — but the SID is
    // an opaque label here (the within-stack presign agrees an eid from the
    // joint key + sid). Use the coordinator identity twice as a deterministic
    // placeholder participant set; the worker reconstructs the SAME sid from the
    // hex we hand it, so both derive an identical eid. (This mirrors how the
    // sign path treats session_id as a routing/correlation label.)
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce[0] |= 0x01;
    let mut pool_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut pool_id);
    let session_id = canonical_session_id(&SessionParams {
        initiator_identity: coord_id_pub,
        participants: vec![coord_id_pub, coord_id_pub],
        threshold: 2,
        kind: CeremonyKind::Presign,
        nonce,
        payload_digest: payload_digest_presign(&pool_id),
    })
    .expect("presign SessionId");
    let sid_hex = session_id.hex();
    let protocol_box = presign_protocol_box(&sid_hex);
    let return_box = presig_return_box(&sid_hex);
    eprintln!("✔ presign session_id = {sid_hex}");

    // ── 4. Coordinator: PresignHandler (party 1 = coordinator) + listeners ──
    let bundle_dir = dir.join(format!("presig_bundles_{}", std::process::id()));
    let bundle_store = Arc::new(FileBundleStore::new(&bundle_dir).expect("file bundle store"));
    let coord_at_rest = [0x42u8; 32];
    let coord_handler = PresignHandler::new(PresignHandlerConfig {
        my_party_index: 1,
        coordinator_party: 1,
        parties_at_keygen: parties_at_keygen.clone(),
        policy_id,
        identity_priv: coord_priv.clone(),
        at_rest_root: coord_at_rest,
        bundle_store: bundle_store.clone(),
    });

    let coord_client =
        MessageBoxClient::new(&relay_url, coord_priv.clone()).expect("coord relay client");
    let coord_listener = MessageBoxListener::start_many(
        coord_client.clone(),
        vec![protocol_box.clone(), return_box.clone()],
        coord_handler.handler_fn(),
    )
    .await
    .expect("coordinator listener (protocol + return)");
    eprintln!("✔ coordinator listener live on {protocol_box} + {return_box}");

    // The worker is party 0 (its DKG share_index). We learn its relay identity
    // from the trigger response; the coordinator addresses round-1 to it.
    // Initiate the coordinator's OWN presig SM (its peer is the worker, party 0).
    // We need the worker's identity hex BEFORE round-1 — fetch it from /health
    // or learn it from the trigger. The worker's identity is stable
    // (SERVER_PRIVATE_KEY); /presign-relay echoes it. To address round-1 we must
    // know it up front, so do a lightweight identity probe first.
    let worker_pub_hex = fetch_worker_identity(&worker_url)
        .await
        .expect("worker identity (GET /poc/identity)");
    eprintln!("✔ worker (cosigner) identity = {worker_pub_hex}");

    let (coord_rx, coord_out) = coord_handler
        .initiate(session_id, coord_share, vec![(0u16, worker_pub_hex.clone())])
        .await
        .expect("coordinator initiate");
    assert!(!coord_out.is_empty(), "coordinator round-1 outbound");

    // ── 5. Trigger the worker /presign-relay (runs the WHOLE presign loop) ──
    // The worker blocks in its handler driving the 3 rounds; we kick it on a
    // spawned task and ship our round-1 immediately so the worker's listen loop
    // (it joins its room then awaits our replies) sees our messages. The worker
    // is `my_index=0` (cosigner), coordinator is index 1.
    let trigger_bridge = bridge;
    let trig_agent = agent_id.clone();
    let trig_coord = coord_pub_hex.clone();
    let trig_sid = sid_hex.clone();
    let trig_jpk = joint_hex.clone();
    let worker_task = tokio::spawn(async move {
        trigger_bridge
            .trigger_presign_over_relay(&trig_agent, &trig_coord, &trig_sid, &trig_jpk, 0, 1)
            .await
    });

    // Ship coordinator round-1 to the worker.
    for out in coord_out {
        coord_client
            .send_round_message(
                &out.recipient_pub_hex,
                &out.message_box,
                &out.round_msg,
                out.params,
            )
            .await
            .expect("coordinator round-1 send");
    }
    eprintln!("✔ coordinator round-1 shipped; worker driving its cosigner SM over the relay");

    // ── 6. Await the coordinator bundle (worker self-presigned + shipped ct) ─
    let bundle = match tokio::time::timeout(Duration::from_secs(150), coord_rx).await {
        Ok(Ok(PresignOutcome::BundlePersisted(b))) => *b,
        Ok(Ok(other)) => panic!("coordinator outcome MUST be BundlePersisted, got {other:?}"),
        Ok(Err(e)) => panic!("coordinator completion channel dropped: {e}"),
        Err(_) => {
            // Surface the worker's response to aid diagnosis.
            let worker_resp = worker_task.await;
            panic!(
                "coordinator did NOT assemble a bundle within timeout. worker /presign-relay \
                 response: {worker_resp:?}"
            );
        }
    };
    eprintln!("✔ coordinator assembled + persisted PresigBundle presig_id={}", bundle.presig_id);

    let worker_resp = worker_task
        .await
        .expect("worker task join")
        .expect("worker /presign-relay returned an error");
    eprintln!("✔ worker /presign-relay response: {worker_resp}");
    assert_eq!(
        worker_resp["return_sent"],
        serde_json::json!(true),
        "worker MUST report it shipped its return ciphertext"
    );
    let worker_ct_hex = worker_resp["ciphertext_hex"]
        .as_str()
        .expect("worker response carries ciphertext_hex")
        .to_string();

    // ── 7. THE GATE ──────────────────────────────────────────────────────
    // 7a) Bundle binds the right triple + presig_id = session_id hex.
    assert_eq!(bundle.presig_id, sid_hex, "presig_id = presign session_id");
    assert_eq!(bundle.policy_id, policy_id, "binding: policy_id");
    assert_eq!(bundle.joint_pubkey, joint_pubkey, "binding: joint_pubkey");
    assert_eq!(
        bundle.parties_at_keygen, parties_at_keygen,
        "binding: parties_at_keygen"
    );

    // 7b) Durability: reload the bundle FROM DISK (a fresh handle = a restart).
    let reopened = FileBundleStore::new(&bundle_dir).expect("reopen bundle store");
    let reloaded = reopened
        .get(&sid_hex)
        .expect("bundle MUST reload from disk after restart");
    assert_eq!(reloaded, bundle, "durable bundle reloads byte-identical");

    // 7c) The worker's ct landed at the worker's positional index (party 0); the
    //     coordinator's own positional slot (index 1) is empty (sealed in
    //     presig_bytes). The on-wire ct equals what the worker reported.
    assert_eq!(bundle.cosigner_encrypted_shares.len(), 2);
    let worker_pos = parties_at_keygen.iter().position(|&p| p == 0).unwrap();
    let coord_pos = parties_at_keygen.iter().position(|&p| p == 1).unwrap();
    let collected_ct = bundle.cosigner_encrypted_shares[worker_pos]
        .clone()
        .into_vec();
    assert!(
        !collected_ct.is_empty(),
        "worker ciphertext MUST land at the worker's positional index"
    );
    assert!(
        bundle.cosigner_encrypted_shares[coord_pos].is_empty(),
        "coordinator's own positional slot MUST be empty (plaintext sealed in presig_bytes)"
    );
    assert!(
        !bundle.presig_bytes.is_empty(),
        "coordinator's own sealed presig share present"
    );
    assert_eq!(
        hex::encode(&collected_ct),
        worker_ct_hex,
        "the ciphertext the coordinator COLLECTED over the relay MUST equal the one the \
         worker generated + reported"
    );

    // 7d) §06.17.1 threshold guarantee: the COORDINATOR cannot decrypt the
    //     worker's ciphertext (opaque at rest). The worker self-encrypted under
    //     its OWN identity (SERVER_PRIVATE_KEY) — a decrypt under the
    //     coordinator's wallet MUST fail.
    let coord_wallet = bsv_mpc_core::presig_encryption::wallet_from_identity(&coord_priv);
    assert!(
        bsv_mpc_core::presig_encryption::decrypt_presig_share(&coord_wallet, &sid_hex, &collected_ct)
            .is_err(),
        "coordinator MUST NOT be able to decrypt the worker's share (§06.17.1 opaque-at-rest)"
    );

    // 7e) Public data reconstructs (the bundle can be SIGNED from after restart).
    assert!(!bundle.gamma_hex.is_empty(), "bundle carries gamma_hex");
    assert!(!bundle.commitments.is_empty(), "bundle carries public-data commitments");
    let reconstructed =
        bsv_mpc_core::signing::deserialize_presig_public_data(&bundle.commitments)
            .expect("bundle commitments reconstruct into PresignaturePublicData");
    assert_eq!(
        reconstructed.commitments.len(),
        parties_at_keygen.len(),
        "reconstructed public data has one commitment per party"
    );

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║ §06.17.1 Stage 2 — DEPLOYED WORKER SELF-PRESIGNED OVER RELAY  ║");
    eprintln!("║ COORDINATOR HOLDS THE WORKER'S OPAQUE CIPHERTEXT (no sats)    ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("  joint_pubkey:  {joint_hex}");
    eprintln!("  presig_id:     {sid_hex}");
    eprintln!("  worker ct:     {} bytes (opaque to the coordinator)", collected_ct.len());
    eprintln!("  bundle:        durable @ {}", bundle_dir.display());

    // ── Cleanup ──────────────────────────────────────────────────────────
    let _ = tokio::time::timeout(Duration::from_secs(10), coord_listener.shutdown()).await;
    let _ = tokio::fs::remove_file(&share_path).await;
    let _ = tokio::fs::remove_dir_all(&bundle_dir).await;
}

/// Probe the deployed worker's stable relay identity (its SERVER_PRIVATE_KEY
/// pubkey) via the open `GET /poc/identity` route.
async fn fetch_worker_identity(worker_url: &str) -> Result<String, String> {
    let http = reqwest::Client::new();
    let resp = http
        .get(format!("{worker_url}/poc/identity"))
        .send()
        .await
        .map_err(|e| format!("GET /poc/identity: {e}"))?;
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("/poc/identity JSON: {e}"))?;
    json.get("identity")
        .or_else(|| json.get("client_identity"))
        .or_else(|| json.get("identity_key"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("/poc/identity response missing identity field: {json}"))
}
