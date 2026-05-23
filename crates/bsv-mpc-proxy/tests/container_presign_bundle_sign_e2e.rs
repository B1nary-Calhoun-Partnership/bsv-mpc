//! **§06.17.1 CONTAINER-target hermetic gate (issue #30 / #25c Stage 2).**
//!
//! Proves the full coordinator-holds-ciphertext loop end-to-end against a REAL
//! in-process `bsv-mpc-service` (the deployed CF Container runs this exact native
//! binary) over the LIVE MessageBox relay — **no sats**:
//!
//! 1. Generate real 2-of-2 cggmp24 key shares locally (keygen + auxinfo via the
//!    `round_based` simulator — same as `bsv-mpc-core`'s presigning tests). Seed
//!    the in-process service with `share_A` (party 0, the container/cosigner);
//!    the proxy coordinator holds `share_B` (party 1).
//! 2. Set `MPC_SERVER_PRIVATE_KEY` so the service's NEW relay routes use a stable
//!    relay / BRC-2 identity (the same key it self-encrypts and decrypts its
//!    presig share under). Auth runs in dev mode here (the route auth gate is
//!    proven separately in `service_owner_authz_e2e`); this gate isolates the
//!    §06.17.1 crypto loop.
//! 3. The proxy runs `relay_presign::coordinate_presign_over_relay`: it triggers
//!    `/presign-relay/init` (container arms a `PresignHandler` cosigner +
//!    listener, generates + BRC-2 self-encrypts its OWN presig share, ships the
//!    ciphertext back), assembles + persists the `PresigBundle` to a
//!    `FileBundleStore`.
//! 4. **THE GATE:**
//!    - the persisted bundle carries the container's OWN encrypted share at
//!      positional index 0 (the cosigner slot), and the coordinator CANNOT
//!      decrypt it (threshold preserved);
//!    - reload the bundle from disk (durable across restart);
//!    - the proxy signs from the reloaded bundle via
//!      `combine_sign_from_bundle_over_relay`: it ships the container's own
//!      ciphertext to `/sign-relay`, the container decrypts it under ITS OWN
//!      identity, issues + relays its partial, the proxy combines;
//!    - the resulting ECDSA signature **verifies under the joint key**.
//!
//! Gated on `CONTAINER_PRESIG_E2E=1` (real Paillier-prime keygen ~30-60s + live
//! relay):
//!
//! ```bash
//! CONTAINER_PRESIG_E2E=1 MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-proxy --test container_presign_bundle_sign_e2e \
//!     --release -- --nocapture --test-threads=1
//! ```

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv_mpc_core::presig_encryption::{decrypt_and_issue_partial, wallet_from_identity};
use bsv_mpc_core::types::{
    EncryptedShare, JointPublicKey, PolicyId, SessionId, ShareIndex, ThresholdConfig,
};
use bsv_mpc_proxy::relay_presign::{coordinate_presign_over_relay, CosignerArm};
use bsv_mpc_proxy::relay_sign::{combine_sign_from_bundle_over_relay, DoTrigger};
use bsv_mpc_service::{
    build_router, AppState, AuthState, FileBundleStore, SqliteShareStorage,
};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use rand::RngCore;

fn opt_in() -> bool {
    std::env::var("CONTAINER_PRESIG_E2E").ok().as_deref() == Some("1")
}

fn relay_url() -> String {
    std::env::var("MESSAGEBOX_RELAY_URL")
        .unwrap_or_else(|_| "https://rust-message-box.dev-a3e.workers.dev".to_string())
}

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("fresh priv")
}

// ─── round_based simulator buffered-sink helpers (mirror of the core tests) ───

#[pin_project::pin_project]
struct BufferedSink<M, Inner> {
    #[pin]
    messages: VecDeque<M>,
    #[pin]
    inner: Inner,
}
type BufferedDelivery<M, D> = (
    <D as round_based::Delivery<M>>::Receive,
    BufferedSink<round_based::Outgoing<M>, <D as round_based::Delivery<M>>::Send>,
);
impl<M: Unpin, Inner: futures::Sink<M>> futures::Sink<M> for BufferedSink<M, Inner> {
    type Error = Inner::Error;
    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn start_send(
        self: std::pin::Pin<&mut Self>,
        item: M,
    ) -> std::result::Result<(), Self::Error> {
        self.project().messages.get_mut().push_back(item);
        Ok(())
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        while !self.messages.is_empty() {
            let mut projection = self.as_mut().project();
            let mut inner = projection.inner;
            std::task::ready!(inner.as_mut().poll_ready(cx))?;
            if let Some(item) = projection.messages.pop_front() {
                inner.as_mut().start_send(item)?;
            }
        }
        self.project().inner.poll_flush(cx)
    }
    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}
fn buffer_outgoing<M, D, R>(
    party: round_based::MpcParty<M, D, R>,
) -> round_based::MpcParty<M, BufferedDelivery<M, D>, R>
where
    M: Unpin,
    D: round_based::Delivery<M>,
    R: round_based::runtime::AsyncRuntime,
{
    party.map_delivery(|delivery| {
        let (incoming, outgoing) = delivery.split();
        let buffered_outgoing = BufferedSink {
            messages: VecDeque::new(),
            inner: outgoing,
        };
        (incoming, buffered_outgoing)
    })
}
fn generate_blum_prime(rng: &mut impl rand::RngCore, bits: u32) -> cggmp24::backend::Integer {
    use cggmp24::backend::Integer;
    loop {
        let n = Integer::generate_prime(rng, bits);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}
fn pregenerated_primes(
    rng: &mut impl rand::RngCore,
) -> cggmp24::PregeneratedPrimes<SecurityLevel128> {
    use cggmp24::security_level::SecurityLevel;
    let bits = SecurityLevel128::RSA_PRIME_BITLEN;
    let primes = [
        generate_blum_prime(rng, bits),
        generate_blum_prime(rng, bits),
        generate_blum_prime(rng, bits),
        generate_blum_prime(rng, bits),
    ];
    cggmp24::PregeneratedPrimes::try_from(primes).expect("primes")
}
async fn run_dkg_2of2() -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    let (n, t): (u16, u16) = (2, 2);
    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);
    let incomplete = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut prng = rand::rngs::OsRng;
        async move {
            cggmp24::keygen::<Secp256k1>(eid, i, n)
                .set_threshold(t)
                .start(&mut prng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();
    let eid_aux_bytes: [u8; 32] = rng.gen();
    let eid_aux = ExecutionId::new(&eid_aux_bytes);
    let primes: Vec<_> = (0..n).map(|_| pregenerated_primes(&mut rng)).collect();
    let aux = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut prng = rand::rngs::OsRng;
        let pregenerated = primes[usize::from(i)].clone();
        async move {
            cggmp24::aux_info_gen(eid_aux, i, n, pregenerated)
                .start(&mut prng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();
    incomplete
        .into_iter()
        .zip(aux)
        .map(|(s, a)| cggmp24::KeyShare::from_parts((s, a)).expect("key share valid"))
        .collect()
}

/// Wrap a cggmp24 KeyShare into our `EncryptedShare` (ciphertext = plaintext JSON,
/// the on-the-wire shape `PresigningManager` deserializes), joint pubkey filled.
fn wrap_key_share(
    key_share: &cggmp24::KeyShare<Secp256k1, SecurityLevel128>,
    index: u16,
    config: ThresholdConfig,
    session_id: SessionId,
) -> EncryptedShare {
    EncryptedShare {
        nonce: vec![0u8; 12],
        ciphertext: serde_json::to_vec(key_share).expect("serialize key share"),
        session_id,
        share_index: ShareIndex(index),
        config,
        joint_pubkey_compressed: key_share.core.shared_public_key.to_bytes(true).to_vec(),
    }
}

fn deterministic_sighash(seed: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::digest(seed);
    h[0] |= 0x01;
    let mut a = [0u8; 32];
    a.copy_from_slice(&h);
    a
}

#[tokio::test]
async fn container_self_presigns_coordinator_holds_ct_then_signs_from_bundle() {
    if !opt_in() {
        eprintln!(
            "CONTAINER_PRESIG_E2E not set — skipping. To run:\n  \
             CONTAINER_PRESIG_E2E=1 cargo test -p bsv-mpc-proxy \
             --test container_presign_bundle_sign_e2e --release -- --nocapture --test-threads=1"
        );
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let relay_url = relay_url();
    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let parties_at_keygen = vec![0u16, 1u16];
    let policy_id = PolicyId([0x09; 32]);
    let coordinator_party = 1u16; // proxy = coordinator (holds the bundle)
    let cosigner_party = 0u16; // container = cosigner (self-encrypts its share)

    // ── 1. Local real 2-of-2 DKG ──
    eprintln!("(generating real 2-of-2 key shares — Paillier primes, ~30-60s)");
    let key_shares = run_dkg_2of2().await;
    let joint_pubkey = key_shares[0].core.shared_public_key.to_bytes(true).to_vec();
    let agent_id = hex::encode(&joint_pubkey);
    eprintln!("✔ joint_pubkey (agent_id) = {agent_id}");

    let dkg_session = SessionId::from_str_hash(&format!("dkg-{agent_id}"));
    let container_share = wrap_key_share(&key_shares[0], 0, config, dkg_session);
    let proxy_share = wrap_key_share(&key_shares[1], 1, config, dkg_session);

    // ── 2. The container's stable relay / BRC-2 identity (MPC_SERVER_PRIVATE_KEY).
    let container_identity = fresh_priv();
    std::env::set_var(
        "MPC_SERVER_PRIVATE_KEY",
        hex::encode(container_identity.to_bytes()),
    );
    std::env::set_var("MESSAGEBOX_RELAY_URL", &relay_url);

    // ── 3. Boot the in-process bsv-mpc-service with share_A seeded ──
    let data_dir = tempfile::tempdir().expect("tempdir");
    let mut storage = SqliteShareStorage::open(data_dir.path().to_str().unwrap()).expect("storage");
    // Seed share_A keyed by the joint pubkey (agent_id), dev-mode owner (empty).
    storage
        .store_share_with_owner(&agent_id, &container_share, "")
        .expect("seed container share_A");
    let state = Arc::new(AppState {
        data_dir: data_dir.path().to_str().unwrap().to_string(),
        storage: RwLock::new(storage),
        started_at: chrono::Utc::now(),
        provision: None,
        // Dev-mode auth: this gate isolates the §06.17.1 crypto loop (route auth
        // is proven in service_owner_authz_e2e). The relay/BRC-2 identity comes
        // from MPC_SERVER_PRIVATE_KEY via server_identity_priv_from_env(), NOT
        // from AuthState — so dev-mode auth + a known relay identity coexist.
        auth: AuthState::dev(),
        custody: None,
    });
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let svc_addr = listener.local_addr().unwrap();
    let svc_url = format!("http://{svc_addr}");
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });
    // Wait for liveness.
    let http = reqwest::Client::new();
    for _ in 0..50 {
        if http
            .get(format!("{svc_url}/health"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    eprintln!("✔ in-process bsv-mpc-service live at {svc_url}");

    // ── 4. Proxy = coordinator: presign over the relay, assemble + persist bundle.
    let proxy_identity = fresh_priv();
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let bundle_store = Arc::new(FileBundleStore::new(bundle_dir.path()).expect("bundle store"));
    let at_rest_root = [0x42u8; 32];

    let presign_session = SessionId::from_str_hash(&format!("presig-{agent_id}-1"));

    // Dev-mode service ⇒ no auth headers needed; the request_signer is a no-op.
    let no_auth_signer = move |_m: &str,
                               _p: &str,
                               _b: &[u8]|
          -> bsv_mpc_core::error::Result<Vec<(String, String)>> { Ok(vec![]) };

    let bundle = coordinate_presign_over_relay(
        &relay_url,
        proxy_identity.clone(),
        proxy_share.clone(),
        coordinator_party,
        cosigner_party,
        parties_at_keygen.clone(),
        policy_id,
        at_rest_root,
        presign_session,
        bundle_store.clone(),
        CosignerArm {
            url: format!("{svc_url}/presign-relay/init"),
            agent_id: agent_id.clone(),
        },
        &no_auth_signer,
        Duration::from_secs(120),
    )
    .await
    .expect("coordinator presign over relay → bundle");
    eprintln!("✔ PresigBundle assembled + persisted (presig_id={})", bundle.presig_id);

    // ── 5. THE GATE: bundle holds the container's OWN ct; coordinator can't read it.
    assert_eq!(bundle.presig_id, presign_session.hex());
    assert_eq!(bundle.joint_pubkey, joint_pubkey, "binding: joint_pubkey");
    assert_eq!(bundle.parties_at_keygen, parties_at_keygen);
    assert_eq!(bundle.cosigner_encrypted_shares.len(), 2);
    // Coordinator = party 1 → its own positional slot (index 1) is empty (plaintext
    // sealed in presig_bytes); the container (party 0) ct lands at index 0.
    let container_ct = bundle.cosigner_encrypted_shares[0].clone().into_vec();
    assert!(!container_ct.is_empty(), "container ct at positional index 0");
    assert!(
        bundle.cosigner_encrypted_shares[1].is_empty(),
        "coordinator's own slot empty"
    );
    assert!(!bundle.presig_bytes.is_empty(), "coordinator own sealed share");
    assert!(!bundle.commitments.is_empty(), "durable public-data commitments");

    // The container ct DECRYPTS under the container identity (genuine share), and
    // the coordinator (proxy identity) CANNOT decrypt it (§06.17.1 threshold).
    let container_wallet = wallet_from_identity(&container_identity);
    let recovered =
        bsv_mpc_core::presig_encryption::decrypt_presig_share(&container_wallet, &bundle.presig_id, &container_ct)
            .expect("container ct decrypts under container identity");
    let _p: cggmp24::Presignature<Secp256k1> =
        serde_json::from_slice(&recovered).expect("decrypts to a valid cggmp24 Presignature");
    assert!(
        decrypt_and_issue_partial(
            &wallet_from_identity(&proxy_identity),
            &bundle.presig_id,
            &container_ct,
            &[0u8; 32],
            None,
        )
        .is_err(),
        "coordinator MUST NOT decrypt the container's share (§06.17.1)"
    );
    eprintln!("✔ container holds its own share; coordinator cannot read it (threshold preserved)");

    // ── 6. Reload the bundle from disk (durable across restart).
    let reloaded = bundle_store
        .get(&bundle.presig_id)
        .expect("bundle reloads from disk");
    drop(bundle);

    // ── 7. Sign from the reloaded bundle: ship the container's own ct to
    //       /sign-relay, container decrypts + co-signs, proxy combines.
    let sighash = deterministic_sighash(reloaded.presig_id.as_bytes());
    let coord_at_rest = bsv_mpc_core::presig_at_rest::derive_presig_at_rest_key(
        &at_rest_root,
        &reloaded.presig_id,
    );
    let own_presig_json =
        bsv_mpc_core::presig_at_rest::unseal_presig_bytes(&reloaded.presig_bytes, &coord_at_rest)
            .expect("unseal coordinator own presig share");

    let sign_session = SessionId::from_str_hash(&format!("sign-{}-1", reloaded.presig_id));
    let joint_key = JointPublicKey {
        compressed: joint_pubkey.clone(),
        address: String::new(),
    };
    let trigger = DoTrigger {
        url: format!("{svc_url}/sign-relay"),
        presig_a_json: vec![],
        do_index: cosigner_party,
        agent_id: Some(agent_id.clone()),
        auth_headers: vec![],
        cosigner_encrypted_share: None, // shipped explicitly by the bundle-combine fn
        brc42_offset: None,
    };
    let participants: Vec<u16> = parties_at_keygen.clone();
    let sig_result = combine_sign_from_bundle_over_relay(
        &relay_url,
        proxy_identity.clone(),
        proxy_share.clone(),
        participants,
        config,
        sign_session,
        &sighash,
        &own_presig_json,
        &reloaded.commitments,
        reloaded.cosigner_encrypted_shares[0].clone().into_vec(),
        &reloaded.presig_id,
        &joint_key,
        trigger,
        Some(&no_auth_signer),
        Duration::from_secs(60),
    )
    .await
    .expect("sign from bundle over relay → final signature");
    eprintln!("✔ combine complete — DER sig {} bytes", sig_result.signature.len());

    // ── 8. The signature VERIFIES under the joint key (BSV-valid ECDSA, low-s).
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_result.r);
    s.copy_from_slice(&sig_result.s);
    let bsv_sig = Signature::new(r, s);
    assert!(bsv_sig.is_low_s(), "§06.17.1 signature MUST be low-s (BIP-62)");
    let pubkey = PublicKey::from_bytes(&joint_pubkey).expect("joint pubkey");
    assert!(
        pubkey.verify(&sighash, &bsv_sig),
        "§06.17.1 signature MUST verify under the joint key"
    );
    eprintln!(
        "✔✔ §06.17.1 CONTAINER target proven: container self-presigned + self-encrypted, \
         coordinator held only the ciphertext, signed from the durable bundle, \
         signature verifies under the joint key {agent_id}"
    );
}
