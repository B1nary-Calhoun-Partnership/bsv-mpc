//! **DECISIVE EXPERIMENT #2: `{0,2}` non-contiguous presign over the REAL relay
//! with RESHARED (PSS-output) shares — NOT fresh DKG shares.**
//!
//! `presign_noncontiguous_02_realrelay_e2e.rs` proved the `{0,2}` topology over
//! the real relay PASSES when the shares come from a FRESH 3-party DKG. The
//! hermetic `recovery_sign_after_reshare.rs` proved RESHARED shares presign+sign
//! `{0,2}` over the in-process SIMULATOR. The DEPLOYED #40 recovery container's
//! share is NEITHER of those: it is a RESHARED (cross-(t,n) PSS) share, index 0,
//! driven over the REAL RELAY — and that is the deterministically-timing-out
//! combination.
//!
//! This test isolates exactly that last untested variable: it builds the new-set
//! `{0,1,2}` shares via the SAME `ResharCoordinator` PSS path the recovery flow
//! uses (DKG 2-of-3 → lose party 2 → survivors {0,1} reshare onto fresh 2-of-3),
//! then gives party 0's reshared share to the in-process `bsv-mpc-service`
//! cosigner and party 2's to the proxy coordinator, and runs the `{0,2}` presign
//! over the REAL relay. The cosigner's stored share_index is 0 (matching its
//! `my_party_index = 0`) so the SHARE-CONTENT variable is isolated from the index
//! variable (which a sibling test already covered).
//!
//! Verdict:
//!   - PASS ⇒ reshared share content is fine over the relay → the deployed bug is
//!     the CONTAINER'S RUNTIME STATE, not the share content.
//!   - FAIL ⇒ reshared share content breaks over the relay → root-cause via the
//!     `presign_index_diverge` trace.
//!
//! Gated on `NONCONTIG_PRESIG_E2E=1` (two real DKGs + auxinfo + live relay):
//!
//! ```bash
//! NONCONTIG_PRESIG_E2E=1 MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   RUST_LOG=presign_index_diverge=trace \
//!   cargo test -p bsv-mpc-proxy --test presign_noncontiguous_02_reshared_realrelay_e2e \
//!     --release -- --nocapture --test-threads=1
//! ```

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::reshar_coordinator::{
    ContributorInputs, ResharCommit, ResharConfig, ResharCoordinator, ResharRoundResult,
};
use bsv_mpc_core::types::{
    EncryptedShare, PolicyId, RoundMessage, SessionId, ShareIndex, ThresholdConfig,
};
use bsv_mpc_proxy::relay_presign::{coordinate_presign_over_relay, CosignerArm};
use bsv_mpc_service::{build_router, AppState, AuthState, FileBundleStore, SqliteShareStorage};
use cggmp24::key_share::IncompleteKeyShare;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use generic_ec::{NonZero, Scalar, SecretScalar};
use rand::RngCore;

fn opt_in() -> bool {
    std::env::var("NONCONTIG_PRESIG_E2E").ok().as_deref() == Some("1")
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
    fn start_send(self: std::pin::Pin<&mut Self>, item: M) -> std::result::Result<(), Self::Error> {
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
        (
            incoming,
            BufferedSink {
                messages: VecDeque::new(),
                inner: outgoing,
            },
        )
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
fn test_primes(
    rng: &mut impl rand::RngCore,
) -> cggmp24::key_refresh::PregeneratedPrimes<SecurityLevel128> {
    use cggmp24::security_level::SecurityLevel;
    let b = SecurityLevel128::RSA_PRIME_BITLEN;
    cggmp24::key_refresh::PregeneratedPrimes::try_from([
        generate_blum_prime(rng, b),
        generate_blum_prime(rng, b),
        generate_blum_prime(rng, b),
        generate_blum_prime(rng, b),
    ])
    .expect("primes have wrong bit size")
}

/// `t-of-n` keygen → `n` `IncompleteKeyShare`s (no aux — used for the OLD sharing,
/// from which we extract secrets + eval points). Mirrors recovery_sign_after_reshare.
fn keygen(n: u16, t: u16) -> Vec<IncompleteKeyShare<Secp256k1>> {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
    let eid = ExecutionId::new(&eid_bytes);
    round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut r = rand::rngs::OsRng;
        async move {
            cggmp24::keygen::<Secp256k1>(eid, i, n)
                .set_threshold(t)
                .start(&mut r, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec()
}

/// Fresh `aux_info_gen(n)` for the NEW party set.
fn aux_gen(n: u16) -> Vec<cggmp24::key_share::AuxInfo<SecurityLevel128>> {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
    let eid = ExecutionId::new(&eid_bytes);
    let primes: Vec<_> = (0..n).map(|_| test_primes(&mut rng)).collect();
    round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut r = rand::rngs::OsRng;
        let pre = primes[usize::from(i)].clone();
        async move {
            cggmp24::aux_info_gen(eid, i, n, pre)
                .start(&mut r, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec()
}

fn old_secret(share: &IncompleteKeyShare<Secp256k1>) -> Scalar<Secp256k1> {
    let d = share.clone().into_inner();
    *<SecretScalar<Secp256k1> as AsRef<Scalar<Secp256k1>>>::as_ref(&d.x)
}

/// **Build the new-set `{0,1,2}` shares EXACTLY like the #40 recovery flow.**
/// DKG 2-of-3 → lose party 2 → survivors {0,1} reshare (PSS over
/// `ResharCoordinator`s, in-process router) onto a fresh 2-of-3 → fresh aux →
/// `KeyShare::from_parts`. Returns the 3 RESHARED signing-ready key shares.
fn reshared_new_set() -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
    eprintln!("[reshared] DKG 2-of-3 (the funded sharing) — keygen with Blum test primes");
    let old_n: u16 = 3;
    let old_t: u16 = 2;
    let old = keygen(old_n, old_t);
    let joint_point = *old[0].shared_public_key;
    let jpk_bytes = joint_point.to_bytes(true).to_vec();

    let old_dirty0 = old[0].clone().into_inner();
    let old_eval: Vec<NonZero<Scalar<Secp256k1>>> =
        old_dirty0.key_info.vss_setup.as_ref().unwrap().I.clone();
    let old_secrets: Vec<Scalar<Secp256k1>> = old.iter().map(old_secret).collect();

    // Lose party 2; survivors {0,1} = t reshare onto a fresh 2-of-3.
    let survivors: Vec<u16> = vec![0, 1];
    let new_t: u16 = 2;
    let n_new: u16 = 3;
    let new_eval: Vec<NonZero<Scalar<Secp256k1>>> = (1..=n_new)
        .map(|i| NonZero::from_scalar(Scalar::from(i as u64)).unwrap())
        .collect();
    let contributor_new_indices: Vec<u16> = vec![0, 1];
    let subset_old_eval: Vec<NonZero<Scalar<Secp256k1>>> =
        survivors.iter().map(|&k| old_eval[k as usize]).collect();

    eprintln!("[reshared] survivors {{0,1}} reshare 2-of-3 → 2-of-3 (PSS over ResharCoordinators)");
    let mut coords: Vec<ResharCoordinator> = (0..n_new)
        .map(|j| {
            let contributor = contributor_new_indices
                .iter()
                .position(|&c| c == j)
                .map(|pos| ContributorInputs {
                    my_subset_pos: pos,
                    subset_eval_points: subset_old_eval.clone(),
                    my_old_secret: old_secrets[survivors[pos] as usize],
                });
            ResharCoordinator::new(ResharConfig {
                session_id: SessionId::from_str_hash("decisive-reshare"),
                my_new_index: j,
                new_eval_points: new_eval.clone(),
                new_t,
                contributor_new_indices: contributor_new_indices.clone(),
                original_joint_pubkey: jpk_bytes.clone(),
                contributor,
            })
            .expect("reshar coordinator")
        })
        .collect();

    // In-process router (mirror of recovery_sign_after_reshare).
    let mut queue: VecDeque<(u16, RoundMessage)> = VecDeque::new();
    let mut commits: Vec<Option<ResharCommit>> = (0..n_new).map(|_| None).collect();
    let enqueue = |q: &mut VecDeque<(u16, RoundMessage)>, from: u16, msgs: Vec<RoundMessage>| {
        for m in msgs {
            match m.to {
                Some(ShareIndex(j)) => q.push_back((j, m)),
                None => {
                    for j in 0..n_new {
                        if j != from {
                            q.push_back((j, m.clone()));
                        }
                    }
                }
            }
        }
    };
    for j in 0..n_new {
        let out = coords[j as usize].init().unwrap();
        enqueue(&mut queue, j, out);
    }
    let mut guard = 0;
    while let Some((rcpt, msg)) = queue.pop_front() {
        guard += 1;
        assert!(guard < 1_000_000, "reshare did not converge");
        match coords[rcpt as usize].process_round(vec![msg]).unwrap() {
            ResharRoundResult::NextRound(out) => enqueue(&mut queue, rcpt, out),
            ResharRoundResult::Complete(c) => commits[rcpt as usize] = Some(*c),
        }
    }
    let commits: Vec<ResharCommit> = commits
        .into_iter()
        .map(|c| c.expect("every new party committed"))
        .collect();
    for c in &commits {
        assert_eq!(
            c.joint_pubkey_compressed, jpk_bytes,
            "reshare MUST preserve the joint pubkey"
        );
    }

    eprintln!("[reshared] fresh aux_info_gen(3) + KeyShare::from_parts");
    let incompletes: Vec<IncompleteKeyShare<Secp256k1>> = commits
        .iter()
        .map(|c| serde_json::from_slice(&c.incomplete_share_json).expect("incomplete share"))
        .collect();
    let new_aux = aux_gen(n_new);
    let new_shares: Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> = incompletes
        .into_iter()
        .zip(new_aux)
        .map(|(core, a)| cggmp24::KeyShare::from_parts((core, a)).expect("new 2-of-3 key share"))
        .collect();
    assert_eq!(new_shares.len(), 3, "rotated set has 3 shares");
    new_shares
}

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

/// Run `{0,2}` presign over the real relay using RESHARED shares. Coordinator =
/// party 2 (SM-position 1); in-process cosigner = party 0 (SM-position 0).
/// Returns whether the coordinator assembled a bundle within the timeout.
async fn run_reshared_presign_over_relay(label: &str) -> bool {
    let relay_url = relay_url();
    let t: u16 = 2;
    let n: u16 = 3;
    let parties_at_keygen = vec![0u16, 2u16];
    let coordinator_party = 2u16;
    let cosigner_party = 0u16;
    let config = ThresholdConfig::new(t, n).expect("config");
    let policy_id = PolicyId([0x09; 32]);

    eprintln!("[{label}] building RESHARED new-set shares like the #40 recovery flow…");
    let key_shares = reshared_new_set();
    let joint_pubkey = key_shares[0].core.shared_public_key.to_bytes(true).to_vec();
    let agent_id = hex::encode(&joint_pubkey);
    eprintln!("[{label}] ✔ reshared joint_pubkey (agent_id) = {agent_id}");

    let dkg_session = SessionId::from_str_hash(&format!("dkg-{agent_id}"));
    // Cosigner = party 0 (share_index 0, matches my_party_index 0); coordinator = party 2.
    let cosigner_share = wrap_key_share(
        &key_shares[cosigner_party as usize],
        cosigner_party,
        config,
        dkg_session,
    );
    let coord_share = wrap_key_share(
        &key_shares[coordinator_party as usize],
        coordinator_party,
        config,
        dkg_session,
    );

    // Container/service stable relay identity.
    let container_identity = fresh_priv();
    std::env::set_var(
        "MPC_SERVER_PRIVATE_KEY",
        hex::encode(container_identity.to_bytes()),
    );
    std::env::set_var("MESSAGEBOX_RELAY_URL", &relay_url);

    // Boot the in-process bsv-mpc-service with the cosigner share seeded.
    let data_dir = tempfile::tempdir().expect("tempdir");
    let mut storage = SqliteShareStorage::open(data_dir.path().to_str().unwrap()).expect("storage");
    storage
        .store_share_with_owner(&agent_id, &cosigner_share, "")
        .expect("seed cosigner share");
    let state = Arc::new(AppState {
        data_dir: data_dir.path().to_str().unwrap().to_string(),
        storage: RwLock::new(storage),
        started_at: chrono::Utc::now(),
        provision: None,
        auth: AuthState::dev(),
        custody: None,
    });
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let svc_addr = listener.local_addr().unwrap();
    let svc_url = format!("http://{svc_addr}");
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
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
    eprintln!("[{label}] ✔ in-process bsv-mpc-service live at {svc_url}");

    // Proxy = coordinator.
    let proxy_identity = fresh_priv();
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let bundle_store = Arc::new(FileBundleStore::new(bundle_dir.path()).expect("bundle store"));
    let at_rest_root = [0x42u8; 32];
    let presign_session = SessionId::from_str_hash(&format!("presig-{agent_id}-{label}"));

    let no_auth_signer =
        move |_m: &str,
              _p: &str,
              _b: &[u8]|
              -> bsv_mpc_core::error::Result<Vec<(String, String)>> { Ok(vec![]) };

    let result = coordinate_presign_over_relay(
        &relay_url,
        proxy_identity.clone(),
        coord_share.clone(),
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
        Duration::from_secs(90),
    )
    .await;

    match result {
        Ok(bundle) => {
            eprintln!(
                "[{label}] ✔ PresigBundle assembled — presig_id={} parties={:?} cosigner_shares={}",
                bundle.presig_id,
                bundle.parties_at_keygen,
                bundle.cosigner_encrypted_shares.len()
            );
            assert_eq!(
                bundle.joint_pubkey, joint_pubkey,
                "[{label}] joint_pubkey binding"
            );
            assert_eq!(
                bundle.parties_at_keygen, parties_at_keygen,
                "[{label}] subset binding"
            );
            true
        }
        Err(e) => {
            eprintln!("[{label}] ✘ presign FAILED: {e}");
            false
        }
    }
}

/// **DECISIVE: `{0,2}` non-contiguous presign over the REAL relay with RESHARED
/// shares (index 0 cosigner) — the deployed #40 recovery container's exact share
/// provenance.**
#[tokio::test]
async fn presign_realrelay_noncontiguous_02_reshared_decisive() {
    if !opt_in() {
        eprintln!(
            "NONCONTIG_PRESIG_E2E not set — skipping. To run:\n  \
             NONCONTIG_PRESIG_E2E=1 RUST_LOG=presign_index_diverge=trace cargo test -p bsv-mpc-proxy \
             --test presign_noncontiguous_02_reshared_realrelay_e2e --release -- --nocapture --test-threads=1"
        );
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let ok = run_reshared_presign_over_relay("02-reshared").await;
    assert!(
        ok,
        "DECISIVE: a RESHARED-share {{0,2}} presign over the real relay (index-0 cosigner) \
         MUST assemble a bundle. If it FAILS, the reshared share content is the deployed bug; \
         if it PASSES, the deployed bug is the container's runtime state, not the share content."
    );
}
