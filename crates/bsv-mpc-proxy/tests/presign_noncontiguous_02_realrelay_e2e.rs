//! **DECISIVE EXPERIMENT: `{0,2}` non-contiguous presign over the REAL relay
//! with an IN-PROCESS `bsv-mpc-service` cosigner (NOT the deployed container).**
//!
//! This isolates the SECOND presign-over-relay bug that the in-process router
//! repro (`presign_noncontiguous_02_repro.rs`) does NOT capture. That repro
//! serializes delivery in-process and only exercises the wrap/dispatch layer; it
//! cannot reproduce anything that depends on the REAL relay's ordering / dedup /
//! WS-push-vs-backfill behaviour, nor on the inner encrypted `WireMessage` the
//! cggmp24 SM actually reads its sender from.
//!
//! Topology = the failing mainnet recovery topology:
//!   parties_at_keygen = [0, 2], coordinator_party = 2 (proxy, SM-position 1),
//!   cosigner_party = 0 (in-process service, SM-position 0).
//!
//! It is the EXACT structure of `container_presign_bundle_sign_e2e.rs` (same
//! relay client, same in-process `build_router` service, same
//! `coordinate_presign_over_relay` coordinator) but with the non-contiguous
//! 2-of-3 subset instead of the contiguous 2-of-2 `{0,1}`.
//!
//! Verdict:
//!   - PASS  ⇒ the second bug is specific to the DEPLOYED CONTAINER's state.
//!   - FAIL  ⇒ the second bug reproduces locally against the real relay; root-cause it.
//!
//! Gated on `NONCONTIG_PRESIG_E2E=1` (real Paillier-prime keygen ~30-90s + live relay):
//!
//! ```bash
//! NONCONTIG_PRESIG_E2E=1 MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-proxy --test presign_noncontiguous_02_realrelay_e2e \
//!     --release -- --nocapture --test-threads=1
//! ```

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::types::{EncryptedShare, PolicyId, SessionId, ShareIndex, ThresholdConfig};
use bsv_mpc_proxy::relay_presign::{coordinate_presign_over_relay, CosignerArm};
use bsv_mpc_service::{build_router, AppState, AuthState, FileBundleStore, SqliteShareStorage};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
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

/// `t`-of-`n` DKG via the sim → `n` complete signing-ready key shares.
async fn run_dkg(n: u16, t: u16) -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
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

/// Run a presign over the real relay for the given non-contiguous subset and
/// return whether the coordinator assembled a bundle within the timeout.
///
/// `cosigner_stored_index` is the `share_index` the in-process service's stored
/// share carries. In the healthy case it equals `cosigner_party`. Set it to a
/// DIFFERENT value to reproduce the deployed container's post-reshare state,
/// where the stored share's index no longer matches the `my_party_index` the
/// coordinator arms it with — `PresigningManager::my_signing_index()` then runs
/// the cosigner SM at the WRONG signing position.
async fn run_presign_over_relay(
    parties_at_keygen: Vec<u16>,
    coordinator_party: u16,
    cosigner_party: u16,
    cosigner_stored_index: u16,
    t: u16,
    n: u16,
    label: &str,
) -> bool {
    let relay_url = relay_url();
    let config = ThresholdConfig::new(t, n).expect("config");
    let policy_id = PolicyId([0x09; 32]);

    // ── 1. Local real t-of-n DKG ──
    eprintln!("[{label}] generating real {t}-of-{n} key shares — Paillier primes, ~30-90s");
    let key_shares = run_dkg(n, t).await;
    let joint_pubkey = key_shares[0].core.shared_public_key.to_bytes(true).to_vec();
    let agent_id = hex::encode(&joint_pubkey);
    eprintln!("[{label}] ✔ joint_pubkey (agent_id) = {agent_id}");

    let dkg_session = SessionId::from_str_hash(&format!("dkg-{agent_id}"));
    // The in-process service (cosigner) holds the cosigner_party share; the proxy
    // coordinator holds the coordinator_party share.
    let cosigner_share = wrap_key_share(
        &key_shares[cosigner_party as usize],
        cosigner_stored_index,
        config,
        dkg_session,
    );
    let coord_share = wrap_key_share(
        &key_shares[coordinator_party as usize],
        coordinator_party,
        config,
        dkg_session,
    );

    // ── 2. The container/service's stable relay / BRC-2 identity. ──
    let container_identity = fresh_priv();
    std::env::set_var(
        "MPC_SERVER_PRIVATE_KEY",
        hex::encode(container_identity.to_bytes()),
    );
    std::env::set_var("MESSAGEBOX_RELAY_URL", &relay_url);

    // ── 3. Boot the in-process bsv-mpc-service with the cosigner share seeded ──
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

    // ── 4. Proxy = coordinator: presign over the relay, assemble + persist bundle.
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

/// **CONTROL: `{0,1}` contiguous over the real relay.** Proven-good topology.
/// If this fails too, the failure is environmental (relay down), not the bug.
#[tokio::test]
async fn presign_realrelay_contiguous_01_control() {
    if !opt_in() {
        eprintln!("NONCONTIG_PRESIG_E2E not set — skipping.");
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let ok = run_presign_over_relay(vec![0, 1], 1, 0, 0, 2, 2, "01").await;
    assert!(
        ok,
        "CONTROL {{0,1}} presign over the real relay MUST assemble a bundle"
    );
}

/// **DECISIVE: `{0,2}` non-contiguous, coordinator = party 2 (SM-position 1),
/// over the REAL relay with an in-process service cosigner.**
#[tokio::test]
async fn presign_realrelay_noncontiguous_02_decisive() {
    if !opt_in() {
        eprintln!(
            "NONCONTIG_PRESIG_E2E not set — skipping. To run:\n  \
             NONCONTIG_PRESIG_E2E=1 cargo test -p bsv-mpc-proxy \
             --test presign_noncontiguous_02_realrelay_e2e --release -- --nocapture --test-threads=1"
        );
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    // Healthy case: stored cosigner share_index (0) matches the arm my_party_index (0).
    let ok = run_presign_over_relay(vec![0, 2], 2, 0, 0, 2, 3, "02").await;
    assert!(
        ok,
        "DECISIVE {{0,2}} presign over the real relay MUST assemble a bundle \
         (coordinator at SM-position 1, in-process service cosigner)"
    );
}

/// **ROOT-CAUSE REPRODUCTION of the deployed-container `{0,2}` timeout.**
///
/// Identical to the decisive case EXCEPT the in-process service's stored cosigner
/// share carries `share_index = 2` while the coordinator arms it with
/// `my_party_index = 0` and `parties_at_keygen = [0, 2]`. This models the
/// deployed container's state after a cross-(t,n) reshare, where the stored
/// share's index no longer equals the party index the proxy passes.
///
/// `PresigningManager::my_signing_index()` (presigning.rs:476) derives the
/// cggmp24 signing position from `share.share_index`, NOT from `my_party_index`:
///   position of stored index 2 in [0,2] = 1  (should be 0).
/// So the cosigner runs its SM at the WRONG signing position — its presig math is
/// bound to the wrong Lagrange/eval point. The coordinator consumes the
/// cosigner's round-1/round-2 but its SM rejects/cannot advance on them, so it
/// "produces 0 outbound" and the ceremony times out — EXACTLY the deployed
/// symptom. We assert the presign FAILS (times out), proving the mechanism.
#[tokio::test]
async fn presign_realrelay_noncontiguous_02_container_index_mismatch_repro() {
    if !opt_in() {
        eprintln!("NONCONTIG_PRESIG_E2E not set — skipping.");
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    // Stored cosigner share_index = 2, but armed as my_party_index = 0 → mismatch.
    let ok = run_presign_over_relay(vec![0, 2], 2, 0, 2, 2, 3, "02-mismatch").await;
    assert!(
        !ok,
        "REPRO: a stored cosigner share_index that mismatches my_party_index MUST \
         stall the presign (coordinator produces 0 outbound, then times out) — this \
         is the deployed-container second bug"
    );
}
