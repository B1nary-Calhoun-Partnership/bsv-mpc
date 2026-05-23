//! **FULL cross-(t,n) reshare 2-of-2 → 2-of-3 over the LIVE relay** — the exact
//! composition the deployed mainnet path uses (issue #35c pt2 validation).
//!
//! Three in-process party-agents (own BRC-31 relay identities) each run BOTH
//! ceremonies over the deployed Calhoun relay, in two sequential phases (each on
//! its own dedicated box — the proven dkg_2of3 / reshar_3of4 patterns):
//!
//! - **Phase A (aux):** a throwaway 2-of-3 DKG (`DkgHandler`, `mpc-dkg`) — keep
//!   each party's own aux (aux is key-independent).
//! - **Phase B (PSS):** the cross-(t,n) reshare of the ORIGINAL 2-of-2 key onto
//!   the 3-party polynomial (`ResharHandler`, `mpc-refresh`).
//!
//! Then `combine_reshared_with_aux(pss_incomplete, throwaway_dkg_keyshare)` →
//! each party's signing-ready KeyShare for the ORIGINAL key.
//!
//! **Gate:** every 2-of-3 subset signs + verifies against the ORIGINAL joint key;
//! address unchanged. This is the deployed mechanism end-to-end on real transport
//! (the deployed `/reshare-relay` endpoint just moves party 0 onto the container).
//!
//! ```bash
//! MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-service --test reshar_full_2of2_to_2of3_via_messagebox_e2e \
//!     -- --nocapture --test-threads=1
//! ```

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::reshar_coordinator::{combine_reshared_with_aux, ContributorInputs, ResharConfig};
use bsv_mpc_core::types::{SessionId, ThresholdConfig};
use bsv_mpc_messagebox::types::{BOX_DKG, BOX_REFRESH};
use bsv_mpc_messagebox::MessageBoxClient;
use bsv_mpc_service::storage::SqliteShareStorage;
use bsv_mpc_service::{DkgHandler, MessageBoxListener, ResharHandler};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::signing::DataToSign;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::{ExecutionId, PregeneratedPrimes};
use generic_ec::{NonZero, Point, Scalar, SecretScalar};
use rand::RngCore;
use sha2::Sha256;

fn relay_url() -> Option<String> {
    std::env::var("MESSAGEBOX_RELAY_URL").ok()
}
fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("priv")
}

// ── cggmp24 sim infra (old keygen + signing) ──
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
    fn poll_ready(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::result::Result<(), Self::Error>> { std::task::Poll::Ready(Ok(())) }
    fn start_send(self: std::pin::Pin<&mut Self>, item: M) -> std::result::Result<(), Self::Error> { self.project().messages.get_mut().push_back(item); Ok(()) }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        while !self.messages.is_empty() {
            let mut p = self.as_mut().project();
            let mut inner = p.inner;
            std::task::ready!(inner.as_mut().poll_ready(cx))?;
            if let Some(item) = p.messages.pop_front() { inner.as_mut().start_send(item)?; }
        }
        self.project().inner.poll_flush(cx)
    }
    fn poll_close(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::result::Result<(), Self::Error>> { self.project().inner.poll_close(cx) }
}
fn buffer_outgoing<M, D, R>(party: round_based::MpcParty<M, D, R>) -> round_based::MpcParty<M, BufferedDelivery<M, D>, R>
where M: Unpin, D: round_based::Delivery<M>, R: round_based::runtime::AsyncRuntime {
    party.map_delivery(|d| { let (i, o) = d.split(); (i, BufferedSink { messages: VecDeque::new(), inner: o }) })
}
async fn keygen(n: u16, t: u16) -> Vec<cggmp24::key_share::IncompleteKeyShare<Secp256k1>> {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);
    round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut r = rand::rngs::OsRng;
        async move { cggmp24::keygen::<Secp256k1>(eid, i, n).set_threshold(t).start(&mut r, party).await }
    }).unwrap().expect_ok().into_vec()
}
async fn sign_verify(shares: &[cggmp24::KeyShare<Secp256k1, SecurityLevel128>], parts: &[u16], joint: &Point<Secp256k1>, msg: &[u8]) {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);
    let pv = parts.to_vec();
    let data = DataToSign::<Secp256k1>::digest::<Sha256>(msg);
    let sig = round_based::sim::run_with_setup(parts.iter().map(|i| &shares[usize::from(*i)]), |i, party, share| {
        let party = buffer_outgoing(party);
        let mut r = rand::rngs::OsRng;
        let p = pv.clone();
        async move { cggmp24::signing(eid, i, &p, share).sign(&mut r, party, &data).await }
    }).unwrap().expect_ok().expect_eq();
    sig.verify(joint, &data).expect("post-reshare sig MUST verify vs ORIGINAL joint key");
}

fn fresh_storage() -> Arc<std::sync::RwLock<SqliteShareStorage>> {
    let dir = tempfile::tempdir().expect("tempdir");
    let s = SqliteShareStorage::open(dir.path().to_str().unwrap()).expect("open");
    std::mem::forget(dir);
    Arc::new(std::sync::RwLock::new(s))
}

#[tokio::test]
async fn full_reshare_2of2_to_2of3_over_messagebox() {
    let Some(relay_url) = relay_url() else {
        eprintln!("MESSAGEBOX_RELAY_URL not set — skipping full reshare e2e.");
        return;
    };
    let _ = tracing_subscriber::fmt::try_init();
    let t0 = std::time::Instant::now();

    // ── OLD 2-of-2 keygen → secrets + eval points (the funded key K) ──
    let old = keygen(2, 2).await;
    let original_joint = *old[0].shared_public_key;
    let jpk_bytes = original_joint.to_bytes(true).to_vec();
    let old_dirty0 = old[0].clone().into_inner();
    let old_eval: Vec<NonZero<Scalar<Secp256k1>>> = old_dirty0.key_info.vss_setup.as_ref().unwrap().I.clone();
    let old_secrets: Vec<Scalar<Secp256k1>> = old.iter().map(|s| {
        let d = s.clone().into_inner();
        *<SecretScalar<Secp256k1> as AsRef<Scalar<Secp256k1>>>::as_ref(&d.x)
    }).collect();
    eprintln!("✔ original joint_pubkey = {}", hex::encode(&jpk_bytes));

    // ── NEW 2-of-3 params ──
    let new_cfg = ThresholdConfig::new(2, 3).expect("2-of-3");
    let n_new: u16 = 3;
    let new_t: u16 = 2;
    let new_eval: Vec<NonZero<Scalar<Secp256k1>>> =
        (1..=n_new).map(|i| NonZero::from_scalar(Scalar::from(i as u64)).unwrap()).collect();
    let contributor_new_indices: Vec<u16> = vec![0, 1]; // old 0,1 continue + contribute
    let subset_old_eval: Vec<NonZero<Scalar<Secp256k1>>> = vec![old_eval[0], old_eval[1]];

    // ── 3 agents on the relay ──
    let mut privs = Vec::new();
    let mut clients = Vec::new();
    let mut pubs = Vec::new();
    for _ in 0..n_new {
        let p = fresh_priv();
        let c = MessageBoxClient::new(&relay_url, p.clone()).expect("client");
        let ph = c.identity_hex().await.expect("id");
        privs.push(p); clients.push(c); pubs.push(ph);
    }
    eprintln!("✔ 3 agents on the relay");

    // ── Pre-generate 3 Paillier prime sets in parallel (the slow step) ──
    eprintln!("(generating 3 Paillier prime sets — ~30-90s each, parallel)");
    let mut primes = tokio::task::spawn_blocking(|| {
        (0..3).map(|_| std::thread::spawn(|| PregeneratedPrimes::<SecurityLevel128>::generate(&mut rand::rngs::OsRng)))
            .collect::<Vec<_>>().into_iter().map(|h| h.join().unwrap()).collect::<Vec<_>>()
    }).await.expect("prime gen");

    let dkg_session = { let mut b = [0u8; 32]; rand::rngs::OsRng.fill_bytes(&mut b); SessionId(b) };
    let reshare_session = { let mut b = [0u8; 32]; rand::rngs::OsRng.fill_bytes(&mut b); SessionId(b) };
    let timeout = Duration::from_secs(240);

    // ════ PHASE A — throwaway 2-of-3 DKG over the relay (keep each party's aux) ══
    // Dedicated BOX_DKG listeners (the proven dkg_2of3 pattern), run to completion
    // first; phases are independent (aux is key-independent).
    let dkg_handlers: Vec<DkgHandler> = (0..n_new).map(|i| DkgHandler::new(new_cfg, i, fresh_storage())).collect();
    for h in &dkg_handlers { h.seed_primes_for(dkg_session, primes.remove(0)); }
    let mut dkg_listeners = Vec::new();
    for i in 0..n_new as usize {
        dkg_listeners.push(MessageBoxListener::start(clients[i].clone(), BOX_DKG, dkg_handlers[i].handler_fn()).await.expect("dkg listener"));
    }
    let mut dkg_rxs = Vec::new();
    let mut dkg_sends: Vec<(usize, _)> = Vec::new();
    for j in 0..n_new {
        let peers: Vec<(u16, String)> = (0..n_new).filter(|&k| k != j).map(|k| (k, pubs[k as usize].clone())).collect();
        let (rx, out) = dkg_handlers[j as usize].initiate(dkg_session, peers).await.expect("dkg initiate");
        dkg_rxs.push(rx);
        dkg_sends.push((j as usize, out));
    }
    for (j, out) in dkg_sends {
        for o in out { clients[j].send_round_message(&o.recipient_pub_hex, &o.message_box, &o.round_msg, o.params).await.expect("ship dkg round-1"); }
    }
    eprintln!("✔ phase A: throwaway DKG initiated — awaiting aux");
    let mut throwaway: Vec<bsv_mpc_core::types::DkgResult> = Vec::new();
    for j in 0..n_new as usize {
        let r = tokio::time::timeout(timeout, dkg_rxs.remove(0)).await
            .unwrap_or_else(|_| panic!("agent {j} DKG timeout")).expect("dkg channel");
        throwaway.push(r);
    }
    for l in dkg_listeners { let _ = tokio::time::timeout(Duration::from_secs(10), l.shutdown()).await; }
    eprintln!("✔ phase A done: 3 parties hold fresh 2-of-3 aux");

    // ════ PHASE B — cross-(t,n) PSS reshare of K over the relay ═════════════════
    let reshar_handlers: Vec<ResharHandler> = (0..n_new).map(|_| ResharHandler::new()).collect();
    let mut pss_listeners = Vec::new();
    for i in 0..n_new as usize {
        pss_listeners.push(MessageBoxListener::start(clients[i].clone(), BOX_REFRESH, reshar_handlers[i].handler_fn()).await.expect("pss listener"));
    }
    let mut pss_rxs = Vec::new();
    let mut pss_sends: Vec<(usize, _)> = Vec::new();
    for j in 0..n_new {
        let peers: Vec<(u16, String)> = (0..n_new).filter(|&k| k != j).map(|k| (k, pubs[k as usize].clone())).collect();
        let contributor = if (j as usize) < usize::from(new_t) {
            Some(ContributorInputs { my_subset_pos: j as usize, subset_eval_points: subset_old_eval.clone(), my_old_secret: old_secrets[j as usize] })
        } else { None };
        let config = ResharConfig {
            session_id: reshare_session,
            my_new_index: j,
            new_eval_points: new_eval.clone(),
            new_t,
            contributor_new_indices: contributor_new_indices.clone(),
            original_joint_pubkey: jpk_bytes.clone(),
            contributor,
        };
        let (rx, out) = reshar_handlers[j as usize].initiate(config, peers).await.expect("pss initiate");
        pss_rxs.push(rx);
        pss_sends.push((j as usize, out));
    }
    for (j, out) in pss_sends {
        for o in out { clients[j].send_round_message(&o.recipient_pub_hex, &o.message_box, &o.round_msg, o.params).await.expect("ship pss round-1"); }
    }
    eprintln!("✔ phase B: PSS reshare initiated — awaiting reshared shares");

    // ── Combine each agent's reshared share (K) with its throwaway aux ──
    let mut key_shares: Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> = Vec::new();
    for (j, tw) in throwaway.iter().enumerate() {
        let pss = tokio::time::timeout(timeout, pss_rxs.remove(0)).await
            .unwrap_or_else(|_| panic!("agent {j} PSS timeout")).expect("pss channel");
        assert_eq!(pss.joint_pubkey_compressed, jpk_bytes, "agent {j}: joint pubkey unchanged");
        let combined_json = combine_reshared_with_aux(&pss.incomplete_share_json, &tw.share.ciphertext)
            .unwrap_or_else(|e| panic!("agent {j} combine: {e}"));
        key_shares.push(serde_json::from_slice(&combined_json).expect("combined key share"));
    }
    for l in pss_listeners { let _ = tokio::time::timeout(Duration::from_secs(10), l.shutdown()).await; }
    eprintln!("✔ all 3 agents combined: PSS reshare (K) + throwaway-DKG aux → new 2-of-3 KeyShares");

    // ── THE GATE: every 2-of-3 subset signs vs the ORIGINAL key ──
    let msg = b"full reshare 2-of-2 -> 2-of-3 over the relay, spend original address";
    for subset in &[[0u16, 1], [0, 2], [1, 2]] {
        sign_verify(&key_shares, subset, &original_joint, msg).await;
    }
    eprintln!("✔✔ 2-of-2 → 2-of-3 FULL reshare over the relay: address preserved, every 2-of-3 subset SIGNS");
    eprintln!("✔ done — total {:?}", t0.elapsed());
}
