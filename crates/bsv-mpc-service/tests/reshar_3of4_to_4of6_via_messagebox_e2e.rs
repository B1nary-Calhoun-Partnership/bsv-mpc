//! **Cross-(t,n) reshare 3-of-4 → 4-of-6 over the LIVE MessageBox relay** —
//! MPC-Spec §18.2 `reshare_change_threshold` (issue #35c, transport gate).
//!
//! Six in-process party-agents (each its own BRC-31 relay identity +
//! `ResharHandler` + `MessageBoxListener` on `mpc-refresh`) run the distributed
//! PSS reshare over the deployed Calhoun relay. Old 3-of-4 shares are generated
//! locally (keygen sim); the test then drives the 2-round PSS over the REAL relay
//! → each agent's new-set `IncompleteKeyShare` → fresh `aux_info_gen(6)` → EVERY
//! 4-of-6 subset signs + verifies against the ORIGINAL joint key.
//!
//! Proves the cross-(t,n) PSS works over the real transport (the deployed
//! container's transport layer); the deployed-container endpoint + mainnet spend
//! build on this.
//!
//! Gated on `MESSAGEBOX_RELAY_URL`:
//! ```bash
//! MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-service --test reshar_3of4_to_4of6_via_messagebox_e2e \
//!     -- --nocapture --test-threads=1
//! ```

use std::collections::VecDeque;
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::reshar_coordinator::{ContributorInputs, ResharConfig};
use bsv_mpc_core::types::SessionId;
use bsv_mpc_messagebox::types::BOX_REFRESH;
use bsv_mpc_messagebox::MessageBoxClient;
use bsv_mpc_service::{MessageBoxListener, ResharHandler};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::signing::DataToSign;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
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

// ── cggmp24 sim infra ──
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
        _: &mut std::task::Context<'_>,
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
            let mut p = self.as_mut().project();
            let mut inner = p.inner;
            std::task::ready!(inner.as_mut().poll_ready(cx))?;
            if let Some(item) = p.messages.pop_front() {
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
    party.map_delivery(|d| {
        let (i, o) = d.split();
        (
            i,
            BufferedSink {
                messages: VecDeque::new(),
                inner: o,
            },
        )
    })
}
fn blum(rng: &mut impl rand::RngCore, bits: u32) -> cggmp24::backend::Integer {
    use cggmp24::backend::Integer;
    loop {
        let n = Integer::generate_prime(rng, bits);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}
fn primes(rng: &mut impl rand::RngCore) -> cggmp24::PregeneratedPrimes<SecurityLevel128> {
    use cggmp24::security_level::SecurityLevel;
    let b = SecurityLevel128::RSA_PRIME_BITLEN;
    cggmp24::PregeneratedPrimes::try_from([blum(rng, b), blum(rng, b), blum(rng, b), blum(rng, b)])
        .expect("primes")
}
async fn keygen(n: u16, t: u16) -> Vec<cggmp24::key_share::IncompleteKeyShare<Secp256k1>> {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
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
async fn aux_gen(n: u16) -> Vec<cggmp24::key_share::AuxInfo<SecurityLevel128>> {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);
    let pr: Vec<_> = (0..n).map(|_| primes(&mut rng)).collect();
    round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut r = rand::rngs::OsRng;
        let pre = pr[usize::from(i)].clone();
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
async fn sign_verify(
    shares: &[cggmp24::KeyShare<Secp256k1, SecurityLevel128>],
    parts: &[u16],
    joint: &Point<Secp256k1>,
    msg: &[u8],
) {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);
    let pv = parts.to_vec();
    let data = DataToSign::<Secp256k1>::digest::<Sha256>(msg);
    let sig = round_based::sim::run_with_setup(
        parts.iter().map(|i| &shares[usize::from(*i)]),
        |i, party, share| {
            let party = buffer_outgoing(party);
            let mut r = rand::rngs::OsRng;
            let p = pv.clone();
            async move {
                cggmp24::signing(eid, i, &p, share)
                    .sign(&mut r, party, &data)
                    .await
            }
        },
    )
    .unwrap()
    .expect_ok()
    .expect_eq();
    sig.verify(joint, &data)
        .expect("post-reshare sig MUST verify vs ORIGINAL joint key");
}

#[tokio::test]
async fn reshar_3of4_to_4of6_over_messagebox() {
    let Some(relay_url) = relay_url() else {
        eprintln!("MESSAGEBOX_RELAY_URL not set — skipping cross-(t,n) relay e2e.");
        return;
    };
    let _ = tracing_subscriber::fmt::try_init();
    let t0 = std::time::Instant::now();

    // ── OLD 3-of-4 keygen → eval points + secrets ──
    eprintln!("(local 3-of-4 keygen ~seconds)");
    let old = keygen(4, 3).await;
    let original_joint = *old[0].shared_public_key;
    let jpk_bytes = original_joint.to_bytes(true).to_vec();
    let old_dirty0 = old[0].clone().into_inner();
    let old_eval: Vec<NonZero<Scalar<Secp256k1>>> =
        old_dirty0.key_info.vss_setup.as_ref().unwrap().I.clone();
    let old_secrets: Vec<Scalar<Secp256k1>> = old
        .iter()
        .map(|s| {
            let d = s.clone().into_inner();
            *<SecretScalar<Secp256k1> as AsRef<Scalar<Secp256k1>>>::as_ref(&d.x)
        })
        .collect();
    eprintln!("✔ original joint_pubkey = {}", hex::encode(&jpk_bytes));

    // ── NEW 4-of-6 params ──
    let new_t: u16 = 4;
    let n_new: u16 = 6;
    let new_eval: Vec<NonZero<Scalar<Secp256k1>>> = (1..=n_new)
        .map(|i| NonZero::from_scalar(Scalar::from(i as u64)).unwrap())
        .collect();
    let contributor_new_indices: Vec<u16> = (0..new_t).collect();
    let subset_old_eval: Vec<NonZero<Scalar<Secp256k1>>> =
        (0..new_t).map(|k| old_eval[k as usize]).collect();

    // ── 6 party-agents on the live relay ──
    let session_id = SessionId::from_str_hash(&format!("reshar-e2e-{}", {
        let mut b = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut b);
        hex::encode(b)
    }));
    let mut privs = Vec::new();
    let mut clients = Vec::new();
    let mut pubs = Vec::new();
    for _ in 0..n_new {
        let p = fresh_priv();
        let c = MessageBoxClient::new(&relay_url, p.clone()).expect("client");
        let pubhex = c.identity_hex().await.expect("id");
        privs.push(p);
        clients.push(c);
        pubs.push(pubhex);
    }
    eprintln!("✔ {n_new} agents on the relay");

    let handlers: Vec<ResharHandler> = (0..n_new).map(|_| ResharHandler::new()).collect();
    let mut listeners = Vec::new();
    for j in 0..n_new as usize {
        let l =
            MessageBoxListener::start(clients[j].clone(), BOX_REFRESH, handlers[j].handler_fn())
                .await
                .expect("listener");
        listeners.push(l);
    }

    // ── Initiate all agents BEFORE round-1 traffic flows ──
    let mut rxs = Vec::new();
    let mut all_round1 = Vec::new();
    for j in 0..n_new {
        let contributor = if (j as usize) < usize::from(new_t) {
            Some(ContributorInputs {
                my_subset_pos: j as usize,
                subset_eval_points: subset_old_eval.clone(),
                my_old_secret: old_secrets[j as usize],
            })
        } else {
            None
        };
        let config = ResharConfig {
            session_id,
            my_new_index: j,
            new_eval_points: new_eval.clone(),
            new_t,
            contributor_new_indices: contributor_new_indices.clone(),
            original_joint_pubkey: jpk_bytes.clone(),
            contributor,
        };
        let peers: Vec<(u16, String)> = (0..n_new)
            .filter(|&k| k != j)
            .map(|k| (k, pubs[k as usize].clone()))
            .collect();
        let (rx, out) = handlers[j as usize]
            .initiate(config, peers)
            .await
            .expect("initiate");
        rxs.push(rx);
        all_round1.push((j, out));
    }
    for (j, out) in all_round1 {
        for o in out {
            clients[j as usize]
                .send_round_message(&o.recipient_pub_hex, &o.message_box, &o.round_msg, o.params)
                .await
                .expect("ship round-1");
        }
    }
    eprintln!("✔ round-1 shipped — relay drives the PSS");

    // ── Await all 6 commits ──
    let timeout = Duration::from_secs(60);
    let mut commits = Vec::new();
    for (j, rx) in rxs.into_iter().enumerate() {
        let c = tokio::time::timeout(timeout, rx)
            .await
            .unwrap_or_else(|_| panic!("agent {j} MUST finish PSS within timeout"))
            .expect("completion channel");
        assert_eq!(
            c.joint_pubkey_compressed, jpk_bytes,
            "joint pubkey unchanged (agent {j})"
        );
        commits.push(c);
    }
    eprintln!("✔ all {n_new} agents committed the PSS (joint pubkey unchanged)");

    // ── Reassemble → fresh aux(6) → sign every 4-of-6 subset ──
    let incompletes: Vec<cggmp24::key_share::IncompleteKeyShare<Secp256k1>> = commits
        .iter()
        .map(|c| serde_json::from_slice(&c.incomplete_share_json).expect("incomplete share"))
        .collect();
    let aux = aux_gen(n_new).await;
    let key_shares: Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> = incompletes
        .into_iter()
        .zip(aux)
        .map(|(core, a)| cggmp24::KeyShare::from_parts((core, a)).expect("4-of-6 key share"))
        .collect();

    let msg = b"cross-(t,n) reshare over the live relay, spend original address";
    for subset in &[[0u16, 1, 2, 3], [0, 1, 4, 5], [2, 3, 4, 5]] {
        sign_verify(&key_shares, subset, &original_joint, msg).await;
    }
    eprintln!("✔✔ 3-of-4 → 4-of-6 over the relay: address preserved, every 4-of-6 subset SIGNS");

    for h in &handlers {
        assert_eq!(h.live_session_count(), 0, "cleaned up");
    }
    for l in listeners {
        let _ = tokio::time::timeout(Duration::from_secs(10), l.shutdown()).await;
    }
    eprintln!("✔ done — total {:?}", t0.elapsed());
}
