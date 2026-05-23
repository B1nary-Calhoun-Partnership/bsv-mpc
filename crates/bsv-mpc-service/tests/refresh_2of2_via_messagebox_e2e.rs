//! **Within-stack 2-of-2 key-refresh e2e via MessageBox** — MPC-Spec §18.2 gate
//! (issue #10c).
//!
//! Boots two in-process `bsv-mpc-service` refresh peers (party 0 + party 1),
//! each with a live `MessageBoxClient` (own BRC-31 identity vs the deployed
//! Calhoun relay), a `RefreshHandler`, and a `MessageBoxListener` on
//! `mpc-refresh`. Real 2-of-2 key shares are generated LOCALLY first (keygen +
//! auxinfo via the `round_based` simulator), then the test drives the 2-round
//! **distributed PSS refresh over the live relay**.
//!
//! **Merge gate (no sats — refresh + transport only):**
//!   1. Both peers complete with a `RefreshCommit`.
//!   2. Both report the SAME, UNCHANGED joint pubkey (the §18 invariant).
//!   3. Each peer's rotated secret share DIFFERS from its pre-refresh share
//!      (proactive re-randomization actually happened).
//!   4. The two rotated shares SIGN together and the signature verifies against
//!      the ORIGINAL joint key — proving the relay-driven refresh produced a
//!      working, consistent new sharing of the same key.
//!
//! Gated on `MESSAGEBOX_RELAY_URL`. Run with:
//! ```bash
//! MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-service --test refresh_2of2_via_messagebox_e2e \
//!     -- --nocapture --test-threads=1
//! ```

use std::collections::VecDeque;
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::types::{EncryptedShare, SessionId, ShareIndex, ThresholdConfig};
use bsv_mpc_messagebox::types::BOX_REFRESH;
use bsv_mpc_messagebox::MessageBoxClient;
use bsv_mpc_service::{MessageBoxListener, RefreshHandler};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::signing::DataToSign;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use generic_ec::{Point, Scalar, SecretScalar};
use rand::RngCore;
use sha2::Sha256;

fn relay_url() -> Option<String> {
    std::env::var("MESSAGEBOX_RELAY_URL").ok()
}

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("fresh priv must be valid")
}

// ── Local 2-of-2 DKG via the round_based simulator (mirror of the presign e2e) ──

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
        (
            incoming,
            BufferedSink {
                messages: VecDeque::new(),
                inner: outgoing,
            },
        )
    })
}

fn generate_blum_prime(rng: &mut impl rand::RngCore, bits_size: u32) -> cggmp24::backend::Integer {
    use cggmp24::backend::Integer;
    loop {
        let n = Integer::generate_prime(rng, bits_size);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}

fn generate_pregenerated_primes(
    rng: &mut impl rand::RngCore,
) -> cggmp24::PregeneratedPrimes<SecurityLevel128> {
    use cggmp24::security_level::SecurityLevel;
    let bitsize = SecurityLevel128::RSA_PRIME_BITLEN;
    cggmp24::PregeneratedPrimes::try_from([
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
    ])
    .expect("primes have wrong bit size")
}

async fn run_dkg_2of2() -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    let (n, t) = (2u16, 2u16);

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
    let primes: Vec<_> = (0..n).map(|_| generate_pregenerated_primes(&mut rng)).collect();
    let aux = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut prng = rand::rngs::OsRng;
        let pre = primes[usize::from(i)].clone();
        async move { cggmp24::aux_info_gen(eid_aux, i, n, pre).start(&mut prng, party).await }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    incomplete
        .into_iter()
        .zip(aux)
        .map(|(s, a)| cggmp24::KeyShare::from_parts((s, a)).expect("valid key share"))
        .collect()
}

fn wrap_key_share(
    ks: &cggmp24::KeyShare<Secp256k1, SecurityLevel128>,
    index: u16,
    config: ThresholdConfig,
    session_id: SessionId,
) -> EncryptedShare {
    EncryptedShare {
        nonce: vec![0u8; 12],
        ciphertext: serde_json::to_vec(ks).expect("key share serialize"),
        session_id,
        share_index: ShareIndex(index),
        config,
        joint_pubkey_compressed: ks.core.shared_public_key.to_bytes(true).to_vec(),
    }
}

fn secret_of(ks: &cggmp24::KeyShare<Secp256k1, SecurityLevel128>) -> Scalar<Secp256k1> {
    *<SecretScalar<Secp256k1> as AsRef<Scalar<Secp256k1>>>::as_ref(&ks.core.x)
}

/// Sign 2-of-2 with the given shares and verify against `joint`.
async fn sign_2of2_and_verify(
    shares: &[cggmp24::KeyShare<Secp256k1, SecurityLevel128>],
    joint: &Point<Secp256k1>,
    msg: &[u8],
) {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);
    let participants = vec![0u16, 1u16];
    let data = DataToSign::<Secp256k1>::digest::<Sha256>(msg);
    let sig = round_based::sim::run_with_setup(
        participants.iter().map(|i| &shares[usize::from(*i)]),
        |i, party, share| {
            let party = buffer_outgoing(party);
            let mut prng = rand::rngs::OsRng;
            let p = participants.clone();
            async move {
                cggmp24::signing(eid, i, &p, share)
                    .sign(&mut prng, party, &data)
                    .await
            }
        },
    )
    .unwrap()
    .expect_ok()
    .expect_eq();
    sig.verify(joint, &data)
        .expect("post-refresh signature MUST verify against the ORIGINAL joint key");
}

#[tokio::test]
async fn within_stack_2of2_refresh_rotates_and_signs_via_messagebox() {
    let Some(relay_url) = relay_url() else {
        eprintln!(
            "MESSAGEBOX_RELAY_URL not set — skipping 2-of-2 refresh e2e. To run: \
             MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
             cargo test -p bsv-mpc-service --test refresh_2of2_via_messagebox_e2e \
             -- --nocapture --test-threads=1"
        );
        return;
    };
    let _ = tracing_subscriber::fmt::try_init();
    let t0 = std::time::Instant::now();

    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let parties = vec![0u16, 1u16];

    // ----- Local real 2-of-2 DKG -----
    eprintln!("(generating real 2-of-2 key shares locally — Paillier primes, ~30-60s)");
    let key_shares = run_dkg_2of2().await;
    let joint_point = *key_shares[0].core.shared_public_key;
    let joint_pubkey = joint_point.to_bytes(true).to_vec();
    let old_secrets = [secret_of(&key_shares[0]), secret_of(&key_shares[1])];
    eprintln!("✔ joint_pubkey = {}", hex::encode(&joint_pubkey));

    // ----- Identities + session -----
    let p0_priv = fresh_priv();
    let p1_priv = fresh_priv();
    let session_id = SessionId::from_str_hash(&format!(
        "refresh-e2e-{}",
        hex::encode({
            let mut b = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut b);
            b
        })
    ));

    let p0_client = MessageBoxClient::new(&relay_url, p0_priv.clone()).expect("p0 client");
    let p1_client = MessageBoxClient::new(&relay_url, p1_priv.clone()).expect("p1 client");
    let p0_pub = p0_client.identity_hex().await.expect("p0 id");
    let p1_pub = p1_client.identity_hex().await.expect("p1 id");
    eprintln!("✔ party0 = {p0_pub}\n✔ party1 = {p1_pub}");

    // ----- Handlers + listeners on mpc-refresh -----
    let h0 = RefreshHandler::new(0, parties.clone());
    let h1 = RefreshHandler::new(1, parties.clone());
    let l0 = MessageBoxListener::start(p0_client.clone(), BOX_REFRESH, h0.handler_fn())
        .await
        .expect("p0 listener");
    let l1 = MessageBoxListener::start(p1_client.clone(), BOX_REFRESH, h1.handler_fn())
        .await
        .expect("p1 listener");

    // ----- Initiate BOTH before round-1 traffic flows -----
    let share0 = wrap_key_share(&key_shares[0], 0, config, session_id);
    let share1 = wrap_key_share(&key_shares[1], 1, config, session_id);
    let (rx0, out0) = h0
        .initiate(session_id, share0, vec![(1u16, p1_pub.clone())])
        .await
        .expect("p0 initiate");
    let (rx1, out1) = h1
        .initiate(session_id, share1, vec![(0u16, p0_pub.clone())])
        .await
        .expect("p1 initiate");
    assert!(!out0.is_empty() && !out1.is_empty(), "both round-1 outbound");

    for out in out0 {
        p0_client
            .send_round_message(&out.recipient_pub_hex, &out.message_box, &out.round_msg, out.params)
            .await
            .expect("p0 round-1 send");
    }
    for out in out1 {
        p1_client
            .send_round_message(&out.recipient_pub_hex, &out.message_box, &out.round_msg, out.params)
            .await
            .expect("p1 round-1 send");
    }
    eprintln!("✔ round-1 shipped — listeners drive the 2-round PSS refresh");

    // ----- Await both commits -----
    let timeout = Duration::from_secs(60);
    let commit0 = tokio::time::timeout(timeout, rx0)
        .await
        .expect("p0 MUST finish refresh within timeout")
        .expect("p0 completion channel");
    let commit1 = tokio::time::timeout(timeout, rx1)
        .await
        .expect("p1 MUST finish refresh within timeout")
        .expect("p1 completion channel");
    eprintln!("✔ both peers committed the refresh");

    // ----- THE GATE -----
    // (2) Joint pubkey unchanged on BOTH sides.
    assert_eq!(commit0.joint_pubkey_compressed, joint_pubkey, "p0 joint pubkey unchanged");
    assert_eq!(commit1.joint_pubkey_compressed, joint_pubkey, "p1 joint pubkey unchanged");

    // Rebuild rotated cggmp24 KeyShares from the committed rotated shares.
    let rotated: Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> = [&commit0, &commit1]
        .iter()
        .map(|c| serde_json::from_slice(&c.rotated_share.ciphertext).expect("rotated key share"))
        .collect();

    // (3) Every secret share rotated; shared pubkey unchanged on each.
    for (i, ks) in rotated.iter().enumerate() {
        assert_eq!(*ks.core.shared_public_key, joint_point, "shared pubkey unchanged");
        assert_ne!(secret_of(ks), old_secrets[i], "secret share[{i}] MUST rotate");
    }

    // (4) The rotated shares sign together → verify against the ORIGINAL joint key.
    sign_2of2_and_verify(&rotated, &joint_point, b"sign after relay refresh").await;
    eprintln!("✔✔ refresh over MessageBox: shares rotated, joint key preserved, rotated shares SIGN");

    assert_eq!(h0.live_session_count(), 0, "p0 cleaned up");
    assert_eq!(h1.live_session_count(), 0, "p1 cleaned up");

    for l in [l0, l1] {
        let _ = tokio::time::timeout(Duration::from_secs(10), l.shutdown()).await;
    }
    eprintln!("✔ done — total wall-clock {:?}", t0.elapsed());
}
