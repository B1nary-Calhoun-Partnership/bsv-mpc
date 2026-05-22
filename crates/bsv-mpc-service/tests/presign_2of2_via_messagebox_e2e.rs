//! **Within-stack 2-of-2 presign e2e via MessageBox** — MPC-Spec #4 item 3
//! (§06.16 + §06.17.2) gate.
//!
//! Boots a coordinator (party 0) and a cosigner (party 1) as in-process
//! bsv-mpc-service participants, each with a live `MessageBoxClient` (own BRC-31
//! identity against the deployed Calhoun relay), a `PresignHandler`, and
//! `MessageBoxListener`s. Real 2-of-2 key shares are generated LOCALLY first
//! (keygen + auxinfo via the `round_based` simulator — same pattern as
//! `bsv-mpc-core`'s `presigning.rs` tests), so no slow DKG-over-relay is needed;
//! the test then drives the **3-round presign over the live relay**.
//!
//! After round 3 (§06.16): the cosigner BRC-2 self-encrypts its presig share and
//! ships the ciphertext to the coordinator on `presig_return_{sid}`; the
//! coordinator collects it positionally and assembles + persists the
//! `PresigBundle` (§06.17.1).
//!
//! **Merge gate (no sats — presign + transport only):**
//!   1. The 3-round presign completes over the relay (both managers reach
//!      `Complete`).
//!   2. The cosigner's return ciphertext arrives on `presig_return_{sid}` and
//!      lands at positional index 1 of `cosigner_encrypted_shares`.
//!   3. The persisted `PresigBundle` carries the right binding triple
//!      (policy_id, joint_pubkey, parties_at_keygen) and the coordinator's own
//!      sealed share in `presig_bytes`.
//!   4. The collected ciphertext DECRYPTS (BRC-2) back to the cosigner's real
//!      serialized presig share — proving the wire carried the genuine share,
//!      not a placeholder.
//!
//! Gated on `MESSAGEBOX_RELAY_URL`. Run with:
//! ```bash
//! MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-service --test presign_2of2_via_messagebox_e2e \
//!     -- --nocapture --test-threads=1
//! ```

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::canonical::{canonical_session_id, payload_digest_presign, CeremonyKind, SessionParams};
use bsv_mpc_core::presig_encryption::{decrypt_presig_share, wallet_from_identity};
use bsv_mpc_core::types::{EncryptedShare, PolicyId, SessionId, ShareIndex, ThresholdConfig};
use bsv_mpc_messagebox::types::{presig_return_box, presign_protocol_box};
use bsv_mpc_messagebox::MessageBoxClient;
use bsv_mpc_service::{
    InMemoryBundleStore, MessageBoxListener, PresignHandler, PresignHandlerConfig, PresignOutcome,
};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use rand::RngCore;

fn relay_url() -> Option<String> {
    std::env::var("MESSAGEBOX_RELAY_URL").ok()
}

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("fresh priv must be valid")
}

// ---------------------------------------------------------------------------
// Local 2-of-2 DKG via the round_based simulator (mirror of
// bsv-mpc-core/src/presigning.rs test helpers). Produces real cggmp24 key
// shares so the presign-over-relay path runs against genuine material.
// ---------------------------------------------------------------------------

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
    let primes = [
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
    ];
    cggmp24::PregeneratedPrimes::try_from(primes).expect("primes have wrong bit size")
}

async fn run_dkg_2of2() -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
    use rand::Rng;

    let mut rng = rand::rngs::OsRng;
    let n: u16 = 2;
    let t: u16 = 2;

    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);

    let incomplete_shares = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut party_rng = rand::rngs::OsRng;
        async move {
            cggmp24::keygen::<Secp256k1>(eid, i, n)
                .set_threshold(t)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let eid_bytes_aux: [u8; 32] = rng.gen();
    let eid_aux = ExecutionId::new(&eid_bytes_aux);
    let primes: Vec<_> = (0..n)
        .map(|_| generate_pregenerated_primes(&mut rng))
        .collect();

    let aux_infos = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut party_rng = rand::rngs::OsRng;
        let pregenerated = primes[usize::from(i)].clone();
        async move {
            cggmp24::aux_info_gen(eid_aux, i, n, pregenerated)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    incomplete_shares
        .into_iter()
        .zip(aux_infos)
        .map(|(share, aux)| {
            cggmp24::KeyShare::from_parts((share, aux)).expect("key share validation passes")
        })
        .collect()
}

/// Wrap a cggmp24 KeyShare into our `EncryptedShare` (placeholder at-rest
/// encryption — `ciphertext` holds the plaintext JSON, the format
/// `PresigningManager` deserializes). `joint_pubkey_compressed` is filled (the
/// presign handler requires it).
fn wrap_key_share(
    key_share: &cggmp24::KeyShare<Secp256k1, SecurityLevel128>,
    index: u16,
    config: ThresholdConfig,
    session_id: SessionId,
) -> EncryptedShare {
    EncryptedShare {
        nonce: vec![0u8; 12],
        ciphertext: serde_json::to_vec(key_share).expect("key share serialize"),
        session_id,
        share_index: ShareIndex(index),
        config,
        joint_pubkey_compressed: key_share.core.shared_public_key.to_bytes(true).to_vec(),
    }
}

#[tokio::test]
async fn within_stack_2of2_presign_assembles_bundle_via_messagebox() {
    let Some(relay_url) = relay_url() else {
        eprintln!(
            "MESSAGEBOX_RELAY_URL not set — skipping 2-of-2 presign e2e. \
             To run: MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
             cargo test -p bsv-mpc-service --test presign_2of2_via_messagebox_e2e \
             -- --nocapture --test-threads=1"
        );
        return;
    };
    let _ = tracing_subscriber::fmt::try_init();
    let t0 = std::time::Instant::now();

    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let parties_at_keygen = vec![0u16, 1u16];
    let policy_id = PolicyId([0x09; 32]);

    // ----- Local real 2-of-2 DKG (keygen + auxinfo) -----
    eprintln!("(generating real 2-of-2 key shares locally — Paillier primes, ~30-60s)");
    let dkg_t0 = std::time::Instant::now();
    let key_shares = run_dkg_2of2().await;
    eprintln!("✔ key shares ready in {:?}", dkg_t0.elapsed());
    let joint_pubkey = key_shares[0].core.shared_public_key.to_bytes(true).to_vec();
    eprintln!("✔ joint_pubkey = {}", hex::encode(&joint_pubkey));

    // ----- Canonical presign SessionId (§04, kind=Presign, pool-bound) -----
    let coord_priv = fresh_priv();
    let cosigner_priv = fresh_priv();
    let coord_id_pub: [u8; 33] = coord_priv
        .public_key()
        .to_compressed()
        .as_slice()
        .try_into()
        .unwrap();
    let cosigner_id_pub: [u8; 33] = cosigner_priv
        .public_key()
        .to_compressed()
        .as_slice()
        .try_into()
        .unwrap();
    let pool_id = {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b
    };
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce[0] |= 0x01; // §04.9 non-zero
    let session_id = canonical_session_id(&SessionParams {
        initiator_identity: coord_id_pub,
        participants: vec![coord_id_pub, cosigner_id_pub],
        threshold: 2,
        kind: CeremonyKind::Presign,
        nonce,
        payload_digest: payload_digest_presign(&pool_id),
    })
    .expect("presign SessionId");
    let sid_hex = session_id.hex();
    eprintln!("✔ presign session_id = {sid_hex}");

    let protocol_box = presign_protocol_box(&sid_hex);
    let return_box = presig_return_box(&sid_hex);
    eprintln!("✔ mailboxes: protocol={protocol_box} return={return_box}");

    // ----- Live MessageBox clients (own identity each) -----
    let coord_client = MessageBoxClient::new(&relay_url, coord_priv.clone()).expect("coord client");
    let cosigner_client =
        MessageBoxClient::new(&relay_url, cosigner_priv.clone()).expect("cosigner client");
    let coord_pub_hex = coord_client.identity_hex().await.expect("coord id");
    let cosigner_pub_hex = cosigner_client.identity_hex().await.expect("cosigner id");
    eprintln!("✔ coordinator = {coord_pub_hex}");
    eprintln!("✔ cosigner    = {cosigner_pub_hex}");

    // ----- Handlers -----
    let bundle_store = Arc::new(InMemoryBundleStore::new());
    let coord_at_rest = [0x42u8; 32];
    let coord_handler = PresignHandler::new(PresignHandlerConfig {
        my_party_index: 0,
        coordinator_party: 0,
        parties_at_keygen: parties_at_keygen.clone(),
        policy_id,
        identity_priv: coord_priv.clone(),
        at_rest_root: coord_at_rest,
        bundle_store: bundle_store.clone(),
    });
    let cosigner_handler = PresignHandler::new(PresignHandlerConfig {
        my_party_index: 1,
        coordinator_party: 0,
        parties_at_keygen: parties_at_keygen.clone(),
        policy_id,
        identity_priv: cosigner_priv.clone(),
        at_rest_root: [0x99u8; 32], // cosigner doesn't seal anything; value irrelevant
        bundle_store: Arc::new(InMemoryBundleStore::new()),
    });

    // ----- Listeners -----
    // Coordinator listens on BOTH boxes via a SINGLE connection (start_many):
    // two competing subscriptions would split the identity's relay queue
    // non-deterministically (return ct → protocol path, protocol msgs → return
    // path). One connection + sentinel-round routing is race-free.
    let coord_listener = MessageBoxListener::start_many(
        coord_client.clone(),
        vec![protocol_box.clone(), return_box.clone()],
        coord_handler.handler_fn(),
    )
    .await
    .expect("coord listener (protocol + return)");
    // Cosigner listens on the protocol box only.
    let cosigner_proto_listener = MessageBoxListener::start(
        cosigner_client.clone(),
        &protocol_box,
        cosigner_handler.handler_fn(),
    )
    .await
    .expect("cosigner protocol listener");
    eprintln!("✔ listeners live");

    // ----- Initiate BOTH before any round-1 traffic flows -----
    let coord_share = wrap_key_share(&key_shares[0], 0, config, session_id);
    let cosigner_share = wrap_key_share(&key_shares[1], 1, config, session_id);

    let (coord_rx, coord_out) = coord_handler
        .initiate(
            session_id,
            coord_share,
            vec![(1u16, cosigner_pub_hex.clone())],
        )
        .await
        .expect("coord initiate");
    let (cosigner_rx, cosigner_out) = cosigner_handler
        .initiate(
            session_id,
            cosigner_share,
            vec![(0u16, coord_pub_hex.clone())],
        )
        .await
        .expect("cosigner initiate");
    assert!(!coord_out.is_empty(), "coord round-1 outbound");
    assert!(!cosigner_out.is_empty(), "cosigner round-1 outbound");

    // Ship round-1 from both.
    for out in coord_out {
        coord_client
            .send_round_message(&out.recipient_pub_hex, &out.message_box, &out.round_msg, out.params)
            .await
            .expect("coord round-1 send");
    }
    for out in cosigner_out {
        cosigner_client
            .send_round_message(&out.recipient_pub_hex, &out.message_box, &out.round_msg, out.params)
            .await
            .expect("cosigner round-1 send");
    }
    eprintln!("✔ round-1 shipped — listeners drive the 3-round presign");

    // ----- Await both completions -----
    let timeout = Duration::from_secs(120);
    let cosigner_outcome = tokio::time::timeout(timeout, cosigner_rx)
        .await
        .expect("cosigner MUST finish presign within timeout")
        .expect("cosigner completion channel");
    assert!(
        matches!(cosigner_outcome, PresignOutcome::ReturnShipped),
        "cosigner outcome MUST be ReturnShipped"
    );
    eprintln!("✔ cosigner completed 3 rounds + shipped return ciphertext");

    let coord_outcome = tokio::time::timeout(timeout, coord_rx)
        .await
        .expect("coordinator MUST assemble bundle within timeout")
        .expect("coordinator completion channel");
    let bundle = match coord_outcome {
        PresignOutcome::BundlePersisted(b) => *b,
        other => panic!("coordinator outcome MUST be BundlePersisted, got {other:?}"),
    };
    eprintln!("✔ coordinator assembled + persisted the PresigBundle");

    // ----- THE GATE -----
    // 1) Bundle persisted under the canonical presig_id (= session_id hex).
    assert_eq!(bundle.presig_id, sid_hex, "presig_id = presign session_id");
    let stored = bundle_store.get(&sid_hex).expect("bundle MUST be in the store");
    assert_eq!(stored, bundle, "store holds the same bundle the coordinator fired");

    // 2) Binding triple.
    assert_eq!(bundle.policy_id, policy_id, "binding: policy_id");
    assert_eq!(bundle.joint_pubkey, joint_pubkey, "binding: joint_pubkey");
    assert_eq!(
        bundle.parties_at_keygen, parties_at_keygen,
        "binding: parties_at_keygen (ascending)"
    );

    // 3) Positional cosigner_encrypted_shares: index 0 = coordinator (empty,
    //    its plaintext lives sealed in presig_bytes); index 1 = cosigner ct.
    assert_eq!(bundle.cosigner_encrypted_shares.len(), 2);
    assert!(
        bundle.cosigner_encrypted_shares[0].is_empty(),
        "coordinator's positional slot is empty"
    );
    let cosigner_ct = bundle.cosigner_encrypted_shares[1].clone().into_vec();
    assert!(
        !cosigner_ct.is_empty(),
        "cosigner ciphertext MUST land at positional index 1"
    );
    assert!(
        !bundle.presig_bytes.is_empty(),
        "coordinator's own sealed presig share present"
    );

    // 3b) Durable public data (#25a): the bundle carries CBOR commitments +
    //     gamma_hex that reconstruct into a usable PresignaturePublicData — so a
    //     coordinator can combine from the persisted bundle after a restart, not
    //     just from an in-memory pool.
    assert!(!bundle.gamma_hex.is_empty(), "bundle MUST carry gamma_hex");
    assert!(!bundle.commitments.is_empty(), "bundle MUST carry public-data commitments");
    let reconstructed =
        bsv_mpc_core::signing::deserialize_presig_public_data(&bundle.commitments)
            .expect("bundle commitments MUST reconstruct into PresignaturePublicData");
    assert_eq!(
        reconstructed.commitments.len(),
        parties_at_keygen.len(),
        "reconstructed public data has one commitment per party"
    );

    // 4) The collected ciphertext DECRYPTS back to the cosigner's real
    //    serialized presig share — proving the relay carried the genuine
    //    BRC-2 ciphertext (not a placeholder). decrypt under the cosigner's
    //    wallet + the canonical presig_id (§06.16 / §06.20 round-trip).
    let cosigner_wallet = wallet_from_identity(&cosigner_priv);
    let recovered = decrypt_presig_share(&cosigner_wallet, &sid_hex, &cosigner_ct)
        .expect("cosigner ciphertext MUST decrypt under (cosigner wallet, presig_id)");
    assert!(
        !recovered.is_empty(),
        "decrypted cosigner presig share MUST be non-empty"
    );
    // It is a serialized cggmp24 presignature — must deserialize.
    let _presig: cggmp24::Presignature<Secp256k1> = serde_json::from_slice(&recovered)
        .expect("decrypted bytes MUST be a serialized cggmp24 Presignature");
    eprintln!(
        "✔✔ PresigBundle assembled over MessageBox — presig_id={sid_hex} \
         joint_pubkey={} cosigner_ct={} bytes (decrypts to a valid cggmp24 Presignature)",
        hex::encode(&joint_pubkey),
        cosigner_ct.len()
    );

    // A wrong-wallet decrypt MUST fail (the §06.16 self-encryption guarantee).
    assert!(
        decrypt_presig_share(&wallet_from_identity(&coord_priv), &sid_hex, &cosigner_ct).is_err(),
        "coordinator MUST NOT be able to decrypt the cosigner's share (opaque at rest, §06.17.1)"
    );

    assert_eq!(coord_handler.live_session_count(), 0, "coordinator cleaned up");
    assert_eq!(cosigner_handler.live_session_count(), 0, "cosigner cleaned up");

    // ----- Cleanup -----
    for l in [coord_listener, cosigner_proto_listener] {
        let _ = tokio::time::timeout(Duration::from_secs(10), l.shutdown()).await;
    }
    eprintln!("✔ done — total wall-clock {:?}", t0.elapsed());
}
