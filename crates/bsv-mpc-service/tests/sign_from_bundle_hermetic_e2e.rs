//! **§06.17.1 Stage-1 hermetic capstone (issue #30 / #25c)** — the full
//! coordinator-holds-ciphertext SIGN path, minus the live deploy + mainnet TX.
//!
//! This is the §06.17.1 end-to-end MINUS the live deploy (that is Stage 2, the
//! deployed mainnet TXID, run by the orchestrator after review). It is FULLY
//! HERMETIC: no relay, no sats, no network — so it runs unconditionally in CI
//! and gates the FUNDS-path durable-bundle logic on every commit.
//!
//! ## What it proves (the §06.17.1 sign-from-bundle invariant)
//!
//! 1. **Per-party presig**: a real 2-of-2 CGGMP'24 DKG + presign via the
//!    `round_based` simulator. Each party gets its OWN presig share — the
//!    coordinator never generates the cosigner's share.
//! 2. **Cosigner self-encrypts its OWN share** (§06.16): the cosigner BRC-2
//!    self-encrypts `serde_json(presig1.0)` under (its wallet, presig_id). This
//!    `ct` is EXACTLY what the deployed worker would generate + ship to the
//!    coordinator over MessageBox at presign-time (the relay carries this
//!    opaque blob; cf. `presign_2of2_via_messagebox_e2e`).
//! 3. **Coordinator assembles a durable `PresigBundle`** the same way
//!    `PresignHandler::try_finalize_bundle` does: own share SEALED at-rest
//!    (`seal_presig_bytes`), shared public data as CBOR commitments + gamma_hex
//!    (`serialize_party_presig_with_public_data`, #25a), cosigner ciphertext at
//!    positional index 1.
//! 4. **Durability**: persist the bundle to a `FileBundleStore` and RELOAD it
//!    FROM DISK before signing — proving a coordinator that restarted (holding
//!    only the persisted bytes, never the live `(Presignature,
//!    PresignaturePublicData)` tuple, which is not `Serialize`) can still sign.
//! 5. **Sign FROM the reloaded bundle** (the new `SigningCoordinator::sign_from_bundle`):
//!      - unseal the coordinator's own presig share,
//!      - reconstruct `PresignaturePublicData` via `deserialize_presig_public_data`,
//!      - `sign_from_bundle` → coordinator's own partial,
//!      - SHIP the cosigner ciphertext; the cosigner (worker, on the deployed
//!        topology) decrypts via `decrypt_and_issue_partial` (#25b) → its partial,
//!      - `process_round` combines → final ECDSA signature,
//!      - the signature **VERIFIES under the joint pubkey**.
//! 6. **Threshold guarantee (§06.17.1)**: the coordinator MUST NOT be able to
//!    decrypt the cosigner's ciphertext (opaque at rest) — proven by a
//!    wrong-wallet decrypt that MUST fail.
//!
//! What is NOT covered here (Stage 2, separate): the deployed CF Worker running
//! the presign SM over MessageBox as a cosigner (it currently presigns over
//! direct HTTP via `/presign/init`+`/presign/round`), the proxy wiring the
//! bundle's ciphertext into the live `/sign-relay` trigger (the relay_sign
//! `cosigner_encrypted_share` field + the worker decrypt branch ARE added, but
//! their on-the-wire exercise is the deployed TXID gate), and the real mainnet
//! broadcast. See the report / issue #30.
//!
//! Run: `cargo test -p bsv-mpc-service --test sign_from_bundle_hermetic_e2e -- --nocapture`

use std::collections::VecDeque;

use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv_mpc_core::presig_at_rest::{derive_presig_at_rest_key, seal_presig_bytes, unseal_presig_bytes};
use bsv_mpc_core::presig_encryption::{
    decrypt_and_issue_partial, encrypt_presig_share, wallet_from_identity,
};
use bsv_mpc_core::presigning::serialize_party_presig_with_public_data;
use bsv_mpc_core::signing::{deserialize_presig_public_data, SigningCoordinator, SigningRoundResult};
use bsv_mpc_core::types::{
    EncryptedShare, PolicyId, PresigBundle, RoundMessage, SessionId, ShareIndex, ThresholdConfig,
};
use bsv_mpc_service::FileBundleStore;
use bsv_mpc_service::presign_handler::BundleStore;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::{ExecutionId, Presignature};
use rand::RngCore;

// ---------------------------------------------------------------------------
// Identity helpers
// ---------------------------------------------------------------------------

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("fresh priv must be valid")
}

// ---------------------------------------------------------------------------
// Local 2-of-2 DKG + presign via the round_based simulator — verbatim mirror of
// sign_mainnet_presig_consume_e2e's helpers (no relay, no network).
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

/// Generate the 2-of-2 presignatures in-process via the simulator. Each party
/// gets its OWN `(Presignature, PresignaturePublicData)` — the coordinator
/// never holds the cosigner's share. Mirror of
/// `sign_mainnet_presig_consume_e2e::generate_presignatures_2of2`.
async fn generate_presignatures_2of2(
    key_shares: &[cggmp24::KeyShare<Secp256k1, SecurityLevel128>],
) -> Vec<(
    Presignature<Secp256k1>,
    cggmp24::signing::PresignaturePublicData<Secp256k1>,
)> {
    use rand::Rng;
    let participants: Vec<u16> = vec![0, 1];
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let eid_presign = ExecutionId::new(&eid_bytes);
    round_based::sim::run_with_setup(
        participants.iter().map(|i| &key_shares[usize::from(*i)]),
        |i, party, share| {
            let party = buffer_outgoing(party);
            let mut party_rng = rand::rngs::OsRng;
            let participants = participants.clone();
            async move {
                cggmp24::signing(eid_presign, i, &participants, share)
                    .generate_presignature(&mut party_rng, party)
                    .await
            }
        },
    )
    .unwrap()
    .expect_ok()
    .into_vec()
}

/// Wrap a cggmp24 KeyShare into our `EncryptedShare` (placeholder at-rest
/// encryption — `ciphertext` holds the plaintext JSON, the format
/// `SigningCoordinator` deserializes). Mirror of
/// `sign_mainnet_presig_consume_e2e::key_share_to_encrypted`.
fn key_share_to_encrypted(
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

/// A deterministic 32-byte sighash for the hermetic combine (no real tx — we
/// only need a valid scalar to sign + verify against the joint key).
fn deterministic_sighash(tag: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"sign-from-bundle-hermetic-");
    h.update(tag);
    let out = h.finalize();
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(&out);
    sighash
}

// ---------------------------------------------------------------------------
// THE CAPSTONE
// ---------------------------------------------------------------------------

#[tokio::test]
async fn coordinator_signs_from_durable_bundle_with_cosigner_encrypted_own_share() {
    let t0 = std::time::Instant::now();
    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let participants: Vec<u16> = vec![0, 1];
    let parties_at_keygen: Vec<u16> = vec![0, 1];
    // Party 0 = coordinator, party 1 = cosigner (positional bundle convention).

    // ===== 1) Real 2-of-2 DKG (local, no relay) =====
    eprintln!("(generating real 2-of-2 key shares locally — Paillier primes, ~30-60s)");
    let dkg_t0 = std::time::Instant::now();
    let key_shares = run_dkg_2of2().await;
    eprintln!("✔ key shares ready in {:?}", dkg_t0.elapsed());

    let joint_compressed = key_shares[0].core.shared_public_key.to_bytes(true);
    let mut joint_pubkey_arr = [0u8; 33];
    joint_pubkey_arr.copy_from_slice(joint_compressed.as_ref());
    let joint_pubkey =
        PublicKey::from_bytes(&joint_pubkey_arr).expect("joint pubkey from compressed bytes");
    eprintln!("✔ DKG complete — joint_pubkey={}", hex::encode(joint_pubkey_arr));

    // ===== 2) Per-party presig (each party gets its OWN share) =====
    let presigs = generate_presignatures_2of2(&key_shares).await;
    assert_eq!(presigs.len(), 2, "one presig tuple per party");
    let mut it = presigs.into_iter();
    let presig0 = it.next().unwrap(); // coordinator (party 0)
    let presig1 = it.next().unwrap(); // cosigner (party 1)

    // The canonical presig_id binds the BRC-2 key + the at-rest key. On the
    // deployed topology this is the presign session_id hex; here a fresh random
    // hex stands in (any stable id works for the round-trip).
    let session = SessionId::from_str_hash("sign-from-bundle-hermetic");
    let presig_id = session.hex();

    // ===== 3) COSIGNER self-encrypts its OWN share (§06.16) =====
    // This is exactly what the deployed worker does at presign-time and ships to
    // the coordinator over MessageBox (cf. presign_2of2_via_messagebox_e2e). The
    // coordinator only ever receives this opaque ciphertext.
    let cosigner_priv = fresh_priv();
    let cosigner_wallet = wallet_from_identity(&cosigner_priv);
    let cosigner_share_bytes =
        serde_json::to_vec(&presig1.0).expect("serialize cosigner presig share");
    let cosigner_ct = encrypt_presig_share(&cosigner_wallet, &presig_id, &cosigner_share_bytes)
        .expect("§06.16 BRC-2 encrypt cosigner OWN presig share");
    assert!(!cosigner_ct.is_empty(), "cosigner ciphertext must be non-empty");
    eprintln!(
        "✔ cosigner generated + BRC-2-encrypted its OWN share — presig_id={presig_id} ct={} bytes",
        cosigner_ct.len()
    );

    // ===== 4) COORDINATOR assembles a durable PresigBundle =====
    // Mirror PresignHandler::{on_presign_complete, try_finalize_bundle}: the
    // coordinator seals its OWN share at-rest, serializes the shared public data
    // to CBOR (#25a), and lands the cosigner ct at positional index 1.
    let coord_priv = fresh_priv();
    let at_rest_root = {
        let mut r = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut r);
        r
    };
    let raw0: Box<dyn std::any::Any + Send> = Box::new(presig0);
    let (coord_serialized, public_data_cbor, gamma_hex) =
        serialize_party_presig_with_public_data(raw0)
            .expect("serialize coordinator presig + public data");
    let at_rest_key = derive_presig_at_rest_key(&at_rest_root, &presig_id);
    let own_presig_sealed =
        seal_presig_bytes(&coord_serialized, &at_rest_key).expect("seal coordinator presig");

    let policy_id = PolicyId([0x7au8; 32]);
    let bundle = PresigBundle {
        presig_id: presig_id.clone(),
        presig_bytes: own_presig_sealed,
        // Positional: index 0 = coordinator (empty — plaintext lives sealed in
        // presig_bytes), index 1 = cosigner ciphertext.
        cosigner_encrypted_shares: vec![
            serde_bytes::ByteBuf::new(),
            serde_bytes::ByteBuf::from(cosigner_ct.clone()),
        ],
        gamma_hex,
        commitments: public_data_cbor,
        policy_id,
        joint_pubkey: joint_pubkey_arr.to_vec(),
        parties_at_keygen: parties_at_keygen.clone(),
        generated_at: 1_700_000_000,
    };
    eprintln!("✔ coordinator assembled PresigBundle");

    // ===== 5) DURABLE: persist to FileBundleStore + RELOAD from disk =====
    let tmp = std::env::temp_dir().join(format!(
        "bsv-mpc-bundle-{}-{}",
        std::process::id(),
        presig_id
    ));
    let store = FileBundleStore::new(&tmp).expect("open file bundle store");
    store.persist(&bundle).expect("persist bundle to disk");
    // Drop the in-memory bundle: the coordinator now holds NOTHING but disk.
    drop(bundle);
    let reloaded = store
        .get(&presig_id)
        .expect("bundle MUST reload from disk (durable across coordinator restart)");
    eprintln!("✔ bundle persisted + reloaded from disk at {}", tmp.display());

    // Binding triple survives the round-trip.
    assert_eq!(reloaded.policy_id, policy_id, "binding: policy_id durable");
    assert_eq!(
        reloaded.joint_pubkey,
        joint_pubkey_arr.to_vec(),
        "binding: joint_pubkey durable"
    );
    assert_eq!(
        reloaded.parties_at_keygen, parties_at_keygen,
        "binding: parties_at_keygen durable"
    );
    assert_eq!(
        reloaded.cosigner_encrypted_shares.len(),
        2,
        "positional cosigner_encrypted_shares durable"
    );
    assert!(
        reloaded.cosigner_encrypted_shares[0].is_empty(),
        "coordinator's positional slot empty"
    );
    assert_eq!(
        reloaded.cosigner_encrypted_shares[1].as_slice(),
        cosigner_ct.as_slice(),
        "cosigner ciphertext durable at positional index 1"
    );
    assert!(!reloaded.gamma_hex.is_empty(), "gamma_hex durable");
    assert!(!reloaded.commitments.is_empty(), "public-data commitments durable");

    // ===== 6) §06.17.1 threshold: coordinator CANNOT read the cosigner share =====
    let coord_wallet = wallet_from_identity(&coord_priv);
    assert!(
        decrypt_and_issue_partial(
            &coord_wallet,
            &reloaded.presig_id,
            reloaded.cosigner_encrypted_shares[1].as_slice(),
            &[0u8; 32],
            None,
        )
        .is_err(),
        "coordinator MUST NOT be able to decrypt the cosigner's share (opaque at rest, §06.17.1)"
    );
    eprintln!("✔ coordinator cannot decrypt the cosigner ciphertext (threshold preserved)");

    // ===== 7) SIGN FROM THE RELOADED BUNDLE =====
    let sighash = deterministic_sighash(presig_id.as_bytes());

    // (a) Coordinator: unseal its OWN share + reconstruct public data, then
    //     issue its partial via the NEW durable entry point sign_from_bundle.
    let coord_at_rest_key = derive_presig_at_rest_key(&at_rest_root, &reloaded.presig_id);
    let coord_presig_json = unseal_presig_bytes(&reloaded.presig_bytes, &coord_at_rest_key)
        .expect("unseal coordinator own presig share from the durable bundle");
    let public_data = deserialize_presig_public_data(&reloaded.commitments)
        .expect("reconstruct PresignaturePublicData from the durable bundle commitments");

    let coord_share = key_share_to_encrypted(&key_shares[0], 0, config, session);
    let mut coord = SigningCoordinator::new(session, coord_share, config, participants.clone());
    let _coord_out = coord
        .sign_from_bundle(&sighash, &coord_presig_json, public_data)
        .expect("coordinator sign_from_bundle (durable §06.17.1 path)");
    eprintln!("✔ coordinator issued its partial via sign_from_bundle (from reloaded bundle)");

    // (b) Cosigner (the deployed worker on the live topology): decrypt the
    //     bundle's ciphertext under ITS OWN identity (#25b decrypt_and_issue_partial)
    //     and issue its partial. None = base key (no BRC-42 offset).
    let cosigner_partial_json = decrypt_and_issue_partial(
        &cosigner_wallet,
        &reloaded.presig_id,
        reloaded.cosigner_encrypted_shares[1].as_slice(),
        &sighash,
        None,
    )
    .expect("cosigner decrypt_and_issue_partial from the bundle ciphertext (§06.20)");
    eprintln!("✔ cosigner decrypted its own ciphertext + issued its partial");

    // (c) Coordinator combines.
    let combine_result = coord
        .process_round(vec![RoundMessage {
            session_id: session,
            round: 1,
            from: ShareIndex(1),
            to: None,
            payload: cosigner_partial_json,
        }])
        .expect("coordinator combine partials");
    let signing_result = match combine_result {
        SigningRoundResult::Complete(r) => r,
        SigningRoundResult::NextRound(_) => {
            panic!("§06.17.1 1-round consume MUST complete in a single round")
        }
    };
    eprintln!(
        "✔ combine complete — DER sig {} bytes",
        signing_result.signature.len()
    );

    // ===== 8) THE GATE: signature verifies under the joint pubkey =====
    let mut r_arr = [0u8; 32];
    let mut s_arr = [0u8; 32];
    r_arr.copy_from_slice(&signing_result.r);
    s_arr.copy_from_slice(&signing_result.s);
    let bsv_sig = Signature::new(r_arr, s_arr);
    assert!(
        bsv_sig.is_low_s(),
        "MPC signature MUST be low-s (BIP-62)"
    );
    assert!(
        joint_pubkey.verify(&sighash, &bsv_sig),
        "§06.17.1 sign-from-bundle signature MUST verify under the joint pubkey"
    );

    // Cleanup the temp store.
    let _ = std::fs::remove_dir_all(&tmp);

    eprintln!();
    eprintln!("╔═══════════════════════════════════════════════════════════════╗");
    eprintln!("║  §06.17.1 STAGE-1 HERMETIC: COORDINATOR SIGNED FROM A         ║");
    eprintln!("║  DURABLE BUNDLE — cosigner generated + encrypted its OWN      ║");
    eprintln!("║  share; coordinator never held the plaintext.                ║");
    eprintln!("╚═══════════════════════════════════════════════════════════════╝");
    eprintln!("  presig_id:    {presig_id}");
    eprintln!("  joint_pubkey: {}", hex::encode(joint_pubkey_arr));
    eprintln!("  sig verifies: YES (low-s, joint key)");
    eprintln!("  total wall-clock: {:?}", t0.elapsed());
}
