//! Full-software 2-party hermetic sign (#41 proof-plan Tier 4.1).
//!
//! Proves `WalletClient::sign` produces a REAL threshold-ECDSA signature from a
//! device-sealed share + an in-process cosigner, end-to-end, **minus the device
//! biometric** (the `InMemoryKeyStore` stands in for the Secure Enclave). The
//! signature is verified against the joint public key with the BSV SDK.
//!
//! Native only: it runs a real cggmp24 DKG + aux-info generation via the
//! `round_based` simulator (Blum-prime shortcut), so it's excluded from wasm.
#![cfg(not(target_arch = "wasm32"))]

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

use async_trait::async_trait;
use bsv_mpc_client::{
    BroadcastResult, ChainServices, ClientError, InMemoryKeyStore, KeyStore, RoundTransport,
    StoredShare, Utxo, WalletClient, WalletStorage,
};
use bsv_mpc_core::signing::{SigningCoordinator, SigningRoundResult};
use bsv_mpc_core::{
    EncryptedShare, JointPublicKey, RoundMessage, SessionId, ShareIndex, ThresholdConfig,
};
use cggmp24::security_level::{SecurityLevel, SecurityLevel128};
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use std::rc::Rc;

// ── round_based sim harness (mirrors bsv-mpc-core signing.rs tests) ───────────

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

fn generate_test_primes(
    rng: &mut impl rand::RngCore,
) -> cggmp24::key_refresh::PregeneratedPrimes<SecurityLevel128> {
    let bits = SecurityLevel128::RSA_PRIME_BITLEN;
    let primes = [
        generate_blum_prime(rng, bits),
        generate_blum_prime(rng, bits),
        generate_blum_prime(rng, bits),
        generate_blum_prime(rng, bits),
    ];
    cggmp24::key_refresh::PregeneratedPrimes::try_from(primes).expect("primes wrong bit size")
}

fn dkg_key_shares(n: u16, t: u16) -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
    let mut rng = rand::rngs::OsRng;

    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
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

    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
    let eid_aux = ExecutionId::new(&eid_bytes);
    let primes: Vec<_> = (0..n).map(|_| generate_test_primes(&mut rng)).collect();
    let aux = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut prng = rand::rngs::OsRng;
        let pregen = primes[usize::from(i)].clone();
        async move {
            cggmp24::aux_info_gen(eid_aux, i, n, pregen)
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
        .map(|(s, a)| {
            cggmp24::KeyShare::<Secp256k1, SecurityLevel128>::from_parts((s, a))
                .expect("key share validation")
        })
        .collect()
}

// ── test seams ────────────────────────────────────────────────────────────────

#[derive(Default)]
struct MemStorage {
    shares: RefCell<HashMap<String, StoredShare>>,
}
#[async_trait(?Send)]
impl WalletStorage for MemStorage {
    async fn put_share(&self, share: StoredShare) -> Result<(), ClientError> {
        self.shares
            .borrow_mut()
            .insert(share.agent_id.clone(), share);
        Ok(())
    }
    async fn get_share(&self, agent_id: &str) -> Result<Option<StoredShare>, ClientError> {
        Ok(self.shares.borrow().get(agent_id).cloned())
    }
    async fn list_agents(&self) -> Result<Vec<String>, ClientError> {
        Ok(self.shares.borrow().keys().cloned().collect())
    }
}

struct NoChain;
#[async_trait(?Send)]
impl ChainServices for NoChain {
    async fn list_utxos(&self, _a: &str) -> Result<Vec<Utxo>, ClientError> {
        Ok(vec![])
    }
    async fn broadcast(&self, _t: &str) -> Result<BroadcastResult, ClientError> {
        Err(ClientError::NotImplemented("broadcast (test)"))
    }
}

/// In-process cosigner: wraps party-1's coordinator and answers each round
/// exchange, staying one logical step ahead of the client (see Phase 4b notes).
struct InProcessCosigner {
    coord: RefCell<SigningCoordinator>,
    pending: RefCell<Option<Vec<RoundMessage>>>,
}
#[async_trait(?Send)]
impl RoundTransport for InProcessCosigner {
    async fn exchange(
        &self,
        client_msgs: Vec<RoundMessage>,
    ) -> Result<Vec<RoundMessage>, ClientError> {
        let to_return = self
            .pending
            .borrow_mut()
            .take()
            .ok_or_else(|| ClientError::Core("cosigner has no pending round".into()))?;
        match self
            .coord
            .borrow_mut()
            .process_round(client_msgs)
            .map_err(|e| ClientError::Core(e.to_string()))?
        {
            SigningRoundResult::NextRound(next) => *self.pending.borrow_mut() = Some(next),
            SigningRoundResult::Complete(_) => {} // cosigner done; client completes on the returned msgs
        }
        Ok(to_return)
    }
}

#[tokio::test]
async fn wallet_client_signs_a_real_threshold_ecdsa_signature() {
    let config = ThresholdConfig::new(2, 2).unwrap();
    let key_shares = dkg_key_shares(2, 2);
    let session_bytes = [0x7au8; 32];
    let session = SessionId::from_bytes(session_bytes);

    let joint_compressed = key_shares[0].core.shared_public_key.to_bytes(true).to_vec();
    let joint = JointPublicKey {
        compressed: joint_compressed.clone(),
        address: String::new(),
    };

    // Client (party 0): device-seal its key-share JSON; store the metadata.
    let keystore = Rc::new(InMemoryKeyStore::new());
    keystore
        .seal_share("agent-1", &serde_json::to_vec(&key_shares[0]).unwrap())
        .await
        .unwrap();
    let storage = Rc::new(MemStorage::default());
    storage.shares.borrow_mut().insert(
        "agent-1".into(),
        StoredShare {
            agent_id: "agent-1".into(),
            share_index: 0,
            threshold: 2,
            parties: 2,
            session_id: session_bytes.to_vec(),
            joint_pubkey: serde_json::to_vec(&joint).unwrap(),
        },
    );

    // Cosigner (party 1): an in-process coordinator pre-initialized for this sighash.
    // A fixed 32-byte prehashed sighash (BSV sighashes are prehashed scalars).
    let sighash: [u8; 32] = [0x3c; 32];
    let cosigner_share = EncryptedShare {
        nonce: vec![0u8; 12],
        ciphertext: serde_json::to_vec(&key_shares[1]).unwrap(),
        session_id: session,
        share_index: ShareIndex(1),
        config,
        joint_pubkey_compressed: joint_compressed.clone(),
    };
    let mut cosigner_coord = SigningCoordinator::new(session, cosigner_share, config, vec![0, 1]);
    let cosigner_pending = cosigner_coord
        .init_round(&sighash, None)
        .expect("cosigner init");
    let cosigner = InProcessCosigner {
        coord: RefCell::new(cosigner_coord),
        pending: RefCell::new(Some(cosigner_pending)),
    };

    // Drive the real ceremony through WalletClient::sign.
    let client = WalletClient::new("agent-1".into(), storage, Rc::new(NoChain), keystore);
    let result = client
        .sign(&cosigner, &sighash, "Approve payment", None)
        .await
        .expect("threshold sign must complete");

    // It must be a real ECDSA signature over `sighash` under the joint key.
    assert_eq!(result.signature[0], 0x30, "DER SEQUENCE tag");
    let bsv_pubkey = bsv::PublicKey::from_bytes(&joint_compressed).expect("pubkey");
    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(&result.r);
    compact[32..].copy_from_slice(&result.s);
    let bsv_sig = bsv::Signature::from_compact(&compact).expect("sig");
    assert!(
        bsv_pubkey.verify(&sighash, &bsv_sig),
        "BSV SDK must verify the threshold signature against the joint key"
    );
}
