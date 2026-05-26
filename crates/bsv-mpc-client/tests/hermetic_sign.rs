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

/// The UniFFI host-driven signing session (`FfiSigningSession`) drives a real
/// 2-party sign the way a Swift/Kotlin shell would: the host pumps round messages
/// between two sessions. Proves the sync FFI facade produces a valid signature.
#[cfg(feature = "native")]
#[test]
fn ffi_signing_session_drives_a_real_threshold_signature() {
    use bsv_mpc_client::ffi::{FfiSignStep, FfiSigningSession};

    let key_shares = dkg_key_shares(2, 2);
    let session_id = vec![0x5bu8; 32];
    let joint = key_shares[0].core.shared_public_key.to_bytes(true).to_vec();
    let sighash = [0x9fu8; 32];

    let mk = |i: u16| {
        FfiSigningSession::new(
            serde_json::to_vec(&key_shares[usize::from(i)]).unwrap(),
            joint.clone(),
            session_id.clone(),
            i,
            2,
            2,
        )
        .expect("ffi session")
    };
    let s0 = mk(0);
    let s1 = mk(1);

    let mut out0 = s0.init(sighash.to_vec(), None).expect("s0 init");
    let mut out1 = s1.init(sighash.to_vec(), None).expect("s1 init");

    for _ in 0..20 {
        let step0 = s0.process(out1.clone()).expect("s0 process");
        let step1 = s1.process(out0.clone()).expect("s1 process");
        match (step0, step1) {
            (FfiSignStep::NextRound { messages: n0 }, FfiSignStep::NextRound { messages: n1 }) => {
                out0 = n0;
                out1 = n1;
            }
            (
                FfiSignStep::Complete {
                    r,
                    s,
                    signature_der,
                },
                FfiSignStep::Complete { .. },
            ) => {
                assert_eq!(signature_der[0], 0x30, "DER SEQUENCE");
                let pk = bsv::PublicKey::from_bytes(&joint).unwrap();
                let mut compact = [0u8; 64];
                compact[..32].copy_from_slice(&r);
                compact[32..].copy_from_slice(&s);
                let sig = bsv::Signature::from_compact(&compact).unwrap();
                assert!(
                    pk.verify(&sighash, &sig),
                    "BSV SDK must verify the FFI-driven sig"
                );
                return;
            }
            _ => panic!("FFI signing sessions desynchronized"),
        }
    }
    panic!("FFI signing did not complete within 20 rounds");
}

// ── Mainnet capstone (gated E2E_MAINNET=1; BURNS REAL SATS) ───────────────────

fn mainnet_opt_in() -> bool {
    std::env::var("E2E_MAINNET")
        .map(|v| v == "1")
        .unwrap_or(false)
}

async fn find_utxo_on_woc(
    http: &reqwest::Client,
    fund_txid: &str,
    locking_hex: &str,
) -> Option<(u32, u64)> {
    let url = format!("https://api.whatsonchain.com/v1/bsv/main/tx/hash/{fund_txid}");
    for attempt in 1..=10 {
        tokio::time::sleep(std::time::Duration::from_secs(attempt * 3)).await;
        let Ok(resp) = http.get(&url).send().await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(json) = resp.json::<serde_json::Value>().await else {
            continue;
        };
        let Some(vouts) = json["vout"].as_array() else {
            continue;
        };
        for v in vouts {
            if v["scriptPubKey"]["hex"].as_str().unwrap_or("") == locking_hex {
                let n = v["n"].as_u64().unwrap_or(0) as u32;
                let value = (v["value"].as_f64().unwrap_or(0.0) * 100_000_000.0 + 0.5) as u64;
                return Some((n, value));
            }
        }
    }
    None
}

async fn broadcast_via_arc(http: &reqwest::Client, raw_tx_hex: &str) -> bool {
    for arc in &["https://arc.taal.com", "https://arc.gorillapool.io"] {
        let url = format!("{arc}/v1/tx");
        let Ok(resp) = http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("XDeployment-ID", "bsv-mpc-client-capstone")
            .json(&serde_json::json!({ "rawTx": raw_tx_hex }))
            .send()
            .await
        else {
            continue;
        };
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        eprintln!(
            "  ARC {url}: status={status} body={}",
            text.chars().take(300).collect::<String>()
        );
        if status.is_success()
            || text.contains("SEEN_ON_NETWORK")
            || text.contains("STORED")
            || text.contains("MINED")
        {
            return true;
        }
    }
    false
}

/// wallet:3321 returns the funding tx as `tx` (atomic BEEF byte array); extract
/// the raw hex so we can self-broadcast it (the wallet's broadcaster is unreliable).
fn raw_tx_hex_from_create_action(resp: &serde_json::Value) -> Option<String> {
    let arr = resp.get("tx")?.as_array()?;
    let beef: Vec<u8> = arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect();
    let tx = bsv::Transaction::from_atomic_beef(&beef)
        .or_else(|_| bsv::Transaction::from_beef(&beef, None))
        .ok()?;
    Some(tx.to_hex())
}

/// #41 CLIENT MAINNET CAPSTONE — the client signs a REAL mainnet tx.
///
/// Local 2-of-2 → fund the joint P2PKH via wallet:3321 → `WalletClient::sign`
/// (share device-sealed in `InMemoryKeyStore` = audited enclave stand-in; cosigner
/// over the `RoundTransport` seam) → broadcast via ARC → WoC-confirmed TXID. The
/// only thing not exercised is the physical biometric tap (a 100cash-on-device
/// follow-up; the Simulator uses MockKeyStore regardless).
#[tokio::test]
async fn mainnet_capstone_client_signs_real_tx() {
    if !mainnet_opt_in() {
        eprintln!(
            "E2E_MAINNET=1 not set — skipping #41 client mainnet capstone (BURNS REAL SATS).\n\
             Run: E2E_MAINNET=1 cargo test -p bsv-mpc-client --test hermetic_sign \\\n\
               mainnet_capstone -- --nocapture --test-threads=1"
        );
        return;
    }
    let http = reqwest::Client::new();
    const WALLET: &str = "http://localhost:3321";

    // 1. Local 2-of-2 → joint P2PKH.
    let key_shares = dkg_key_shares(2, 2);
    let mut joint_33 = [0u8; 33];
    joint_33.copy_from_slice(&key_shares[0].core.shared_public_key.to_bytes(true));
    let joint_pub = bsv::PublicKey::from_bytes(&joint_33).expect("joint pubkey");
    let joint_locking =
        bsv_mpc_client::txbuild::p2pkh_locking_script_from_hash(&joint_pub.hash160());
    let joint_locking_hex = hex::encode(&joint_locking);
    eprintln!("✔ joint P2PKH locking: {joint_locking_hex}");

    // 2. Fund via wallet:3321; self-broadcast the funding tx via ARC; find the UTXO.
    let funding: u64 = 2000;
    let fund_resp: serde_json::Value = http
        .post(format!("{WALLET}/createAction"))
        .header("Origin", "http://admin.com")
        .json(&serde_json::json!({
            "description": "bsv-mpc #41 client capstone fund",
            "outputs": [{ "satoshis": funding, "lockingScript": joint_locking_hex, "outputDescription": "MPC joint P2PKH" }]
        }))
        .send()
        .await
        .expect("3321 reachable")
        .json()
        .await
        .expect("fund json");
    let fund_txid = fund_resp["txid"].as_str().expect("fund txid").to_string();
    if let Some(fund_raw) = raw_tx_hex_from_create_action(&fund_resp) {
        eprintln!(
            "  funding self-broadcast via ARC: {}",
            broadcast_via_arc(&http, &fund_raw).await
        );
    }
    eprintln!("✔ funded: {fund_txid}");
    let (vout, value) = find_utxo_on_woc(&http, &fund_txid, &joint_locking_hex)
        .await
        .expect("funding UTXO MUST appear on WoC");
    eprintln!("✔ UTXO {fund_txid}:{vout} = {value} sats");

    // 3. Destination = P2PKH of the wallet:3321 identity key (return the funds).
    let idpk: serde_json::Value = http
        .post(format!("{WALLET}/getPublicKey"))
        .header("Origin", "http://admin.com")
        .json(&serde_json::json!({ "identityKey": true }))
        .send()
        .await
        .expect("3321")
        .json()
        .await
        .expect("idpk json");
    let dest_pub =
        bsv::PublicKey::from_bytes(&hex::decode(idpk["publicKey"].as_str().unwrap()).unwrap())
            .unwrap();
    let dest_locking = bsv_mpc_client::txbuild::p2pkh_locking_script_from_hash(&dest_pub.hash160());

    // 4. Build the spend + BIP-143 sighash (mirrors the proxy: v1, sighash 0x41).
    let fee = bsv_mpc_client::txbuild::estimate_mining_fee(1, 1);
    let spend_amount = value - fee;
    let mut txid_internal = [0u8; 32];
    txid_internal.copy_from_slice(&hex::decode(&fund_txid).unwrap());
    txid_internal.reverse(); // display → internal byte order
    let inputs = [(txid_internal, vout, 0xffff_ffffu32)];
    let outputs_refs = [(spend_amount, dest_locking.as_slice())];
    let sighash =
        bsv_mpc_client::txbuild::compute_bip143_sighash(&bsv_mpc_client::txbuild::SighashParams {
            version: 1,
            inputs: &inputs,
            outputs: &outputs_refs,
            locktime: 0,
            input_index: 0,
            subscript: &joint_locking,
            input_satoshis: value,
            sighash_type: 0x41,
        });

    // 5. THE CLIENT SIGNS — device-sealed share unsealed via the keystore, cosigner
    //    driven over the RoundTransport seam.
    let session_bytes = [0x41u8; 32];
    let session = SessionId::from_bytes(session_bytes);
    let keystore = Rc::new(InMemoryKeyStore::new());
    keystore
        .seal_share("agent-1", &serde_json::to_vec(&key_shares[0]).unwrap())
        .await
        .unwrap();
    let storage = Rc::new(MemStorage::default());
    let joint_jpk = JointPublicKey {
        compressed: joint_33.to_vec(),
        address: String::new(),
    };
    storage.shares.borrow_mut().insert(
        "agent-1".into(),
        StoredShare {
            agent_id: "agent-1".into(),
            share_index: 0,
            threshold: 2,
            parties: 2,
            session_id: session_bytes.to_vec(),
            joint_pubkey: serde_json::to_vec(&joint_jpk).unwrap(),
        },
    );
    let config = ThresholdConfig::new(2, 2).unwrap();
    let cosigner_share = EncryptedShare {
        nonce: vec![0u8; 12],
        ciphertext: serde_json::to_vec(&key_shares[1]).unwrap(),
        session_id: session,
        share_index: ShareIndex(1),
        config,
        joint_pubkey_compressed: joint_33.to_vec(),
    };
    let mut cosigner_coord = SigningCoordinator::new(session, cosigner_share, config, vec![0, 1]);
    let pending = cosigner_coord
        .init_round(&sighash, None)
        .expect("cosigner init");
    let cosigner = InProcessCosigner {
        coord: RefCell::new(cosigner_coord),
        pending: RefCell::new(Some(pending)),
    };
    let client = WalletClient::new("agent-1".into(), storage, Rc::new(NoChain), keystore);
    let result = client
        .sign(&cosigner, &sighash, "Approve mainnet spend", None)
        .await
        .expect("client threshold sign");

    // 6. PRE-FLIGHT (fail-closed): low-s + verify under the joint key BEFORE broadcast.
    let sig = bsv::Signature::from_der(&result.signature).expect("DER sig");
    assert!(
        sig.is_low_s(),
        "MUST be low-s (BIP-62) — refusing to broadcast"
    );
    assert!(
        joint_pub.verify(&sighash, &sig),
        "MUST verify under joint key — refusing to broadcast"
    );

    // 7. Assemble the signed tx + broadcast via ARC.
    let mut sig_checksig = result.signature.clone();
    sig_checksig.push(0x41);
    let unlocking = bsv_mpc_client::txbuild::build_p2pkh_unlocking_script(&sig_checksig, &joint_33);
    let signed = [(txid_internal, vout, unlocking, 0xffff_ffffu32)];
    let raw_tx = bsv_mpc_client::txbuild::serialize_signed_tx(
        1,
        &signed,
        &[(spend_amount, dest_locking.clone())],
        0,
    );
    let raw_hex = hex::encode(&raw_tx);
    let spend_txid = bsv_mpc_client::txbuild::compute_txid(&raw_tx);
    eprintln!("✔ client-signed spend {spend_txid} ({spend_amount} sats → wallet:3321)");
    let ok = broadcast_via_arc(&http, &raw_hex).await;
    assert!(ok, "spend MUST broadcast — TXID={spend_txid} raw={raw_hex}");
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #41 CLIENT MAINNET CAPSTONE — threshold sig broadcast to net  ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("  TXID: {spend_txid}");
    eprintln!("  view: https://whatsonchain.com/tx/{spend_txid}");
}
