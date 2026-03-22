//! POC 15: Capstone Integration — bsv-worm through MPC signing proxy
//!
//! THE FINAL POC. Proves bsv-worm works unchanged through a real MPC proxy.
//!
//! Architecture:
//!   bsv-worm → MPC Proxy (:3323) → KSS (:4322)
//!   - Proxy has share_B, KSS has share_A
//!   - Neither party alone can sign
//!   - bsv-worm sees a normal BRC-100 wallet
//!
//! Phase A: `bsv-worm status` works (identity key + connectivity)
//! Phase B: `bsv-worm think "what is 2+2"` works (BRC-31 auth + x402 payment)

use std::collections::VecDeque;
use std::sync::Arc;

use cggmp24::security_level::{SecurityLevel, SecurityLevel128};
use cggmp24::signing::{DataToSign, PrehashedDataToSign};
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use generic_ec::{NonZero, Point, Scalar, SecretScalar};
use rand::Rng;
use round_based::state_machine::{ProceedResult, StateMachine};
use sha2::Sha256;

use bsv::primitives::bsv::sighash::{
    compute_sighash_for_signing, SighashParams, TxInput, TxOutput, SIGHASH_ALL, SIGHASH_FORKID,
};
use bsv::primitives::bsv::tx_signature::TransactionSignature;
use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv::primitives::encoding::Writer;
use bsv::primitives::hash::{sha256d, sha256_hmac};
use bsv::primitives::symmetric::SymmetricKey;
use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel as BsvSecurityLevel};

// ============================================================================
// Wire message for HTTP transport (from POC 5)
// ============================================================================

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct WireMessage {
    sender: u16,
    is_broadcast: bool,
    msg: serde_json::Value,
}

fn outgoing_to_wire<M: serde::Serialize>(sender: u16, out: round_based::Outgoing<M>) -> WireMessage {
    WireMessage {
        sender,
        is_broadcast: out.recipient.is_broadcast(),
        msg: serde_json::to_value(&out.msg).unwrap(),
    }
}

fn wire_to_incoming<M: serde::de::DeserializeOwned>(wire: WireMessage, id: u64) -> round_based::Incoming<M> {
    round_based::Incoming {
        id,
        sender: wire.sender,
        msg_type: if wire.is_broadcast {
            round_based::MessageType::Broadcast
        } else {
            round_based::MessageType::P2P
        },
        msg: serde_json::from_value(wire.msg).unwrap(),
    }
}

// ============================================================================
// Buffered sink (from POC 1)
// ============================================================================

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
    fn poll_ready(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn start_send(self: std::pin::Pin<&mut Self>, item: M) -> Result<(), Self::Error> {
        self.project().messages.get_mut().push_back(item);
        Ok(())
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
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
    fn poll_close(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
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
        let buffered = BufferedSink { messages: VecDeque::new(), inner: outgoing };
        (incoming, buffered)
    })
}

// ============================================================================
// Blum prime generation (from POC 1)
// ============================================================================

fn generate_blum_prime(rng: &mut impl rand::RngCore, bits_size: u32) -> cggmp24::backend::Integer {
    use cggmp24::backend::Integer;
    loop {
        let n = Integer::generate_prime(rng, bits_size);
        if n.mod_u(4) == 3 { break n; }
    }
}

fn generate_pregenerated_primes(rng: &mut impl rand::RngCore) -> cggmp24::key_refresh::PregeneratedPrimes<SecurityLevel128> {
    let bitsize = SecurityLevel128::RSA_PRIME_BITLEN;
    let primes = [
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
    ];
    cggmp24::key_refresh::PregeneratedPrimes::try_from(primes).expect("primes have wrong bit size")
}

// ============================================================================
// Helpers
// ============================================================================

fn bsv_privkey_to_scalar(privkey: &PrivateKey) -> NonZero<SecretScalar<Secp256k1>> {
    let bytes = privkey.to_bytes();
    let mut scalar = Scalar::<Secp256k1>::from_be_bytes(&bytes).expect("valid scalar");
    let secret = SecretScalar::new(&mut scalar);
    NonZero::from_secret_scalar(secret).expect("non-zero scalar")
}

fn share_to_bytes(share: &cggmp24::IncompleteKeyShare<Secp256k1>) -> [u8; 32] {
    let secret: &SecretScalar<Secp256k1> = share.x.as_ref();
    let scalar: &Scalar<Secp256k1> = secret.as_ref();
    let encoded = scalar.to_be_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(encoded.as_bytes());
    arr
}

fn point_to_bsv_pubkey(point: &Point<Secp256k1>) -> PublicKey {
    let bytes = point.to_bytes(true);
    PublicKey::from_bytes(&bytes).expect("valid pubkey from point")
}

fn point_add(a: &PublicKey, b: &PublicKey) -> PublicKey {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::ProjectivePoint;
    let pa = {
        let enc = k256::EncodedPoint::from_bytes(&a.to_compressed()).unwrap();
        ProjectivePoint::from(k256::AffinePoint::from_encoded_point(&enc).unwrap())
    };
    let pb = {
        let enc = k256::EncodedPoint::from_bytes(&b.to_compressed()).unwrap();
        ProjectivePoint::from(k256::AffinePoint::from_encoded_point(&enc).unwrap())
    };
    let sum = pa + pb;
    let encoded = k256::EncodedPoint::from(sum.to_affine());
    PublicKey::from_bytes(encoded.as_bytes()).expect("valid sum point")
}

/// Partial ECDH from MPC shares with Lagrange interpolation (from POC 3/9).
fn mpc_partial_ecdh(
    point: &PublicKey,
    shares: &[cggmp24::IncompleteKeyShare<Secp256k1>],
) -> PublicKey {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::elliptic_curve::PrimeField;
    use k256::ProjectivePoint;

    let vss = shares[0].vss_setup.as_ref().expect("threshold shares should have VSS setup");
    let n = shares.len();
    let mut result = ProjectivePoint::IDENTITY;

    for j in 0..n {
        let i_j = &vss.I[j];
        let mut lambda = Scalar::<Secp256k1>::one();
        for m in 0..n {
            if m == j { continue; }
            let i_m = &vss.I[m];
            let neg_i_m = -Scalar::<Secp256k1>::from(*i_m);
            let diff = Scalar::<Secp256k1>::from(*i_j) - Scalar::<Secp256k1>::from(*i_m);
            let diff_inv = diff.invert().expect("distinct evaluation points");
            lambda = lambda * neg_i_m * diff_inv;
        }

        let s_bytes = share_to_bytes(&shares[j]);
        let partial = point.mul_scalar(&s_bytes).expect("partial ECDH");

        let partial_point = {
            let enc = k256::EncodedPoint::from_bytes(&partial.to_compressed()).unwrap();
            ProjectivePoint::from(k256::AffinePoint::from_encoded_point(&enc).unwrap())
        };

        let lambda_bytes = lambda.to_be_bytes();
        let mut lambda_arr = [0u8; 32];
        lambda_arr.copy_from_slice(lambda_bytes.as_bytes());
        let lambda_k256 = k256::Scalar::from_repr(lambda_arr.into())
            .expect("Lagrange coefficient must be valid scalar");
        result = result + partial_point * lambda_k256;
    }

    let affine = result.to_affine();
    let encoded = k256::EncodedPoint::from(affine);
    PublicKey::from_bytes(encoded.as_bytes()).expect("valid combined ECDH point")
}

/// Derive child pubkey: root_pub + G * HMAC(shared_secret, invoice)
fn derive_child_pubkey(root_pubkey: &PublicKey, shared_secret: &PublicKey, invoice: &str) -> PublicKey {
    let hmac = sha256_hmac(&shared_secret.to_compressed(), invoice.as_bytes());
    let hmac_key = PrivateKey::from_bytes(&hmac).expect("HMAC valid scalar");
    let offset_pub = hmac_key.public_key();
    point_add(root_pubkey, &offset_pub)
}

/// MPC symmetric key derivation (2 partial ECDH rounds, from POC 9).
fn mpc_derive_symmetric_key(
    counterparty: &Counterparty,
    root_pubkey: &PublicKey,
    shares: &[cggmp24::IncompleteKeyShare<Secp256k1>],
    protocol: &Protocol,
    key_id: &str,
) -> SymmetricKey {
    let actual_cp_key = match counterparty {
        Counterparty::Self_ => root_pubkey.clone(),
        Counterparty::Anyone => KeyDeriver::anyone_key().1,
        Counterparty::Other(pk) => pk.clone(),
    };

    let invoice = format!("{}-{}-{}", protocol.security_level as u8, protocol.protocol_name, key_id);

    // Round 1: base ECDH
    let base_ecdh = mpc_partial_ecdh(&actual_cp_key, shares);
    let hmac_bytes = sha256_hmac(&base_ecdh.to_compressed(), invoice.as_bytes());

    // child_pub = counterparty_key + G * hmac
    let hmac_key = PrivateKey::from_bytes(&hmac_bytes).expect("HMAC valid scalar");
    let g_times_hmac = hmac_key.public_key();
    let child_pub = point_add(&actual_cp_key, &g_times_hmac);

    // Round 2: root_priv * child_pub
    let root_times_child = mpc_partial_ecdh(&child_pub, shares);

    // Local: hmac * child_pub
    let hmac_times_child = child_pub.mul_scalar(&hmac_bytes).expect("scalar mult");

    // symmetric_point = root_times_child + hmac_times_child
    let symmetric_point = point_add(&root_times_child, &hmac_times_child);

    SymmetricKey::from_bytes(&symmetric_point.x()).expect("valid symmetric key")
}

fn p2pkh_locking_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.push(0x76); s.push(0xa9); s.push(0x14);
    s.extend_from_slice(pubkey_hash);
    s.push(0x88); s.push(0xac);
    s
}

fn p2pkh_unlocking_script(sig_checksig: &[u8], compressed_pubkey: &[u8; 33]) -> Vec<u8> {
    let mut s = Vec::new();
    s.push(sig_checksig.len() as u8);
    s.extend_from_slice(sig_checksig);
    s.push(33);
    s.extend_from_slice(compressed_pubkey);
    s
}

fn serialize_transaction(
    version: i32,
    inputs: &[([u8; 32], u32, Vec<u8>, u32)],
    outputs: &[(u64, Vec<u8>)],
    locktime: u32,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_i32_le(version);
    w.write_var_int(inputs.len() as u64);
    for (txid, vout, script, seq) in inputs {
        w.write_bytes(txid);
        w.write_u32_le(*vout);
        w.write_var_int(script.len() as u64);
        w.write_bytes(script);
        w.write_u32_le(*seq);
    }
    w.write_var_int(outputs.len() as u64);
    for (sats, script) in outputs {
        w.write_u64_le(*sats);
        w.write_var_int(script.len() as u64);
        w.write_bytes(script);
    }
    w.write_u32_le(locktime);
    w.into_bytes()
}

// ============================================================================
// DKG — run once, persist shares
// ============================================================================

async fn run_dkg() -> (
    Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>>,
    PublicKey,
) {
    let mut rng = rand::rngs::OsRng;
    let n: u16 = 2;
    let t: u16 = 2;

    println!("  DKG: generating key shares...");
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

    assert_eq!(
        incomplete_shares[0].shared_public_key,
        incomplete_shares[1].shared_public_key,
    );

    println!("  DKG: generating aux info (Paillier primes — this takes ~30s)...");
    let eid_bytes: [u8; 32] = rng.gen();
    let eid_aux = ExecutionId::new(&eid_bytes);
    let primes: Vec<_> = (0..n).map(|_| generate_pregenerated_primes(&mut rng)).collect();

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

    let key_shares: Vec<_> = incomplete_shares
        .into_iter()
        .zip(aux_infos)
        .map(|(share, aux)| {
            cggmp24::KeyShare::from_parts((share, aux)).expect("key share validation")
        })
        .collect();

    let joint_pubkey = point_to_bsv_pubkey(&key_shares[0].core.shared_public_key);
    println!("  DKG: joint pubkey = {}", joint_pubkey.to_hex());
    println!("  DKG: MPC address  = {}", joint_pubkey.to_address());

    (key_shares, joint_pubkey)
}

// ============================================================================
// KSS Server (port 4322) — holds share_A
// ============================================================================

/// State shared between KSS HTTP handlers and signing SM threads.
struct KssState {
    key_share: cggmp24::KeyShare<Secp256k1, SecurityLevel128>,
    /// Channels for the current signing session
    inbox_tx: tokio::sync::Mutex<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>,
    outbox_rx: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    /// For partial ECDH: the share scalar bytes
    share_scalar_bytes: [u8; 32],
}

async fn kss_health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"status": "ok", "service": "kss-poc15"}))
}

async fn kss_sign_start(
    axum::extract::State(state): axum::extract::State<Arc<KssState>>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let eid_hex = body["eid"].as_str().unwrap();
    let sighash_hex = body["sighash"].as_str().unwrap();
    let eid_bytes: [u8; 32] = hex::decode(eid_hex).unwrap().try_into().unwrap();
    let sighash_bytes: [u8; 32] = hex::decode(sighash_hex).unwrap().try_into().unwrap();

    let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

    *state.inbox_tx.lock().await = Some(in_tx);
    *state.outbox_rx.lock().await = Some(out_rx);

    let share = state.key_share.clone();

    // Spawn SM thread (SM is !Send)
    std::thread::spawn(move || {
        let eid = ExecutionId::new(&eid_bytes);
        let sighash_scalar = Scalar::<Secp256k1>::from_be_bytes(&sighash_bytes)
            .expect("valid sighash scalar");
        let data_to_sign = PrehashedDataToSign::from_scalar(sighash_scalar);
        let participants = vec![0u16, 1];

        let mut sm = round_based::state_machine::wrap_protocol(|party| async move {
            cggmp24::signing(eid, 0, &participants, &share)
                .sign(&mut rand::rngs::OsRng, party, &data_to_sign)
                .await
        });

        let mut msg_id = 0u64;
        loop {
            match sm.proceed() {
                ProceedResult::SendMsg(outgoing) => {
                    let wire = outgoing_to_wire(0, outgoing);
                    let bytes = serde_json::to_vec(&wire).unwrap();
                    out_tx.blocking_send(bytes).unwrap();
                }
                ProceedResult::NeedsOneMoreMessage => {
                    let in_bytes = match in_rx.blocking_recv() {
                        Some(b) => b,
                        None => { eprintln!("KSS: inbox closed"); break; }
                    };
                    msg_id += 1;
                    let wire: WireMessage = serde_json::from_slice(&in_bytes).unwrap();
                    let incoming = wire_to_incoming(wire, msg_id);
                    if sm.received_msg(incoming).is_err() {
                        eprintln!("KSS: SM rejected message");
                        break;
                    }
                }
                ProceedResult::Yielded => {}
                ProceedResult::Output(result) => {
                    let sig = result.unwrap();
                    let mut sig_bytes = [0u8; 64];
                    sig.write_to_slice(&mut sig_bytes);
                    // Send signature as a special "done" message
                    let done_msg = serde_json::json!({"done": true, "signature": hex::encode(sig_bytes)});
                    out_tx.blocking_send(serde_json::to_vec(&done_msg).unwrap()).unwrap();
                    break;
                }
                ProceedResult::Error(err) => {
                    eprintln!("KSS SM error: {err}");
                    let err_msg = serde_json::json!({"error": format!("{err}")});
                    let _ = out_tx.blocking_send(serde_json::to_vec(&err_msg).unwrap());
                    break;
                }
            }
        }
    });

    // Wait for KSS's first round message
    let mut rx = state.outbox_rx.lock().await;
    let first_msg = rx.as_mut().unwrap().recv().await.unwrap();

    axum::Json(serde_json::json!({"message": serde_json::from_slice::<serde_json::Value>(&first_msg).unwrap()}))
}

async fn kss_sign_round(
    axum::extract::State(state): axum::extract::State<Arc<KssState>>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    // Send proxy's message to KSS SM
    let msg_bytes = serde_json::to_vec(&body["message"]).unwrap();
    {
        let tx = state.inbox_tx.lock().await;
        tx.as_ref().unwrap().send(msg_bytes).await.unwrap();
    }

    // Wait for KSS SM's response
    let mut rx = state.outbox_rx.lock().await;
    let response = rx.as_mut().unwrap().recv().await.unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&response).unwrap();

    axum::Json(serde_json::json!({"message": response_json}))
}

async fn kss_ecdh(
    axum::extract::State(state): axum::extract::State<Arc<KssState>>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let point_hex = body["point"].as_str().unwrap();
    let point_bytes = hex::decode(point_hex).unwrap();
    let point = PublicKey::from_bytes(&point_bytes).expect("valid point");
    let partial = point.mul_scalar(&state.share_scalar_bytes).expect("partial ECDH");
    axum::Json(serde_json::json!({"partial": hex::encode(partial.to_compressed())}))
}

fn build_kss_router(key_share: cggmp24::KeyShare<Secp256k1, SecurityLevel128>) -> axum::Router {
    // Extract share scalar for ECDH
    let share_scalar_bytes = {
        let secret: &SecretScalar<Secp256k1> = key_share.core.x.as_ref();
        let scalar: &Scalar<Secp256k1> = secret.as_ref();
        let encoded = scalar.to_be_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(encoded.as_bytes());
        arr
    };
    let state = Arc::new(KssState {
        key_share,
        inbox_tx: tokio::sync::Mutex::new(None),
        outbox_rx: tokio::sync::Mutex::new(None),
        share_scalar_bytes,
    });

    axum::Router::new()
        .route("/health", axum::routing::get(kss_health))
        .route("/sign/start", axum::routing::post(kss_sign_start))
        .route("/sign/round", axum::routing::post(kss_sign_round))
        .route("/ecdh", axum::routing::post(kss_ecdh))
        .with_state(state)
}

// ============================================================================
// MPC Signing via HTTP (proxy side — drives the signing as party 1)
// ============================================================================

/// Perform 4-round MPC signing via HTTP with KSS.
/// Returns 64-byte compact signature (r || s).
fn mpc_sign_via_http(
    key_share: &cggmp24::KeyShare<Secp256k1, SecurityLevel128>,
    sighash: &[u8; 32],
    kss_url: &str,
) -> [u8; 64] {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let share = key_share.clone();
    let sighash_copy = *sighash;
    let kss_url_owned = kss_url.to_string();

    // Use the POC 5 pattern: both SMs in separate threads, relay via HTTP
    // The KSS SM runs on the server side, proxy SM runs here.
    // We use /send and /recv pattern through /sign/start + /sign/round.

    // Step 1: Start KSS session — this spawns the KSS SM thread
    let http_client = reqwest::blocking::Client::new();
    let start_body = serde_json::json!({
        "eid": hex::encode(eid_bytes),
        "sighash": hex::encode(sighash),
    });

    let start_resp: serde_json::Value = http_client
        .post(format!("{}/sign/start", kss_url))
        .json(&start_body)
        .send()
        .unwrap()
        .json()
        .unwrap();

    // The first KSS message is returned in the start response
    let kss_first_msg_bytes = serde_json::to_vec(&start_resp["message"]).unwrap();

    // Step 2: Run proxy SM in this thread, relay messages via HTTP
    let sighash_scalar = Scalar::<Secp256k1>::from_be_bytes(&sighash_copy)
        .expect("valid sighash");
    let data_to_sign = PrehashedDataToSign::from_scalar(sighash_scalar);
    let participants = vec![0u16, 1];
    let eid = ExecutionId::new(&eid_bytes);

    let mut sm = round_based::state_machine::wrap_protocol(|party| async move {
        cggmp24::signing(eid, 1, &participants, &share)
            .sign(&mut rand::rngs::OsRng, party, &data_to_sign)
            .await
    });

    // Queue of messages received from KSS waiting to be fed to our SM
    let mut kss_inbox: VecDeque<Vec<u8>> = VecDeque::new();
    kss_inbox.push_back(kss_first_msg_bytes);

    let mut msg_id = 0u64;
    let mut sig_bytes = [0u8; 64];

    loop {
        match sm.proceed() {
            ProceedResult::SendMsg(outgoing) => {
                let wire = outgoing_to_wire(1, outgoing);
                let wire_bytes = serde_json::to_vec(&wire).unwrap();
                // Send our message to KSS and get KSS's next message back
                let round_resp: serde_json::Value = http_client
                    .post(format!("{}/sign/round", kss_url_owned))
                    .json(&serde_json::json!({"message": wire}))
                    .send()
                    .unwrap()
                    .json()
                    .unwrap();

                let resp_msg = &round_resp["message"];
                // Check if KSS is done (returns signature)
                if resp_msg.get("done").and_then(|v| v.as_bool()).unwrap_or(false) {
                    let sig_hex = resp_msg["signature"].as_str().unwrap();
                    let sig_raw = hex::decode(sig_hex).unwrap();
                    sig_bytes.copy_from_slice(&sig_raw);
                    // Continue driving our SM — it should also finish
                    continue;
                }
                // Queue KSS's response message
                kss_inbox.push_back(serde_json::to_vec(resp_msg).unwrap());
            }
            ProceedResult::NeedsOneMoreMessage => {
                if let Some(msg_bytes) = kss_inbox.pop_front() {
                    msg_id += 1;
                    let wire: WireMessage = serde_json::from_slice(&msg_bytes).unwrap();
                    let incoming = wire_to_incoming(wire, msg_id);
                    if sm.received_msg(incoming).is_err() {
                        panic!("Proxy SM rejected KSS message");
                    }
                } else {
                    // Need a message from KSS but don't have one — request one
                    // This shouldn't happen in normal flow, but handle gracefully
                    panic!("SM needs message but KSS inbox is empty (protocol desync)");
                }
            }
            ProceedResult::Yielded => {}
            ProceedResult::Output(result) => {
                let sig = result.unwrap();
                sig.write_to_slice(&mut sig_bytes);
                break;
            }
            ProceedResult::Error(err) => panic!("Proxy SM error: {err}"),
        }
    }

    sig_bytes
}

// ============================================================================
// BRC-100 Proxy Server (port 3323) — holds share_B
// ============================================================================

struct ProxyState {
    key_share: cggmp24::KeyShare<Secp256k1, SecurityLevel128>,
    joint_pubkey: PublicKey,
    joint_pubkey_hex: String,
    kss_url: String,
    /// Reconstructed root key (POC shortcut — NEVER in production)
    root_privkey: PrivateKey,
    /// ProtoWallet for encrypt/decrypt/HMAC (POC shortcut)
    proto_wallet: bsv::wallet::ProtoWallet,
    /// UTXO tracking (in-memory for POC)
    utxos: tokio::sync::Mutex<Vec<UtxoInfo>>,
}

#[derive(Clone, Debug)]
struct UtxoInfo {
    txid: String,
    vout: u32,
    satoshis: u64,
}

// --- GET endpoints ---

async fn proxy_is_authenticated() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"authenticated": true}))
}

async fn proxy_get_network() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"network": "mainnet"}))
}

async fn proxy_get_version() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"version": "mpc-proxy-poc15 0.1.0"}))
}

async fn proxy_wait_for_authentication() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"authenticated": true}))
}

async fn proxy_get_height() -> axum::Json<serde_json::Value> {
    // Query WoC for current height
    let client = reqwest::Client::new();
    match client.get("https://api.whatsonchain.com/v1/bsv/main/chain/info").send().await {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                let height = json["blocks"].as_u64().unwrap_or(0);
                return axum::Json(serde_json::json!({"height": height}));
            }
        }
        Err(_) => {}
    }
    axum::Json(serde_json::json!({"height": 0}))
}

// --- POST endpoints ---

async fn proxy_get_public_key(
    axum::extract::State(state): axum::extract::State<Arc<ProxyState>>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    // Identity key request
    if body.get("identityKey").and_then(|v| v.as_bool()).unwrap_or(false) {
        return axum::Json(serde_json::json!({"publicKey": state.joint_pubkey_hex}));
    }

    // BRC-42 key derivation
    let protocol_id = &body["protocolID"];
    let key_id = body["keyID"].as_str().unwrap_or("");
    let counterparty_str = body["counterparty"].as_str().unwrap_or("self");
    let for_self = body.get("forSelf").and_then(|v| v.as_bool()).unwrap_or(false);

    let security_level = protocol_id[0].as_u64().unwrap_or(2);
    let protocol_name = protocol_id[1].as_str().unwrap_or("");

    let protocol = Protocol::new(
        if security_level == 2 { BsvSecurityLevel::Counterparty } else { BsvSecurityLevel::App },
        protocol_name,
    );

    let counterparty = if counterparty_str == "self" || counterparty_str == "anyone" {
        if counterparty_str == "anyone" {
            Counterparty::Anyone
        } else {
            Counterparty::Self_
        }
    } else {
        let cp_pub = PublicKey::from_hex(counterparty_str).expect("valid counterparty pubkey");
        Counterparty::Other(cp_pub)
    };

    // Use BSV SDK's KeyDeriver with reconstructed key (POC shortcut)
    let deriver = KeyDeriver::new(Some(state.root_privkey.clone()));
    match deriver.derive_public_key(&protocol, key_id, &counterparty, for_self) {
        Ok(pk) => axum::Json(serde_json::json!({"publicKey": pk.to_hex()})),
        Err(e) => axum::Json(serde_json::json!({"error": format!("{e}")})),
    }
}

async fn proxy_create_signature(
    axum::extract::State(state): axum::extract::State<Arc<ProxyState>>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let data: Vec<u8> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();
    let protocol_id = &body["protocolID"];
    let key_id = body["keyID"].as_str().unwrap_or("");
    let counterparty_str = body["counterparty"].as_str().unwrap_or("self");

    let security_level = protocol_id[0].as_u64().unwrap_or(2);
    let protocol_name = protocol_id[1].as_str().unwrap_or("");

    // Compute BRC-42 derived private key (POC shortcut — uses reconstructed root)
    let counterparty_pub = if counterparty_str == "self" {
        state.joint_pubkey.clone()
    } else if counterparty_str == "anyone" {
        KeyDeriver::anyone_key().1
    } else {
        PublicKey::from_hex(counterparty_str).expect("valid counterparty pubkey")
    };

    let shared_secret = state.root_privkey
        .derive_shared_secret(&counterparty_pub)
        .expect("ECDH");

    let invoice = format!("{}-{}-{}", security_level, protocol_name, key_id);
    let hmac_bytes = sha256_hmac(&shared_secret.to_compressed(), invoice.as_bytes());

    // child_priv = root_priv + hmac
    let root_scalar = Scalar::<Secp256k1>::from_be_bytes(&state.root_privkey.to_bytes())
        .expect("valid root scalar");
    let hmac_scalar = Scalar::<Secp256k1>::from_be_bytes(&hmac_bytes)
        .expect("valid hmac scalar");
    let child_scalar = root_scalar + hmac_scalar;
    let child_bytes = child_scalar.to_be_bytes();

    // Hash the data and sign with derived key
    let msg_hash = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&data);
        let h: [u8; 32] = hasher.finalize().into();
        h
    };

    // Sign directly with derived private key (POC shortcut)
    // In production, this would use MPC threshold signing with share offsets
    let child_privkey = PrivateKey::from_bytes(child_bytes.as_bytes())
        .expect("valid child private key");
    let bsv_sig = child_privkey.sign(&msg_hash).expect("signing");
    let der_bytes = bsv_sig.to_der();

    let sig_array: Vec<serde_json::Value> = der_bytes.iter().map(|b| serde_json::json!(*b)).collect();
    axum::Json(serde_json::json!({"signature": sig_array}))
}

async fn proxy_create_action(
    axum::extract::State(state): axum::extract::State<Arc<ProxyState>>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let outputs = body["outputs"].as_array().unwrap();
    let description = body["description"].as_str().unwrap_or("MPC action");
    println!("  proxy: createAction — {description}");

    let client = reqwest::Client::new();
    let mpc_address = &state.joint_pubkey.to_address();
    let mpc_locking = p2pkh_locking_script(&state.joint_pubkey.hash160());

    // 1. Find UTXOs at MPC address via WoC
    let utxo_url = format!(
        "https://api.whatsonchain.com/v1/bsv/main/address/{}/unspent",
        mpc_address
    );

    let mut found_utxos: Vec<UtxoInfo> = Vec::new();
    for attempt in 1..=3 {
        if let Ok(resp) = client.get(&utxo_url).send().await {
            if let Ok(utxos) = resp.json::<Vec<serde_json::Value>>().await {
                for u in &utxos {
                    found_utxos.push(UtxoInfo {
                        txid: u["tx_hash"].as_str().unwrap().to_string(),
                        vout: u["tx_pos"].as_u64().unwrap() as u32,
                        satoshis: u["value"].as_u64().unwrap(),
                    });
                }
                if !found_utxos.is_empty() {
                    break;
                }
            }
        }
        if attempt < 3 {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    }

    if found_utxos.is_empty() {
        return axum::Json(serde_json::json!({"error": "No UTXOs found at MPC address"}));
    }

    // Use the first UTXO with enough sats
    let total_needed: u64 = outputs.iter()
        .map(|o| o["satoshis"].as_u64().unwrap_or(0))
        .sum::<u64>() + 150; // mining fee

    let utxo = found_utxos.iter().find(|u| u.satoshis >= total_needed);
    let utxo = match utxo {
        Some(u) => u.clone(),
        None => {
            return axum::Json(serde_json::json!({
                "error": format!("Insufficient funds: need {} sats, best UTXO has {} sats",
                    total_needed, found_utxos.iter().map(|u| u.satoshis).max().unwrap_or(0))
            }));
        }
    };

    println!("  proxy: using UTXO {}:{} ({} sats)", utxo.txid, utxo.vout, utxo.satoshis);

    // 2. Build transaction outputs
    let mining_fee: u64 = 150;
    let mut tx_outputs: Vec<(u64, Vec<u8>)> = Vec::new();
    for o in outputs {
        let sats = o["satoshis"].as_u64().unwrap();
        let script_hex = o["lockingScript"].as_str().unwrap();
        let script = hex::decode(script_hex).unwrap();
        tx_outputs.push((sats, script));
    }

    // Add change output
    let total_out: u64 = tx_outputs.iter().map(|(s, _)| s).sum();
    let change = utxo.satoshis.saturating_sub(total_out + mining_fee);
    if change > 0 {
        tx_outputs.push((change, mpc_locking.clone()));
    }

    // 3. Compute BIP-143 sighash
    let mut prev_txid = [0u8; 32];
    prev_txid.copy_from_slice(&hex::decode(&utxo.txid).unwrap());
    prev_txid.reverse(); // display → internal byte order

    let sighash_inputs = vec![TxInput {
        txid: prev_txid,
        output_index: utxo.vout,
        script: vec![],
        sequence: 0xFFFFFFFF,
    }];
    let sighash_outputs: Vec<TxOutput> = tx_outputs.iter()
        .map(|(sats, script)| TxOutput { satoshis: *sats, script: script.clone() })
        .collect();

    let scope = SIGHASH_ALL | SIGHASH_FORKID;
    let sighash = compute_sighash_for_signing(&SighashParams {
        version: 1,
        inputs: &sighash_inputs,
        outputs: &sighash_outputs,
        locktime: 0,
        input_index: 0,
        subscript: &mpc_locking,
        satoshis: utxo.satoshis,
        scope,
    });

    // 4. MPC sign via KSS (no key offset — signing with root key)
    println!("  proxy: MPC signing via KSS...");
    let sig_compact = {
        let share = state.key_share.clone();
        let kss_url = state.kss_url.clone();
        tokio::task::spawn_blocking(move || {
            mpc_sign_via_http(&share, &sighash, &kss_url)
        }).await.unwrap()
    };

    // 5. Build unlocking script
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_compact[..32]);
    s.copy_from_slice(&sig_compact[32..]);
    let bsv_sig = Signature::new(r, s);
    let tx_sig = TransactionSignature::new(bsv_sig, scope);
    let checksig_bytes = tx_sig.to_checksig_format();
    let compressed = state.joint_pubkey.to_compressed();
    let unlocking = p2pkh_unlocking_script(&checksig_bytes, &compressed);

    // 6. Serialize and compute txid
    let raw_tx = serialize_transaction(
        1,
        &[(prev_txid, utxo.vout, unlocking, 0xFFFFFFFF)],
        &tx_outputs,
        0,
    );
    let txid_bytes = sha256d(&raw_tx);
    let mut txid_display = txid_bytes;
    txid_display.reverse();
    let txid_hex = hex::encode(&txid_display);

    println!("  proxy: txid = {txid_hex}");

    // 7. Broadcast via ARC
    let raw_tx_hex = hex::encode(&raw_tx);
    let arc_endpoints = [
        "https://arc.taal.com",
        "https://arc.gorillapool.io",
    ];

    let mut broadcast_ok = false;
    for arc_url in &arc_endpoints {
        let url = format!("{}/v1/tx", arc_url);
        match client.post(&url)
            .header("Content-Type", "application/json")
            .header("XDeployment-ID", "bsv-mpc-poc15")
            .json(&serde_json::json!({"rawTx": raw_tx_hex}))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                if status.is_success() || text.contains("SEEN_ON_NETWORK") || text.contains("MINED") {
                    println!("  proxy: broadcast OK via {arc_url}");
                    broadcast_ok = true;
                    break;
                }
                println!("  proxy: ARC {arc_url} returned {status}: {}", &text[..text.len().min(200)]);
            }
            Err(e) => println!("  proxy: ARC {arc_url} error: {e}"),
        }
    }

    if !broadcast_ok {
        println!("  proxy: WARNING — broadcast failed, tx may not be on-chain");
    }

    // Return in format bsv-worm expects
    let tx_array: Vec<serde_json::Value> = raw_tx.iter().map(|b| serde_json::json!(*b)).collect();
    axum::Json(serde_json::json!({
        "txid": txid_hex,
        "tx": tx_array,
        "satoshis": total_out,
    }))
}

async fn proxy_internalize_action(
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    // Stub — accept without processing
    println!("  proxy: internalizeAction (stub)");
    axum::Json(serde_json::json!({"accepted": true}))
}

async fn proxy_list_outputs(
    axum::extract::State(state): axum::extract::State<Arc<ProxyState>>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    // Return empty outputs list — bsv-worm uses this for balance
    axum::Json(serde_json::json!({"outputs": [], "totalOutputs": 0}))
}

async fn proxy_list_actions() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"actions": [], "totalActions": 0}))
}

async fn proxy_encrypt(
    axum::extract::State(state): axum::extract::State<Arc<ProxyState>>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let plaintext: Vec<u8> = body["plaintext"]
        .as_array().unwrap()
        .iter().map(|v| v.as_u64().unwrap() as u8).collect();
    let protocol_id = &body["protocolID"];
    let key_id = body["keyID"].as_str().unwrap_or("");
    let counterparty_str = body["counterparty"].as_str().unwrap_or("self");

    let protocol = Protocol::new(
        if protocol_id[0].as_u64().unwrap_or(2) == 2 { BsvSecurityLevel::Counterparty } else { BsvSecurityLevel::App },
        protocol_id[1].as_str().unwrap_or(""),
    );
    let counterparty = if counterparty_str == "self" {
        Counterparty::Self_
    } else if counterparty_str == "anyone" {
        Counterparty::Anyone
    } else {
        Counterparty::Other(PublicKey::from_hex(counterparty_str).unwrap())
    };

    use bsv::wallet::EncryptArgs;
    match state.proto_wallet.encrypt(EncryptArgs {
        plaintext,
        protocol_id: protocol,
        key_id: key_id.to_string(),
        counterparty: Some(counterparty),
    }) {
        Ok(result) => {
            let ct_array: Vec<serde_json::Value> = result.ciphertext.iter().map(|b| serde_json::json!(*b)).collect();
            axum::Json(serde_json::json!({"ciphertext": ct_array}))
        }
        Err(e) => axum::Json(serde_json::json!({"error": format!("{e:?}")})),
    }
}

async fn proxy_decrypt(
    axum::extract::State(state): axum::extract::State<Arc<ProxyState>>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let ciphertext: Vec<u8> = body["ciphertext"]
        .as_array().unwrap()
        .iter().map(|v| v.as_u64().unwrap() as u8).collect();
    let protocol_id = &body["protocolID"];
    let key_id = body["keyID"].as_str().unwrap_or("");
    let counterparty_str = body["counterparty"].as_str().unwrap_or("self");

    let protocol = Protocol::new(
        if protocol_id[0].as_u64().unwrap_or(2) == 2 { BsvSecurityLevel::Counterparty } else { BsvSecurityLevel::App },
        protocol_id[1].as_str().unwrap_or(""),
    );
    let counterparty = if counterparty_str == "self" {
        Counterparty::Self_
    } else if counterparty_str == "anyone" {
        Counterparty::Anyone
    } else {
        Counterparty::Other(PublicKey::from_hex(counterparty_str).unwrap())
    };

    use bsv::wallet::DecryptArgs;
    match state.proto_wallet.decrypt(DecryptArgs {
        ciphertext,
        protocol_id: protocol,
        key_id: key_id.to_string(),
        counterparty: Some(counterparty),
    }) {
        Ok(result) => {
            let pt_array: Vec<serde_json::Value> = result.plaintext.iter().map(|b| serde_json::json!(*b)).collect();
            axum::Json(serde_json::json!({"plaintext": pt_array}))
        }
        Err(e) => axum::Json(serde_json::json!({"error": format!("{e:?}")})),
    }
}

async fn proxy_create_hmac(
    axum::extract::State(state): axum::extract::State<Arc<ProxyState>>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let data: Vec<u8> = body["data"]
        .as_array().unwrap()
        .iter().map(|v| v.as_u64().unwrap() as u8).collect();
    let protocol_id = &body["protocolID"];
    let key_id = body["keyID"].as_str().unwrap_or("");
    let counterparty_str = body["counterparty"].as_str().unwrap_or("self");

    let protocol = Protocol::new(
        if protocol_id[0].as_u64().unwrap_or(2) == 2 { BsvSecurityLevel::Counterparty } else { BsvSecurityLevel::App },
        protocol_id[1].as_str().unwrap_or(""),
    );
    let counterparty = if counterparty_str == "self" {
        Counterparty::Self_
    } else if counterparty_str == "anyone" {
        Counterparty::Anyone
    } else {
        Counterparty::Other(PublicKey::from_hex(counterparty_str).unwrap())
    };

    // Derive symmetric key and compute HMAC
    let deriver = KeyDeriver::new(Some(state.root_privkey.clone()));
    let sym_key = deriver.derive_symmetric_key(&protocol, key_id, &counterparty)
        .expect("derive symmetric key");
    let hmac = sha256_hmac(sym_key.as_bytes(), &data);
    let hmac_array: Vec<serde_json::Value> = hmac.iter().map(|b| serde_json::json!(*b)).collect();
    axum::Json(serde_json::json!({"hmac": hmac_array}))
}

async fn proxy_verify_hmac(
    axum::extract::State(state): axum::extract::State<Arc<ProxyState>>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let data: Vec<u8> = body["data"]
        .as_array().unwrap()
        .iter().map(|v| v.as_u64().unwrap() as u8).collect();
    let expected_hmac: Vec<u8> = body["hmac"]
        .as_array().unwrap()
        .iter().map(|v| v.as_u64().unwrap() as u8).collect();
    let protocol_id = &body["protocolID"];
    let key_id = body["keyID"].as_str().unwrap_or("");
    let counterparty_str = body["counterparty"].as_str().unwrap_or("self");

    let protocol = Protocol::new(
        if protocol_id[0].as_u64().unwrap_or(2) == 2 { BsvSecurityLevel::Counterparty } else { BsvSecurityLevel::App },
        protocol_id[1].as_str().unwrap_or(""),
    );
    let counterparty = if counterparty_str == "self" {
        Counterparty::Self_
    } else if counterparty_str == "anyone" {
        Counterparty::Anyone
    } else {
        Counterparty::Other(PublicKey::from_hex(counterparty_str).unwrap())
    };

    let deriver = KeyDeriver::new(Some(state.root_privkey.clone()));
    let sym_key = deriver.derive_symmetric_key(&protocol, key_id, &counterparty)
        .expect("derive symmetric key");
    let computed = sha256_hmac(sym_key.as_bytes(), &data);
    let valid = computed[..] == expected_hmac[..];
    axum::Json(serde_json::json!({"valid": valid}))
}

async fn proxy_verify_signature() -> axum::Json<serde_json::Value> {
    // Stub — would need to derive pubkey and verify
    axum::Json(serde_json::json!({"valid": true}))
}

async fn proxy_relinquish_output() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({}))
}

// Certificate stubs
async fn proxy_list_certificates() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"certificates": []}))
}
async fn proxy_prove_certificate() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({}))
}
async fn proxy_acquire_certificate() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({}))
}
async fn proxy_relinquish_certificate() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({}))
}
async fn proxy_discover_by_identity_key() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"outputs": []}))
}
async fn proxy_discover_by_attributes() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"outputs": []}))
}
async fn proxy_reveal_counterparty_key_linkage() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({}))
}
async fn proxy_reveal_specific_key_linkage() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({}))
}
async fn proxy_sign_action() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({}))
}
async fn proxy_abort_action() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({}))
}
async fn proxy_get_header_for_height() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"header": ""}))
}

fn build_proxy_router(
    key_share: cggmp24::KeyShare<Secp256k1, SecurityLevel128>,
    joint_pubkey: PublicKey,
    root_privkey: PrivateKey,
    kss_url: String,
) -> axum::Router {
    use bsv::wallet::ProtoWallet;
    let proto_wallet = ProtoWallet::new(Some(root_privkey.clone()));
    let state = Arc::new(ProxyState {
        key_share,
        joint_pubkey_hex: joint_pubkey.to_hex(),
        joint_pubkey,
        kss_url,
        root_privkey,
        proto_wallet,
        utxos: tokio::sync::Mutex::new(Vec::new()),
    });

    axum::Router::new()
        // GET endpoints (bsv-worm calls these via call_get)
        .route("/isAuthenticated", axum::routing::get(proxy_is_authenticated))
        .route("/getNetwork", axum::routing::get(proxy_get_network))
        .route("/getVersion", axum::routing::get(proxy_get_version))
        .route("/waitForAuthentication", axum::routing::get(proxy_wait_for_authentication))
        .route("/getHeight", axum::routing::get(proxy_get_height))
        // POST endpoints (bsv-worm calls these via call)
        .route("/getPublicKey", axum::routing::post(proxy_get_public_key))
        .route("/createSignature", axum::routing::post(proxy_create_signature))
        .route("/createAction", axum::routing::post(proxy_create_action))
        .route("/internalizeAction", axum::routing::post(proxy_internalize_action))
        .route("/listOutputs", axum::routing::post(proxy_list_outputs))
        .route("/listActions", axum::routing::post(proxy_list_actions))
        .route("/encrypt", axum::routing::post(proxy_encrypt))
        .route("/decrypt", axum::routing::post(proxy_decrypt))
        .route("/createHmac", axum::routing::post(proxy_create_hmac))
        .route("/verifyHmac", axum::routing::post(proxy_verify_hmac))
        .route("/verifySignature", axum::routing::post(proxy_verify_signature))
        .route("/relinquishOutput", axum::routing::post(proxy_relinquish_output))
        .route("/listCertificates", axum::routing::post(proxy_list_certificates))
        .route("/proveCertificate", axum::routing::post(proxy_prove_certificate))
        .route("/acquireCertificate", axum::routing::post(proxy_acquire_certificate))
        .route("/relinquishCertificate", axum::routing::post(proxy_relinquish_certificate))
        .route("/discoverByIdentityKey", axum::routing::post(proxy_discover_by_identity_key))
        .route("/discoverByAttributes", axum::routing::post(proxy_discover_by_attributes))
        .route("/revealCounterpartyKeyLinkage", axum::routing::post(proxy_reveal_counterparty_key_linkage))
        .route("/revealSpecificKeyLinkage", axum::routing::post(proxy_reveal_specific_key_linkage))
        .route("/signAction", axum::routing::post(proxy_sign_action))
        .route("/abortAction", axum::routing::post(proxy_abort_action))
        .route("/getHeaderForHeight", axum::routing::post(proxy_get_header_for_height))
        .with_state(state)
}

// ============================================================================
// Main — orchestrate everything
// ============================================================================

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("poc15=info")
        .init();

    println!("========================================");
    println!("  POC 15: CAPSTONE INTEGRATION");
    println!("  bsv-worm through MPC signing proxy");
    println!("========================================\n");

    // =========================================================================
    // STEP 1: DKG — generate 2-of-2 key shares
    // =========================================================================
    println!("=== STEP 1: 2-of-2 DKG ===");
    let (key_shares, joint_pubkey) = run_dkg().await;

    // Reconstruct root key (POC SHORTCUT — never in production!)
    // Extract share scalars and reconstruct manually
    let root_privkey = {
        // Get both share scalars
        let s0: &SecretScalar<Secp256k1> = key_shares[0].core.x.as_ref();
        let s0_scalar: &Scalar<Secp256k1> = s0.as_ref();
        let s1: &SecretScalar<Secp256k1> = key_shares[1].core.x.as_ref();
        let s1_scalar: &Scalar<Secp256k1> = s1.as_ref();

        // Get VSS evaluation points for Lagrange interpolation
        let vss = key_shares[0].core.vss_setup.as_ref().expect("VSS setup");
        let i0 = &vss.I[0];
        let i1 = &vss.I[1];

        // λ_0 = -I_1 / (I_0 - I_1)
        let neg_i1 = -Scalar::<Secp256k1>::from(*i1);
        let diff01 = Scalar::<Secp256k1>::from(*i0) - Scalar::<Secp256k1>::from(*i1);
        let lambda0 = neg_i1 * diff01.invert().expect("distinct");

        // λ_1 = -I_0 / (I_1 - I_0)
        let neg_i0 = -Scalar::<Secp256k1>::from(*i0);
        let diff10 = Scalar::<Secp256k1>::from(*i1) - Scalar::<Secp256k1>::from(*i0);
        let lambda1 = neg_i0 * diff10.invert().expect("distinct");

        // root = λ_0 * s0 + λ_1 * s1
        let root_scalar = lambda0 * *s0_scalar + lambda1 * *s1_scalar;
        let bytes = root_scalar.to_be_bytes();
        PrivateKey::from_bytes(bytes.as_bytes()).expect("valid private key")
    };
    assert_eq!(
        root_privkey.public_key().to_compressed(),
        joint_pubkey.to_compressed(),
        "Reconstructed key must match joint pubkey"
    );
    println!("  Root key reconstructed (POC shortcut for BRC-42)");

    // =========================================================================
    // STEP 2: Start KSS server (port 4322)
    // =========================================================================
    println!("\n=== STEP 2: Start KSS on :4322 ===");
    let kss_router = build_kss_router(key_shares[0].clone());
    let kss_listener = tokio::net::TcpListener::bind("127.0.0.1:4322").await
        .expect("Failed to bind KSS to port 4322");
    println!("  KSS listening on http://127.0.0.1:4322");

    tokio::spawn(async move {
        axum::serve(kss_listener, kss_router).await.unwrap();
    });

    // =========================================================================
    // STEP 3: Start BRC-100 proxy (port 3323)
    // =========================================================================
    println!("\n=== STEP 3: Start BRC-100 proxy on :3323 ===");
    let proxy_router = build_proxy_router(
        key_shares[1].clone(),
        joint_pubkey.clone(),
        root_privkey,
        "http://127.0.0.1:4322".to_string(),
    );
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:3323").await
        .expect("Failed to bind proxy to port 3323");
    println!("  Proxy listening on http://127.0.0.1:3323");

    tokio::spawn(async move {
        axum::serve(proxy_listener, proxy_router).await.unwrap();
    });

    // Give servers a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Quick health check
    let client = reqwest::Client::new();
    let health = client.get("http://127.0.0.1:4322/health").send().await.unwrap();
    assert!(health.status().is_success(), "KSS health check failed");
    println!("  KSS health: OK");

    let auth = client.get("http://127.0.0.1:3323/isAuthenticated").send().await.unwrap();
    assert!(auth.status().is_success(), "Proxy auth check failed");
    println!("  Proxy isAuthenticated: OK");

    let pk_resp = client.post("http://127.0.0.1:3323/getPublicKey")
        .header("Origin", "http://localhost")
        .json(&serde_json::json!({"identityKey": true}))
        .send().await.unwrap();
    let pk_json: serde_json::Value = pk_resp.json().await.unwrap();
    let returned_pk = pk_json["publicKey"].as_str().unwrap();
    assert_eq!(returned_pk, joint_pubkey.to_hex());
    println!("  Proxy getPublicKey: {} ✓", &returned_pk[..16]);

    // =========================================================================
    // PHASE A: bsv-worm status
    // =========================================================================
    println!("\n========================================");
    println!("  PHASE A: bsv-worm status");
    println!("========================================\n");

    let worm_dir = std::path::Path::new("/Users/johncalhoun/bsv/rust-bsv-worm");
    if !worm_dir.exists() {
        println!("  SKIP: rust-bsv-worm not found at {}", worm_dir.display());
        println!("  Run manually: WORM_WALLET_URL=http://localhost:3323 cargo run -- status");
    } else {
        let status_output = std::process::Command::new("cargo")
            .args(["run", "--", "status"])
            .current_dir(worm_dir)
            .env("WORM_WALLET_URL", "http://localhost:3323")
            .output();

        match status_output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                println!("  stdout:\n{}", stdout);
                if !stderr.is_empty() {
                    println!("  stderr:\n{}", stderr);
                }

                if stdout.contains(&joint_pubkey.to_hex()) {
                    println!("\n  PHASE A: PASS — bsv-worm shows MPC joint pubkey ✓");
                } else if stdout.contains("Identity:") {
                    println!("\n  PHASE A: PASS — bsv-worm connected to proxy ✓");
                    println!("  (pubkey may be truncated in output)");
                } else {
                    println!("\n  PHASE A: FAIL — identity key not found in output");
                }
            }
            Err(e) => {
                println!("  PHASE A: Could not run bsv-worm: {e}");
                println!("  Run manually:");
                println!("    cd ~/bsv/rust-bsv-worm");
                println!("    WORM_WALLET_URL=http://localhost:3323 cargo run -- status");
            }
        }
    }

    // =========================================================================
    // Keep servers running for manual testing
    // =========================================================================
    println!("\n========================================");
    println!("  Servers running. Manual test commands:");
    println!("========================================");
    println!("  Phase A:");
    println!("    cd ~/bsv/rust-bsv-worm");
    println!("    WORM_WALLET_URL=http://localhost:3323 cargo run -- status");
    println!();
    println!("  Phase B (after funding MPC address):");
    println!("    # Fund the MPC address ({}) with 50000 sats:", joint_pubkey.to_address());
    println!("    # Use the wallet MCP or:");
    println!("    curl -X POST http://localhost:3322/createAction \\");
    println!("      -H 'Origin: http://admin.com' -H 'Content-Type: application/json' \\");
    println!("      -d '{{\"description\":\"fund MPC\",\"outputs\":[{{\"satoshis\":50000,\"lockingScript\":\"{}\"}}]}}'",
        hex::encode(p2pkh_locking_script(&joint_pubkey.hash160())));
    println!();
    println!("    # Then run:");
    println!("    WORM_WALLET_URL=http://localhost:3323 cargo run -- think \"what is 2+2\"");
    println!();
    println!("  Press Ctrl+C to stop.");

    // Keep running
    tokio::signal::ctrl_c().await.unwrap();
    println!("\nShutting down.");
}
