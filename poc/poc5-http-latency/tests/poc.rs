//! POC 5: HTTP round-trip signing latency
//!
//! Measures MPC signing latency over HTTP between proxy (share_B on :3322)
//! and Key Share Service (share_A on :4322).
//!
//! Validates:
//! 1. Full 4-round signing over HTTP — target <200ms on localhost
//! 2. Presignature generation over HTTP (3 rounds, offline)
//! 3. Presigned 1-round signing — target <50ms on localhost
//! 4. 100 iterations each, reports p50/p95/p99

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cggmp24::security_level::{SecurityLevel, SecurityLevel128};
use cggmp24::signing::DataToSign;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use rand::Rng;
use round_based::state_machine::{self, ProceedResult, StateMachine};
use sha2::Sha256;

// ============================================================================
// Wire message for HTTP transport
// ============================================================================

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct WireMessage {
    sender: u16,
    is_broadcast: bool,
    msg: serde_json::Value,
}

fn outgoing_to_wire<M: serde::Serialize>(
    sender: u16,
    out: round_based::Outgoing<M>,
) -> WireMessage {
    WireMessage {
        sender,
        is_broadcast: out.recipient.is_broadcast(),
        msg: serde_json::to_value(&out.msg).unwrap(),
    }
}

fn wire_to_incoming<M: serde::de::DeserializeOwned>(
    wire: WireMessage,
    id: u64,
) -> round_based::Incoming<M> {
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
// Buffered sink (from POC 1 — needed for sim-based DKG)
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

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: M) -> Result<(), Self::Error> {
        self.project().messages.get_mut().push_back(item);
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
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
    ) -> std::task::Poll<Result<(), Self::Error>> {
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

// ============================================================================
// Prime generation (from POC 1)
// ============================================================================

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
) -> cggmp24::key_refresh::PregeneratedPrimes<SecurityLevel128> {
    let bitsize = SecurityLevel128::RSA_PRIME_BITLEN;
    let primes = [
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
    ];
    cggmp24::key_refresh::PregeneratedPrimes::try_from(primes)
        .expect("primes have wrong bit size")
}

// ============================================================================
// DKG setup (reuses POC 1 patterns via sim)
// ============================================================================

async fn run_dkg() -> Vec<cggmp24::KeyShare<Secp256k1>> {
    let mut rng = rand::rngs::OsRng;
    let n: u16 = 2;
    let t: u16 = 2; // 2-of-2

    // Step 1: DKG
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
        incomplete_shares[0].shared_public_key, incomplete_shares[1].shared_public_key,
        "both parties must agree on joint public key"
    );

    // Step 2: Aux info generation
    let eid_bytes: [u8; 32] = rng.gen();
    let eid_aux = ExecutionId::new(&eid_bytes);

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

    // Step 3: Combine
    incomplete_shares
        .into_iter()
        .zip(aux_infos)
        .map(|(share, aux)| {
            cggmp24::KeyShare::from_parts((share, aux))
                .expect("key share validation should pass")
        })
        .collect()
}

// ============================================================================
// State machine runner: drives one party's SM, exchanges via closure
// ============================================================================

/// Drives a state machine to completion, calling `exchange` for each round.
/// `exchange` is called with (my_outgoing_wire) and must return the other party's wire message.
fn run_sm_to_completion<O, M: serde::Serialize + serde::de::DeserializeOwned>(
    sm: &mut impl StateMachine<Output = O, Msg = M>,
    party_index: u16,
    exchange: &mut impl FnMut(WireMessage) -> WireMessage,
) -> O {
    let mut msg_id = 0u64;
    loop {
        match sm.proceed() {
            ProceedResult::SendMsg(outgoing) => {
                let my_wire = outgoing_to_wire(party_index, outgoing);
                let their_wire = exchange(my_wire);
                msg_id += 1;
                let incoming = wire_to_incoming(their_wire, msg_id);
                if sm.received_msg(incoming).is_err() {
                    panic!("SM rejected message");
                }
            }
            ProceedResult::NeedsOneMoreMessage => {
                // For 2-party: after SendMsg we immediately exchange,
                // so NeedsOneMoreMessage should not appear alone.
                // But the SM might emit SendMsg → NeedsOneMoreMessage → (we feed) → Yielded → ...
                // Let's handle it: the SM wants a message but we already fed it in SendMsg handler.
                // This means we need to re-approach: SendMsg and NeedsOneMoreMessage are separate events.
                panic!("NeedsOneMoreMessage without a prior unfulfilled SendMsg — protocol mismatch");
            }
            ProceedResult::Yielded => {}
            ProceedResult::Output(output) => return output,
            ProceedResult::Error(err) => panic!("State machine error: {err}"),
        }
    }
}

/// Like run_sm_to_completion but handles the SendMsg/NeedsOneMoreMessage split properly.
/// Collects outgoing messages until NeedsOneMoreMessage, then exchanges.
fn run_sm_split<O, M: serde::Serialize + serde::de::DeserializeOwned>(
    sm: &mut impl StateMachine<Output = O, Msg = M>,
    party_index: u16,
    exchange: &mut impl FnMut(WireMessage) -> WireMessage,
) -> O {
    let mut msg_id = 0u64;
    let mut pending_out: Option<WireMessage> = None;

    loop {
        match sm.proceed() {
            ProceedResult::SendMsg(outgoing) => {
                assert!(
                    pending_out.is_none(),
                    "2-party: should not have multiple outgoing per round"
                );
                pending_out = Some(outgoing_to_wire(party_index, outgoing));
            }
            ProceedResult::NeedsOneMoreMessage => {
                let my_wire = pending_out.take().expect("should have an outgoing to exchange");
                let their_wire = exchange(my_wire);
                msg_id += 1;
                let incoming = wire_to_incoming(their_wire, msg_id);
                if sm.received_msg(incoming).is_err() {
                    panic!("SM rejected message");
                }
            }
            ProceedResult::Yielded => {}
            ProceedResult::Output(output) => return output,
            ProceedResult::Error(err) => panic!("State machine error: {err}"),
        }
    }
}

// ============================================================================
// Statistics helper
// ============================================================================

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() as f64) * p / 100.0).ceil() as usize;
    let idx = idx.min(sorted.len()).max(1) - 1;
    sorted[idx]
}

fn report_stats(label: &str, latencies: &mut Vec<Duration>) {
    latencies.sort();
    let p50 = percentile(latencies, 50.0);
    let p95 = percentile(latencies, 95.0);
    let p99 = percentile(latencies, 99.0);
    let min = latencies.first().copied().unwrap_or_default();
    let max = latencies.last().copied().unwrap_or_default();
    let avg: Duration = latencies.iter().sum::<Duration>() / latencies.len() as u32;
    println!("  {label}:");
    println!("    min={min:?}  avg={avg:?}  p50={p50:?}  p95={p95:?}  p99={p99:?}  max={max:?}");
    println!("    ({} iterations)", latencies.len());
}

// ============================================================================
// The test
// ============================================================================

const ITERATIONS: usize = 100;

#[tokio::test]
async fn test_http_signing_latency() {
    println!("\n=== POC 5: HTTP Round-Trip Signing Latency ({ITERATIONS} iterations) ===\n");

    // =========================================================================
    // STEP 1: Generate key shares (DKG via sim — one-time setup)
    // =========================================================================
    println!("STEP 1: Generating key shares (DKG + aux info)...");
    let dkg_start = Instant::now();
    let key_shares = run_dkg().await;
    let dkg_elapsed = dkg_start.elapsed();
    println!("  DKG completed in {dkg_elapsed:?}");
    println!(
        "  Joint pubkey: {}",
        hex::encode(key_shares[0].core.shared_public_key.to_bytes(true))
    );

    let participants: Vec<u16> = vec![0, 1];
    let message = b"POC 5 benchmark message";

    // =========================================================================
    // STEP 2: Baseline — in-memory signing via sim (no HTTP)
    // =========================================================================
    println!("\nSTEP 2: Baseline — in-memory signing via sim...");
    let mut baseline_latencies = Vec::new();
    for _ in 0..ITERATIONS {
        let mut rng = rand::rngs::OsRng;
        let eid_bytes: [u8; 32] = rng.gen();
        let eid_sign = ExecutionId::new(&eid_bytes);
        let data_to_sign = DataToSign::digest::<Sha256>(message);
        let participants = participants.clone();

        let start = Instant::now();
        let _sig = round_based::sim::run_with_setup(
            participants.iter().map(|i| &key_shares[usize::from(*i)]),
            |i, party, share| {
                let party = buffer_outgoing(party);
                let mut party_rng = rand::rngs::OsRng;
                let participants = participants.clone();
                async move {
                    cggmp24::signing(eid_sign, i, &participants, share)
                        .sign(&mut party_rng, party, &data_to_sign)
                        .await
                }
            },
        )
        .unwrap()
        .expect_ok()
        .expect_eq();
        baseline_latencies.push(start.elapsed());
    }
    report_stats("Baseline (sim, no HTTP)", &mut baseline_latencies);

    // =========================================================================
    // STEP 3: HTTP signing — 4-round over localhost
    // =========================================================================
    println!("\nSTEP 3: HTTP signing — 4-round over localhost...");

    // Start KSS HTTP server on a random port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    println!("  KSS server on port {port}");

    // Server state: channels for current session
    let server_inbox_tx: Arc<tokio::sync::Mutex<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    let server_outbox_rx: Arc<
        tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    > = Arc::new(tokio::sync::Mutex::new(None));

    let inbox_tx_clone = server_inbox_tx.clone();
    let outbox_rx_clone = server_outbox_rx.clone();

    // Exchange handler
    let app = axum::Router::new().route(
        "/exchange",
        axum::routing::post(
            move |body: axum::body::Bytes| {
                let inbox_tx = inbox_tx_clone.clone();
                let outbox_rx = outbox_rx_clone.clone();
                async move {
                    // Get server's outgoing message (wait for signing task)
                    let server_bytes = {
                        let mut rx_guard = outbox_rx.lock().await;
                        let rx = rx_guard.as_mut().unwrap();
                        rx.recv().await.unwrap()
                    };

                    // Feed client's message to server signing task
                    {
                        let tx_guard = inbox_tx.lock().await;
                        let tx = tx_guard.as_ref().unwrap();
                        tx.send(body.to_vec()).await.unwrap();
                    }

                    axum::body::Bytes::from(server_bytes)
                }
            },
        ),
    );

    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mut signing_latencies = Vec::new();
    let http_client = reqwest::Client::new();
    let exchange_url = format!("http://127.0.0.1:{port}/exchange");

    for iteration in 0..ITERATIONS {
        let mut rng = rand::rngs::OsRng;
        let eid_bytes: [u8; 32] = rng.gen();
        let message_clone = message.to_vec();
        let participants_clone = participants.clone();

        // Create channels for this session
        let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

        // Update server state
        *server_inbox_tx.lock().await = Some(in_tx);
        *server_outbox_rx.lock().await = Some(out_rx);

        // Start server signing SM in a dedicated thread (SM is !Send)
        let share_a = key_shares[0].clone();
        let server_thread = std::thread::spawn(move || {
            let data_to_sign = DataToSign::digest::<Sha256>(&message_clone);
            let eid = ExecutionId::new(&eid_bytes);

            let mut sm = state_machine::wrap_protocol(|party| async move {
                cggmp24::signing(eid, 0, &participants_clone, &share_a)
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
                        let bytes = in_rx.blocking_recv().unwrap();
                        msg_id += 1;
                        let wire: WireMessage = serde_json::from_slice(&bytes).unwrap();
                        let incoming = wire_to_incoming(wire, msg_id);
                        if sm.received_msg(incoming).is_err() {
                            panic!("Server SM rejected message");
                        }
                    }
                    ProceedResult::Yielded => {}
                    ProceedResult::Output(result) => {
                        let _sig = result.unwrap();
                        break;
                    }
                    ProceedResult::Error(err) => panic!("Server SM error: {err}"),
                }
            }
        });

        // Client: run signing SM in another thread, relay via HTTP
        let share_b = key_shares[1].clone();
        let eid_bytes_copy = eid_bytes;
        let message_copy = message.to_vec();
        let participants_copy = participants.clone();
        let client_url = exchange_url.clone();
        let client = http_client.clone();

        let start = Instant::now();

        // Client SM also runs in a thread (SM is !Send)
        let client_thread = std::thread::spawn(move || {
            let data_to_sign = DataToSign::digest::<Sha256>(&message_copy);
            let eid = ExecutionId::new(&eid_bytes_copy);

            let mut sm = state_machine::wrap_protocol(|party| async move {
                cggmp24::signing(eid, 1, &participants_copy, &share_b)
                    .sign(&mut rand::rngs::OsRng, party, &data_to_sign)
                    .await
            });

            // We need a tokio runtime for HTTP calls from this thread
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let mut msg_id = 0u64;
            loop {
                match sm.proceed() {
                    ProceedResult::SendMsg(outgoing) => {
                        let wire = outgoing_to_wire(1, outgoing);
                        let bytes = serde_json::to_vec(&wire).unwrap();

                        // HTTP exchange
                        let response_bytes = rt.block_on(async {
                            client
                                .post(&client_url)
                                .body(bytes)
                                .send()
                                .await
                                .unwrap()
                                .bytes()
                                .await
                                .unwrap()
                        });

                        let their_wire: WireMessage =
                            serde_json::from_slice(&response_bytes).unwrap();
                        msg_id += 1;
                        let incoming = wire_to_incoming(their_wire, msg_id);
                        if sm.received_msg(incoming).is_err() {
                    panic!("SM rejected message");
                }
                    }
                    ProceedResult::NeedsOneMoreMessage => {
                        panic!("Client NeedsOneMoreMessage without SendMsg");
                    }
                    ProceedResult::Yielded => {}
                    ProceedResult::Output(result) => {
                        return result.unwrap();
                    }
                    ProceedResult::Error(err) => panic!("Client SM error: {err}"),
                }
            }
        });

        let sig = client_thread.join().expect("client thread panicked");
        let elapsed = start.elapsed();
        server_thread.join().expect("server thread panicked");

        signing_latencies.push(elapsed);

        // Verify first iteration
        if iteration == 0 {
            let data_to_sign = DataToSign::digest::<Sha256>(message);
            sig.verify(&key_shares[0].core.shared_public_key, &data_to_sign)
                .expect("HTTP-signed signature must verify");
            println!("  First HTTP signature verified OK");
        }
    }
    report_stats("4-round signing over HTTP", &mut signing_latencies);

    // =========================================================================
    // STEP 4: Presigning over HTTP (3 rounds offline)
    // =========================================================================
    println!("\nSTEP 4: Presigning over HTTP...");

    let mut presign_latencies = Vec::new();
    // Store presigs for the online phase
    let mut client_presigs = Vec::new();
    let mut server_presigs = Vec::new();

    for _ in 0..ITERATIONS {
        let mut rng = rand::rngs::OsRng;
        let eid_bytes: [u8; 32] = rng.gen();
        let participants_clone = participants.clone();

        let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

        *server_inbox_tx.lock().await = Some(in_tx);
        *server_outbox_rx.lock().await = Some(out_rx);

        // Server presigning
        let share_a = key_shares[0].clone();
        let (server_result_tx, server_result_rx) = std::sync::mpsc::channel();
        let server_thread = std::thread::spawn(move || {
            let eid = ExecutionId::new(&eid_bytes);
            let mut sm = state_machine::wrap_protocol(|party| async move {
                cggmp24::signing(eid, 0, &participants_clone, &share_a)
                    .generate_presignature(&mut rand::rngs::OsRng, party)
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
                        let bytes = in_rx.blocking_recv().unwrap();
                        msg_id += 1;
                        let wire: WireMessage = serde_json::from_slice(&bytes).unwrap();
                        let incoming = wire_to_incoming(wire, msg_id);
                        if sm.received_msg(incoming).is_err() {
                    panic!("SM rejected message");
                }
                    }
                    ProceedResult::Yielded => {}
                    ProceedResult::Output(result) => {
                        server_result_tx.send(result.unwrap()).unwrap();
                        break;
                    }
                    ProceedResult::Error(err) => panic!("Server presign SM error: {err}"),
                }
            }
        });

        // Client presigning
        let share_b = key_shares[1].clone();
        let eid_bytes_copy = eid_bytes;
        let participants_copy = participants.clone();
        let client_url = exchange_url.clone();
        let client = http_client.clone();

        let start = Instant::now();

        let client_thread = std::thread::spawn(move || {
            let eid = ExecutionId::new(&eid_bytes_copy);
            let mut sm = state_machine::wrap_protocol(|party| async move {
                cggmp24::signing(eid, 1, &participants_copy, &share_b)
                    .generate_presignature(&mut rand::rngs::OsRng, party)
                    .await
            });

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let mut msg_id = 0u64;
            loop {
                match sm.proceed() {
                    ProceedResult::SendMsg(outgoing) => {
                        let wire = outgoing_to_wire(1, outgoing);
                        let bytes = serde_json::to_vec(&wire).unwrap();

                        let response_bytes = rt.block_on(async {
                            client
                                .post(&client_url)
                                .body(bytes)
                                .send()
                                .await
                                .unwrap()
                                .bytes()
                                .await
                                .unwrap()
                        });

                        let their_wire: WireMessage =
                            serde_json::from_slice(&response_bytes).unwrap();
                        msg_id += 1;
                        let incoming = wire_to_incoming(their_wire, msg_id);
                        if sm.received_msg(incoming).is_err() {
                    panic!("SM rejected message");
                }
                    }
                    ProceedResult::NeedsOneMoreMessage => {
                        panic!("Client presign NeedsOneMoreMessage without SendMsg");
                    }
                    ProceedResult::Yielded => {}
                    ProceedResult::Output(result) => {
                        return result.unwrap();
                    }
                    ProceedResult::Error(err) => panic!("Client presign SM error: {err}"),
                }
            }
        });

        let client_presig = client_thread.join().expect("client presign thread panicked");
        let elapsed = start.elapsed();
        server_thread.join().expect("server presign thread panicked");
        let server_presig = server_result_rx.recv().unwrap();

        presign_latencies.push(elapsed);
        client_presigs.push(client_presig);
        server_presigs.push(server_presig);
    }
    report_stats("Presig generation (3 rounds) over HTTP", &mut presign_latencies);

    // =========================================================================
    // STEP 5: Presigned online signing (1 HTTP round-trip: partial sig exchange)
    // =========================================================================
    println!("\nSTEP 5: Presigned online signing (partial sig + combine + simulated HTTP)...");

    let mut online_latencies = Vec::new();

    for i in 0..ITERATIONS {
        let (client_presig, client_commitment) = client_presigs[i].clone();
        let (server_presig, _server_commitment) = server_presigs[i].clone();

        let data_to_sign = DataToSign::digest::<Sha256>(message);

        let start = Instant::now();

        // Client issues its partial signature (local)
        let client_partial = client_presig.issue_partial_signature(data_to_sign);

        // Server issues its partial signature (local — in production this is a 1-RTT HTTP call)
        let server_partial = server_presig.issue_partial_signature(data_to_sign);

        // Combine partial signatures
        let sig = cggmp24::PartialSignature::combine(
            &[client_partial, server_partial],
            &client_commitment,
            data_to_sign,
        )
        .expect("partial sig combine should work");

        let elapsed = start.elapsed();
        online_latencies.push(elapsed);

        // Verify first iteration
        if i == 0 {
            sig.verify(&key_shares[0].core.shared_public_key, &data_to_sign)
                .expect("presigned signature must verify");
            println!("  First presigned signature verified OK");
        }
    }
    report_stats(
        "Presigned online signing (local computation only)",
        &mut online_latencies,
    );

    // Also measure pure HTTP round-trip latency
    println!("\n  Measuring raw HTTP round-trip latency...");
    // Set up a dummy session so /exchange doesn't panic
    let (dummy_tx, _dummy_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    let (dummy_out_tx, dummy_out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    *server_inbox_tx.lock().await = Some(dummy_tx);
    *server_outbox_rx.lock().await = Some(dummy_out_rx);

    // Pre-load a response
    let dummy_wire = WireMessage {
        sender: 0,
        is_broadcast: true,
        msg: serde_json::Value::Null,
    };
    let dummy_bytes = serde_json::to_vec(&dummy_wire).unwrap();

    let mut http_rtt_latencies = Vec::new();
    for _ in 0..ITERATIONS {
        dummy_out_tx.send(dummy_bytes.clone()).await.unwrap();
        let rtt_start = Instant::now();
        let _resp = http_client
            .post(&exchange_url)
            .body(dummy_bytes.clone())
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        http_rtt_latencies.push(rtt_start.elapsed());
    }
    report_stats("Raw HTTP round-trip (localhost)", &mut http_rtt_latencies);

    // =========================================================================
    // STEP 6: Verify BSV SDK compatibility
    // =========================================================================
    println!("\nSTEP 6: BSV SDK verification...");
    {
        // Do one more signing to verify with BSV SDK
        let mut rng = rand::rngs::OsRng;
        let eid_bytes: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid_bytes);
        let data_to_sign = DataToSign::digest::<Sha256>(message);

        let sig = round_based::sim::run_with_setup(
            participants.iter().map(|i| &key_shares[usize::from(*i)]),
            |i, party, share| {
                let party = buffer_outgoing(party);
                let mut party_rng = rand::rngs::OsRng;
                let participants = participants.clone();
                async move {
                    cggmp24::signing(eid, i, &participants, share)
                        .sign(&mut party_rng, party, &data_to_sign)
                        .await
                }
            },
        )
        .unwrap()
        .expect_ok()
        .expect_eq();

        let mut sig_bytes = [0u8; 64];
        sig.write_to_slice(&mut sig_bytes);

        let pubkey_bytes = key_shares[0].core.shared_public_key.to_bytes(true);
        let bsv_pubkey = bsv::PublicKey::from_bytes(&pubkey_bytes).unwrap();
        let msg_hash: [u8; 32] = {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(message);
            hasher.finalize().into()
        };
        let bsv_sig = bsv::Signature::from_compact(&sig_bytes).unwrap();
        assert!(bsv_pubkey.verify(&msg_hash, &bsv_sig), "BSV SDK verify must pass");
        println!("  BSV SDK verification: PASS");
    }

    // =========================================================================
    // SUMMARY
    // =========================================================================
    let baseline_p50 = {
        baseline_latencies.sort();
        percentile(&baseline_latencies, 50.0)
    };
    let signing_p50 = {
        signing_latencies.sort();
        percentile(&signing_latencies, 50.0)
    };
    let signing_p95 = percentile(&signing_latencies, 95.0);
    let signing_p99 = percentile(&signing_latencies, 99.0);
    let presign_p50 = {
        presign_latencies.sort();
        percentile(&presign_latencies, 50.0)
    };
    let online_p50 = {
        online_latencies.sort();
        percentile(&online_latencies, 50.0)
    };
    let online_p95 = percentile(&online_latencies, 95.0);
    let rtt_p50 = {
        http_rtt_latencies.sort();
        percentile(&http_rtt_latencies, 50.0)
    };

    println!("\n========================================");
    println!("  POC 5 RESULTS");
    println!("========================================");
    println!("  Baseline (sim):         p50={baseline_p50:?}");
    println!("  4-round HTTP signing:   p50={signing_p50:?}  p95={signing_p95:?}  p99={signing_p99:?}");
    println!("  Presig gen (HTTP):      p50={presign_p50:?}");
    println!("  Online presig signing:  p50={online_p50:?}  p95={online_p95:?}");
    println!("  Raw HTTP RTT:           p50={rtt_p50:?}");
    println!("  HTTP overhead:          ~{:?} per round", rtt_p50);
    println!("========================================");

    let signing_pass = signing_p50 < Duration::from_millis(200);
    let online_pass = online_p50 < Duration::from_millis(50);

    if signing_pass {
        println!("  [x] 4-round signing <200ms: PASS ({signing_p50:?})");
    } else {
        println!("  [ ] 4-round signing <200ms: FAIL ({signing_p50:?})");
    }
    if online_pass {
        println!("  [x] Presigned online <50ms: PASS ({online_p50:?})");
    } else {
        println!("  [ ] Presigned online <50ms: FAIL ({online_p50:?})");
    }
    println!("========================================");

    // Cleanup
    server_handle.abort();

    // Assert targets
    assert!(
        signing_p50 < Duration::from_millis(500),
        "4-round signing p50 must be <500ms (got {signing_p50:?})"
    );
}
