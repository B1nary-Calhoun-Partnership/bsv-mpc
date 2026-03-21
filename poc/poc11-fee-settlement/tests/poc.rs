//! POC 11: Fee settlement — MPC nodes co-sign a payout transaction
//!
//! Validates that MPC nodes can use their OWN threshold signing to settle
//! accumulated fees proportionally. This is the Level 2 fee settlement
//! mechanism where nodes self-settle without a trusted accumulator.
//!
//! Flow:
//! 1. Three MPC nodes run 2-of-3 DKG among THEMSELVES (separate from agent DKG)
//! 2. Each node has its own individual P2PKH address (identity key → payout address)
//! 3. Fund the settlement address (the nodes' 2-of-3 joint address) from wallet
//! 4. Tally participation: Node A 45%, Node B 35%, Node C 20%
//! 5. Build settlement tx: spend fee UTXO → 3 proportional P2PKH outputs
//! 6. Any 2 of 3 nodes co-sign the settlement tx using their threshold signing
//! 7. Verify the settlement tx with BSV SDK
//! 8. Broadcast to mainnet
//!
//! The tricky part: the fee UTXOs are locked to the MPC NODES' joint address,
//! NOT the agent's MPC address. This is a SEPARATE threshold signing setup.

use std::collections::VecDeque;
use std::time::Instant;

use bsv::primitives::bsv::sighash::{
    compute_sighash_for_signing, SighashParams, TxInput, TxOutput, SIGHASH_ALL, SIGHASH_FORKID,
};
use bsv::primitives::bsv::tx_signature::TransactionSignature;
use bsv::primitives::ec::{PublicKey, Signature};
use bsv::primitives::encoding::Writer;
use bsv::primitives::hash::sha256d;

use cggmp24::security_level::SecurityLevel128;
use cggmp24::signing::PrehashedDataToSign;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use generic_ec::Scalar;
use rand::Rng;

// ---- Buffered sink (from POC 1) ----

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
        let buffered = BufferedSink {
            messages: VecDeque::new(),
            inner: outgoing,
        };
        (incoming, buffered)
    })
}

// ---- Blum prime generation ----

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
    use cggmp24::security_level::SecurityLevel;
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

// ---- Helpers ----

fn p2pkh_locking_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

fn p2pkh_unlocking_script(sig_checksig: &[u8], compressed_pubkey: &[u8; 33]) -> Vec<u8> {
    let mut script = Vec::new();
    script.push(sig_checksig.len() as u8);
    script.extend_from_slice(sig_checksig);
    script.push(33);
    script.extend_from_slice(compressed_pubkey);
    script
}

fn serialize_transaction(
    version: i32,
    inputs: &[(
        [u8; 32], // txid (internal byte order)
        u32,      // vout
        Vec<u8>,  // unlocking script
        u32,      // sequence
    )],
    outputs: &[(u64, Vec<u8>)], // (satoshis, locking_script)
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

fn log_transaction(
    log_path: &str,
    label: &str,
    txid: &str,
    raw_hex: &str,
    address: &str,
    joint_pubkey: &str,
    amount_sats: u64,
) {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .expect("should open log file");
    writeln!(f, "--- {} ---", label).ok();
    writeln!(
        f,
        "timestamp: unix_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    )
    .ok();
    writeln!(f, "txid: {}", txid).ok();
    writeln!(f, "address: {}", address).ok();
    writeln!(f, "joint_pubkey: {}", joint_pubkey).ok();
    writeln!(f, "amount_sats: {}", amount_sats).ok();
    writeln!(f, "raw_hex: {}", raw_hex).ok();
    writeln!(f, "").ok();
}

// ---- Settlement calculation (mirrors bsv-mpc-overlay::proofs::calculate_settlement) ----

struct NodeShare {
    name: String,
    pubkey: PublicKey,
    proof_count: u64,
    fee_sats: u64,
}

fn calculate_settlement(
    nodes: &[(String, PublicKey, u64)], // (name, pubkey, proof_count)
    total_fees_sats: u64,
) -> Vec<NodeShare> {
    let total_proofs: u64 = nodes.iter().map(|(_, _, c)| c).sum();
    let mut shares: Vec<NodeShare> = Vec::new();
    let mut allocated: u64 = 0;

    for (_i, (name, pubkey, count)) in nodes.iter().enumerate() {
        let fee = if total_proofs > 0 {
            (total_fees_sats * count) / total_proofs
        } else {
            0
        };
        allocated += fee;
        shares.push(NodeShare {
            name: name.clone(),
            pubkey: pubkey.clone(),
            proof_count: *count,
            fee_sats: fee,
        });
    }

    // Assign remainder to first node (highest participation)
    let remainder = total_fees_sats - allocated;
    if remainder > 0 && !shares.is_empty() {
        shares[0].fee_sats += remainder;
    }

    shares
}

// ---- Threshold signing helper (from POC 12) ----

async fn sign_with_subset(
    key_shares: &[cggmp24::KeyShare<Secp256k1, SecurityLevel128>],
    participants: &[u16],
    data_to_sign: &PrehashedDataToSign<Secp256k1>,
) -> Result<cggmp24::signing::Signature<Secp256k1>, String> {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);
    let participants_vec = participants.to_vec();

    let result = round_based::sim::run_with_setup(
        participants.iter().map(|i| &key_shares[usize::from(*i)]),
        |i, party, share| {
            let party = buffer_outgoing(party);
            let mut party_rng = rand::rngs::OsRng;
            let p = participants_vec.clone();
            async move {
                cggmp24::signing(eid, i, &p, share)
                    .sign(&mut party_rng, party, data_to_sign)
                    .await
            }
        },
    );

    match result {
        Ok(sim_output) => {
            let results = sim_output.into_vec();
            let mut sigs = Vec::new();
            for (i, r) in results.into_iter().enumerate() {
                match r {
                    Ok(sig) => sigs.push(sig),
                    Err(e) => return Err(format!("party {} failed: {:?}", i, e)),
                }
            }
            Ok(sigs.into_iter().next().unwrap())
        }
        Err(e) => Err(format!("simulation failed: {:?}", e)),
    }
}

// =========================================================================
// TEST: Fee settlement — nodes co-sign a proportional payout
// =========================================================================
#[tokio::test]
async fn test_fee_settlement_mpc_cosign() {
    let mut rng = rand::rngs::OsRng;
    let n: u16 = 3;
    let t: u16 = 2; // 2-of-3 threshold
    let log_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tx_log.txt");

    // =========================================================================
    // STEP 1: Generate 3 individual node identity keys (payout addresses)
    // =========================================================================
    println!("=== STEP 1: Generate node identity keys ===");

    let node_a_privkey = bsv::PrivateKey::random();
    let node_b_privkey = bsv::PrivateKey::random();
    let node_c_privkey = bsv::PrivateKey::random();

    let node_a_pubkey = node_a_privkey.public_key().clone();
    let node_b_pubkey = node_b_privkey.public_key().clone();
    let node_c_pubkey = node_c_privkey.public_key().clone();

    println!("  Node A address: {} (45% of signings)", node_a_pubkey.to_address());
    println!("  Node B address: {} (35% of signings)", node_b_pubkey.to_address());
    println!("  Node C address: {} (20% of signings)", node_c_pubkey.to_address());

    // =========================================================================
    // STEP 2: 3-party DKG (2-of-3) among nodes for fee settlement address
    // =========================================================================
    println!("\n=== STEP 2: 3-party DKG (2-of-3) for settlement address ===");

    let dkg_start = Instant::now();

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

    let joint_pubkey_bytes = incomplete_shares[0].shared_public_key.to_bytes(true);
    let joint_pubkey =
        PublicKey::from_bytes(&joint_pubkey_bytes).expect("valid BSV pubkey from joint key");
    let settlement_address = joint_pubkey.to_address();

    // Verify all 3 nodes agree on the same joint pubkey
    for (i, share) in incomplete_shares.iter().enumerate() {
        assert_eq!(
            share.shared_public_key,
            incomplete_shares[0].shared_public_key,
            "Node {} must agree on joint pubkey",
            i
        );
    }

    let dkg_elapsed = dkg_start.elapsed();
    println!("  DKG completed in {:?}", dkg_elapsed);
    println!("  Settlement joint pubkey: {}", joint_pubkey.to_hex());
    println!("  Settlement address: {}", settlement_address);
    println!("  All 3 nodes agree on joint pubkey: YES");

    // =========================================================================
    // STEP 3: Aux info generation + complete key shares
    // =========================================================================
    println!("\n=== STEP 3: Aux info gen + complete key shares ===");

    let aux_start = Instant::now();

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

    let key_shares: Vec<_> = incomplete_shares
        .into_iter()
        .zip(aux_infos)
        .map(|(share, aux)| {
            cggmp24::KeyShare::from_parts((share, aux))
                .expect("key share validation should pass")
        })
        .collect();

    let aux_elapsed = aux_start.elapsed();
    println!("  Aux info completed in {:?}", aux_elapsed);
    println!("  Key shares ready for {} nodes", key_shares.len());

    // =========================================================================
    // STEP 4: Simulate fee accumulation (tally participation)
    // =========================================================================
    println!("\n=== STEP 4: Tally participation + calculate settlement ===");

    // Simulated participation counts over an epoch
    // Node A: 45 signings (45%), Node B: 35 signings (35%), Node C: 20 signings (20%)
    let nodes = vec![
        ("Node A".to_string(), node_a_pubkey, 45u64),
        ("Node B".to_string(), node_b_pubkey, 35u64),
        ("Node C".to_string(), node_c_pubkey, 20u64),
    ];

    // Fund the settlement address with enough sats to distribute
    let funding_amount: u64 = 3000; // sats to distribute as fees
    let mining_fee: u64 = 150; // mining fee for settlement tx (~4 outputs)
    let distributable = funding_amount - mining_fee;

    let shares = calculate_settlement(&nodes, distributable);

    println!("  Total participation proofs: 100");
    println!("  Total fees to distribute: {} sats", distributable);
    println!("  Mining fee: {} sats", mining_fee);
    for share in &shares {
        let pct = (share.fee_sats as f64 / distributable as f64) * 100.0;
        println!(
            "    {} ({}%): {} proofs → {} sats ({:.1}%)",
            share.name,
            share.proof_count,
            share.proof_count,
            share.fee_sats,
            pct
        );
    }

    // Verify settlement totals
    let total_settled: u64 = shares.iter().map(|s| s.fee_sats).sum();
    assert_eq!(
        total_settled, distributable,
        "Settlement must distribute all fees: {} != {}",
        total_settled, distributable
    );
    println!("  Settlement total: {} sats (all fees distributed)", total_settled);

    // =========================================================================
    // STEP 5: Fund the settlement address from wallet
    // =========================================================================
    println!("\n=== STEP 5: Fund settlement address ===");

    let client = reqwest::Client::new();

    let fund_body = serde_json::json!({
        "description": "POC 11: fund fee settlement address",
        "outputs": [{
            "satoshis": funding_amount,
            "lockingScript": hex::encode(p2pkh_locking_script(&joint_pubkey.hash160())),
            "outputDescription": "Fee settlement 2-of-3 P2PKH"
        }]
    });

    let fund_resp = client
        .post("http://localhost:3321/createAction")
        .header("Origin", "http://admin.com")
        .header("Content-Type", "application/json")
        .json(&fund_body)
        .send()
        .await
        .expect("funding request should reach wallet");

    let fund_status = fund_resp.status();
    let fund_text = fund_resp.text().await.unwrap();
    println!(
        "  Funding response ({}): {}",
        fund_status,
        &fund_text[..fund_text.len().min(200)]
    );

    if !fund_status.is_success() {
        panic!("Funding failed: {}", fund_text);
    }

    let fund_json: serde_json::Value =
        serde_json::from_str(&fund_text).expect("funding response should be JSON");

    let fund_txid = fund_json["txid"]
        .as_str()
        .expect("funding response should have txid");
    println!("  Funding txid: {}", fund_txid);

    log_transaction(
        log_path,
        "FUNDING (POC 11 - fee settlement)",
        fund_txid,
        "(wallet BEEF tx)",
        &settlement_address,
        &joint_pubkey.to_hex(),
        funding_amount,
    );

    // =========================================================================
    // STEP 6: Find the fee UTXO via WhatsOnChain
    // =========================================================================
    println!("\n=== STEP 6: Find fee UTXO ===");

    let settlement_locking = p2pkh_locking_script(&joint_pubkey.hash160());
    let settlement_locking_hex = hex::encode(&settlement_locking);
    let mut utxo_vout: u32 = 0;
    let mut utxo_value: u64 = funding_amount;
    let mut found = false;

    let woc_tx_url = format!(
        "https://api.whatsonchain.com/v1/bsv/main/tx/hash/{}",
        fund_txid
    );

    for attempt in 1..=6 {
        let wait_secs = attempt * 3;
        println!(
            "  Attempt {}: waiting {}s for WoC indexing...",
            attempt, wait_secs
        );
        tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;

        if let Ok(resp) = client.get(&woc_tx_url).send().await {
            if resp.status().is_success() {
                let tx_json: serde_json::Value = resp.json().await.unwrap();
                if let Some(vouts) = tx_json["vout"].as_array() {
                    for vout_obj in vouts {
                        let script_hex = vout_obj["scriptPubKey"]["hex"]
                            .as_str()
                            .unwrap_or("");
                        if script_hex == settlement_locking_hex {
                            utxo_vout = vout_obj["n"].as_u64().unwrap() as u32;
                            let value_bsv = vout_obj["value"].as_f64().unwrap_or(0.0);
                            utxo_value = (value_bsv * 100_000_000.0 + 0.5) as u64;
                            found = true;
                            break;
                        }
                    }
                }
                if found {
                    println!(
                        "  Found fee UTXO: {}:{} ({} sats)",
                        fund_txid, utxo_vout, utxo_value
                    );
                    break;
                }
            }
        }
    }

    assert!(found, "Must find fee UTXO on WoC within retries");

    // Recalculate distributable with actual UTXO value
    let distributable = utxo_value - mining_fee;
    let shares = calculate_settlement(&nodes, distributable);

    // =========================================================================
    // STEP 7: Build settlement transaction (fee UTXO → 3 proportional outputs)
    // =========================================================================
    println!("\n=== STEP 7: Build settlement transaction ===");

    // Parse funding txid to internal byte order
    let mut prev_txid = [0u8; 32];
    let txid_bytes = hex::decode(fund_txid).expect("valid txid hex");
    prev_txid.copy_from_slice(&txid_bytes);
    prev_txid.reverse(); // display → internal byte order

    // Build outputs: one P2PKH per node, proportional to participation
    let outputs: Vec<(u64, Vec<u8>)> = shares
        .iter()
        .map(|share| {
            let script = p2pkh_locking_script(&share.pubkey.hash160());
            (share.fee_sats, script)
        })
        .collect();

    println!("  Input: {} sats from fee UTXO", utxo_value);
    for (i, share) in shares.iter().enumerate() {
        println!(
            "  Output {}: {} sats to {} ({})",
            i,
            share.fee_sats,
            share.pubkey.to_address(),
            share.name
        );
    }
    println!("  Mining fee: {} sats", mining_fee);

    // Verify balance equation
    let total_outputs: u64 = outputs.iter().map(|(s, _)| s).sum();
    assert_eq!(
        utxo_value,
        total_outputs + mining_fee,
        "Balance: {} != {} + {}",
        utxo_value,
        total_outputs,
        mining_fee
    );
    println!(
        "  Balance: {} == {} + {} (mining fee)",
        utxo_value, total_outputs, mining_fee
    );

    // Compute BIP-143 sighash
    let sighash_inputs = vec![TxInput {
        txid: prev_txid,
        output_index: utxo_vout,
        script: vec![],
        sequence: 0xFFFFFFFF,
    }];

    let sighash_outputs: Vec<TxOutput> = outputs
        .iter()
        .map(|(sats, script)| TxOutput {
            satoshis: *sats,
            script: script.clone(),
        })
        .collect();

    let scope = SIGHASH_ALL | SIGHASH_FORKID;
    let sighash = compute_sighash_for_signing(&SighashParams {
        version: 1,
        inputs: &sighash_inputs,
        outputs: &sighash_outputs,
        locktime: 0,
        input_index: 0,
        subscript: &settlement_locking,
        satoshis: utxo_value,
        scope,
    });

    println!(
        "  Sighash: {} (covers {} outputs)",
        hex::encode(&sighash),
        outputs.len()
    );

    // =========================================================================
    // STEP 8: 2-of-3 threshold sign with different subsets
    // =========================================================================
    println!("\n=== STEP 8: 2-of-3 threshold signing ===");

    let sighash_scalar = Scalar::<Secp256k1>::from_be_bytes(&sighash)
        .expect("sighash should be a valid scalar");
    let data_to_sign = PrehashedDataToSign::from_scalar(sighash_scalar);

    // Sign with nodes A+B (indices 0,1) — the primary settlement signers
    let sign_start = Instant::now();
    let sig_ab = sign_with_subset(&key_shares, &[0, 1], &data_to_sign)
        .await
        .expect("2-of-3 signing (A+B) should succeed");
    let sign_ab_elapsed = sign_start.elapsed();
    println!("  Subset A+B (0,1): signed in {:?}", sign_ab_elapsed);

    // Verify cggmp24 internally
    sig_ab
        .verify(&key_shares[0].core.shared_public_key, &data_to_sign)
        .expect("cggmp24 verification should pass for A+B");
    println!("  cggmp24 verify (A+B): PASS");

    // Also verify A+C and B+C can sign (any 2-of-3)
    let sign_start = Instant::now();
    let sig_ac = sign_with_subset(&key_shares, &[0, 2], &data_to_sign)
        .await
        .expect("2-of-3 signing (A+C) should succeed");
    let sign_ac_elapsed = sign_start.elapsed();
    println!("  Subset A+C (0,2): signed in {:?}", sign_ac_elapsed);

    sig_ac
        .verify(&key_shares[0].core.shared_public_key, &data_to_sign)
        .expect("cggmp24 verification should pass for A+C");
    println!("  cggmp24 verify (A+C): PASS");

    let sign_start = Instant::now();
    let sig_bc = sign_with_subset(&key_shares, &[1, 2], &data_to_sign)
        .await
        .expect("2-of-3 signing (B+C) should succeed");
    let sign_bc_elapsed = sign_start.elapsed();
    println!("  Subset B+C (1,2): signed in {:?}", sign_bc_elapsed);

    sig_bc
        .verify(&key_shares[0].core.shared_public_key, &data_to_sign)
        .expect("cggmp24 verification should pass for B+C");
    println!("  cggmp24 verify (B+C): PASS");

    // Verify below-threshold (1-of-3) fails
    let sig_a_only = sign_with_subset(&key_shares, &[0], &data_to_sign).await;
    assert!(
        sig_a_only.is_err(),
        "Signing with only 1 of 3 nodes MUST fail"
    );
    println!("  Single node (below threshold): correctly rejected");

    // =========================================================================
    // STEP 9: BSV SDK verification
    // =========================================================================
    println!("\n=== STEP 9: BSV SDK verification ===");

    // Use the A+B signature for the broadcast transaction
    let mut sig_bytes = [0u8; 64];
    sig_ab.write_to_slice(&mut sig_bytes);

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_bytes[..32]);
    s.copy_from_slice(&sig_bytes[32..]);

    let bsv_sig = Signature::new(r, s);
    assert!(bsv_sig.is_low_s(), "Signature must be low-S (BIP-62)");
    let bsv_verify = joint_pubkey.verify(&sighash, &bsv_sig);
    assert!(bsv_verify, "BSV SDK verification must pass");
    println!("  BSV SDK verify: PASS");
    println!("  Signature is low-S (BIP-62): YES");

    // Also verify A+C and B+C signatures with BSV SDK
    for (label, sig) in [("A+C", &sig_ac), ("B+C", &sig_bc)] {
        let mut sb = [0u8; 64];
        sig.write_to_slice(&mut sb);
        let mut rv = [0u8; 32];
        let mut sv = [0u8; 32];
        rv.copy_from_slice(&sb[..32]);
        sv.copy_from_slice(&sb[32..]);
        let bsv_s = Signature::new(rv, sv);
        assert!(
            joint_pubkey.verify(&sighash, &bsv_s),
            "BSV SDK verification must pass for {}",
            label
        );
        println!("  BSV SDK verify ({}): PASS", label);
    }

    // =========================================================================
    // STEP 10: Build and serialize the settlement transaction
    // =========================================================================
    println!("\n=== STEP 10: Build unlocking script + serialize tx ===");

    let tx_sig = TransactionSignature::new(bsv_sig, scope);
    let checksig_bytes = tx_sig.to_checksig_format();
    let compressed_pubkey = joint_pubkey.to_compressed();
    let unlocking = p2pkh_unlocking_script(&checksig_bytes, &compressed_pubkey);

    println!("  Unlocking script: {} bytes", unlocking.len());

    let raw_tx = serialize_transaction(
        1,
        &[(prev_txid, utxo_vout, unlocking, 0xFFFFFFFF)],
        &outputs,
        0,
    );

    let txid = sha256d(&raw_tx);
    let mut txid_display = txid;
    txid_display.reverse();
    let txid_hex = hex::encode(&txid_display);

    println!("  Raw tx: {} bytes", raw_tx.len());
    println!("  TXID: {}", txid_hex);
    println!("  Outputs: {}", outputs.len());

    log_transaction(
        log_path,
        "SETTLEMENT (POC 11)",
        &txid_hex,
        &hex::encode(&raw_tx),
        &settlement_address,
        &joint_pubkey.to_hex(),
        total_outputs,
    );

    // =========================================================================
    // STEP 11: Broadcast to mainnet via ARC
    // =========================================================================
    println!("\n=== STEP 11: Broadcast to mainnet via ARC ===");

    let raw_tx_hex = hex::encode(&raw_tx);
    let mut broadcast_success = false;

    let arc_endpoints = [
        "https://arc.taal.com",
        "https://arc.gorillapool.io",
    ];

    for arc_url in &arc_endpoints {
        let url = format!("{}/v1/tx", arc_url);
        println!("  Trying ARC: {}", url);

        let arc_resp = client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("XDeployment-ID", "bsv-mpc-poc11")
            .json(&serde_json::json!({ "rawTx": raw_tx_hex }))
            .send()
            .await;

        match arc_resp {
            Ok(resp) => {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                println!("    Status: {}", status);
                println!("    Response: {}", &text[..text.len().min(300)]);

                if status.is_success()
                    || text.contains("SEEN_ON_NETWORK")
                    || text.contains("MINED")
                {
                    broadcast_success = true;
                    println!("  BROADCAST SUCCESS via {}", arc_url);
                    break;
                }
            }
            Err(e) => {
                println!("    Error: {}", e);
            }
        }
    }

    assert!(broadcast_success, "Settlement tx must be accepted by ARC");

    // =========================================================================
    // STEP 12: Verify on WhatsOnChain
    // =========================================================================
    println!("\n=== STEP 12: Verify on WhatsOnChain ===");

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let verify_url = format!(
        "https://api.whatsonchain.com/v1/bsv/main/tx/hash/{}",
        txid_hex
    );
    let verify_resp = client.get(&verify_url).send().await;

    match verify_resp {
        Ok(resp) if resp.status().is_success() => {
            let tx_json: serde_json::Value = resp.json().await.unwrap_or_default();
            let vout_count = tx_json["vout"].as_array().map_or(0, |v| v.len());
            println!(
                "  Settlement TX confirmed on WhatsOnChain! ({} outputs)",
                vout_count
            );
            assert_eq!(
                vout_count, 3,
                "Must have 3 outputs (one per node)"
            );
        }
        _ => {
            println!("  TX not yet visible on WhatsOnChain (may take a moment)");
            println!(
                "  Check: https://whatsonchain.com/tx/{}",
                txid_hex
            );
        }
    }

    // =========================================================================
    // SUMMARY
    // =========================================================================
    println!("\n========================================");
    println!("  POC 11 RESULT: FEE SETTLEMENT VALIDATED");
    println!("========================================");
    println!("  [x] 3 MPC nodes with individual identity keys");
    println!("  [x] 2-of-3 DKG among nodes: {:?}", dkg_elapsed);
    println!("  [x] Settlement address: {}", settlement_address);
    println!(
        "  [x] Fee tally: A=45%, B=35%, C=20% of {} signings",
        nodes.iter().map(|(_, _, c)| c).sum::<u64>()
    );
    println!("  [x] Proportional distribution:");
    for share in &shares {
        println!(
            "        {} → {} sats ({}%)",
            share.name,
            share.fee_sats,
            share.proof_count
        );
    }
    println!("  [x] All 3 subsets (A+B, A+C, B+C) can co-sign: YES");
    println!("  [x] Below-threshold (single node) rejected: YES");
    println!("  [x] BSV SDK verification: PASS for all 3 subsets");
    println!("  [x] Balance equation: {} = {} + {}", utxo_value, total_outputs, mining_fee);
    println!("  [x] Settlement tx broadcast to mainnet");
    println!("  TXID: {}", txid_hex);
    println!("  View: https://whatsonchain.com/tx/{}", txid_hex);
    println!("========================================");
}

// =========================================================================
// TEST: Settlement calculation edge cases (no MPC, no network)
// =========================================================================
#[test]
fn test_settlement_calculation() {
    let dummy_pubkey = || {
        let pk = bsv::PrivateKey::random();
        pk.public_key()
    };

    // --- Case 1: Normal proportional split ---
    println!("Case 1: Normal proportional split (45/35/20)");
    let nodes = vec![
        ("A".to_string(), dummy_pubkey(), 45u64),
        ("B".to_string(), dummy_pubkey(), 35u64),
        ("C".to_string(), dummy_pubkey(), 20u64),
    ];
    let shares = calculate_settlement(&nodes, 10000);
    // 45/100 * 10000 = 4500, 35/100 * 10000 = 3500, 20/100 * 10000 = 2000
    assert_eq!(shares[0].fee_sats, 4500);
    assert_eq!(shares[1].fee_sats, 3500);
    assert_eq!(shares[2].fee_sats, 2000);
    let total: u64 = shares.iter().map(|s| s.fee_sats).sum();
    assert_eq!(total, 10000);
    println!("  PASS: 4500 + 3500 + 2000 = 10000");

    // --- Case 2: Uneven split with remainder ---
    println!("Case 2: Uneven split (remainder goes to first node)");
    let nodes = vec![
        ("A".to_string(), dummy_pubkey(), 1u64),
        ("B".to_string(), dummy_pubkey(), 1u64),
        ("C".to_string(), dummy_pubkey(), 1u64),
    ];
    let shares = calculate_settlement(&nodes, 100);
    // 1/3 * 100 = 33 each, remainder = 1 → first node gets 34
    assert_eq!(shares[0].fee_sats, 34);
    assert_eq!(shares[1].fee_sats, 33);
    assert_eq!(shares[2].fee_sats, 33);
    let total: u64 = shares.iter().map(|s| s.fee_sats).sum();
    assert_eq!(total, 100);
    println!("  PASS: 34 + 33 + 33 = 100");

    // --- Case 3: Single node gets everything ---
    println!("Case 3: Single active node");
    let nodes = vec![
        ("A".to_string(), dummy_pubkey(), 100u64),
        ("B".to_string(), dummy_pubkey(), 0u64),
        ("C".to_string(), dummy_pubkey(), 0u64),
    ];
    let shares = calculate_settlement(&nodes, 5000);
    assert_eq!(shares[0].fee_sats, 5000);
    assert_eq!(shares[1].fee_sats, 0);
    assert_eq!(shares[2].fee_sats, 0);
    println!("  PASS: 5000 + 0 + 0 = 5000");

    // --- Case 4: Zero total proofs ---
    println!("Case 4: Zero total proofs");
    let nodes = vec![
        ("A".to_string(), dummy_pubkey(), 0u64),
        ("B".to_string(), dummy_pubkey(), 0u64),
    ];
    let shares = calculate_settlement(&nodes, 1000);
    assert_eq!(shares[0].fee_sats, 1000); // remainder goes to first
    assert_eq!(shares[1].fee_sats, 0);
    println!("  PASS: 1000 + 0 = 1000 (remainder to first)");

    // --- Case 5: Large amounts ---
    println!("Case 5: Large fee pool (1 BSV = 100M sats)");
    let nodes = vec![
        ("A".to_string(), dummy_pubkey(), 500u64),
        ("B".to_string(), dummy_pubkey(), 300u64),
        ("C".to_string(), dummy_pubkey(), 200u64),
    ];
    let shares = calculate_settlement(&nodes, 100_000_000);
    assert_eq!(shares[0].fee_sats, 50_000_000);
    assert_eq!(shares[1].fee_sats, 30_000_000);
    assert_eq!(shares[2].fee_sats, 20_000_000);
    let total: u64 = shares.iter().map(|s| s.fee_sats).sum();
    assert_eq!(total, 100_000_000);
    println!("  PASS: 0.5 + 0.3 + 0.2 = 1.0 BSV");

    println!("\nAll settlement calculation tests passed.");
}
