//! POC 7: Fee injection — inject fee output into a transaction, MPC sign, broadcast
//!
//! Validates:
//! 1. Build a normal P2PKH transaction (1 input, 1 recipient output, 1 change)
//! 2. Inject a fee output (1000 sats to a P2PKH address) BEFORE signing
//! 3. Adjust change to account for the fee
//! 4. Verify: total inputs = total outputs + mining fee
//! 5. MPC-sign the transaction (2-of-2 CGGMP'24 threshold ECDSA)
//! 6. Verify signature with BSV SDK
//! 7. Broadcast to mainnet and confirm

use std::collections::VecDeque;

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

use poc7_fee_injection::{inject_fee_output, inject_split_fee, FeeInjectionError};

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
    mpc_address: &str,
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
    writeln!(f, "timestamp: unix_{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()).ok();
    writeln!(f, "txid: {}", txid).ok();
    writeln!(f, "mpc_address: {}", mpc_address).ok();
    writeln!(f, "joint_pubkey: {}", joint_pubkey).ok();
    writeln!(f, "amount_sats: {}", amount_sats).ok();
    writeln!(f, "raw_hex: {}", raw_hex).ok();
    writeln!(f, "").ok();
}

// =========================================================================
// TEST: Fee injection with MPC signing + mainnet broadcast
// =========================================================================
#[tokio::test]
async fn test_fee_injection_with_mpc_signing() {
    let mut rng = rand::rngs::OsRng;
    let n: u16 = 2;
    let t: u16 = 2;
    let log_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tx_log.txt");

    // =========================================================================
    // STEP 1: Two-party DKG
    // =========================================================================
    println!("=== STEP 1: Two-party DKG ===");

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
    let mpc_address = joint_pubkey.to_address();
    println!("  Joint pubkey: {}", joint_pubkey.to_hex());
    println!("  MPC address: {}", mpc_address);

    // =========================================================================
    // STEP 2: Aux info generation + complete key shares
    // =========================================================================
    println!("\n=== STEP 2: Aux info gen + complete key shares ===");

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

    println!("  Key shares ready for {} parties", key_shares.len());

    // =========================================================================
    // STEP 3: Generate a "fee node" keypair (simulates MPC node operator)
    // =========================================================================
    println!("\n=== STEP 3: Generate fee node address ===");

    // Use a deterministic-looking but random keypair for the fee recipient.
    // In production, this would be the MPC node operator's address.
    let fee_privkey = bsv::PrivateKey::random();
    let fee_pubkey = fee_privkey.public_key();
    let fee_address = fee_pubkey.to_address();
    let fee_locking_script = p2pkh_locking_script(&fee_pubkey.hash160());
    let fee_sats: u64 = 1000;

    println!("  Fee node address: {}", fee_address);
    println!("  Fee amount: {} sats", fee_sats);

    // =========================================================================
    // STEP 4: Fund the MPC address
    // =========================================================================
    println!("\n=== STEP 4: Fund MPC address ===");

    let client = reqwest::Client::new();
    let funding_amount: u64 = 3500; // sats

    let fund_body = serde_json::json!({
        "description": "POC 7: fund MPC address for fee injection test",
        "outputs": [{
            "satoshis": funding_amount,
            "lockingScript": hex::encode(p2pkh_locking_script(&joint_pubkey.hash160())),
            "outputDescription": "MPC P2PKH output"
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
    println!("  Funding response ({}): {}", fund_status, &fund_text[..fund_text.len().min(200)]);

    if !fund_status.is_success() {
        panic!("Funding failed: {}", fund_text);
    }

    let fund_json: serde_json::Value =
        serde_json::from_str(&fund_text).expect("funding response should be JSON");

    let fund_txid = fund_json["txid"]
        .as_str()
        .expect("funding response should have txid");
    println!("  Funding txid: {}", fund_txid);

    // =========================================================================
    // STEP 5: Find our UTXO via WhatsOnChain
    // =========================================================================
    println!("\n=== STEP 5: Find UTXO ===");

    let mpc_locking = p2pkh_locking_script(&joint_pubkey.hash160());
    let mpc_locking_hex = hex::encode(&mpc_locking);
    let mut utxo_vout: u32 = 0;
    let mut utxo_value: u64 = funding_amount;
    let mut found = false;

    let woc_tx_url = format!(
        "https://api.whatsonchain.com/v1/bsv/main/tx/hash/{}",
        fund_txid
    );

    for attempt in 1..=6 {
        let wait_secs = attempt * 3;
        println!("  Attempt {}: waiting {}s for WoC indexing...", attempt, wait_secs);
        tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;

        if let Ok(resp) = client.get(&woc_tx_url).send().await {
            if resp.status().is_success() {
                let tx_json: serde_json::Value = resp.json().await.unwrap();
                if let Some(vouts) = tx_json["vout"].as_array() {
                    for vout_obj in vouts {
                        let script_hex = vout_obj["scriptPubKey"]["hex"]
                            .as_str()
                            .unwrap_or("");
                        if script_hex == mpc_locking_hex {
                            utxo_vout = vout_obj["n"].as_u64().unwrap() as u32;
                            let value_bsv = vout_obj["value"].as_f64().unwrap_or(0.0);
                            utxo_value = (value_bsv * 100_000_000.0 + 0.5) as u64;
                            found = true;
                            break;
                        }
                    }
                }
                if found {
                    println!("  Found UTXO: {}:{} ({} sats)", fund_txid, utxo_vout, utxo_value);
                    break;
                }
            }
        }
    }

    assert!(found, "Must find funding UTXO on WoC within retries");

    log_transaction(
        log_path,
        "FUNDING (POC 7)",
        fund_txid,
        "(wallet BEEF tx)",
        &mpc_address,
        &joint_pubkey.to_hex(),
        utxo_value,
    );

    // =========================================================================
    // STEP 6: Build transaction WITH fee injection
    // =========================================================================
    println!("\n=== STEP 6: Build transaction with fee injection ===");

    // Parse funding txid to internal byte order
    let mut prev_txid = [0u8; 32];
    let txid_bytes = hex::decode(fund_txid).expect("valid txid hex");
    prev_txid.copy_from_slice(&txid_bytes);
    prev_txid.reverse(); // display → internal byte order

    let mining_fee: u64 = 150; // slightly higher for 3-output tx (~250 bytes)

    // Get wallet's identity key (recipient for returned funds)
    let ident_resp = client
        .post("http://localhost:3321/getPublicKey")
        .header("Origin", "http://admin.com")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({"identityKey": true}))
        .send()
        .await
        .expect("identity key request should work");

    let ident_json: serde_json::Value = ident_resp.json().await.unwrap();
    let wallet_pubkey_hex = ident_json["publicKey"]
        .as_str()
        .expect("should have publicKey");
    let wallet_pubkey = PublicKey::from_hex(wallet_pubkey_hex).expect("valid wallet pubkey");

    // --- Build the NORMAL transaction first (1 recipient + 1 change) ---
    let recipient_sats: u64 = 1000;
    let recipient_script = p2pkh_locking_script(&wallet_pubkey.hash160());

    // Change = input - recipient - mining_fee (BEFORE fee injection)
    let change_before_fee = utxo_value - recipient_sats - mining_fee;
    let change_script = p2pkh_locking_script(&wallet_pubkey.hash160());

    let mut outputs: Vec<(u64, Vec<u8>)> = vec![
        (recipient_sats, recipient_script),   // output 0: recipient
        (change_before_fee, change_script),   // output 1: change
    ];

    println!("  BEFORE fee injection:");
    println!("    Input:     {} sats", utxo_value);
    println!("    Recipient: {} sats (output 0)", outputs[0].0);
    println!("    Change:    {} sats (output 1)", outputs[1].0);
    println!("    Mining fee: {} sats", mining_fee);
    println!("    Total:     {} == {}", utxo_value,
             outputs[0].0 + outputs[1].0 + mining_fee);

    // --- INJECT FEE OUTPUT (the core of POC 7) ---
    let injection = inject_fee_output(
        &mut outputs,
        1, // change is at index 1
        fee_sats,
        fee_locking_script.clone(),
    ).expect("fee injection should succeed");

    println!("\n  AFTER fee injection:");
    println!("    Input:     {} sats", utxo_value);
    println!("    Recipient: {} sats (output 0)", outputs[0].0);
    println!("    Change:    {} sats (output 1, was {})", outputs[1].0, injection.original_change);
    println!("    Fee:       {} sats (output {})", outputs[2].0, injection.fee_output_index);
    println!("    Mining fee: {} sats", mining_fee);

    // --- VERIFY BALANCE EQUATION ---
    let total_outputs: u64 = outputs.iter().map(|(s, _)| s).sum();
    assert_eq!(
        utxo_value,
        total_outputs + mining_fee,
        "Balance equation: inputs ({}) must equal outputs ({}) + mining fee ({})",
        utxo_value, total_outputs, mining_fee
    );
    println!("  BALANCE: {} == {} + {} ✓", utxo_value, total_outputs, mining_fee);

    // =========================================================================
    // STEP 7: Compute sighash (fee output is part of hashOutputs in BIP-143)
    // =========================================================================
    println!("\n=== STEP 7: Compute BIP-143 sighash (includes fee output) ===");

    let locking_script = p2pkh_locking_script(&joint_pubkey.hash160());

    let sighash_inputs = vec![TxInput {
        txid: prev_txid,
        output_index: utxo_vout,
        script: vec![],
        sequence: 0xFFFFFFFF,
    }];

    // ALL outputs (recipient + change + fee) go into hashOutputs
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
        subscript: &locking_script,
        satoshis: utxo_value,
        scope,
    });

    println!("  Sighash: {} (covers {} outputs)", hex::encode(&sighash), outputs.len());

    // =========================================================================
    // STEP 8: MPC threshold sign the sighash
    // =========================================================================
    println!("\n=== STEP 8: MPC threshold sign ===");

    let sighash_scalar = Scalar::<Secp256k1>::from_be_bytes(&sighash)
        .expect("sighash should be a valid scalar");
    let data_to_sign = PrehashedDataToSign::from_scalar(sighash_scalar);

    let eid_bytes: [u8; 32] = rng.gen();
    let eid_sign = ExecutionId::new(&eid_bytes);
    let participants: Vec<u16> = vec![0, 1];

    let sig = round_based::sim::run_with_setup(
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

    // Extract signature
    let mut sig_bytes = [0u8; 64];
    sig.write_to_slice(&mut sig_bytes);

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_bytes[..32]);
    s.copy_from_slice(&sig_bytes[32..]);

    println!("  MPC signature r: {}", hex::encode(&r));
    println!("  MPC signature s: {}", hex::encode(&s));

    // Verify with cggmp24 internal verifier
    sig.verify(&key_shares[0].core.shared_public_key, &data_to_sign)
        .expect("cggmp24 internal verification should pass");
    println!("  cggmp24 internal verify: PASS");

    // =========================================================================
    // STEP 9: Verify with BSV SDK
    // =========================================================================
    println!("\n=== STEP 9: BSV SDK verification ===");

    let bsv_sig = Signature::new(r, s);
    assert!(bsv_sig.is_low_s(), "Signature must be low-S (BIP-62)");
    let bsv_verify = joint_pubkey.verify(&sighash, &bsv_sig);
    assert!(bsv_verify, "BSV SDK verification must pass");
    println!("  BSV SDK verify: PASS");

    // =========================================================================
    // STEP 10: Build unlocking script and serialize transaction
    // =========================================================================
    println!("\n=== STEP 10: Build unlocking script + serialize tx ===");

    let tx_sig = TransactionSignature::new(bsv_sig, scope);
    let checksig_bytes = tx_sig.to_checksig_format();
    let compressed_pubkey = joint_pubkey.to_compressed();
    let unlocking = p2pkh_unlocking_script(&checksig_bytes, &compressed_pubkey);

    println!("  Unlocking script: {} bytes", unlocking.len());

    // Serialize the full signed transaction with ALL 3 outputs
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
    println!("  Outputs in tx: {}", outputs.len());

    log_transaction(
        log_path,
        "MPC SPEND WITH FEE (POC 7)",
        &txid_hex,
        &hex::encode(&raw_tx),
        &mpc_address,
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
            .header("XDeployment-ID", "bsv-mpc-poc7")
            .json(&serde_json::json!({ "rawTx": raw_tx_hex }))
            .send()
            .await;

        match arc_resp {
            Ok(resp) => {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                println!("    Status: {}", status);
                println!("    Response: {}", &text[..text.len().min(300)]);

                if status.is_success() || text.contains("SEEN_ON_NETWORK") || text.contains("MINED") {
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

    assert!(broadcast_success, "Transaction must be accepted by ARC");

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
            println!("  TX confirmed on WhatsOnChain! ({} outputs)", vout_count);
            assert_eq!(vout_count, 3, "Must have 3 outputs (recipient + change + fee)");
        }
        _ => {
            println!("  TX not yet visible on WhatsOnChain (may take a moment)");
            println!("  Check: https://whatsonchain.com/tx/{}", txid_hex);
        }
    }

    // =========================================================================
    // SUMMARY
    // =========================================================================
    println!("\n========================================");
    println!("  POC 7 RESULT: FEE INJECTION VALIDATED");
    println!("========================================");
    println!("  [x] 2-of-2 DKG on secp256k1");
    println!("  [x] Funded MPC address: {} ({} sats)", mpc_address, utxo_value);
    println!("  [x] Built normal tx (1 recipient + 1 change)");
    println!("  [x] Injected fee output: {} sats to {}", fee_sats, fee_address);
    println!("  [x] Adjusted change: {} → {} sats", injection.original_change, injection.new_change);
    println!("  [x] Balance equation: {} == {} + {} ✓", utxo_value, total_outputs, mining_fee);
    println!("  [x] BIP-143 sighash covers all {} outputs", outputs.len());
    println!("  [x] MPC threshold signed (2-of-2 CGGMP'24)");
    println!("  [x] BSV SDK signature verification passed");
    println!("  [x] Broadcast to mainnet");
    println!("  TXID: {}", txid_hex);
    println!("  View: https://whatsonchain.com/tx/{}", txid_hex);
    println!("========================================");
}

// =========================================================================
// TEST: Fee injection edge cases (no MPC, no network — pure unit tests)
// =========================================================================
#[test]
fn test_fee_injection_edge_cases() {
    let dummy_script = |id: u8| -> Vec<u8> {
        p2pkh_locking_script(&[id; 20])
    };

    // --- Case 1: Normal injection ---
    println!("Case 1: Normal fee injection");
    let mut outputs = vec![
        (5000u64, dummy_script(1)),  // recipient
        (4900u64, dummy_script(2)),  // change (input was 10000, mining fee 100)
    ];
    let _result = inject_fee_output(&mut outputs, 1, 1000, dummy_script(3)).unwrap();
    assert_eq!(outputs.len(), 3);
    assert_eq!(outputs[1].0, 3900); // change reduced
    assert_eq!(outputs[2].0, 1000); // fee added
    // Balance: 10000 = 5000 + 3900 + 1000 + 100 ✓
    let total: u64 = outputs.iter().map(|(s, _)| s).sum();
    assert_eq!(10000u64, total + 100);
    println!("  PASS: balance 10000 == {} + 100", total);

    // --- Case 2: Exact change (change goes to 0) ---
    println!("Case 2: Fee equals change");
    let mut outputs = vec![
        (5000u64, dummy_script(1)),
        (1000u64, dummy_script(2)),
    ];
    let _result = inject_fee_output(&mut outputs, 1, 1000, dummy_script(3)).unwrap();
    assert_eq!(outputs[1].0, 0);
    println!("  PASS: change is 0 sats (dust — but valid)");

    // --- Case 3: Insufficient change (graceful failure) ---
    println!("Case 3: Insufficient change");
    let mut outputs = vec![
        (5000u64, dummy_script(1)),
        (500u64, dummy_script(2)),
    ];
    let err = inject_fee_output(&mut outputs, 1, 1000, dummy_script(3)).unwrap_err();
    assert!(matches!(err, FeeInjectionError::InsufficientChange { .. }));
    // Verify outputs are NOT modified on failure
    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[1].0, 500); // unchanged
    println!("  PASS: graceful failure, outputs unchanged");

    // --- Case 4: Split fee among 3 operators ---
    println!("Case 4: Split fee among 3 operators");
    let mut outputs = vec![
        (2000u64, dummy_script(1)),  // recipient
        (7900u64, dummy_script(2)),  // change
    ];
    let fee_scripts = vec![dummy_script(10), dummy_script(11), dummy_script(12)];
    let _results = inject_split_fee(&mut outputs, 1, 999, &fee_scripts).unwrap();
    assert_eq!(outputs.len(), 5); // recipient + change + 3 fee outputs
    assert_eq!(outputs[1].0, 6901); // 7900 - 999
    assert_eq!(outputs[2].0, 333); // 333 + 0 remainder
    assert_eq!(outputs[3].0, 333);
    assert_eq!(outputs[4].0, 333);
    let total: u64 = outputs.iter().map(|(s, _)| s).sum();
    assert_eq!(10000u64, total + 100); // 2000 + 6901 + 333 + 333 + 333 + 100 = 10000
    println!("  PASS: split fee, balance 10000 == {} + 100", total);

    // --- Case 5: Fee injection with change at index 0 ---
    println!("Case 5: Change output at index 0");
    let mut outputs = vec![
        (8000u64, dummy_script(1)),  // change is first
        (1900u64, dummy_script(2)),  // recipient is second
    ];
    let _result = inject_fee_output(&mut outputs, 0, 1000, dummy_script(3)).unwrap();
    assert_eq!(outputs[0].0, 7000);
    assert_eq!(outputs[2].0, 1000);
    println!("  PASS: change at index 0 works");

    println!("\nAll edge cases passed.");
}
