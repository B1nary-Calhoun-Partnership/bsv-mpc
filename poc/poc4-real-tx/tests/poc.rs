//! POC 4: Sign a real BSV transaction on MAINNET using MPC threshold signing
//!
//! This is the definitive proof that bsv-mpc can produce valid BSV transactions.
//!
//! Flow:
//! 1. Two-party DKG → joint public key → BSV P2PKH address
//! 2. Fund the MPC address (send 1,500 sats from wallet at localhost:3321)
//! 3. Query WhatsOnChain for UTXO
//! 4. Build P2PKH spending transaction
//! 5. Compute BIP-143 sighash
//! 6. MPC threshold sign the sighash
//! 7. Build unlocking script (DER sig + pubkey)
//! 8. Broadcast to mainnet
//! 9. Verify on WhatsOnChain

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

// ---- Helper: P2PKH locking script from pubkey hash ----

fn p2pkh_locking_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

// ---- Helper: P2PKH unlocking script from sig + pubkey ----

fn p2pkh_unlocking_script(sig_checksig: &[u8], compressed_pubkey: &[u8; 33]) -> Vec<u8> {
    let mut script = Vec::new();
    // Push signature (checksig format: DER + sighash byte)
    script.push(sig_checksig.len() as u8);
    script.extend_from_slice(sig_checksig);
    // Push compressed public key
    script.push(33);
    script.extend_from_slice(compressed_pubkey);
    script
}

// ---- Helper: serialize a raw transaction ----

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

    // Version
    w.write_i32_le(version);

    // Input count
    w.write_var_int(inputs.len() as u64);
    for (txid, vout, script, seq) in inputs {
        w.write_bytes(txid);
        w.write_u32_le(*vout);
        w.write_var_int(script.len() as u64);
        w.write_bytes(script);
        w.write_u32_le(*seq);
    }

    // Output count
    w.write_var_int(outputs.len() as u64);
    for (sats, script) in outputs {
        w.write_u64_le(*sats);
        w.write_var_int(script.len() as u64);
        w.write_bytes(script);
    }

    // Locktime
    w.write_u32_le(locktime);

    w.into_bytes()
}

/// Log transaction details to a recovery file
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
    writeln!(f, "timestamp: {}", chrono_like_now()).ok();
    writeln!(f, "txid: {}", txid).ok();
    writeln!(f, "mpc_address: {}", mpc_address).ok();
    writeln!(f, "joint_pubkey: {}", joint_pubkey).ok();
    writeln!(f, "amount_sats: {}", amount_sats).ok();
    writeln!(f, "raw_hex: {}", raw_hex).ok();
    writeln!(f, "").ok();
}

fn chrono_like_now() -> String {
    use std::time::SystemTime;
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    format!("unix_{}", d.as_secs())
}

// ---- The Test ----

#[tokio::test]
async fn test_mpc_signed_mainnet_transaction() {
    let mut rng = rand::rngs::OsRng;
    let n: u16 = 2;
    let t: u16 = 2;

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
    let address = joint_pubkey.to_address();
    println!("  Joint pubkey: {}", joint_pubkey.to_hex());
    println!("  MPC address: {}", address);

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
    // STEP 3: Fund the MPC address
    // =========================================================================
    println!("\n=== STEP 3: Fund MPC address ===");

    let log_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tx_log.txt");

    let client = reqwest::Client::new();
    let funding_amount: u64 = 1500; // sats — well under 10,000 budget

    // Use bsv-wallet at localhost:3321 to send funds
    let fund_body = serde_json::json!({
        "description": "POC 4: fund MPC address",
        "outputs": [{
            "satoshis": funding_amount,
            "lockingScript": hex::encode(p2pkh_locking_script(&joint_pubkey.hash160())),
            "outputDescription": "MPC P2PKH output"
        }]
    });

    let fund_resp = client
        .post("http://localhost:3321/createAction")
        .header("Origin", "http://localhost")
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

    // Extract the funding txid
    let fund_txid = fund_json["txid"]
        .as_str()
        .expect("funding response should have txid");
    println!("  Funding txid: {}", fund_txid);

    // =========================================================================
    // STEP 4: Find our UTXO via WhatsOnChain
    // =========================================================================
    println!("\n=== STEP 4: Find UTXO ===");

    // Fetch the funding tx from WoC to find our output index (retry with backoff)
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
                            // WoC returns value in BSV — use round to avoid float issues
                            let value_bsv = vout_obj["value"].as_f64().unwrap_or(0.0);
                            utxo_value = (value_bsv * 100_000_000.0 + 0.5) as u64;
                            found = true;
                            break;
                        }
                    }
                }
                if found {
                    println!("  Found UTXO via WoC: {}:{} ({} sats)", fund_txid, utxo_vout, utxo_value);
                    break;
                }
            }
        }
    }

    assert!(found, "Must find funding UTXO on WoC within retries");

    // Log funding tx for recovery
    log_transaction(
        log_path,
        "FUNDING",
        fund_txid,
        "(wallet BEEF tx - see wallet logs)",
        &address,
        &joint_pubkey.to_hex(),
        utxo_value,
    );

    // =========================================================================
    // STEP 5: Build spending transaction
    // =========================================================================
    println!("\n=== STEP 5: Build spending transaction ===");

    // Parse the funding txid from hex (display order → internal byte order)
    let mut prev_txid = [0u8; 32];
    let txid_bytes = hex::decode(fund_txid).expect("valid txid hex");
    prev_txid.copy_from_slice(&txid_bytes);
    prev_txid.reverse(); // display → internal byte order

    // Calculate fee: P2PKH tx with 1 input, 1 output ≈ 192 bytes → ~20 sats at 100 sat/kb
    // Use 100 sats to be safe
    let fee: u64 = 100;

    // Send remaining back to the bsv-wallet identity key (return the funds)
    // Get wallet's identity key
    let ident_resp = client
        .post("http://localhost:3321/getPublicKey")
        .header("Origin", "http://localhost")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({"identityKey": true}))
        .send()
        .await
        .expect("identity key request should work");

    let ident_json: serde_json::Value = ident_resp.json().await.unwrap();
    let wallet_pubkey_hex = ident_json["publicKey"]
        .as_str()
        .expect("should have publicKey");
    let wallet_pubkey =
        PublicKey::from_hex(wallet_pubkey_hex).expect("valid wallet pubkey");

    let change_amount = utxo_value.checked_sub(fee).expect("UTXO must cover fee");
    let change_script = p2pkh_locking_script(&wallet_pubkey.hash160());

    println!("  Input: {} sats", utxo_value);
    println!("  Output: {} sats to wallet ({})", change_amount, &wallet_pubkey_hex[..16]);
    println!("  Fee: {} sats", fee);

    // Build sighash inputs/outputs for BIP-143
    let locking_script = p2pkh_locking_script(&joint_pubkey.hash160());

    let sighash_inputs = vec![TxInput {
        txid: prev_txid,
        output_index: utxo_vout,
        script: vec![], // empty for unsigned
        sequence: 0xFFFFFFFF,
    }];

    let sighash_outputs = vec![TxOutput {
        satoshis: change_amount,
        script: change_script.clone(),
    }];

    // Compute BIP-143 sighash
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

    println!("  Sighash: {}", hex::encode(&sighash));

    // =========================================================================
    // STEP 6: MPC threshold sign the sighash
    // =========================================================================
    println!("\n=== STEP 6: MPC threshold sign ===");

    // Convert sighash to a cggmp24 scalar for signing
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

    // Extract signature bytes
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

    // Verify with BSV SDK
    let bsv_sig = Signature::new(r, s);
    assert!(
        bsv_sig.is_low_s(),
        "Signature must be low-S (BIP-62)"
    );
    let bsv_verify = joint_pubkey.verify(&sighash, &bsv_sig);
    assert!(bsv_verify, "BSV SDK verification must pass");
    println!("  BSV SDK verify: PASS");

    // =========================================================================
    // STEP 7: Build unlocking script and serialize transaction
    // =========================================================================
    println!("\n=== STEP 7: Build unlocking script + serialize tx ===");

    let tx_sig = TransactionSignature::new(bsv_sig, scope);
    let checksig_bytes = tx_sig.to_checksig_format();
    let compressed_pubkey = joint_pubkey.to_compressed();
    let unlocking = p2pkh_unlocking_script(&checksig_bytes, &compressed_pubkey);

    println!("  Unlocking script: {} bytes", unlocking.len());
    println!("  Checksig sig: {} bytes", checksig_bytes.len());

    // Serialize the full signed transaction
    let raw_tx = serialize_transaction(
        1, // version
        &[(prev_txid, utxo_vout, unlocking, 0xFFFFFFFF)],
        &[(change_amount, change_script)],
        0, // locktime
    );

    let txid = sha256d(&raw_tx);
    let mut txid_display = txid;
    txid_display.reverse();
    println!("  Raw tx: {} bytes", raw_tx.len());
    println!("  TXID: {}", hex::encode(&txid_display));
    println!("  Raw tx hex: {}", hex::encode(&raw_tx));

    // Log spending tx for recovery
    log_transaction(
        log_path,
        "MPC SPEND",
        &hex::encode(&txid_display),
        &hex::encode(&raw_tx),
        &address,
        &joint_pubkey.to_hex(),
        change_amount,
    );

    // =========================================================================
    // STEP 8: Broadcast to mainnet via ARC
    // =========================================================================
    println!("\n=== STEP 8: Broadcast to mainnet via ARC ===");

    let raw_tx_hex = hex::encode(&raw_tx);
    let mut broadcast_success = false;

    // Try ARC endpoints (TAAL mainnet, then GorillaPool)
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
            .header("XDeployment-ID", "bsv-mpc-poc4")
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
    // STEP 9: Verify on WhatsOnChain
    // =========================================================================
    println!("\n=== STEP 9: Verify on WhatsOnChain ===");

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let verify_url = format!(
        "https://api.whatsonchain.com/v1/bsv/main/tx/hash/{}",
        hex::encode(&txid_display)
    );
    let verify_resp = client.get(&verify_url).send().await;

    match verify_resp {
        Ok(resp) if resp.status().is_success() => {
            println!("  TX confirmed on WhatsOnChain!");
            println!(
                "  View: https://whatsonchain.com/tx/{}",
                hex::encode(&txid_display)
            );
        }
        _ => {
            println!("  TX not yet visible on WhatsOnChain (may take a moment)");
            println!(
                "  Check: https://whatsonchain.com/tx/{}",
                hex::encode(&txid_display)
            );
        }
    }

    // =========================================================================
    // SUMMARY
    // =========================================================================
    println!("\n========================================");
    println!("  POC 4 RESULT: MPC-SIGNED BSV TRANSACTION");
    println!("========================================");
    println!("  [x] 2-of-2 DKG on secp256k1");
    println!("  [x] Funded MPC address: {}", address);
    println!("  [x] BIP-143 sighash computed");
    println!("  [x] MPC threshold signed");
    println!("  [x] Signature is low-S (BIP-62)");
    println!("  [x] BSV SDK verification passed");
    println!("  [x] Transaction broadcast to mainnet");
    println!("  TXID: {}", hex::encode(&txid_display));
    println!("========================================");
}
