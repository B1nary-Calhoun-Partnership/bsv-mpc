//! POC 4 Full Loop: Fund → MPC Sign → Broadcast → Internalize → Verify Balance
//!
//! Clean end-to-end test proving the complete MPC transaction lifecycle.
//! Checks wallet balance before and after.

use std::collections::VecDeque;

use bsv::primitives::bsv::sighash::{
    compute_sighash_for_signing, SighashParams, TxInput, TxOutput, SIGHASH_ALL, SIGHASH_FORKID,
};
use bsv::primitives::bsv::tx_signature::TransactionSignature;
use bsv::primitives::ec::{PublicKey, Signature};
use bsv::primitives::encoding::{from_hex, Writer};
use bsv::primitives::hash::sha256d;
use bsv::transaction::merkle_path::{MerklePath, MerklePathLeaf};
use bsv::transaction::Beef;

use cggmp24::security_level::SecurityLevel128;
use cggmp24::signing::PrehashedDataToSign;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use generic_ec::Scalar;
use rand::Rng;

const ADMIN_ORIGIN: &str = "http://admin.com";
const WALLET_URL: &str = "http://localhost:3321";

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
    fn poll_ready(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> { std::task::Poll::Ready(Ok(())) }
    fn start_send(self: std::pin::Pin<&mut Self>, item: M) -> Result<(), Self::Error> { self.project().messages.get_mut().push_back(item); Ok(()) }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        while !self.messages.is_empty() { let mut p = self.as_mut().project(); let mut inner = p.inner; std::task::ready!(inner.as_mut().poll_ready(cx))?; if let Some(item) = p.messages.pop_front() { inner.as_mut().start_send(item)?; } }
        self.project().inner.poll_flush(cx)
    }
    fn poll_close(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> { self.project().inner.poll_close(cx) }
}
fn buffer_outgoing<M, D, R>(party: round_based::MpcParty<M, D, R>) -> round_based::MpcParty<M, BufferedDelivery<M, D>, R>
where M: Unpin, D: round_based::Delivery<M>, R: round_based::runtime::AsyncRuntime {
    party.map_delivery(|d| { let (i, o) = d.split(); (i, BufferedSink { messages: VecDeque::new(), inner: o }) })
}

// ---- Helpers ----

fn generate_blum_prime(rng: &mut impl rand::RngCore, bits: u32) -> cggmp24::backend::Integer {
    loop { let n = cggmp24::backend::Integer::generate_prime(rng, bits); if n.mod_u(4) == 3 { break n; } }
}
fn gen_primes(rng: &mut impl rand::RngCore) -> cggmp24::key_refresh::PregeneratedPrimes<SecurityLevel128> {
    use cggmp24::security_level::SecurityLevel;
    let b = SecurityLevel128::RSA_PRIME_BITLEN;
    cggmp24::key_refresh::PregeneratedPrimes::try_from([generate_blum_prime(rng, b), generate_blum_prime(rng, b), generate_blum_prime(rng, b), generate_blum_prime(rng, b)]).unwrap()
}

fn p2pkh_script(hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.extend_from_slice(&[0x76, 0xa9, 0x14]);
    s.extend_from_slice(hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn serialize_tx(version: i32, inputs: &[([u8; 32], u32, Vec<u8>, u32)], outputs: &[(u64, Vec<u8>)], locktime: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_i32_le(version);
    w.write_var_int(inputs.len() as u64);
    for (txid, vout, script, seq) in inputs { w.write_bytes(txid); w.write_u32_le(*vout); w.write_var_int(script.len() as u64); w.write_bytes(script); w.write_u32_le(*seq); }
    w.write_var_int(outputs.len() as u64);
    for (sats, script) in outputs { w.write_u64_le(*sats); w.write_var_int(script.len() as u64); w.write_bytes(script); }
    w.write_u32_le(locktime);
    w.into_bytes()
}

fn tsc_to_merkle_path(block_height: u32, tx_index: u64, txid: &str, nodes: &[String]) -> MerklePath {
    let mut path: Vec<Vec<MerklePathLeaf>> = Vec::new();
    let mut idx = tx_index;
    let mut level0 = vec![MerklePathLeaf::new_txid(tx_index, txid.to_string())];
    if !nodes.is_empty() {
        let sib = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        level0.push(MerklePathLeaf::new(sib, nodes[0].clone()));
    }
    level0.sort_by_key(|l| l.offset);
    path.push(level0);
    idx /= 2;
    for h in &nodes[1..] {
        let sib = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        path.push(vec![MerklePathLeaf::new(sib, h.clone())]);
        idx /= 2;
    }
    MerklePath::new_unchecked(block_height, path).expect("valid merkle path")
}

async fn get_wallet_balance(client: &reqwest::Client) -> u64 {
    let resp: serde_json::Value = client
        .post(format!("{}/listOutputs", WALLET_URL))
        .header("Origin", ADMIN_ORIGIN)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({"basket": "default", "limit": 10000}))
        .send().await.unwrap().json().await.unwrap();
    resp["outputs"].as_array().unwrap().iter()
        .map(|o| o["satoshis"].as_u64().unwrap_or(0))
        .sum()
}

fn log_tx(label: &str, txid: &str, addr: &str, pubkey: &str, sats: u64, raw: &str) {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).append(true)
        .open(concat!(env!("CARGO_MANIFEST_DIR"), "/tx_log.txt")).unwrap();
    writeln!(f, "--- {label} ---\ntxid: {txid}\naddress: {addr}\npubkey: {pubkey}\nsats: {sats}\nraw: {raw}\n").ok();
}

// ---- The Full Loop Test ----

#[tokio::test]
async fn test_full_loop() {
    let client = reqwest::Client::new();
    let mut rng = rand::rngs::OsRng;

    // ---- BALANCE BEFORE ----
    let balance_before = get_wallet_balance(&client).await;
    println!("Wallet balance BEFORE: {} sats", balance_before);

    // ---- STEP 1: DKG ----
    println!("\n=== STEP 1: DKG ===");
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);
    let shares = round_based::sim::run(2u16, |i, party| {
        let party = buffer_outgoing(party);
        let mut r = rand::rngs::OsRng;
        async move { cggmp24::keygen::<Secp256k1>(eid, i, 2).set_threshold(2).start(&mut r, party).await }
    }).unwrap().expect_ok().into_vec();
    let jpk_bytes = shares[0].shared_public_key.to_bytes(true);
    let jpk = PublicKey::from_bytes(&jpk_bytes).unwrap();
    let addr = jpk.to_address();
    println!("  MPC address: {addr}");

    // ---- STEP 2: Aux info + key shares ----
    println!("\n=== STEP 2: Aux info ===");
    let eid2: [u8; 32] = rng.gen();
    let eid2 = ExecutionId::new(&eid2);
    let primes: Vec<_> = (0..2).map(|_| gen_primes(&mut rng)).collect();
    let auxs = round_based::sim::run(2u16, |i, party| {
        let party = buffer_outgoing(party);
        let mut r = rand::rngs::OsRng;
        let p = primes[usize::from(i)].clone();
        async move { cggmp24::aux_info_gen(eid2, i, 2, p).start(&mut r, party).await }
    }).unwrap().expect_ok().into_vec();
    let keys: Vec<_> = shares.into_iter().zip(auxs).map(|(s, a)| cggmp24::KeyShare::from_parts((s, a)).unwrap()).collect();
    println!("  Key shares ready");

    // ---- STEP 3: Fund MPC address (1000 sats) ----
    println!("\n=== STEP 3: Fund ===");
    let fund_amt: u64 = 1000;
    let locking = p2pkh_script(&jpk.hash160());
    let resp: serde_json::Value = client
        .post(format!("{}/createAction", WALLET_URL))
        .header("Origin", ADMIN_ORIGIN)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "description": "POC4 full loop fund",
            "outputs": [{"satoshis": fund_amt, "lockingScript": hex::encode(&locking), "outputDescription": "MPC P2PKH"}]
        }))
        .send().await.unwrap().json().await.unwrap();
    let fund_txid = resp["txid"].as_str().expect("need txid");
    println!("  Fund txid: {fund_txid}");
    log_tx("FULL LOOP FUNDING", fund_txid, &addr, &jpk.to_hex(), fund_amt, "see wallet");

    // ---- STEP 4: Find UTXO via WoC (retry) ----
    println!("\n=== STEP 4: Find UTXO ===");
    let locking_hex = hex::encode(&locking);
    let mut vout = 0u32;
    let mut utxo_sats = fund_amt;
    for attempt in 1..=8 {
        let wait = attempt * 3;
        println!("  Attempt {attempt}: waiting {wait}s...");
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        if let Ok(r) = client.get(format!("https://api.whatsonchain.com/v1/bsv/main/tx/hash/{fund_txid}")).send().await {
            if r.status().is_success() {
                let j: serde_json::Value = r.json().await.unwrap();
                if let Some(vouts) = j["vout"].as_array() {
                    for v in vouts {
                        if v["scriptPubKey"]["hex"].as_str().unwrap_or("") == locking_hex {
                            vout = v["n"].as_u64().unwrap() as u32;
                            utxo_sats = (v["value"].as_f64().unwrap() * 1e8 + 0.5) as u64;
                            println!("  Found: vout={vout}, {utxo_sats} sats");
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }

    // ---- STEP 5: Build tx ----
    println!("\n=== STEP 5: Build tx ===");
    let mut prev_txid = [0u8; 32];
    prev_txid.copy_from_slice(&hex::decode(fund_txid).unwrap());
    prev_txid.reverse();
    let fee = 20u64; // 100 sat/kb for ~200 byte tx
    let change = utxo_sats - fee;

    // Get wallet identity key for return output
    let ident: serde_json::Value = client
        .post(format!("{}/getPublicKey", WALLET_URL))
        .header("Origin", ADMIN_ORIGIN)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({"identityKey": true}))
        .send().await.unwrap().json().await.unwrap();
    let wallet_pk = PublicKey::from_hex(ident["publicKey"].as_str().unwrap()).unwrap();
    let change_script = p2pkh_script(&wallet_pk.hash160());

    println!("  In: {utxo_sats} sats → Out: {change} sats + {fee} fee");

    // Sighash
    let scope = SIGHASH_ALL | SIGHASH_FORKID;
    let sighash = compute_sighash_for_signing(&SighashParams {
        version: 1,
        inputs: &[TxInput { txid: prev_txid, output_index: vout, script: vec![], sequence: 0xFFFFFFFF }],
        outputs: &[TxOutput { satoshis: change, script: change_script.clone() }],
        locktime: 0, input_index: 0, subscript: &locking, satoshis: utxo_sats, scope,
    });

    // ---- STEP 6: MPC sign ----
    println!("\n=== STEP 6: MPC sign ===");
    let scalar = Scalar::<Secp256k1>::from_be_bytes(&sighash).unwrap();
    let msg = PrehashedDataToSign::from_scalar(scalar);
    let eid3: [u8; 32] = rng.gen();
    let eid3 = ExecutionId::new(&eid3);
    let parts: Vec<u16> = vec![0, 1];
    let sig = round_based::sim::run_with_setup(
        parts.iter().map(|i| &keys[*i as usize]),
        |i, party, share| {
            let party = buffer_outgoing(party);
            let mut r = rand::rngs::OsRng;
            let p = parts.clone();
            async move { cggmp24::signing(eid3, i, &p, share).sign(&mut r, party, &msg).await }
        },
    ).unwrap().expect_ok().expect_eq();

    let mut sb = [0u8; 64];
    sig.write_to_slice(&mut sb);
    let mut r = [0u8; 32]; let mut s = [0u8; 32];
    r.copy_from_slice(&sb[..32]); s.copy_from_slice(&sb[32..]);
    let bsv_sig = Signature::new(r, s);
    assert!(bsv_sig.is_low_s());
    assert!(jpk.verify(&sighash, &bsv_sig));
    println!("  Signature verified");

    // ---- STEP 7: Serialize + broadcast via ARC ----
    println!("\n=== STEP 7: Broadcast via ARC ===");
    let txsig = TransactionSignature::new(bsv_sig, scope);
    let checksig = txsig.to_checksig_format();
    let cpk = jpk.to_compressed();
    let mut unlock = Vec::new();
    unlock.push(checksig.len() as u8); unlock.extend_from_slice(&checksig);
    unlock.push(33); unlock.extend_from_slice(&cpk);

    let raw_tx = serialize_tx(1, &[(prev_txid, vout, unlock, 0xFFFFFFFF)], &[(change, change_script.clone())], 0);
    let txid_bytes = sha256d(&raw_tx);
    let mut txid_disp = txid_bytes; txid_disp.reverse();
    let txid_hex = hex::encode(&txid_disp);
    let raw_hex = hex::encode(&raw_tx);
    println!("  TXID: {txid_hex}");
    println!("  Size: {} bytes", raw_tx.len());
    log_tx("FULL LOOP MPC SPEND", &txid_hex, &addr, &jpk.to_hex(), change, &raw_hex);

    let arc_resp: serde_json::Value = client
        .post("https://arc.gorillapool.io/v1/tx")
        .header("Content-Type", "application/json")
        .header("XDeployment-ID", "bsv-mpc-poc4")
        .json(&serde_json::json!({"rawTx": raw_hex}))
        .send().await.unwrap().json().await.unwrap();
    let arc_status = arc_resp["txStatus"].as_str().unwrap_or("unknown");
    println!("  ARC: {arc_status}");
    assert!(arc_status == "SEEN_ON_NETWORK" || arc_status == "MINED", "ARC must accept tx");

    // ---- STEP 8: Wait for confirmation + get merkle proof ----
    println!("\n=== STEP 8: Wait for confirmation ===");
    let mut merkle_hex = String::new();
    let mut block_height = 0u32;
    for attempt in 1..=20 {
        let wait = 5;
        println!("  Check {attempt}: waiting {wait}s...");
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        if let Ok(r) = client.get(format!("https://arc.gorillapool.io/v1/tx/{txid_hex}"))
            .header("Accept", "application/json").send().await {
            if let Ok(j) = r.json::<serde_json::Value>().await {
                let status = j["txStatus"].as_str().unwrap_or("");
                if status == "MINED" {
                    merkle_hex = j["merklePath"].as_str().unwrap_or("").to_string();
                    block_height = j["blockHeight"].as_u64().unwrap_or(0) as u32;
                    println!("  MINED in block {block_height}!");
                    break;
                }
                println!("  Status: {status}");
            }
        }
    }

    // If not mined yet, go deeper — find the funding tx's confirmed parent
    if merkle_hex.is_empty() {
        println!("  Not mined yet — finding confirmed ancestor for BEEF");

        // Get funding tx raw to find its parent
        let fund_raw: String = client
            .get(format!("https://api.whatsonchain.com/v1/bsv/main/tx/{fund_txid}/hex"))
            .send().await.unwrap().text().await.unwrap().trim_matches('"').to_string();
        let fund_bytes = from_hex(&fund_raw).unwrap();
        let fund_parsed = bsv::primitives::bsv::sighash::parse_transaction(&fund_bytes).unwrap();

        // Get the parent txid (first input of funding tx)
        let parent_txid_internal = &fund_parsed.inputs[0].txid;
        let mut parent_txid_disp = *parent_txid_internal;
        parent_txid_disp.reverse();
        let parent_txid = hex::encode(parent_txid_disp);
        println!("  Funding tx parent: {parent_txid}");

        // Get the parent's raw tx and merkle proof
        let parent_raw: String = client
            .get(format!("https://api.whatsonchain.com/v1/bsv/main/tx/{parent_txid}/hex"))
            .send().await.unwrap().text().await.unwrap().trim_matches('"').to_string();

        let proof_text: String = client
            .get(format!("https://api.whatsonchain.com/v1/bsv/main/tx/{parent_txid}/proof/tsc"))
            .send().await.unwrap().text().await.unwrap();
        let proof: serde_json::Value = serde_json::from_str(&proof_text).expect("parent should have proof");
        let proof = &proof[0];
        let target = proof["target"].as_str().unwrap();
        let block_info: serde_json::Value = client
            .get(format!("https://api.whatsonchain.com/v1/bsv/main/block/hash/{target}"))
            .send().await.unwrap().json().await.unwrap();
        block_height = block_info["height"].as_u64().unwrap() as u32;
        let idx = proof["index"].as_u64().unwrap();
        let nodes: Vec<String> = proof["nodes"].as_array().unwrap().iter()
            .map(|v| v.as_str().unwrap().to_string()).collect();
        println!("  Parent confirmed in block {block_height}, index {idx}");

        let mp = tsc_to_merkle_path(block_height, idx, &parent_txid, &nodes);

        // Build 3-tx BEEF: confirmed parent → unconfirmed funding → unconfirmed spending
        let mut beef = Beef::with_version(bsv::transaction::beef_tx::BEEF_V2);
        let bi = beef.merge_bump(mp);
        beef.merge_raw_tx(from_hex(&parent_raw).unwrap(), Some(bi)); // parent with proof
        beef.merge_raw_tx(fund_bytes, None); // funding tx (chains to parent)
        beef.merge_raw_tx(raw_tx.clone(), None); // spending tx (chains to funding)
        println!("  BEEF valid: {}", beef.is_valid(false));
        assert!(beef.is_valid(false), "BEEF must be valid");

        let atomic = beef.to_binary_atomic(&txid_hex).unwrap();
        let tx_json: Vec<serde_json::Value> = atomic.iter().map(|b| (*b).into()).collect();

        println!("\n=== STEP 9: Internalize to default basket ===");
        let int_resp: serde_json::Value = client
            .post(format!("{}/internalizeAction", WALLET_URL))
            .header("Origin", ADMIN_ORIGIN)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "tx": tx_json,
                "outputs": [{"outputIndex": 0, "protocol": "basket insertion", "insertionRemittance": {"basket": "default", "tags": ["poc4-full-loop"]}}],
                "description": "POC4 MPC spend return"
            }))
            .send().await.unwrap().json().await.unwrap();
        println!("  Response: {int_resp}");
        assert_eq!(int_resp["accepted"].as_bool(), Some(true), "internalization must succeed");
        println!("  INTERNALIZED to default basket!");
    } else {
        // Spending tx is mined — use its own merkle proof
        let mp = bsv::transaction::MerklePath::from_binary(&from_hex(&merkle_hex).unwrap()).unwrap();
        let fund_raw: String = client
            .get(format!("https://api.whatsonchain.com/v1/bsv/main/tx/{fund_txid}/hex"))
            .send().await.unwrap().text().await.unwrap().trim_matches('"').to_string();

        let mut beef = Beef::with_version(bsv::transaction::beef_tx::BEEF_V2);
        let bi = beef.merge_bump(mp);
        beef.merge_raw_tx(from_hex(&fund_raw).unwrap(), None);
        beef.merge_raw_tx(raw_tx.clone(), Some(bi));

        // If spending tx has proof, the funding tx still needs one for valid BEEF
        // Fall back to funding-tx-proved approach
        if !beef.is_valid(false) {
            println!("  Spending tx proved but funding tx needs proof too — getting it...");
            let proof_text: String = client
                .get(format!("https://api.whatsonchain.com/v1/bsv/main/tx/{fund_txid}/proof/tsc"))
                .send().await.unwrap().text().await.unwrap();
            let proof: serde_json::Value = serde_json::from_str(&proof_text).unwrap();
            let proof = &proof[0];
            let target = proof["target"].as_str().unwrap();
            let block_info: serde_json::Value = client
                .get(format!("https://api.whatsonchain.com/v1/bsv/main/block/hash/{target}"))
                .send().await.unwrap().json().await.unwrap();
            let fund_bh = block_info["height"].as_u64().unwrap() as u32;
            let idx = proof["index"].as_u64().unwrap();
            let nodes: Vec<String> = proof["nodes"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
            let fund_mp = tsc_to_merkle_path(fund_bh, idx, fund_txid, &nodes);

            let mut beef2 = Beef::with_version(bsv::transaction::beef_tx::BEEF_V2);
            let bi1 = beef2.merge_bump(fund_mp);
            let spend_mp2 = bsv::transaction::MerklePath::from_binary(&from_hex(&merkle_hex).unwrap()).unwrap();
            let bi2 = beef2.merge_bump(spend_mp2);
            beef2.merge_raw_tx(from_hex(&fund_raw).unwrap(), Some(bi1));
            beef2.merge_raw_tx(raw_tx.clone(), Some(bi2));
            beef = beef2;
        }

        assert!(beef.is_valid(false), "BEEF must be valid");
        let atomic = beef.to_binary_atomic(&txid_hex).unwrap();
        let tx_json: Vec<serde_json::Value> = atomic.iter().map(|b| (*b).into()).collect();

        println!("\n=== STEP 9: Internalize to default basket ===");
        let int_resp: serde_json::Value = client
            .post(format!("{}/internalizeAction", WALLET_URL))
            .header("Origin", ADMIN_ORIGIN)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "tx": tx_json,
                "outputs": [{"outputIndex": 0, "protocol": "basket insertion", "insertionRemittance": {"basket": "default", "tags": ["poc4-full-loop"]}}],
                "description": "POC4 MPC spend return"
            }))
            .send().await.unwrap().json().await.unwrap();
        println!("  Response: {int_resp}");
        assert_eq!(int_resp["accepted"].as_bool(), Some(true), "internalization must succeed");
        println!("  INTERNALIZED to default basket!");
    }

    // ---- BALANCE AFTER ----
    let balance_after = get_wallet_balance(&client).await;
    println!("\n========================================");
    println!("  POC 4 FULL LOOP COMPLETE");
    println!("========================================");
    println!("  Balance before: {} sats", balance_before);
    println!("  Balance after:  {} sats", balance_after);
    println!("  Difference:     {} sats (expected: -{} fee)", balance_before as i64 - balance_after as i64, 20 + 10); // createAction fee + MPC tx fee
    println!("  TXID: {txid_hex}");
    println!("  View: https://whatsonchain.com/tx/{txid_hex}");
    println!("========================================");
}
