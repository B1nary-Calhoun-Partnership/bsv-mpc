/// Build Atomic BEEF and internalize the MPC spending tx back to the wallet.

use bsv::primitives::encoding::from_hex;
use bsv::transaction::merkle_path::{MerklePath, MerklePathLeaf};
use bsv::transaction::Beef;

/// Convert a WoC TSC merkle proof to a BSV SDK MerklePath.
///
/// TSC format: { index, txOrId, target, nodes: [hash, hash, ...] }
/// BUMP format: block_height + tree of (offset, hash) pairs at each level
fn tsc_to_merkle_path(
    block_height: u32,
    tx_index: u64,
    txid: &str,
    sibling_hashes: &[String],
) -> MerklePath {
    let mut path: Vec<Vec<MerklePathLeaf>> = Vec::new();
    let mut current_index = tx_index;

    // Level 0: the txid itself + its sibling
    let mut level0 = vec![MerklePathLeaf::new_txid(tx_index, txid.to_string())];
    if !sibling_hashes.is_empty() {
        let sibling_index = if current_index % 2 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };
        level0.push(MerklePathLeaf::new(
            sibling_index,
            sibling_hashes[0].clone(),
        ));
    }
    level0.sort_by_key(|l| l.offset);
    path.push(level0);

    // Subsequent levels: each sibling hash
    current_index /= 2;
    for hash in &sibling_hashes[1..] {
        let sibling_index = if current_index % 2 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };
        let level = vec![MerklePathLeaf::new(sibling_index, hash.clone())];
        path.push(level);
        current_index /= 2;
    }

    MerklePath::new_unchecked(block_height, path).expect("valid merkle path")
}

#[tokio::main]
async fn main() {
    let client = reqwest::Client::new();

    let spend_hex = "0100000001e995780347159c7d6c993fc3363511581d9037a509eef2868a54216ff3e46908000000006a47304402200511c1cf041237cb4e3e9fbe9beeaaf9edff772120f56c00717154d5e4a8840a02204640589405bd613f226dd4e3ed8a6ee40eea8e0197497bc39220b4bb030ae65e4121032f305e1e197f917735ef52619e6d4d6928a19e1caf9e9032cccf664fc90c6801ffffffff0178050000000000001976a914956d22e389c5a46f000b575f2de864d976f0b5ec88ac00000000";
    let spend_txid = "2e4a3afa0ae5c9c92422f6c703e36590884165669775cf7c7705a2ae43046bb7";
    let fund_txid = "0869e4f36f21548a86f2ee09a537901d58113536c33f996c7d9c1547037895e9";

    println!("Fetching data...");

    // Get funding tx raw
    let fund_raw: String = client
        .get(format!("https://api.whatsonchain.com/v1/bsv/main/tx/{}/hex", fund_txid))
        .send().await.unwrap().text().await.unwrap()
        .trim_matches('"').to_string();

    // Get funding tx merkle proof from WoC
    let fund_proof_text: String = client
        .get(format!("https://api.whatsonchain.com/v1/bsv/main/tx/{}/proof/tsc", fund_txid))
        .send().await.unwrap().text().await.unwrap();

    let fund_proof: serde_json::Value = serde_json::from_str(&fund_proof_text).unwrap();
    let fund_proof = &fund_proof[0]; // First element of array

    // Get block height from target hash
    let fund_target = fund_proof["target"].as_str().unwrap();
    let fund_block_resp: serde_json::Value = client
        .get(format!("https://api.whatsonchain.com/v1/bsv/main/block/hash/{}", fund_target))
        .send().await.unwrap().json().await.unwrap();
    let fund_block_height = fund_block_resp["height"].as_u64().unwrap() as u32;

    let fund_index = fund_proof["index"].as_u64().unwrap();
    let fund_nodes: Vec<String> = fund_proof["nodes"]
        .as_array().unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    println!("  Funding tx block: {}, index: {}, {} proof nodes", fund_block_height, fund_index, fund_nodes.len());

    let fund_merkle = tsc_to_merkle_path(fund_block_height, fund_index, fund_txid, &fund_nodes);

    // Build BEEF V2 with funding tx (proved) + spending tx (raw, chains to funding)
    let fund_bytes = from_hex(&fund_raw).unwrap();
    let spend_bytes = from_hex(spend_hex).unwrap();

    let mut beef = Beef::with_version(bsv::transaction::beef_tx::BEEF_V2);
    let bump_idx = beef.merge_bump(fund_merkle);
    beef.merge_raw_tx(fund_bytes, Some(bump_idx));
    beef.merge_raw_tx(spend_bytes, None);

    // Validate
    let valid = beef.is_valid(false);
    println!("  BEEF valid: {:?}", valid);

    // Build Atomic BEEF
    let atomic = beef.to_binary_atomic(spend_txid).unwrap();
    println!("  Atomic BEEF: {} bytes", atomic.len());

    // Verify parse roundtrip
    match Beef::from_binary(&atomic) {
        Ok(mut b) => {
            println!("  Parse-back: {} txs, {} bumps, atomic={}", b.txs.len(), b.bumps.len(), b.is_atomic());
            println!("  Parse-back valid: {:?}", b.is_valid(false));
        }
        Err(e) => println!("  Parse-back FAILED: {}", e),
    }

    // Call internalizeAction
    let tx_bytes: Vec<serde_json::Value> = atomic.iter().map(|b| (*b).into()).collect();

    println!("\nCalling internalizeAction (basket insertion)...");
    let body = serde_json::json!({
        "tx": tx_bytes,
        "outputs": [{
            "outputIndex": 0,
            "protocol": "basket insertion",
            "insertionRemittance": {
                "basket": "mpc-recovery",
                "tags": ["poc4"]
            }
        }],
        "description": "recover MPC poc4 funds"
    });

    let resp = client
        .post("http://localhost:3321/internalizeAction")
        .header("Origin", "http://localhost")
        .header("Content-Type", "application/json")
        .json(&body)
        .send().await.unwrap();

    let status = resp.status();
    let text = resp.text().await.unwrap();
    println!("  Status: {}", status);
    println!("  Response: {}", text);

    if status.is_success() {
        println!("\n  SUCCESS — 1,400 sats internalized back to wallet!");
    } else {
        // Also try wallet payment protocol
        println!("\n  Trying wallet payment protocol...");
        let body2 = serde_json::json!({
            "tx": tx_bytes,
            "outputs": [{
                "outputIndex": 0,
                "protocol": "wallet payment",
                "paymentRemittance": {
                    "derivationPrefix": "AAAA",
                    "derivationSuffix": "AAAA",
                    "senderIdentityKey": "032f305e1e197f917735ef52619e6d4d6928a19e1caf9e9032cccf664fc90c6801"
                }
            }],
            "description": "recover MPC poc4 funds"
        });

        let resp2 = client
            .post("http://localhost:3321/internalizeAction")
            .header("Origin", "http://localhost")
            .header("Content-Type", "application/json")
            .json(&body2)
            .send().await.unwrap();

        println!("  Status: {}", resp2.status());
        println!("  Response: {}", resp2.text().await.unwrap());
    }
}
