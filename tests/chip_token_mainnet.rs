//! Real-mainnet end-to-end test for the Path A CHIP token flow.
//!
//! Closes MPC-Spec issue #34 and the `feedback_e2e_with_real_sats` discipline
//! for the Path A architectural work shipped 2026-05-17 (chip.rs `4565bd7`,
//! /capabilities `d21bd6c`, discovery `b88ac68`, ADR-0050 `db795d6`).
//!
//! ## What this test proves end-to-end
//!
//! 1. `bsv_mpc_overlay::chip::create_chip_token` produces a locking script
//!    that BSV mainnet broadcasts admit (the wallet at `:3321` will sign +
//!    fund + broadcast a tx with our PushDrop as a custom output).
//! 2. The canonical `@bsv/overlay-discovery-services` `SHIPTopicManager`
//!    admits the token into the `tm_mpc_signing` topic — this is the
//!    silent-rejection failure mode Path A was designed to fix; if this
//!    test passes, mainnet validators are actually accepting our output.
//! 3. Querying via `LookupResolver` (the same path discovery clients use)
//!    surfaces the published cosigner; round-tripping the result through
//!    OUR `parse_chip_token` re-validates signature linkage on bytes that
//!    travelled the network. Cross-validation: our emitter and our parser
//!    both agree with the canonical overlay.
//!
//! ## Why this test is mandatory
//!
//! Pre-Path-A `create_chip_token` had clean local unit tests AND was
//! silently rejected by every mainnet overlay validator. Real-mainnet e2e
//! is the only check that detects that failure mode. See
//! `~/bsv/mpc/bsv-mpc-old-unscrubbed/.claude/.../memory/feedback_e2e_with_real_sats.md`.
//!
//! ## Prerequisites (test SKIPs loudly if missing, NEVER silent-passes)
//!
//! - `E2E_MAINNET=1` env var
//! - BRC-100 wallet at `http://localhost:3321` (Origin: `http://admin.com`)
//!   with funded mainnet UTXOs (~few hundred sats per run)
//! - Network reachability to mainnet SLAP trackers
//!
//! ## Cost
//!
//! Single tx, dust output (1 sat). Total ~< 1k sats per run (~ cent).
//!
//! ## Run
//!
//! ```bash
//! E2E_MAINNET=1 cargo test --test chip_token_mainnet -- --ignored --nocapture
//! ```

use bsv::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, NetworkPreset,
};
use bsv::primitives::ec::PrivateKey;
use bsv::transaction::Transaction;
use bsv_mpc_overlay::{chip, MPC_TOPIC};
use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;

const WALLET_URL: &str = "http://localhost:3321";
const WALLET_ORIGIN: &str = "http://admin.com";

/// Per-attempt overlay query timeout (ms).
const QUERY_TIMEOUT_MS: u64 = 10_000;

/// Total time to wait for the overlay to index + admit the token.
const DISCOVERY_DEADLINE: Duration = Duration::from_secs(60);

/// Poll interval while waiting for indexing.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real mainnet: requires E2E_MAINNET=1, wallet at :3321, ~1k sats"]
async fn live_chip_token_roundtrip_mainnet() {
    eprintln!("\n╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  E2E: Path A CHIP token roundtrip — real mainnet            ║");
    eprintln!("║  MPC-Spec issue #34 · ADR-0050 · partnership e2e gate       ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝\n");

    // ── Gate ───────────────────────────────────────────────────────────────
    if std::env::var("E2E_MAINNET").is_err() {
        eprintln!("SKIP: set E2E_MAINNET=1 to run this real-mainnet test.\n");
        return;
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("build reqwest client");

    // Prereq: wallet:3321 must respond. Fail loudly if not — per the
    // partnership rule, no silent-skip when E2E_MAINNET is opted in.
    assert_wallet_reachable(&client).await;

    // ── Step 1: ephemeral identity + canonical signed CHIP token ──────────
    eprintln!("[1/4] Creating canonical signed CHIP token...");
    let identity_priv = PrivateKey::random();
    let identity_pub_hex = identity_priv.public_key().to_hex();

    // Use a deterministic + obviously-test domain so the test's published
    // CHIP token can be identified in overlay results without colliding
    // with any real cosigner. The identity_key is ephemeral per-run, so
    // multiple test runs don't collide with themselves either.
    let domain = format!("https://chip-e2e-test-{}.invalid", &identity_pub_hex[..16]);

    let chip_script = chip::create_chip_token(&identity_priv, &domain)
        .expect("create_chip_token must produce a valid signed SHIP token");
    eprintln!("    identity_key: {}", identity_pub_hex);
    eprintln!("    domain:       {}", domain);
    eprintln!(
        "    script bytes: {} (5-field signed PushDrop)",
        chip_script.len()
    );

    // Sanity: round-trip locally through OUR parser before we ever hit the wire.
    // If this fails, the rest of the test is moot.
    let token_info = chip::parse_chip_token(&chip_script)
        .expect("local parse_chip_token must succeed on our own output");
    assert_eq!(token_info.identity_key, identity_pub_hex);
    assert_eq!(token_info.domain, domain);

    // ── Step 2: fund + broadcast tx with the CHIP script as a custom output ─
    eprintln!("\n[2/4] Funding + broadcasting tx via wallet at {WALLET_URL}...");
    let fund_resp = create_action_with_custom_output(&client, &chip_script, &domain).await;

    let fund_txid = fund_resp
        .get("txid")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("wallet response missing txid: {fund_resp}"))
        .to_string();
    let beef_bytes = extract_beef_bytes(&fund_resp);

    eprintln!("    funded txid: {fund_txid}");
    eprintln!(
        "    beef bytes:  {} (auto-broadcast by wallet)",
        beef_bytes.len()
    );
    eprintln!("    whatsonchain: https://whatsonchain.com/tx/{fund_txid}");

    // ── Step 2.5: explicit /submit to each known mainnet overlay ──────────
    //
    // Differentiates Path A regression (SHIPTopicManager rejects our token
    // bytes with 4xx invalid-format) from infrastructure gap (no overlay
    // hosts `tm_mpc_signing` topic yet — 4xx "unknown topic"). Without this
    // step, an empty poll result is ambiguous; with it we know exactly which
    // class of failure we're in.
    eprintln!("\n[2.5/4] Pushing BEEF to known mainnet overlays via /submit...");
    let submit_results = submit_to_overlays(
        &client,
        &beef_bytes,
        &NetworkPreset::Mainnet.slap_trackers(),
    )
    .await;
    for (url, status, body_snippet) in &submit_results {
        eprintln!("    {url}/submit → HTTP {status}  {body_snippet}");
    }
    assert_no_path_a_rejection(&submit_results);

    // ── Step 3: poll LookupResolver until our token surfaces on the overlay ─
    //
    // Indexing latency on mainnet: observed 2-30s in POC 14. We wait up to
    // DISCOVERY_DEADLINE; if exceeded we use submit_results to classify
    // the failure (Path A regression vs infra gap vs other).
    eprintln!(
        "\n[3/4] Polling LookupResolver for {} every {}s (deadline {}s)...",
        MPC_TOPIC,
        POLL_INTERVAL.as_secs(),
        DISCOVERY_DEADLINE.as_secs()
    );

    let resolver = LookupResolver::new(LookupResolverConfig {
        network_preset: NetworkPreset::Mainnet,
        ..Default::default()
    });
    let question = LookupQuestion::new("ls_ship", json!({ "topics": [MPC_TOPIC] }));

    let start = std::time::Instant::now();
    let mut attempts = 0;
    let mut admitted_token: Option<chip::ChipTokenInfo> = None;

    while start.elapsed() < DISCOVERY_DEADLINE {
        attempts += 1;
        tokio::time::sleep(POLL_INTERVAL).await;

        let answer = match resolver.query(&question, Some(QUERY_TIMEOUT_MS)).await {
            Ok(a) => a,
            Err(e) => {
                eprintln!("    attempt {attempts}: lookup error: {e}");
                continue;
            }
        };

        let LookupAnswer::OutputList { outputs } = answer else {
            eprintln!("    attempt {attempts}: non-OutputList answer (shape: not for our topic)");
            continue;
        };

        eprintln!("    attempt {attempts}: {} outputs returned", outputs.len());

        for output in outputs {
            let tx = match Transaction::from_beef(&output.beef, None) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let Some(out) = tx.outputs.get(output.output_index as usize) else {
                continue;
            };
            // Strict parse — proves the canonical signature linkage validation
            // succeeds on bytes that round-tripped through the overlay (i.e.
            // SHIPTopicManager admitted them AND they survive our re-validation).
            if let Ok(info) = chip::parse_chip_token(&out.locking_script.to_binary()) {
                if info.identity_key == identity_pub_hex {
                    admitted_token = Some(info);
                    break;
                }
            }
        }

        if admitted_token.is_some() {
            break;
        }
    }

    // Hard fail on any non-admission. The test is `#[ignore]` so no
    // automated CI ever runs it — there's no "perpetually-red-CI" concern
    // that would justify softening to a warn-pass. If someone runs this
    // and the token isn't admitted, that's a failure of the e2e gate;
    // they need to see RED and read the classification to know what to do.
    //
    // The classification differentiates BLAME — Path A bug vs infra gap
    // vs outage — but never changes the pass/fail signal. "Partial pass"
    // is the kind of silent-skip ambiguity `feedback_quality_gate_hard`
    // and `feedback_e2e_with_real_sats` explicitly forbid.
    let token = admitted_token.unwrap_or_else(|| {
        let mut had_2xx = false;
        let mut had_topic_unknown = false;
        let mut had_validation_reject = false;
        for (_url, status, body) in &submit_results {
            if (200..300).contains(status) {
                had_2xx = true;
            } else if (400..500).contains(status) {
                if is_topic_not_hosted(body) {
                    had_topic_unknown = true;
                } else if is_path_a_rejection(body) {
                    had_validation_reject = true;
                }
            }
        }

        let classification = if had_validation_reject {
            "CLASS: PATH A REGRESSION — overlay /submit rejected our CHIP token \
             bytes as invalid. chip.rs::create_chip_token output is no longer \
             accepted by canonical SHIPTopicManager. Fix chip.rs to re-conform \
             to @bsv/overlay-discovery-services. This is the exact silent-reject \
             failure mode Path A was designed to fix."
        } else if had_topic_unknown {
            "CLASS: INFRA GAP — Path A construction + broadcast worked (txid \
             above confirms on-chain), but no overlay node on mainnet subscribes \
             to `tm_mpc_signing` yet. M1 #6 (deploy 1 bsv-mpc cosigner) + #10 \
             (rust-mpc 2 cosigners) will deploy a `tm_mpc_signing`-subscribed \
             overlay. Re-run this test after deployment — it will pass without \
             code changes."
        } else if had_2xx {
            "CLASS: ADMISSION-NOT-INDEXED — at least one overlay accepted the \
             BEEF via /submit but no host indexed it under tm_mpc_signing within \
             the deadline. Could be a slow chain→overlay pipeline, topic-routing \
             config, or the accepting overlay silently dropped the submission."
        } else {
            "CLASS: UNCLEAR — all /submit attempts errored without recognizable \
             topic-gap or validation-reject signal. Likely overlay outage or \
             network egress issue. Inspect submit_results above and the \
             on-chain tx via WhatsOnChain."
        };
        panic!(
            "E2E FAIL: ephemeral CHIP token NOT admitted to mainnet overlay \
             within {}s ({} polls).\n\n\
             {classification}\n\n  \
             identity_key: {identity_pub_hex}\n  \
             funded_txid:  {fund_txid}\n  \
             whatsonchain: https://whatsonchain.com/tx/{fund_txid}\n  \
             submit URLs:  {} probed (full response bodies in [2.5/4] output above)\n",
            DISCOVERY_DEADLINE.as_secs(),
            attempts,
            submit_results.len()
        );
    });

    eprintln!(
        "\n[4/4] ✓ CHIP token admitted to mainnet overlay in ~{}s ({} polls)",
        start.elapsed().as_secs(),
        attempts
    );
    assert_eq!(token.identity_key, identity_pub_hex);
    assert_eq!(token.domain, domain);

    eprintln!("\n╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  PATH A END-TO-END VERIFIED ON MAINNET                      ║");
    eprintln!("║  txid: {:54}║", fund_txid);
    eprintln!("╚══════════════════════════════════════════════════════════════╝\n");
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Assert wallet:3321 is reachable + authenticated. Panics loudly with a clear
/// message if not — silent-skip on a real-sats e2e is the exact discipline
/// failure the partnership rule (and #B10 silent-skip cleanup) is closing.
async fn assert_wallet_reachable(client: &Client) {
    let url = format!("{WALLET_URL}/isAuthenticated");
    let resp = client
        .post(&url)
        .header("Origin", WALLET_ORIGIN)
        .header("Content-Type", "application/json")
        .json(&json!({}))
        .send()
        .await
        .unwrap_or_else(|e| {
            panic!(
                "PRECONDITION FAIL: wallet at {WALLET_URL} unreachable: {e}. \
                 Start a BRC-100 wallet (bsv-wallet-cli or equivalent) on port 3321 \
                 with Origin: {WALLET_ORIGIN} accepted, then retry."
            )
        });
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_default();
    assert!(
        status.is_success() && body.get("authenticated") == Some(&Value::Bool(true)),
        "PRECONDITION FAIL: wallet at {WALLET_URL} responded HTTP {status} body={body}. \
         Expected 200 with authenticated:true."
    );
}

/// Call wallet:3321 createAction to fund + broadcast a tx with a single output
/// carrying the given locking script (hex). Returns the JSON response.
///
/// ## Known transient wallet behavior (retries 3x with 1s backoff)
///
/// Under load, the wallet at `:3321` intermittently returns HTTP 400 with
/// body:
///
/// ```json
/// {
///   "code": 6, "isError": true, "name": "WERR_INVALID_PARAMETER",
///   "parameter": "type",
///   "message": "The type parameter must be vin 0, \"custom\" is not a supported unlocking script type."
/// }
/// ```
///
/// for outputs carrying custom (non-P2PKH) `lockingScript`s — like our
/// PushDrop. **Not a bug in the request shape — the exact same JSON one
/// second later succeeds.** Confirmed by John as "happens every now and
/// then when wallet gets overloaded." We retry on this specific error class
/// up to 3 times with 1s backoff; if all 3 attempts hit it, the test panics
/// loudly (we don't want to silent-skip; per the partnership e2e rule the
/// runner needs to see the wallet failure and decide to retry vs investigate).
async fn create_action_with_custom_output(
    client: &Client,
    locking_script: &[u8],
    description_domain: &str,
) -> Value {
    let url = format!("{WALLET_URL}/createAction");
    let body = json!({
        "description": format!("Path A CHIP token e2e test — {description_domain}"),
        "outputs": [{
            // Dust minimum — the CHIP UTXO is spendable later (to revoke) so it
            // needs at least 1 sat. We use 1 sat to keep test cost minimal.
            "satoshis": 1,
            "lockingScript": hex::encode(locking_script),
            "outputDescription": "Path A CHIP token (e2e test, ephemeral identity)"
        }]
    });

    let mut last_response: Value = Value::Null;
    let mut last_status: u16 = 0;
    for attempt in 1..=3 {
        let resp = client
            .post(&url)
            .header("Origin", WALLET_ORIGIN)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .unwrap_or_else(|e| panic!("wallet createAction request failed: {e}"));
        last_status = resp.status().as_u16();
        last_response = resp.json().await.unwrap_or_else(|e| {
            panic!("wallet createAction returned non-JSON (HTTP {last_status}): {e}")
        });

        if last_response.get("txid").is_some() {
            if attempt > 1 {
                eprintln!(
                    "    (recovered on attempt {attempt} — wallet's transient under-load error)"
                );
            }
            return last_response;
        }

        if is_wallet_transient_custom_type_error(&last_response) {
            eprintln!(
                "    attempt {attempt}/3: wallet returned its known transient \
                 \"custom unlocking type\" error (under-load behavior); retrying in 1s..."
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        // Non-retryable wallet error — break to the panic below.
        break;
    }

    panic!(
        "wallet createAction did not return a txid after 3 attempts (last HTTP {last_status}). \
         Last response: {last_response}. \
         Likely causes: wallet has no spendable UTXOs (fund it), wrong Origin \
         header, locking script rejected by wallet's policy, or the known \
         transient WERR_INVALID_PARAMETER \"custom\" error persisted across 3 \
         retries (re-run the test in a few seconds). The CHIP token locking \
         script is a 5-field signed PushDrop; the wallet normally accepts it \
         as an opaque custom output."
    );
}

/// Recognize the wallet's transient under-load error class that's safe to retry.
/// See create_action_with_custom_output docs for the full body shape.
fn is_wallet_transient_custom_type_error(body: &Value) -> bool {
    let msg = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    name == "werr_invalid_parameter" && msg.contains("\"custom\"") && msg.contains("unlocking")
}

/// Push the given BEEF bytes to every overlay URL's `/submit` endpoint with
/// `X-Topics: ["tm_mpc_signing"]`. Returns `(url, http_status, body_snippet)`
/// per overlay for downstream classification. Best-effort — network errors
/// become status `0` and an error snippet, so the caller can still classify.
async fn submit_to_overlays(
    client: &Client,
    beef: &[u8],
    urls: &[&str],
) -> Vec<(String, u16, String)> {
    let topics_header = serde_json::to_string(&[MPC_TOPIC]).expect("serialize topics");
    let mut out = Vec::new();
    for url in urls {
        let submit_url = format!("{}/submit", url.trim_end_matches('/'));
        let result = client
            .post(&submit_url)
            .header("Content-Type", "application/octet-stream")
            .header("X-Topics", &topics_header)
            .body(beef.to_vec())
            .send()
            .await;
        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp
                    .text()
                    .await
                    .unwrap_or_else(|e| format!("<read err: {e}>"));
                let snippet = body.chars().take(200).collect::<String>();
                out.push((url.to_string(), status, snippet));
            }
            Err(e) => {
                out.push((url.to_string(), 0, format!("<network err: {e}>")));
            }
        }
    }
    out
}

/// True when the response looks like the overlay simply doesn't host our
/// topic (`tm_mpc_signing`) — that's an infra gap (M1 #6/#10 deploys the
/// missing cosigner), NOT a Path A code bug. Pattern matches the actual
/// observed message: "This server does not support this topic: tm_mpc_signing"
/// plus generic variants.
fn is_topic_not_hosted(body: &str) -> bool {
    let b = body.to_lowercase();
    b.contains("topic")
        && (b.contains("does not support")
            || b.contains("not support") // covers "doesn't support", "won't support", etc.
            || b.contains("unknown topic")
            || b.contains("no topic manager"))
}

/// True when the response looks like SHIPTopicManager actually validated our
/// token bytes and REJECTED them on format/signature grounds — that IS a
/// Path A regression and must surface as a hard failure.
fn is_path_a_rejection(body: &str) -> bool {
    let b = body.to_lowercase();
    b.contains("signature")
        || b.contains("validation")
        || b.contains("invalid")
        || b.contains("rejected")
        || (b.contains("field") && b.contains("count"))
}

/// Hard-fail if any /submit response indicates SHIPTopicManager rejecting our
/// token's CONTENT/FORMAT. Path A regression must surface immediately,
/// before we waste 60s polling.
fn assert_no_path_a_rejection(results: &[(String, u16, String)]) {
    for (url, status, body) in results {
        if !(400..500).contains(status) {
            continue;
        }
        if is_topic_not_hosted(body) {
            continue; // infra gap, not regression
        }
        if is_path_a_rejection(body) {
            panic!(
                "PATH A REGRESSION: overlay {url}/submit returned HTTP {status} that \
                 looks like SHIPTopicManager rejecting our CHIP token bytes. \
                 Response: {body}. \
                 Fix chip.rs::create_chip_token to re-conform with canonical \
                 @bsv/overlay-discovery-services. This is the exact silent-reject \
                 failure mode Path A was designed to fix."
            );
        }
    }
}

/// Extract the broadcast tx as raw bytes (BEEF or raw) from the wallet's
/// createAction response. The wallet returns the tx either as a hex `rawTx`
/// string OR as a byte-array under `tx` — handle both, fail loudly if neither.
fn extract_beef_bytes(resp: &Value) -> Vec<u8> {
    if let Some(hex_str) = resp.get("rawTx").and_then(|v| v.as_str()) {
        return hex::decode(hex_str)
            .unwrap_or_else(|e| panic!("wallet rawTx field is not valid hex: {e}; resp: {resp}"));
    }
    if let Some(arr) = resp.get("tx").and_then(|v| v.as_array()) {
        return arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect();
    }
    panic!(
        "wallet createAction response has neither rawTx (hex) nor tx (byte array). \
         Response: {resp}"
    );
}
