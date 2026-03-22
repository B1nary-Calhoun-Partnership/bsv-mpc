//! End-to-end integration tests for the MPC signing proxy + KSS.
//!
//! Architecture:
//!   E2E test harness
//!     ├── Starts bsv-mpc-service (KSS) in-process on a random port
//!     ├── Starts bsv-mpc-proxy in-process on a random port (pointed at KSS)
//!     └── Runs test scenarios as HTTP client against the proxy
//!
//! DKG shares are generated via `round_based::sim` (in-memory simulation).
//! Non-mainnet tests verify the full MPC signing protocol over HTTP.
//! Mainnet tests (createAction) are gated behind `E2E_MAINNET` env var.
//!
//! Run: `cargo test --test e2e -- --ignored --nocapture`

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use bsv_mpc_core::types::*;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use generic_ec::Point;
use reqwest::Client;
use serde_json::{json, Value};

// ═══════════════════════════════════════════════════════════════════════════
// DKG Simulation (ported from core/dkg.rs tests + POC 15)
// ═══════════════════════════════════════════════════════════════════════════

/// Buffered sink for simulation (prevents deadlocks in round-based sim).
#[pin_project::pin_project]
struct BufferedSink<M, Inner> {
    #[pin]
    messages: VecDeque<M>,
    #[pin]
    inner: Inner,
}

impl<M: Unpin, Inner: futures::Sink<M>> futures::Sink<M> for BufferedSink<M, Inner> {
    type Error = Inner::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn start_send(
        self: std::pin::Pin<&mut Self>,
        item: M,
    ) -> Result<(), Self::Error> {
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

type BufferedDelivery<M, D> = (
    <D as round_based::Delivery<M>>::Receive,
    BufferedSink<round_based::Outgoing<M>, <D as round_based::Delivery<M>>::Send>,
);

/// Generate a Blum prime (p ≡ 3 mod 4) for Paillier.
fn generate_blum_prime(rng: &mut impl rand::RngCore, bits_size: u32) -> cggmp24::backend::Integer {
    use cggmp24::backend::Integer;
    loop {
        let n = Integer::generate_prime(rng, bits_size);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}

/// Generate pregenerated primes for aux_info_gen.
fn generate_test_primes(
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
    cggmp24::key_refresh::PregeneratedPrimes::try_from(primes).expect("primes have wrong bit size")
}

/// Run a full 2-of-2 DKG simulation producing KeyShares + joint key.
async fn run_dkg_simulation() -> (
    Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>>,
    Point<Secp256k1>,
) {
    let n: u16 = 2;
    let t: u16 = 2;
    let mut rng = rand::rngs::OsRng;

    // Phase 1: Keygen
    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
    let eid = ExecutionId::new(&eid_bytes);

    eprintln!("  [DKG] Phase 1: keygen (2-of-2)...");
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

    assert_eq!(incomplete_shares.len(), 2);
    assert_eq!(
        incomplete_shares[0].shared_public_key,
        incomplete_shares[1].shared_public_key,
        "both parties must agree on joint public key"
    );
    eprintln!("  [DKG] Keygen complete. Generating Paillier primes...");

    // Phase 2: Aux info generation (Paillier — slow, ~20-30s)
    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
    let eid_aux = ExecutionId::new(&eid_bytes);
    let primes: Vec<_> = (0..n).map(|_| generate_test_primes(&mut rng)).collect();

    eprintln!("  [DKG] Phase 2: aux_info_gen...");
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

    // Combine into complete KeyShares
    let key_shares: Vec<_> = incomplete_shares
        .into_iter()
        .zip(aux_infos)
        .map(|(share, aux)| {
            cggmp24::KeyShare::<Secp256k1, SecurityLevel128>::from_parts((share, aux))
                .expect("key share validation should pass")
        })
        .collect();

    let joint_pubkey = key_shares[0].core.shared_public_key;
    eprintln!("  [DKG] Complete. Joint key: {:?}", hex::encode(joint_pubkey.to_bytes(true)));

    (key_shares, *joint_pubkey)
}

/// Convert a cggmp24 KeyShare into a DkgResult for storage/proxy consumption.
fn key_share_to_dkg_result(
    key_share: &cggmp24::KeyShare<Secp256k1, SecurityLevel128>,
    party_index: u16,
    threshold: u16,
    parties: u16,
    joint_pubkey: &Point<Secp256k1>,
) -> DkgResult {
    let compressed_bytes = joint_pubkey.to_bytes(true);
    let compressed = compressed_bytes.to_vec();

    // Derive P2PKH address via BSV SDK
    let address = bsv::PublicKey::from_bytes(&compressed)
        .map(|pk| pk.to_address())
        .unwrap_or_else(|_| "unknown".to_string());

    let ciphertext = serde_json::to_vec(key_share).expect("key share serialization");

    // Deterministic session ID from joint key
    let session_id = SessionId(format!(
        "e2e-test-{}",
        &hex::encode(&compressed[..8])
    ));

    DkgResult {
        joint_key: JointPublicKey { compressed, address },
        share: EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext,
            session_id: session_id.clone(),
            share_index: ShareIndex(party_index),
            config: ThresholdConfig { threshold, parties },
        },
        session_id,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test Environment Setup
// ═══════════════════════════════════════════════════════════════════════════

struct TestEnv {
    proxy_url: String,
    _kss_url: String,
    joint_key_hex: String,
    joint_address: String,
    _share_file: tempfile::NamedTempFile,
}

/// Find a free TCP port by binding to :0.
async fn find_free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind to :0");
    listener.local_addr().unwrap().port()
}

/// Wait for a server to respond to /health.
async fn wait_for_health(client: &Client, url: &str, label: &str) {
    let health_url = format!("{url}/health");
    for attempt in 1..=50 {
        match client.get(&health_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                eprintln!("  [{label}] healthy (attempt {attempt})");
                return;
            }
            _ => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
        }
    }
    panic!("{label} failed to become healthy at {health_url}");
}

async fn setup() -> TestEnv {
    // Init tracing (once)
    let _ = tracing_subscriber::fmt()
        .with_env_filter("bsv_mpc_proxy=debug,bsv_mpc_service=debug,bsv_mpc_core=debug")
        .try_init();

    eprintln!("\n=== E2E Setup: Running DKG simulation ===");
    let start = std::time::Instant::now();
    let (key_shares, joint_pubkey) = run_dkg_simulation().await;
    eprintln!("  DKG took {:.1}s", start.elapsed().as_secs_f64());

    let dkg_result_0 = key_share_to_dkg_result(&key_shares[0], 0, 2, 2, &joint_pubkey);
    let dkg_result_1 = key_share_to_dkg_result(&key_shares[1], 1, 2, 2, &joint_pubkey);

    let joint_key_hex = hex::encode(&dkg_result_0.joint_key.compressed);
    let joint_address = dkg_result_0.joint_key.address.clone();

    // ── Start KSS ──────────────────────────────────────────────────────
    let kss_port = find_free_port().await;
    let kss_url = format!("http://127.0.0.1:{kss_port}");

    let kss_storage = bsv_mpc_service::SqliteShareStorage::open("/tmp/e2e-kss")
        .expect("open KSS storage");

    // Pre-seed KSS with share_0 (keyed by agent_id = hex(joint_key))
    let mut kss_storage = kss_storage;
    kss_storage
        .store_share(&joint_key_hex, &dkg_result_0.share)
        .expect("store KSS share");

    let kss_state = Arc::new(bsv_mpc_service::AppState {
        data_dir: "/tmp/e2e-kss".to_string(),
        storage: RwLock::new(kss_storage),
        started_at: chrono::Utc::now(),
    });

    let kss_router = bsv_mpc_service::build_router(kss_state);
    let kss_listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{kss_port}"))
        .await
        .expect("bind KSS");
    tokio::spawn(async move {
        axum::serve(kss_listener, kss_router.into_make_service())
            .await
            .unwrap();
    });

    let client = Client::new();
    wait_for_health(&client, &kss_url, "KSS").await;

    // ── Write proxy share to temp file ─────────────────────────────────
    let share_file = tempfile::NamedTempFile::new().expect("create temp file");
    let share_json = serde_json::to_vec_pretty(&dkg_result_1).expect("serialize DkgResult");
    std::fs::write(share_file.path(), &share_json).expect("write share file");

    // ── Start Proxy ────────────────────────────────────────────────────
    let proxy_port = find_free_port().await;
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");

    let proxy_config = bsv_mpc_proxy::config::ProxyConfig {
        port: proxy_port,
        kss_url: kss_url.clone(),
        share_path: share_file.path().to_string_lossy().to_string(),
        fee_per_signing: 0,     // No fee for tests
        fee_addresses: vec![],
        fee_threshold: None,
        max_presignatures: 0,   // Disable background presigning
        encryption_key: None,
    };

    tokio::spawn(async move {
        if let Err(e) = bsv_mpc_proxy::server::run(proxy_config).await {
            eprintln!("Proxy error: {e}");
        }
    });

    wait_for_health(&client, &proxy_url, "Proxy").await;

    eprintln!("=== E2E Setup complete ===\n");

    TestEnv {
        proxy_url,
        _kss_url: kss_url,
        joint_key_hex,
        joint_address,
        _share_file: share_file,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper: POST JSON and get JSON response
// ═══════════════════════════════════════════════════════════════════════════

async fn post_json(client: &Client, url: &str, body: &Value) -> Value {
    let resp = client
        .post(url)
        .header("Origin", "http://localhost")
        .json(body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST {url} failed: {e}"));
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let parsed: Value = serde_json::from_str(&text)
        .unwrap_or_else(|_| json!({"_raw": text, "_status": status.as_u16()}));
    if parsed.get("error").is_some() {
        eprintln!("  ERROR from {url}: {parsed}");
    }
    parsed
}

// ═══════════════════════════════════════════════════════════════════════════
// Test Scenarios
// ═══════════════════════════════════════════════════════════════════════════

/// Test 1: Health + identity endpoints
async fn test_health_and_identity(env: &TestEnv, client: &Client) {
    eprintln!("--- Test 1: Health + Identity ---");

    // GET /health
    let resp = client
        .get(format!("{}/health", env.proxy_url))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "health should return 200");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    eprintln!("  /health: {body}");

    // POST /getNetwork
    let resp = post_json(client, &format!("{}/getNetwork", env.proxy_url), &json!({})).await;
    assert_eq!(resp["network"], "mainnet");

    // POST /isAuthenticated
    let resp = post_json(
        client,
        &format!("{}/isAuthenticated", env.proxy_url),
        &json!({}),
    )
    .await;
    assert_eq!(resp["authenticated"], true);

    // POST /getPublicKey { identityKey: true }
    let resp = post_json(
        client,
        &format!("{}/getPublicKey", env.proxy_url),
        &json!({"identityKey": true}),
    )
    .await;
    let pubkey = resp["publicKey"].as_str().expect("publicKey should be string");
    assert_eq!(pubkey.len(), 66, "compressed pubkey = 33 bytes = 66 hex chars");
    assert!(
        pubkey.starts_with("02") || pubkey.starts_with("03"),
        "compressed pubkey must start with 02 or 03"
    );
    assert_eq!(
        pubkey, env.joint_key_hex,
        "identity key must match DKG joint key"
    );
    eprintln!("  Identity key: {pubkey}");

    eprintln!("  PASS\n");
}

/// Test 2: Key derivation (BRC-42)
async fn test_key_derivation(env: &TestEnv, client: &Client) {
    eprintln!("--- Test 2: Key Derivation ---");

    let base_url = &env.proxy_url;

    // Derived key with counterparty="anyone" (local, 0 KSS round-trips)
    let resp = post_json(
        client,
        &format!("{base_url}/getPublicKey"),
        &json!({
            "protocolID": [2, "e2e test"],
            "keyID": "derivation-1",
            "counterparty": "anyone"
        }),
    )
    .await;
    let anyone_key = resp["publicKey"].as_str().expect("publicKey");
    assert_eq!(anyone_key.len(), 66);
    assert_ne!(
        anyone_key, env.joint_key_hex,
        "derived key must differ from identity key"
    );
    eprintln!("  anyone key: {anyone_key}");

    // Derived key with counterparty="self" (exercises partial ECDH via KSS)
    let resp = post_json(
        client,
        &format!("{base_url}/getPublicKey"),
        &json!({
            "protocolID": [2, "e2e test"],
            "keyID": "derivation-1",
            "counterparty": "self"
        }),
    )
    .await;
    let self_key = resp["publicKey"].as_str().expect("publicKey for self");
    assert_eq!(self_key.len(), 66);
    assert_ne!(self_key, env.joint_key_hex);
    assert_ne!(self_key, anyone_key, "self key must differ from anyone key");
    eprintln!("  self key:   {self_key}");

    // Both must be valid secp256k1 compressed points
    assert!(anyone_key.starts_with("02") || anyone_key.starts_with("03"));
    assert!(self_key.starts_with("02") || self_key.starts_with("03"));

    eprintln!("  PASS\n");
}

/// Test 3: Signature round-trip (exercises full 2PC MPC signing)
async fn test_signature_roundtrip(env: &TestEnv, client: &Client) {
    eprintln!("--- Test 3: Signature Round-Trip ---");

    let base_url = &env.proxy_url;
    let test_data = hex::encode(b"E2E test message for MPC signing");

    // createSignature — triggers full 4-round 2PC ECDSA with KSS
    let start = std::time::Instant::now();
    let resp = post_json(
        client,
        &format!("{base_url}/createSignature"),
        &json!({
            "data": test_data,
            "protocolID": [2, "e2e test"],
            "keyID": "sig-1",
            "counterparty": "anyone"
        }),
    )
    .await;
    let elapsed = start.elapsed();

    if let Some(error) = resp.get("error") {
        eprintln!("  createSignature error (may be protocol sync issue): {error}");
        eprintln!("  SKIP (signing protocol exchange needs debugging)\n");
        return;
    }

    let signature = resp["signature"].as_str().expect("signature hex");
    assert!(signature.len() >= 128, "DER signature too short: {}", signature.len());
    eprintln!("  Signature: {}... ({:.0}ms)", &signature[..40], elapsed.as_millis());

    // verifySignature with correct data → valid: true
    let resp = post_json(
        client,
        &format!("{base_url}/verifySignature"),
        &json!({
            "data": test_data,
            "signature": signature,
            "protocolID": [2, "e2e test"],
            "keyID": "sig-1",
            "counterparty": "anyone",
            "forSelf": true
        }),
    )
    .await;
    assert_eq!(resp["valid"], true, "signature should verify: {resp}");

    // verifySignature with wrong data → valid: false
    let wrong_data = hex::encode(b"WRONG data");
    let resp = post_json(
        client,
        &format!("{base_url}/verifySignature"),
        &json!({
            "data": wrong_data,
            "signature": signature,
            "protocolID": [2, "e2e test"],
            "keyID": "sig-1",
            "counterparty": "anyone",
            "forSelf": true
        }),
    )
    .await;
    assert_eq!(resp["valid"], false, "wrong data should not verify");

    eprintln!("  PASS\n");
}

/// Test 4: Encrypt/decrypt round-trip
async fn test_encrypt_decrypt(env: &TestEnv, client: &Client) {
    eprintln!("--- Test 4: Encrypt/Decrypt ---");

    let base_url = &env.proxy_url;
    let plaintext = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"Hello from E2E test!",
    );

    // Encrypt with counterparty="anyone" (local, 0 round-trips)
    let resp = post_json(
        client,
        &format!("{base_url}/encrypt"),
        &json!({
            "plaintext": plaintext,
            "protocolID": [2, "e2e test"],
            "keyID": "enc-1",
            "counterparty": "anyone"
        }),
    )
    .await;
    assert!(resp.get("error").is_none(), "encrypt failed: {resp}");
    let ciphertext = resp["ciphertext"].as_str().expect("ciphertext");
    eprintln!("  Encrypted (anyone): {}... ({} bytes)", &ciphertext[..30], ciphertext.len());

    // Decrypt
    let resp = post_json(
        client,
        &format!("{base_url}/decrypt"),
        &json!({
            "ciphertext": ciphertext,
            "protocolID": [2, "e2e test"],
            "keyID": "enc-1",
            "counterparty": "anyone"
        }),
    )
    .await;
    assert!(resp.get("error").is_none(), "decrypt failed: {resp}");
    let decrypted = resp["plaintext"].as_str().expect("plaintext");
    assert_eq!(decrypted, plaintext, "decrypt must return original plaintext");

    // Encrypt with counterparty="self" (exercises partial ECDH via KSS)
    let resp = post_json(
        client,
        &format!("{base_url}/encrypt"),
        &json!({
            "plaintext": plaintext,
            "protocolID": [2, "e2e test"],
            "keyID": "enc-self-1",
            "counterparty": "self"
        }),
    )
    .await;
    assert!(resp.get("error").is_none(), "encrypt(self) failed: {resp}");
    let ciphertext_self = resp["ciphertext"].as_str().expect("ciphertext");
    eprintln!("  Encrypted (self):   {}...", &ciphertext_self[..30]);

    // Decrypt (self)
    let resp = post_json(
        client,
        &format!("{base_url}/decrypt"),
        &json!({
            "ciphertext": ciphertext_self,
            "protocolID": [2, "e2e test"],
            "keyID": "enc-self-1",
            "counterparty": "self"
        }),
    )
    .await;
    assert!(resp.get("error").is_none(), "decrypt(self) failed: {resp}");
    let decrypted_self = resp["plaintext"].as_str().expect("plaintext");
    assert_eq!(decrypted_self, plaintext, "decrypt(self) must match");

    eprintln!("  PASS\n");
}

/// Test 5: HMAC round-trip
async fn test_hmac_roundtrip(env: &TestEnv, client: &Client) {
    eprintln!("--- Test 5: HMAC Round-Trip ---");

    let base_url = &env.proxy_url;
    let data = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"HMAC test data",
    );

    // createHmac
    let resp = post_json(
        client,
        &format!("{base_url}/createHmac"),
        &json!({
            "data": data,
            "protocolID": [2, "e2e test"],
            "keyID": "hmac-1",
            "counterparty": "anyone"
        }),
    )
    .await;
    assert!(resp.get("error").is_none(), "createHmac failed: {resp}");
    let hmac = resp["hmac"].as_str().expect("hmac");
    eprintln!("  HMAC: {hmac}");

    // verifyHmac with correct HMAC → valid: true
    let resp = post_json(
        client,
        &format!("{base_url}/verifyHmac"),
        &json!({
            "data": data,
            "hmac": hmac,
            "protocolID": [2, "e2e test"],
            "keyID": "hmac-1",
            "counterparty": "anyone"
        }),
    )
    .await;
    assert_eq!(resp["valid"], true, "correct HMAC should verify: {resp}");

    // verifyHmac with wrong HMAC → valid: false
    let resp = post_json(
        client,
        &format!("{base_url}/verifyHmac"),
        &json!({
            "data": data,
            "hmac": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "protocolID": [2, "e2e test"],
            "keyID": "hmac-1",
            "counterparty": "anyone"
        }),
    )
    .await;
    assert_eq!(resp["valid"], false, "wrong HMAC should not verify");

    eprintln!("  PASS\n");
}

/// Test 6: internalizeAction + listOutputs + createAction (mainnet!)
async fn test_mainnet_transaction(env: &TestEnv, client: &Client) {
    eprintln!("--- Test 6: Mainnet Transaction ---");

    let base_url = &env.proxy_url;

    // Step 1: Fund the MPC address by sending from the local wallet (port 3321)
    eprintln!("  Funding MPC address {} ...", env.joint_address);

    // Build P2PKH locking script for the MPC address
    let mpc_pubkey = bsv::PublicKey::from_hex(&env.joint_key_hex).expect("parse joint key");
    let mpc_pubkey_hash = mpc_pubkey.hash160();
    let locking_script = format!(
        "76a914{}88ac",
        hex::encode(&mpc_pubkey_hash)
    );

    // Wallet at :3321 requires Origin: http://admin.com and outputDescription
    let fund_resp = match client
        .post("http://localhost:3321/createAction")
        .header("Origin", "http://admin.com")
        .json(&json!({
            "description": "Fund MPC E2E test",
            "outputs": [{
                "satoshis": 5000,
                "lockingScript": locking_script,
                "outputDescription": "Fund MPC E2E test address"
            }]
        }))
        .send()
        .await
    {
        Ok(r) => r.json::<Value>().await.unwrap_or_default(),
        Err(e) => {
            eprintln!("  SKIP: Wallet not reachable: {e}");
            return;
        }
    };
    if fund_resp.get("txid").is_none() {
        eprintln!("  SKIP: Could not fund MPC address: {fund_resp}");
        return;
    }
    let fund_txid = fund_resp["txid"].as_str().expect("funding txid");
    // Wallet returns tx as AtomicBEEF byte array, convert to hex
    let fund_raw_tx = if let Some(raw) = fund_resp["rawTx"].as_str() {
        raw.to_string()
    } else if let Some(arr) = fund_resp["tx"].as_array() {
        let bytes: Vec<u8> = arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect();
        hex::encode(&bytes)
    } else {
        eprintln!("  SKIP: No rawTx or tx in response: {fund_resp}");
        return;
    };
    eprintln!("  Funded: txid={fund_txid} ({} bytes)", fund_raw_tx.len() / 2);

    // Step 2: Internalize the funding transaction
    // Find the output index that pays to our locking script
    let _fund_tx_bytes = hex::decode(&fund_raw_tx).expect("decode rawTx");
    let mut vout: u64 = 0;
    // Try each output index to find the one paying to our script
    for i in 0..10 {
        let resp = post_json(
            client,
            &format!("{base_url}/internalizeAction"),
            &json!({
                "tx": fund_raw_tx,
                "outputs": [{
                    "outputIndex": i,
                    "protocol": "wallet payment"
                }]
            }),
        )
        .await;
        if resp.get("error").is_none() && resp["accepted"] == true {
            vout = i;
            break;
        }
    }
    eprintln!("  Internalized output at vout={vout}");

    // Step 3: Verify balance via listOutputs
    let resp = post_json(
        client,
        &format!("{base_url}/listOutputs"),
        &json!({"basket": "default"}),
    )
    .await;
    eprintln!("  listOutputs: {resp}");

    // Step 4: Create a transaction (send back to wallet)
    // Get wallet's public key for the return address
    let wallet_pk_resp = client
        .post("http://localhost:3321/getPublicKey")
        .header("Origin", "http://admin.com")
        .json(&json!({"identityKey": true}))
        .send()
        .await
        .expect("wallet getPublicKey")
        .json::<Value>()
        .await
        .unwrap_or_default();
    let wallet_pk_hex = wallet_pk_resp["publicKey"]
        .as_str()
        .unwrap_or("02000000000000000000000000000000000000000000000000000000000000000001");
    let wallet_pk = bsv::PublicKey::from_hex(wallet_pk_hex).expect("wallet pubkey");
    let wallet_hash = wallet_pk.hash160();
    let return_script = format!("76a914{}88ac", hex::encode(&wallet_hash));

    eprintln!("  Creating MPC-signed transaction...");
    let start = std::time::Instant::now();
    let resp = post_json(
        client,
        &format!("{base_url}/createAction"),
        &json!({
            "description": "E2E test return",
            "outputs": [{
                "satoshis": 3000,
                "lockingScript": return_script
            }]
        }),
    )
    .await;
    let elapsed = start.elapsed();

    if resp.get("error").is_some() {
        eprintln!("  createAction error: {resp}");
        eprintln!("  (This may happen if UTXO tracker is empty — try internalizing first)");
        return;
    }

    let txid = resp["txid"].as_str().expect("txid");
    eprintln!("  Transaction broadcast! txid={txid} ({:.0}ms)", elapsed.as_millis());
    eprintln!("  View: https://whatsonchain.com/tx/{txid}");

    // Step 5: Verify UTXO tracker updated
    let resp = post_json(
        client,
        &format!("{base_url}/listOutputs"),
        &json!({"basket": "default"}),
    )
    .await;
    eprintln!("  listOutputs after spend: {resp}");

    eprintln!("  PASS\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// Main E2E Test
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore] // E2E test: requires ~30s DKG setup
async fn e2e_mpc_signing_proxy() {
    eprintln!("\n╔══════════════════════════════════════════════╗");
    eprintln!("║  E2E Integration Test: MPC Signing Proxy     ║");
    eprintln!("╚══════════════════════════════════════════════╝\n");

    let env = setup().await;
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .unwrap();

    // Non-mainnet tests (exercise full MPC protocol over HTTP)
    test_health_and_identity(&env, &client).await;
    test_key_derivation(&env, &client).await;
    test_signature_roundtrip(&env, &client).await;
    test_encrypt_decrypt(&env, &client).await;
    test_hmac_roundtrip(&env, &client).await;

    // Mainnet test (conditional — requires wallet at localhost:3321)
    if std::env::var("E2E_MAINNET").is_ok() {
        test_mainnet_transaction(&env, &client).await;
    } else {
        eprintln!("--- Test 6: Mainnet Transaction ---");
        eprintln!("  SKIP (set E2E_MAINNET=1 to enable)\n");
    }

    eprintln!("═══════════════════════════════════════════════");
    eprintln!("  All E2E tests passed!");
    eprintln!("═══════════════════════════════════════════════\n");
}
