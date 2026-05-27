//! **#5 — primes at-rest, DEPLOYED live gate.**
//!
//! BRC-31-authed `POST /ceremony/seed-primes` against the LIVE worker isolate
//! (`bsv-mpc-kss`), asserting the seeded blob round-trips through the at-rest
//! seal/unseal on the deployed wasm. Because `get_primes` now hex-decodes +
//! AES-256-GCM-unseals, a `reload_matches=true` from the deployed worker PROVES
//! the stored column holds sealed ciphertext (a plaintext column would fail the
//! hex-decode/unseal on read) — i.e. the primes are encrypted at rest, live.
//!
//! No sats. Gated on `PRIMES_AT_REST_DEPLOYED=1`.
//!
//! ```bash
//! PRIMES_AT_REST_DEPLOYED=1 cargo test -p bsv-mpc-proxy \
//!   --test primes_at_rest_deployed_e2e -- --nocapture --test-threads=1
//! ```

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_relay::RelaySession;

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deployed_worker_seals_seeded_primes_at_rest() {
    if std::env::var("PRIMES_AT_REST_DEPLOYED").ok().as_deref() != Some("1") {
        eprintln!("PRIMES_AT_REST_DEPLOYED=1 not set — skipping the deployed primes-at-rest gate.");
        return;
    }
    let worker =
        std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.to_string());
    let http = reqwest::Client::new();

    // BRC-31 handshake with the deployed worker (the route is auth-enforced).
    let identity = PrivateKey::from_bytes(&[0x51u8; 32]).expect("identity key");
    let mut session = RelaySession::new(identity);
    session
        .handshake(&http, &worker)
        .await
        .expect("BRC-31 handshake with the deployed worker");
    eprintln!("✔ BRC-31 handshake OK with {worker}");

    // A fresh session id + an arbitrary primes blob (the seal treats it as opaque
    // bytes; we're proving the at-rest crypto, not prime validity).
    let session_id = {
        use rand::RngCore;
        let mut seed = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        format!("primes-at-rest-verify-{}", hex::encode(seed))
    };
    let primes_json = "{\"p\":\"00deadbeefcafe\",\"q\":\"00feedface\",\"verify\":\"#5 at-rest\"}";
    let body = serde_json::json!({ "session_id": session_id, "primes_json": primes_json });
    let body_bytes = serde_json::to_vec(&body).expect("serialize body");

    let path = "/ceremony/seed-primes";
    let headers = session
        .auth_header_pairs("POST", path, &body_bytes)
        .expect("sign seed-primes request");
    let mut req = http
        .post(format!("{worker}{path}"))
        .header("content-type", "application/json")
        .body(body_bytes);
    for (name, value) in headers {
        req = req.header(name, value);
    }
    let resp = req.send().await.expect("seed-primes request");
    let status = resp.status();
    let json: serde_json::Value = resp.json().await.expect("seed-primes JSON");
    eprintln!("seed-primes response (status {status}): {json}");
    assert!(
        status.is_success(),
        "seed-primes must succeed (status {status})"
    );

    // `stored` + `at_rest_sealed` + `reload_matches`: the deployed worker sealed the
    // blob (ciphertext-hex in the column) and the read path hex-decoded + unsealed it
    // back to the EXACT seeded plaintext. A plaintext column would fail the read.
    assert_eq!(
        json["stored"],
        serde_json::json!(true),
        "primes must be stored"
    );
    assert_eq!(
        json["at_rest_sealed"],
        serde_json::json!(true),
        "the deployed worker must report the blob sealed at rest"
    );
    assert_eq!(
        json["reload_matches"],
        serde_json::json!(true),
        "seal→store→fetch→unseal MUST recover the exact seeded primes on the deployed wasm"
    );
    eprintln!("✔ #5 primes-at-rest verified LIVE on the deployed worker — sealed + round-trips");
}
