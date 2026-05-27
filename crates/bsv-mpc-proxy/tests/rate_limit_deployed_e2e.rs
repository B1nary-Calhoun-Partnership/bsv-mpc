//! **#5 — per-identity rate limiting, DEPLOYED live gate.**
//!
//! Bursts a DEDICATED test identity against the live container's authed `/dkg/init`
//! with an INVALID body, so each request passes BRC-31 verify (consuming a token in
//! `verify_or_allow`) and then 400s BEFORE a coordinator is created — light, no heavy
//! MPC, no state leak. Asserts: (a) a real burst is admitted first, (b) the limiter
//! then returns 429, (c) a FRESH identity is unaffected (per-identity isolation +
//! the service still serves legit callers). 100cash uses distinct identities = distinct
//! buckets, so this gate cannot throttle it.
//!
//! No sats. Gated on `RATE_LIMIT_DEPLOYED=1`.
//!
//! ```bash
//! RATE_LIMIT_DEPLOYED=1 cargo test -p bsv-mpc-proxy \
//!   --test rate_limit_deployed_e2e -- --nocapture --test-threads=1
//! ```

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_relay::RelaySession;

const DEFAULT_CONTAINER: &str = "https://bsv-mpc-service-container.dev-a3e.workers.dev";

async fn handshake(http: &reqwest::Client, url: &str, seed: u8) -> RelaySession {
    let identity = PrivateKey::from_bytes(&[seed; 32]).expect("identity key");
    let mut session = RelaySession::new(identity);
    session
        .handshake(http, url)
        .await
        .expect("BRC-31 handshake with the deployed container");
    session
}

/// Fire one BRC-31-signed POST /dkg/init with an INVALID body; return the HTTP status.
async fn signed_dkg_init(http: &reqwest::Client, url: &str, session: &RelaySession) -> u16 {
    // Invalid DkgInitRequest (missing `config`) → passes verify (token consumed),
    // then 400 before any coordinator is built.
    let body = b"{}".to_vec();
    let headers = session
        .auth_header_pairs("POST", "/dkg/init", &body)
        .expect("sign request");
    let mut req = http
        .post(format!("{url}/dkg/init"))
        .header("content-type", "application/json")
        .body(body);
    for (name, value) in headers {
        req = req.header(name, value);
    }
    match req.send().await {
        Ok(resp) => resp.status().as_u16(),
        Err(_) => 0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deployed_container_rate_limits_per_identity() {
    if std::env::var("RATE_LIMIT_DEPLOYED").ok().as_deref() != Some("1") {
        eprintln!("RATE_LIMIT_DEPLOYED=1 not set — skipping the deployed rate-limit gate.");
        return;
    }
    let url =
        std::env::var("DEPLOYED_CONTAINER_URL").unwrap_or_else(|_| DEFAULT_CONTAINER.to_string());
    let http = reqwest::Client::new();

    // Identity A — the burst victim. (Seed 0xA1; NOT an identity 100cash uses.)
    let session_a = handshake(&http, &url, 0xA1).await;
    eprintln!("✔ handshake OK (identity A); bursting /dkg/init …");

    // Burst back-to-back; record where the FIRST 429 lands. Consumption (network-rate)
    // outpaces the 1/sec refill, so the bucket drains.
    let mut allowed_before_429 = 0usize;
    let mut saw_429 = false;
    let mut first_status = None;
    let mut hist: std::collections::BTreeMap<u16, usize> = std::collections::BTreeMap::new();
    for i in 0..150 {
        let status = signed_dkg_init(&http, &url, &session_a).await;
        *hist.entry(status).or_default() += 1;
        if first_status.is_none() {
            first_status = Some(status);
            eprintln!("  first request status = {status}");
        }
        if status == 429 {
            saw_429 = true;
            eprintln!("✔ first 429 after {allowed_before_429} admitted requests (req #{i})");
            break;
        }
        allowed_before_429 += 1;
    }
    eprintln!("  status histogram: {hist:?}");

    assert_ne!(
        first_status,
        Some(429),
        "a fresh identity's first request must be admitted (full bucket), not 429"
    );
    assert!(
        saw_429,
        "the limiter MUST return 429 once the bucket is exhausted"
    );
    assert!(
        allowed_before_429 >= 50,
        "a real burst must be admitted before throttling (got {allowed_before_429}); \
         the limiter must not throttle from the first request"
    );

    // Identity B — fresh bucket: proves per-identity isolation + that the service still
    // serves legit callers while A is throttled.
    let session_b = handshake(&http, &url, 0xB2).await;
    let b_status = signed_dkg_init(&http, &url, &session_b).await;
    assert_ne!(
        b_status, 429,
        "a DIFFERENT identity must NOT be throttled by A's burst (per-identity isolation)"
    );
    eprintln!(
        "✔ identity B admitted (status {b_status}) while A throttled — per-identity isolation LIVE"
    );
    eprintln!("✔ #5 rate limiting verified LIVE on the deployed container");
}
