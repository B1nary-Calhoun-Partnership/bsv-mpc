//! **Deploy smoke-test** (#8 item 5) — a fast post-deploy guard that the
//! DEPLOYED worker + container are healthy AND actually ENFORCING auth (§07.6).
//! Catches a false-secure deploy (e.g. a secret that silently didn't reach the
//! container → dev mode) without a full DKG.
//!
//! Run after every worker/container deploy:
//! ```bash
//! DEPLOY_SMOKE=1 cargo test -p bsv-mpc-proxy --test deploy_smoke_e2e -- --nocapture
//! ```

use std::time::Duration;

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";
const DEFAULT_CONTAINER: &str = "https://bsv-mpc-service-container.dev-a3e.workers.dev";

fn opt_in() -> bool {
    std::env::var("DEPLOY_SMOKE").ok().as_deref() == Some("1")
}

/// POST a valid-shape body and return the status, retrying past CF-container
/// cold-start 404s (the @cloudflare/containers proxy 404s while a sleeping
/// instance wakes; the real handler status follows).
async fn post_status(http: &reqwest::Client, url: &str, body: serde_json::Value) -> u16 {
    for _ in 0..18 {
        let code = http
            .post(url)
            .json(&body)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map(|r| r.status().as_u16())
            .unwrap_or(0);
        if code != 404 && code != 0 {
            return code;
        }
        tokio::time::sleep(Duration::from_secs(8)).await;
    }
    404
}

async fn health(http: &reqwest::Client, base: &str) -> u16 {
    http.get(format!("{base}/health"))
        .timeout(Duration::from_secs(40))
        .send()
        .await
        .map(|r| r.status().as_u16())
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deployed_endpoints_are_healthy_and_enforced() {
    if !opt_in() {
        eprintln!("DEPLOY_SMOKE=1 not set — skipping deploy smoke-test.");
        return;
    }
    let worker = std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.into());
    let container =
        std::env::var("DEPLOYED_CONTAINER_URL").unwrap_or_else(|_| DEFAULT_CONTAINER.into());
    let http = reqwest::Client::new();

    let pk = "02".to_string() + &"00".repeat(32); // valid-shape 66-hex
    let sh = "00".repeat(32);
    let dkg_body = serde_json::json!({"agent_id":"", "config":{"threshold":2,"parties":2}});
    let ecdh_body = serde_json::json!({"agent_id": pk, "counterparty_pub": pk});

    // ── Worker: healthy + enforcing (unauthed funded-boundary routes → 401). ──
    assert_eq!(
        health(&http, &worker).await,
        200,
        "worker /health must be 200"
    );
    eprintln!("✔ worker /health 200");
    for (path, body) in [
        ("/dkg/init", dkg_body.clone()),
        ("/ecdh", ecdh_body.clone()),
        ("/custody/get-share", serde_json::json!({"agent_id": pk})),
        (
            "/sign-relay",
            serde_json::json!({"agent_id": pk, "sighash_hex": sh}),
        ),
    ] {
        let code = post_status(&http, &format!("{worker}{path}"), body).await;
        assert_eq!(
            code, 401,
            "worker {path} unauthed MUST be 401 (§07.6) — got {code}"
        );
        eprintln!("✔ worker {path} unauthed → 401");
    }

    // ── Container: healthy + enforcing. ──
    assert_eq!(
        health(&http, &container).await,
        200,
        "container /health must be 200"
    );
    eprintln!("✔ container /health 200");
    for (path, body) in [
        ("/dkg/init", dkg_body.clone()),
        ("/ecdh", ecdh_body.clone()),
    ] {
        let code = post_status(&http, &format!("{container}{path}"), body).await;
        assert_eq!(
            code, 401,
            "container {path} unauthed MUST be 401 (§07.6 — NOT dev/false-secure) — got {code}"
        );
        eprintln!("✔ container {path} unauthed → 401");
    }

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  DEPLOY SMOKE PASS — worker + container healthy + ENFORCING    ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
}
