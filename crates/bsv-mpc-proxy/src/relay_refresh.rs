//! Proxy-side **coordinator** for §18.2 key-refresh over the relay (issue #10d,
//! CONTAINER target).
//!
//! The symmetric sibling of [`crate::relay_presign`]: the proxy is one refresh
//! peer, the deployed CF Container is the other. The proxy:
//!
//! 1. Fetches the container's relay identity (`GET /refresh-relay/identity`).
//! 2. Runs its own [`RefreshHandler`] + a `MessageBoxListener` on `mpc-refresh`;
//!    `initiate` registers its slot and ships its round-1 to the container.
//! 3. Arms the container (`POST /refresh-relay/init`) — it subscribes, runs its
//!    own `init`, and ships its round-1 back. The 2-round PSS refresh completes
//!    over the relay; both peers commit a rotated share for the SAME joint key.
//!
//! On commit the proxy returns the [`RefreshCommit`] to the bridge, which
//! hot-swaps + persists the rotated share and fires the §06.18 ShareRefresh
//! invalidation. The container rotates its own share in its `/refresh-relay/init`
//! completion task (see the service `refresh_relay_handlers`).

use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::error::{MpcError, Result};
use bsv_mpc_core::types::{EncryptedShare, SessionId};
use bsv_mpc_core::RefreshCommit;
use bsv_mpc_messagebox::MessageBoxClient;
use bsv_mpc_service::{MessageBoxListener, RefreshHandler};

/// Canonical BRC-31 request signer (same shape as `relay_presign::RequestSigner`).
pub type RequestSigner<'a> =
    &'a (dyn Fn(&str, &str, &[u8]) -> Result<Vec<(String, String)>> + Send + Sync);

/// How the coordinator reaches the container to arm it as a refresh peer.
pub struct PeerArm {
    /// The container's `/refresh-relay/init` URL.
    pub url: String,
    /// The share's `agent_id` (joint pubkey hex) for owner-authz (§08.1).
    pub agent_id: String,
}

#[derive(serde::Deserialize)]
struct ArmResponse {
    peer_pub_hex: String,
}

/// Run the §18.2 refresh over the relay as one peer, returning this peer's
/// rotated-share [`RefreshCommit`].
#[allow(clippy::too_many_arguments)]
pub async fn coordinate_refresh_over_relay(
    relay_url: &str,
    identity_priv: PrivateKey,
    share: EncryptedShare,
    my_party: u16,
    peer_party: u16,
    parties_at_keygen: Vec<u16>,
    session_id: SessionId,
    arm: PeerArm,
    request_signer: RequestSigner<'_>,
    timeout: Duration,
) -> Result<RefreshCommit> {
    let proto = |e: bsv_mpc_messagebox::error::MessageBoxError| MpcError::Protocol(e.to_string());

    // §06 transport discipline (#79): ONE process-local **bounded** HTTP client for
    // both relay triggers below (identity fetch + arm). `reqwest::Client::new()` has
    // no default timeout — the #40-class hang that sat a deployed ceremony at 0% CPU
    // for 68 min; routing through the relay crate's tested `bounded_http_client`
    // fail-closes at `RELAY_HTTP_TIMEOUT` instead.
    let http = bsv_mpc_relay::bounded_http_client(bsv_mpc_relay::RELAY_HTTP_TIMEOUT)?;

    // 1. Coordinator relay client + identity + listener on mpc-refresh.
    let client = MessageBoxClient::new(relay_url, identity_priv.clone()).map_err(proto)?;
    let coord_pub_hex = client.identity_hex().await.map_err(proto)?;

    let handler = RefreshHandler::new(my_party, parties_at_keygen.clone());
    let listener = MessageBoxListener::start(
        client.clone(),
        bsv_mpc_messagebox::types::BOX_REFRESH,
        handler.handler_fn(),
    )
    .await
    .map_err(|e| MpcError::Protocol(format!("coord refresh listener: {e}")))?;

    // 2. Fetch the container's relay identity FIRST (§06.17 ordering invariant:
    //    register our slot + ship round-1 before the peer ships).
    let peer_pub_hex = match fetch_peer_identity(&http, &arm).await {
        Ok(h) => h,
        Err(e) => {
            listener.shutdown().await;
            return Err(e);
        }
    };

    // 3. Initiate our own SM (registers the slot) + ship round-1 to the peer.
    let peers = vec![(peer_party, peer_pub_hex.clone())];
    let (rx, round1_out) = match handler.initiate(session_id, share, peers).await {
        Ok(v) => v,
        Err(e) => {
            listener.shutdown().await;
            return Err(MpcError::Protocol(format!("coord refresh initiate: {e}")));
        }
    };
    for out in &round1_out {
        if let Err(e) = client
            .send_round_message(
                &out.recipient_pub_hex,
                &out.message_box,
                &out.round_msg,
                out.params.clone(),
            )
            .await
        {
            listener.shutdown().await;
            return Err(MpcError::Protocol(format!(
                "ship coord refresh round-1: {e}"
            )));
        }
    }

    // 4. Arm the container — it subscribes (backfilling our round-1), runs init,
    //    and ships its round-1 to us. Verify its identity matches.
    let armed = match arm_peer(
        &http,
        &arm,
        &session_id,
        &coord_pub_hex,
        my_party,
        peer_party,
        &parties_at_keygen,
        request_signer,
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            listener.shutdown().await;
            return Err(e);
        }
    };
    if armed != peer_pub_hex {
        listener.shutdown().await;
        return Err(MpcError::Protocol(format!(
            "container relay identity changed between identity ({peer_pub_hex}) and arm ({armed})"
        )));
    }

    // 5. Await our rotated-share commit.
    let commit = match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            listener.shutdown().await;
            return Err(MpcError::Protocol(format!(
                "coordinator refresh completion channel dropped: {e}"
            )));
        }
        Err(_) => {
            listener.shutdown().await;
            return Err(MpcError::Protocol(
                "timed out awaiting refresh commit over the relay".into(),
            ));
        }
    };
    listener.shutdown().await;
    Ok(commit)
}

/// GET the container's `/refresh-relay/identity` (read-only) → its relay identity hex.
/// `http` is the caller's bounded client (#79) so this trigger can't #40-hang.
async fn fetch_peer_identity(http: &reqwest::Client, arm: &PeerArm) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct IdResponse {
        peer_pub_hex: String,
    }
    let url = arm
        .url
        .replace("/refresh-relay/init", "/refresh-relay/identity");
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| MpcError::Protocol(format!("fetch refresh peer identity: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "/refresh-relay/identity returned {status}: {txt}"
        )));
    }
    let parsed: IdResponse = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse refresh identity response: {e}")))?;
    Ok(parsed.peer_pub_hex)
}

/// POST `/refresh-relay/init`, BRC-31-signed over the canonical wire.
/// `http` is the caller's bounded client (#79) so this trigger can't #40-hang.
#[allow(clippy::too_many_arguments)]
async fn arm_peer(
    http: &reqwest::Client,
    arm: &PeerArm,
    session_id: &SessionId,
    coordinator_pub_hex: &str,
    my_party: u16,
    peer_party: u16,
    parties_at_keygen: &[u16],
    request_signer: RequestSigner<'_>,
) -> Result<String> {
    // The container's `my_party_index` is the PEER party (the proxy is `my_party`).
    let body = serde_json::json!({
        "agent_id": arm.agent_id,
        "session_id": session_id.hex(),
        "peer_pub_hex": coordinator_pub_hex,
        "peer_party": my_party,
        "my_party_index": peer_party,
        "parties_at_keygen": parties_at_keygen,
    });
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| MpcError::Serialization(format!("serialize refresh-relay/init: {e}")))?;
    let path = reqwest::Url::parse(&arm.url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| "/refresh-relay/init".to_string());

    let mut builder = http
        .post(&arm.url)
        .header("content-type", "application/json")
        .body(body_bytes.clone());
    for (name, value) in request_signer("POST", &path, &body_bytes)? {
        builder = builder.header(name, value);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| MpcError::Protocol(format!("arm refresh peer request: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "container /refresh-relay/init returned {status}: {txt}"
        )));
    }
    let parsed: ArmResponse = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse refresh-relay/init response: {e}")))?;
    Ok(parsed.peer_pub_hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Bind a local TCP server that ACCEPTS connections then HOLDS them open forever,
    /// never sending a byte — the exact #40-class scenario (a peer sitting at 0% CPU).
    /// The connection handshakes (so this isn't a fast connect-refused), so only the
    /// client's request timeout can end the call. Returns the bound address.
    async fn stalled_peer() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stalled peer");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock); // hold the socket open, never respond
            }
        });
        addr
    }

    /// #79 regression: the refresh **identity-fetch** trigger against a stalled peer
    /// MUST fail-closed at ~the client bound, not hang forever (#40). A short 2s bound
    /// keeps the test fast; production uses `RELAY_HTTP_TIMEOUT`. An unbounded
    /// `reqwest::Client::new()` (the bug) would never return here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fetch_peer_identity_fails_fast_against_a_stalled_peer() {
        let addr = stalled_peer().await;
        let http =
            bsv_mpc_relay::bounded_http_client(Duration::from_secs(2)).expect("bounded client");
        let arm = PeerArm {
            url: format!("http://{addr}/refresh-relay/init"),
            agent_id: "deadbeef".into(),
        };

        let started = Instant::now();
        let res = fetch_peer_identity(&http, &arm).await;
        let elapsed = started.elapsed();

        assert!(res.is_err(), "a stalled peer must error, not return Ok");
        assert!(
            elapsed >= Duration::from_secs(1) && elapsed < Duration::from_secs(8),
            "identity fetch must fail-closed at ~the 2s bound (took {elapsed:?}) — \
             an unbounded reqwest::Client::new() would hang here indefinitely"
        );
    }

    /// #79 regression: the refresh **arm** trigger (POST `/refresh-relay/init`) against
    /// a stalled peer MUST fail-closed at ~the bound, not hang. Trivial request-signer
    /// (no headers) — we're exercising the transport bound, not the BRC-31 wire.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn arm_peer_fails_fast_against_a_stalled_peer() {
        let addr = stalled_peer().await;
        let http =
            bsv_mpc_relay::bounded_http_client(Duration::from_secs(2)).expect("bounded client");
        let arm = PeerArm {
            url: format!("http://{addr}/refresh-relay/init"),
            agent_id: "deadbeef".into(),
        };
        let signer_fn =
            |_method: &str, _path: &str, _body: &[u8]| -> Result<Vec<(String, String)>> {
                Ok(Vec::new())
            };
        let signer: RequestSigner = &signer_fn;
        let session_id = SessionId::from_str_hash("test");

        let started = Instant::now();
        let res = arm_peer(&http, &arm, &session_id, "02dead", 0, 1, &[0, 1], signer).await;
        let elapsed = started.elapsed();

        assert!(res.is_err(), "a stalled peer must error, not return Ok");
        assert!(
            elapsed >= Duration::from_secs(1) && elapsed < Duration::from_secs(8),
            "arm must fail-closed at ~the 2s bound (took {elapsed:?})"
        );
    }
}
