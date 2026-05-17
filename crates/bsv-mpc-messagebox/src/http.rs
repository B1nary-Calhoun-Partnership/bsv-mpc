//! HTTP routes for the MessageBox transport — `POST /sendMessage`,
//! `POST /listMessages`, `POST /acknowledgeMessage`.
//!
//! Each request is dispatched through `bsv_rs::auth::Peer::to_peer` with a
//! BRC-104 SimplifiedFetchTransport-format payload (per §06.5 + the
//! `bsv-middleware-cloudflare-public` middleware contract). Responses
//! arrive via a per-request listener filtered by 32-byte request ID
//! prefix — same pattern as `bsv-wallet-toolbox-rs/src/storage/client/
//! storage_client.rs:280-510`.

use std::sync::Arc;

use bsv::auth::transports::{HttpRequest, HttpResponse};
use rand::RngCore;
use tokio::sync::{oneshot, Mutex};

use crate::auth::MessageBoxAuth;
use crate::error::{MessageBoxError, Result};
use crate::types::{
    AcknowledgeRequest, AcknowledgeResponse, ListMessagesRequest, ListMessagesResponse,
    SendMessageRequest, SendMessageResponse,
};

/// Default per-request timeout (ms). The Calhoun relay returns within
/// ~600 ms median for our payload sizes; 30 s covers worst-case cold
/// Worker spin-ups + transient backend latency.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// `POST /sendMessage`. Returns the per-recipient ids on success.
pub async fn send_message(
    auth: &MessageBoxAuth,
    request: &SendMessageRequest,
) -> Result<SendMessageResponse> {
    let body = serde_json::to_vec(request)?;
    let raw = call_route(auth, "POST", "/sendMessage", &body).await?;
    parse_relay_response::<SendMessageResponse>(raw)
}

/// `POST /listMessages`. Drains the caller's mailbox.
pub async fn list_messages(
    auth: &MessageBoxAuth,
    message_box: &str,
) -> Result<ListMessagesResponse> {
    let body = serde_json::to_vec(&ListMessagesRequest {
        message_box: message_box.to_string(),
    })?;
    let raw = call_route(auth, "POST", "/listMessages", &body).await?;
    parse_relay_response::<ListMessagesResponse>(raw)
}

/// `POST /acknowledgeMessage`. Idempotent; deletes by id.
pub async fn acknowledge_messages(
    auth: &MessageBoxAuth,
    message_ids: &[String],
) -> Result<AcknowledgeResponse> {
    let body = serde_json::to_vec(&AcknowledgeRequest {
        message_ids: message_ids.to_vec(),
    })?;
    let raw = call_route(auth, "POST", "/acknowledgeMessage", &body).await?;
    parse_relay_response::<AcknowledgeResponse>(raw)
}

// ---------------------------------------------------------------------------
// Internal: round-trip one BRC-104 SimplifiedFetchTransport request.
// ---------------------------------------------------------------------------

/// Build the canonical BRC-104 payload for a request, dispatch via Peer,
/// and wait for the matching response on a listener filtered by the
/// 32-byte request_id prefix. Returns the raw response body bytes.
async fn call_route(
    auth: &MessageBoxAuth,
    method: &str,
    path: &str,
    request_body: &[u8],
) -> Result<Vec<u8>> {
    // 1. Build the HttpRequest the BRC-104 transport expects.
    let mut request_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut request_id);

    let http_request = HttpRequest {
        request_id,
        method: method.to_string(),
        path: path.to_string(),
        search: String::new(),
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: request_body.to_vec(),
    };
    let payload = http_request.to_payload();

    // 2. Set up a one-shot listener filtered by our request_id. This
    //    matches the pattern in bsv-wallet-toolbox-rs storage_client.rs.
    let (tx, rx) = oneshot::channel::<Vec<u8>>();
    let tx = Arc::new(Mutex::new(Some(tx)));
    let tx_for_cb = tx.clone();
    let expected_id = request_id;

    let peer = auth.peer().clone();
    let callback_id = peer
        .listen_for_general_messages(move |_sender, response_payload| {
            let tx = tx_for_cb.clone();
            Box::pin(async move {
                // Match on the leading 32 bytes (request_id). Anything else
                // is for another caller's listener.
                if response_payload.len() >= 32 && response_payload[..32] == expected_id {
                    if let Some(sender) = tx.lock().await.take() {
                        let _ = sender.send(response_payload);
                    }
                }
                Ok(())
            })
        })
        .await;

    // 3. Dispatch. Passing `None` for identity_key lets Peer's session
    //    manager handle the handshake on first contact and cache the
    //    server identity for subsequent calls.
    let send_result = peer.to_peer(&payload, None, Some(DEFAULT_TIMEOUT_MS)).await;
    if let Err(e) = send_result {
        peer.stop_listening_for_general_messages(callback_id).await;
        return Err(MessageBoxError::Http(format!(
            "Peer.to_peer({method} {path}) failed: {e:?}"
        )));
    }

    // 4. Await the matching response.
    let response_payload = match tokio::time::timeout(
        std::time::Duration::from_millis(DEFAULT_TIMEOUT_MS),
        rx,
    )
    .await
    {
        Ok(Ok(payload)) => payload,
        Ok(Err(_)) => {
            peer.stop_listening_for_general_messages(callback_id).await;
            return Err(MessageBoxError::Http(format!(
                "{method} {path}: response channel closed before reply arrived"
            )));
        }
        Err(_) => {
            peer.stop_listening_for_general_messages(callback_id).await;
            return Err(MessageBoxError::Http(format!(
                "{method} {path}: timed out after {DEFAULT_TIMEOUT_MS} ms"
            )));
        }
    };
    peer.stop_listening_for_general_messages(callback_id).await;

    // 5. Parse the BRC-104 HttpResponse from the payload.
    let http_response = HttpResponse::from_payload(&response_payload).map_err(|e| {
        MessageBoxError::Http(format!(
            "{method} {path}: HttpResponse::from_payload failed: {e:?}"
        ))
    })?;

    if http_response.status >= 400 {
        // Try to surface the relay's structured error envelope (matches
        // TS/Go message-box-server byte-for-byte). Fall back to raw text.
        if let Ok(env) = serde_json::from_slice::<ServerErrorEnvelope>(&http_response.body) {
            return Err(MessageBoxError::Server {
                status: http_response.status,
                code: env.code.unwrap_or_default(),
                message: env
                    .description
                    .or(env.message)
                    .unwrap_or_else(|| String::from_utf8_lossy(&http_response.body).into_owned()),
            });
        }
        return Err(MessageBoxError::Http(format!(
            "{method} {path}: {} returned: {}",
            http_response.status,
            String::from_utf8_lossy(&http_response.body)
        )));
    }

    Ok(http_response.body)
}

fn parse_relay_response<T: serde::de::DeserializeOwned>(body: Vec<u8>) -> Result<T> {
    serde_json::from_slice::<T>(&body).map_err(MessageBoxError::Json)
}

/// Shape of the relay's structured JSON error body. Newer servers emit
/// `description`, older ones `message`; we accept both.
#[derive(Debug, serde::Deserialize)]
struct ServerErrorEnvelope {
    #[allow(dead_code)]
    status: Option<String>,
    code: Option<String>,
    description: Option<String>,
    message: Option<String>,
}
