//! Errors emitted by the MessageBox transport client.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MessageBoxError {
    /// HTTP transport failure (network error, non-2xx status with no
    /// structured error, request build failure).
    #[error("HTTP transport error: {0}")]
    Http(String),

    /// WebSocket transport failure (connect, upgrade, frame, close).
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    /// Timed out waiting for a WS milestone (`connected` greeting,
    /// `joinedRoom` ack, post-frame send). Distinct from `WebSocket` so
    /// the reconnect loop in `ws::run_loop` can branch on it.
    #[error("WebSocket timeout: {0}")]
    WsTimeout(String),

    /// BRC-31 mutual auth failure on the request or response side.
    #[error("BRC-31 auth error: {0}")]
    Auth(String),

    /// Canonical envelope wrap/unwrap failure (delegates to bsv-mpc-core).
    #[error("Envelope error: {0}")]
    Envelope(#[from] bsv_mpc_core::MpcError),

    /// MessageBox server returned a structured error (mapped 4xx/5xx body).
    #[error("MessageBox server error: {status} {code} — {message}")]
    Server {
        status: u16,
        code: String,
        message: String,
    },

    /// JSON encode/decode failure on a MessageBox request or response.
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    /// Hex encode/decode failure on the canonical-CBOR body wrap field.
    #[error("Hex encoding error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// Generic protocol error (catch-all for cases not covered by specific variants).
    #[error("Protocol error: {0}")]
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, MessageBoxError>;
