//! Proxy-specific error types.
//!
//! These errors cover the failure modes unique to the signing proxy: MPC
//! protocol failures, share loading issues, fee injection problems, and
//! upstream KSS communication errors. General MPC protocol errors are
//! re-exported from `bsv_mpc_core::error`.

use thiserror::Error;

/// Errors that can occur in the MPC signing proxy.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Failed to load or decrypt the key share from disk.
    ///
    /// Check that `MPC_SHARE_PATH` points to a valid encrypted share file
    /// and that `MPC_ENCRYPTION_KEY` (if set) matches the key used during DKG.
    #[error("Share loading failed: {0}")]
    ShareLoad(String),

    /// The Key Share Service is unreachable or returned an error.
    ///
    /// This can be a network timeout, DNS failure, TLS error, or the KSS
    /// returning an HTTP error status. The proxy cannot sign without KSS
    /// participation.
    #[error("KSS communication error: {0}")]
    KssError(String),

    /// An MPC protocol round failed.
    ///
    /// This wraps errors from `bsv_mpc_core` that occur during DKG, presigning,
    /// or online signing. If identifiable abort is triggered, the misbehaving
    /// party index is included in the message.
    #[error("MPC protocol error: {0}")]
    Protocol(#[from] bsv_mpc_core::MpcError),

    /// Fee injection failed (e.g., invalid addresses, bad threshold config).
    #[error("Fee injection error: {0}")]
    FeeInjection(String),

    /// Transaction construction or serialization failed.
    #[error("Transaction error: {0}")]
    Transaction(String),

    /// The presignature pool is empty and the caller requested non-blocking signing.
    ///
    /// The proxy will fall back to the full 4-round protocol automatically,
    /// but this error is used internally to signal the fallback.
    #[error("No presignatures available — falling back to interactive signing")]
    PresignatureExhausted,

    /// A BRC-100 request was malformed or missing required fields.
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// UTXO management error (e.g., insufficient funds, output not found).
    #[error("UTXO error: {0}")]
    Utxo(String),

    /// Encryption or decryption error for local key operations.
    ///
    /// This covers wallet-native encrypt/decrypt (which use locally-derived
    /// keys, not MPC) and share file decryption.
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Certificate operation failed.
    #[error("Certificate error: {0}")]
    Certificate(String),

    /// Internal proxy error (should not happen in normal operation).
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Proxy-specific result type.
pub type ProxyResult<T> = std::result::Result<T, ProxyError>;

impl From<reqwest::Error> for ProxyError {
    fn from(err: reqwest::Error) -> Self {
        ProxyError::KssError(err.to_string())
    }
}

impl From<serde_json::Error> for ProxyError {
    fn from(err: serde_json::Error) -> Self {
        ProxyError::InvalidRequest(format!("JSON parse error: {err}"))
    }
}

impl From<std::io::Error> for ProxyError {
    fn from(err: std::io::Error) -> Self {
        ProxyError::ShareLoad(format!("IO error: {err}"))
    }
}

/// Convert a `ProxyError` into an axum-compatible HTTP response.
///
/// Maps error variants to appropriate HTTP status codes:
/// - `InvalidRequest` → 400
/// - `PresignatureExhausted` → 503
/// - `KssError` → 502
/// - Everything else → 500
impl axum::response::IntoResponse for ProxyError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;

        let (status, message) = match &self {
            ProxyError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ProxyError::PresignatureExhausted => (
                StatusCode::SERVICE_UNAVAILABLE,
                self.to_string(),
            ),
            ProxyError::KssError(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            ProxyError::Utxo(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg.clone()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        let body = serde_json::json!({
            "error": message,
            "status": status.as_u16(),
        });

        (status, axum::Json(body)).into_response()
    }
}
