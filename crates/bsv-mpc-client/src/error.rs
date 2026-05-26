//! Client-layer error type.

use thiserror::Error;

/// Errors surfaced by the bsv-mpc native/web client.
#[derive(Debug, Error)]
pub enum ClientError {
    /// A host-injected seam (storage / chain / keystore) failed.
    #[error("host {seam}: {reason}")]
    Host { seam: &'static str, reason: String },

    /// Biometric unseal was declined or the sealed share was absent.
    #[error("keystore unseal failed: {0}")]
    Unseal(String),

    /// Underlying MPC core failure.
    #[error("mpc core: {0}")]
    Core(String),

    /// Serialization / deserialization of a wire or stored structure failed.
    #[error("serialization: {0}")]
    Serialization(String),

    /// Functionality staged for a later #41 build phase. Returned (never
    /// `panic!`/`todo!`) so the scaffold compiles and the boundary is explicit.
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
}

impl From<bsv_mpc_core::MpcError> for ClientError {
    fn from(e: bsv_mpc_core::MpcError) -> Self {
        ClientError::Core(e.to_string())
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(e: serde_json::Error) -> Self {
        ClientError::Serialization(e.to_string())
    }
}
