//! Error types for the MPC overlay network module.
//!
//! These errors cover overlay network communication failures, CHIP token
//! parsing issues, and proof publication/querying problems.

/// Errors that can occur during overlay network operations.
#[derive(Debug, thiserror::Error)]
pub enum OverlayError {
    /// The overlay node could not be reached (DNS, TLS, or connection timeout).
    #[error("Overlay node unreachable: {0}")]
    Unreachable(String),

    /// A CHIP token script could not be parsed or has an invalid signature.
    #[error("CHIP token invalid: {0}")]
    InvalidChipToken(String),

    /// The BRC-22 transaction submission was rejected by the overlay node.
    ///
    /// Possible reasons: invalid transaction format, duplicate submission,
    /// failed topic manager admission logic, or invalid proof signature.
    #[error("BRC-22 submission rejected: {0}")]
    SubmissionRejected(String),

    /// A BRC-24 SLAP or BRC-25 CLAP lookup failed.
    #[error("BRC-24 lookup failed: {0}")]
    LookupFailed(String),

    /// No MPC nodes were found matching the discovery query.
    #[error("No MPC nodes found matching query")]
    NoNodesFound,

    /// A participation proof script could not be parsed.
    #[error("Invalid proof format: {0}")]
    InvalidProof(String),

    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
