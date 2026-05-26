//! Host-injected round-message relay seam for the live 2-party signing ceremony.
//!
//! The client drives its own [`SigningCoordinator`](bsv_mpc_core::signing::SigningCoordinator)
//! and ships each round's outgoing messages to the cosigner — and receives the
//! cosigner's — over this seam. In production the host implements it on top of
//! the MessageBox relay (native) or a JS WebSocket (web); in tests an in-process
//! impl wraps the cosigner's coordinator directly.

use async_trait::async_trait;
use bsv_mpc_core::RoundMessage;

use crate::error::ClientError;

/// One synchronous round exchange with the cosigner.
///
/// `?Send`: host/relay implementations are single-threaded (wasm JS / UniFFI).
#[async_trait(?Send)]
pub trait RoundTransport {
    /// Deliver our round messages to the cosigner and return the cosigner's
    /// messages for this round.
    async fn exchange(&self, outgoing: Vec<RoundMessage>)
        -> Result<Vec<RoundMessage>, ClientError>;
}
