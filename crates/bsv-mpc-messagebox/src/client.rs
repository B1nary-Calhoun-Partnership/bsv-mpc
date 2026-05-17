//! Public `MessageBoxClient` API.
//!
//! **STUB** — populated by the client-API task (`crates/bsv-mpc-messagebox`
//! task #14). The shape:
//!
//! ```ignore
//! pub struct MessageBoxClient { /* relay_url, BRC-31 client, reqwest client */ }
//!
//! impl MessageBoxClient {
//!     pub async fn new(relay_url: &str, our_priv: PrivateKey) -> Result<Self>;
//!     pub async fn send(&self, recipient_pub: &PublicKey, message_box: &str,
//!         envelope: &MessageEnvelope) -> Result<()>;
//!     pub async fn subscribe(&self, message_box: &str)
//!         -> Result<impl Stream<Item = Result<MessageEnvelope>>>;
//!     pub async fn acknowledge(&self, message_ids: &[String]) -> Result<()>;
//! }
//! ```

#![allow(dead_code)]
