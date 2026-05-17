//! BRC-31 mutual auth client for MessageBox HTTP + WS upgrade requests.
//!
//! **STUB** — populated by the dedicated BRC-31 client port task
//! (`crates/bsv-mpc-messagebox` task #11). Until then, callers MUST inject
//! pre-built BRC-31 headers via the lower-level [`crate::http`] helpers.
//!
//! The shape this module will land:
//!
//! ```ignore
//! pub struct Brc31Client {
//!     our_priv: PrivateKey,
//!     server_pub: Option<PublicKey>,  // learned during handshake
//!     // ...session state
//! }
//!
//! impl Brc31Client {
//!     pub async fn handshake(&mut self, relay_url: &str) -> Result<()>;
//!     pub fn sign_request_headers(&self, body: &[u8]) -> Result<Headers>;
//!     pub fn verify_response_headers(&self, headers: &Headers, body: &[u8]) -> Result<()>;
//! }
//! ```
//!
//! Implementation will port the proxy↔KSS BRC-31 client from
//! `bsv-mpc-proxy/src/bridge.rs` (`mod auth_headers` + the kss_post path).

#![allow(dead_code)]
