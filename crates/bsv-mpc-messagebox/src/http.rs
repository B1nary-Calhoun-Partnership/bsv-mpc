//! HTTP routes: `POST /sendMessage`, `POST /listMessages`, `POST /acknowledgeMessage`.
//!
//! **STUB** — populated by the HTTP routes task (`crates/bsv-mpc-messagebox`
//! task #12). The shape:
//!
//! ```ignore
//! pub async fn send_message(client: &Client, auth: &Brc31Client,
//!     relay_url: &str, request: &SendMessageRequest)
//!     -> Result<SendMessageResponse>;
//!
//! pub async fn list_messages(client: &Client, auth: &Brc31Client,
//!     relay_url: &str, message_box: &str)
//!     -> Result<ListMessagesResponse>;
//!
//! pub async fn acknowledge_messages(client: &Client, auth: &Brc31Client,
//!     relay_url: &str, message_ids: &[String])
//!     -> Result<AcknowledgeResponse>;
//! ```

#![allow(dead_code)]
