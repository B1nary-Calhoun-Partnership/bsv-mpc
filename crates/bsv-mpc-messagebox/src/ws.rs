//! `/ws` WebSocket subscribe (raw WebSocket per the Calhoun relay
//! `bsv-messagebox-cloudflare-public`; Socket.IO/EngineIO-compatible
//! envelope per §06.4 with parity in the TS server).
//!
//! **STUB** — populated by the WebSocket task (`crates/bsv-mpc-messagebox`
//! task #13). The shape:
//!
//! ```ignore
//! pub async fn subscribe(relay_url: &str, auth: &Brc31Client,
//!     message_box: &str)
//!     -> Result<impl Stream<Item = Result<InboundMessage>>>;
//! ```
//!
//! Heartbeats every 30s (§06.12). Reconnect with exponential backoff,
//! cap 30s. After reconnect, backfill via `/listMessages`.

#![allow(dead_code)]
