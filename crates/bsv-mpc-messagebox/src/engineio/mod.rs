//! Engine.IO v4 + Socket.IO v5 protocol layer for the MessageBox
//! Socket.IO transport.
//!
//! - [`codec`] — packet codec, vendored byte-identical from
//!   `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/codec.rs`.
//!   Target-agnostic (pure `serde_json` + `std`); compiles to both
//!   native and `wasm32-unknown-unknown` without cfg gates.
//!
//! Graduated from `poc/poc17-cf-outbound-ws/src/engineio_codec.rs`
//! (Phase H Step 3 POC) into this crate as Phase H Step 4 sub-gate
//! H-4.1. See `docs/H-STEP-4-PLAN.md`.

pub mod codec;
