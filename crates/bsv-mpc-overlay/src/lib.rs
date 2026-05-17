//! # bsv-mpc-overlay
//!
//! BSV overlay network integration for MPC node discovery and participation
//! proof publication.
//!
//! This crate handles the overlay-facing aspects of the MPC signing network:
//!
//! - **Node Advertisement**: Create and publish CHIP tokens (BRC-23, BRC-48
//!   PushDrop) that advertise an MPC Key Share Service on the overlay network.
//!   Other agents can discover these tokens to find signing partners.
//!
//! - **Node Discovery**: Query the overlay network via SLAP/CLAP lookup
//!   (BRC-24/25) to find MPC nodes that match desired criteria (curve,
//!   threshold configuration, max fee).
//!
//! - **Participation Proofs**: Publish BRC-18 OP_RETURN proofs to the
//!   `tm_mpc_signing` overlay topic recording which nodes participated in
//!   a signing ceremony. These proofs enable on-chain fee distribution —
//!   nodes that sign more transactions earn proportionally more fees.
//!
//! ## Overlay Protocol Stack
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │                 Application Layer                  │
//! │  CHIP tokens (node ads) + Participation proofs     │
//! ├──────────────────────────────────────────────────┤
//! │               Topic: tm_mpc_signing               │
//! ├──────────────────────────────────────────────────┤
//! │  BRC-22 (submit)  │  BRC-24 (SLAP lookup)        │
//! │  BRC-23 (CHIP)    │  BRC-25 (CLAP lookup)        │
//! ├──────────────────────────────────────────────────┤
//! │             BSV Overlay Network                    │
//! │        (SHIP/SLAP host infrastructure)             │
//! └──────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```rust,no_run
//! use bsv_mpc_overlay::{discovery, chip, proofs, types::DiscoveryQuery};
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Discover MPC nodes that support 2-of-3 secp256k1
//! let nodes = discovery::discover_nodes(
//!     "https://overlay.example.com",
//!     &DiscoveryQuery {
//!         curve: Some("secp256k1".into()),
//!         threshold: Some("2-of-3".into()),
//!         max_fee_sats: Some(500),
//!         limit: Some(10),
//!     },
//! ).await?;
//!
//! for node in &nodes {
//!     println!("{} @ {} — {} sats/sig", node.identity_key, node.domain, node.fee_sats);
//! }
//! # Ok(())
//! # }
//! ```

pub mod chip;
pub mod discovery;
pub mod error;
pub mod proofs;
pub mod types;

// Re-export key types for ergonomic imports.
pub use chip::ChipTokenInfo;
pub use error::OverlayError;
pub use types::{DiscoveryQuery, MpcNodeInfo, OverlayProof, MPC_TOPIC};
