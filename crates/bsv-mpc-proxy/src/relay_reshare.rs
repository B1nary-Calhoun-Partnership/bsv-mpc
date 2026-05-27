//! Proxy-side **arm-the-container** helpers for §18.2 cross-(t,n) reshare over the
//! relay (issue #35c pt2, CONTAINER target).
//!
//! These were factored into [`bsv_mpc_relay::reshare`] (issue #66, path a-extended)
//! so the BRC-100 proxy AND the native `bsv-mpc-client` reuse the EXACT
//! mainnet-proven reshare-over-relay ceremony. This module re-exports them so
//! existing `crate::relay_reshare::*` references resolve unchanged.

pub use bsv_mpc_relay::reshare::{
    arm_container, fetch_peer_identity, ContainerArm, RequestSigner, ReshareRelayPeer,
};
