//! **Public API surface lock (compile-only).**
//!
//! H-4.5 regression guard. The H-STEP-4 consumer map flags a specific
//! set of `MessageBoxClient` signatures + re-exported types as
//! "PRESERVE THESE SIGNATURES" — load-bearing for `bsv-mpc-service`'s
//! dispatcher/listener and the `live_relay_proof` gate. The H-4.4 native
//! unification rewrote the internals (raw-WS → Socket.IO + BRC-103);
//! this test pins the *surface* so a future refactor can't silently
//! change a signature or drop a re-export without breaking the build
//! here.
//!
//! Compile-only: the bodies are guarded behind `if false`, so nothing
//! runs — it stays a pure type-check with no relay dependency. The
//! `.await`s + typed bindings pin every signature (param types, return
//! types, async-ness, field layouts). Placeholder values come from
//! [`undef`], whose `-> T` signature keeps each binding a normal
//! (non-diverging) expression so the checks read cleanly.
//!
//! Native-only by nature: the high-level `MessageBoxClient` / `subscribe`
//! API is `#[cfg(not(target_arch = "wasm32"))]` (the wasm32 target
//! carries only the transport substrate — `transport_wasm`). Phase I
//! adds the wasm32 client surface; this lock grows then.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;

use bsv::primitives::ec::PublicKey;
use bsv_mpc_core::envelope::{MessageEnvelope, WrapParams};
use bsv_mpc_core::types::RoundMessage;
use bsv_mpc_messagebox::auth::MessageBoxAuth;
use bsv_mpc_messagebox::{
    subscribe, DecodedEnvelope, DecodedRoundMessage, EnvelopeSubscription, InboundEnvelopeEvent,
    InboundVia, MessageBoxClient, MessageBoxError, Result, RoundMessageSubscription,
    WsSubscription,
};

/// A typed placeholder for compile-only signature checks. Its `-> T`
/// signature makes call sites normal expressions (not diverging), so the
/// bindings below don't trip `unused`/`unreachable` lints. Never invoked
/// at runtime (callers are `if false`-guarded).
fn undef<T>() -> T {
    unreachable!("api_surface is compile-only; bodies are if-false-guarded")
}

/// Pins every load-bearing `MessageBoxClient` signature + the low-level
/// `subscribe` shim. Compile-only (`if false`); the `.await`s resolve
/// the future Output types at compile time, which is the signature
/// check we want.
#[tokio::test]
async fn public_signatures_are_stable() {
    if false {
        // Constructor: (impl Into<String>, PrivateKey) -> Result<Self>.
        let client: MessageBoxClient = MessageBoxClient::new(String::new(), undef()).unwrap();

        // Accessors.
        let _: &str = client.relay_url();
        let _: Result<String> = client.identity_hex().await;

        // Send operations.
        let env: &MessageEnvelope = undef();
        let _: Result<String> = client.send("", "", env).await;
        let _: Result<String> = client.send_with_id("", "", "", env).await;
        let rm: &RoundMessage = undef();
        let params: WrapParams = undef();
        let _: Result<String> = client.send_round_message("", "", rm, params).await;

        // Subscribe operations.
        let _: Result<EnvelopeSubscription> = client.subscribe("").await;
        let _: Result<EnvelopeSubscription> = client.subscribe_many(vec![]).await;
        let _: Result<RoundMessageSubscription> = client.subscribe_round_messages("").await;

        // Acknowledge.
        let ids: Vec<String> = undef();
        let _: Result<()> = client.acknowledge(&ids).await;

        // Subscription handles: next() + shutdown().
        let mut env_sub: EnvelopeSubscription = undef();
        let _: Option<Result<DecodedEnvelope>> = env_sub.next().await;
        env_sub.shutdown().await;

        let mut rm_sub: RoundMessageSubscription = undef();
        let _: Option<Result<DecodedRoundMessage>> = rm_sub.next().await;
        rm_sub.shutdown().await;

        // Low-level subscribe entry (the `ws::subscribe` shim, still
        // re-exported at the crate root; called directly by
        // live_relay_proof.rs).
        let auth: Arc<MessageBoxAuth> = undef();
        let _: Result<WsSubscription> = subscribe(auth, vec![]).await;
    }
}

/// Pins the byte-stable struct/enum field layouts the consumer map marks
/// load-bearing. Field renames/removals fail to compile here.
#[test]
fn struct_layouts_are_stable() {
    if false {
        let ev: InboundEnvelopeEvent = undef();
        let _: String = ev.message_box;
        let _: String = ev.sender;
        let _: String = ev.message_id;
        let _: String = ev.body;
        let _: InboundVia = ev.via;
        let _ = matches!(ev.via, InboundVia::WsPush | InboundVia::Backfill);

        let de: DecodedEnvelope = undef();
        let _: String = de.message_id;
        let _: String = de.sender;
        let _: MessageEnvelope = de.envelope;
        let _: InboundVia = de.via;

        let dr: DecodedRoundMessage = undef();
        let _: String = dr.message_id;
        let _: String = dr.message_box;
        let _: PublicKey = dr.sender_pub;
        let _: RoundMessage = dr.round_msg;
        let _: InboundVia = dr.via;

        // Error type re-export.
        let _: MessageBoxError = undef();
    }
}
