//! Public [`MessageBoxClient`] API — the single entry point external
//! callers use to send / subscribe / acknowledge MPC envelopes over a
//! BSV `message-box-server`-compatible relay.
//!
//! Composes the lower-level modules in this crate:
//!
//! - [`crate::auth::MessageBoxAuth`] — BRC-31 mutual auth for the HTTP
//!   routes via `bsv-rs::Peer + SimplifiedFetchTransport`.
//! - [`crate::http`] — `POST /sendMessage`, `POST /listMessages`,
//!   `POST /acknowledgeMessage`.
//! - [`crate::subscribe`] — Socket.IO + BRC-103 live subscribe (signed
//!   `joinRoom`/`sendMessage` Generals over the upstream
//!   `bsv::auth::SocketIoTransport`) with §06.12 reconnect + backfill.
//! - [`crate::wire`] — canonical CBOR envelope ↔ MessageBox body wrap.
//!
//! The crate-root re-exports both this `MessageBoxClient` API and the
//! lower-level pieces; consumers typically use only this module.
//!
//! ## Lifecycle
//!
//! ```ignore
//! let client = MessageBoxClient::new(relay_url, our_priv)?;
//! let mut sub = client.subscribe(BOX_SIGN).await?;
//! client.send(&recipient_pub_hex, BOX_SIGN, &envelope).await?;
//! while let Some(item) = sub.next().await {
//!     let decoded = item?;
//!     // ... process decoded.envelope ...
//!     client.acknowledge(&[decoded.message_id]).await?;
//! }
//! sub.shutdown().await; // sends leaveRoom for each joined room, then closes
//! ```

use std::sync::Arc;

use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv_mpc_core::envelope::{
    unwrap_envelope_to_round_message, wrap_round_message, MessageEnvelope, WrapParams,
};
use bsv_mpc_core::types::RoundMessage;
use rand::RngCore;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::warn;

use crate::auth::MessageBoxAuth;
use crate::error::{MessageBoxError, Result};
use crate::http;
use crate::subscribe::{self, InboundEnvelopeEvent, InboundVia, WsSubscription};
use crate::types::{MessagePayload, SendMessageRequest};
use crate::wire;

/// One typed envelope event delivered on an [`EnvelopeSubscription`] —
/// the canonical [`MessageEnvelope`] already decoded from the relay's
/// JSON-stringified server-wrap, plus the relay-assigned `message_id`
/// (for `acknowledge`), the sender's BRC-31 identity hex (relay-
/// verified), and the path (`WsPush` vs `Backfill`) for metrics.
#[derive(Debug, Clone)]
pub struct DecodedEnvelope {
    /// Relay-assigned id used in [`MessageBoxClient::acknowledge`].
    pub message_id: String,
    /// Sender's BRC-31 identity-key hex, verified at the relay's HTTP
    /// auth layer. Trustworthy without re-verifying.
    pub sender: String,
    /// The canonical MessageEnvelope per MPC-Spec §05, already
    /// strict-decoded (re-encode-equivalence checked per §05.9.1).
    pub envelope: MessageEnvelope,
    /// Path the envelope arrived via — informational; both paths
    /// produce byte-identical envelopes.
    pub via: InboundVia,
}

/// Public client. Construct once per `(relay_url, our_identity)` pair.
/// Cheap to clone (`Arc`-shared inside); subscribe / send from any task.
#[derive(Clone)]
pub struct MessageBoxClient {
    auth: Arc<MessageBoxAuth>,
    /// Stable BRC-31 identity priv held for outbound envelope signing
    /// (`brc31_sign_envelope`) + inbound envelope decryption
    /// (`brc78_decrypt`). Same key as the one inside the wallet — kept
    /// in clone-able form so we don't need to dig it out of the
    /// `ProtoWallet` on each call.
    identity_priv: PrivateKey,
}

impl MessageBoxClient {
    /// Build a client bound to `relay_url` with `our_priv` as the
    /// stable BRC-31 identity. Starts the underlying `bsv-rs::Peer`
    /// transport callback (required before any HTTP round-trip).
    pub fn new(relay_url: impl Into<String>, our_priv: PrivateKey) -> Result<Self> {
        let auth = MessageBoxAuth::new(relay_url, our_priv.clone())?;
        auth.start();
        Ok(Self {
            auth: Arc::new(auth),
            identity_priv: our_priv,
        })
    }

    /// Our identity-key hex — the address recipients route to.
    pub async fn identity_hex(&self) -> Result<String> {
        self.auth.identity_hex().await
    }

    /// Relay base URL.
    pub fn relay_url(&self) -> &str {
        self.auth.relay_url()
    }

    /// Send `envelope` to `recipient_pub_hex` on `message_box`. Returns
    /// the message_id the relay echoes back (use with [`acknowledge`]).
    ///
    /// Auto-generates a 32-char hex `message_id` from 16 random bytes
    /// per call. The relay requires a non-empty `messageId` for dedup
    /// (`ERR_MESSAGEID_REQUIRED` per `bsv-messagebox-cloudflare-public/
    /// src/validation.rs`); the canonical envelope's
    /// `session_id`/`execution_id_prefix` cover ceremony correlation
    /// orthogonally. Use [`send_with_id`] when you need a caller-
    /// controlled id (idempotent retries, replay protection).
    pub async fn send(
        &self,
        recipient_pub_hex: &str,
        message_box: &str,
        envelope: &MessageEnvelope,
    ) -> Result<String> {
        self.send_with_id(
            recipient_pub_hex,
            message_box,
            &generate_message_id(),
            envelope,
        )
        .await
    }

    /// Like [`send`] but uses the caller-supplied `message_id`. The
    /// relay dedups on `(recipient, message_box, message_id)`; re-sends
    /// of the same tuple are no-ops.
    pub async fn send_with_id(
        &self,
        recipient_pub_hex: &str,
        message_box: &str,
        message_id: &str,
        envelope: &MessageEnvelope,
    ) -> Result<String> {
        let body = wire::wrap_envelope_to_body(envelope);
        let req = SendMessageRequest {
            message: MessagePayload {
                recipient: Some(recipient_pub_hex.to_string()),
                recipients: None,
                message_box: message_box.to_string(),
                message_id: Some(message_id.to_string()),
                body,
            },
            payment: None,
        };
        let resp = http::send_message(&self.auth, &req).await?;
        let first = resp.messages.into_iter().next().ok_or_else(|| {
            MessageBoxError::Protocol(
                "send_message returned success with no per-recipient result".into(),
            )
        })?;
        Ok(first.message_id)
    }

    /// Subscribe to one mailbox on the relay. Returns an
    /// [`EnvelopeSubscription`] whose `next()` yields
    /// [`DecodedEnvelope`]s as they arrive (backfill first, then live
    /// WS push). On `shutdown().await`, a `leaveRoom` is sent for each
    /// subscribed room before the socket closes.
    ///
    /// `subscribe` performs the first connect + join inline (per §06.4
    /// / #13 plan), so a successful `Ok` guarantees you're live on the
    /// box. Reconnects after a drop are handled in the background per
    /// §06.12 (1s → cap 30s exp backoff).
    pub async fn subscribe(&self, message_box: &str) -> Result<EnvelopeSubscription> {
        self.subscribe_many(vec![message_box.to_string()]).await
    }

    /// Subscribe to multiple mailboxes at once on a single WS — cheaper
    /// than one WS per box for callers that consume several at a time.
    pub async fn subscribe_many(&self, boxes: Vec<String>) -> Result<EnvelopeSubscription> {
        let ws_sub = subscribe::subscribe(self.auth.clone(), boxes).await?;
        Ok(EnvelopeSubscription::new(ws_sub))
    }

    /// Acknowledge one or more relay `message_id`s as consumed. Per
    /// §06.13 acknowledgement is best-effort; protocol correctness
    /// does NOT depend on the relay's ack handling. We expose it
    /// because it lets the relay free storage.
    pub async fn acknowledge(&self, message_ids: &[String]) -> Result<()> {
        if message_ids.is_empty() {
            return Ok(());
        }
        let _ = http::acknowledge_messages(&self.auth, message_ids).await?;
        Ok(())
    }

    /// Direct access to the underlying [`MessageBoxAuth`] — escape
    /// hatch for callers that need the bsv-rs `Peer` for non-MessageBox
    /// HTTP routes against the same relay.
    pub fn auth(&self) -> &Arc<MessageBoxAuth> {
        &self.auth
    }

    // ---------------------------------------------------------------------
    // Typed RoundMessage send/subscribe (Phase B of the bsv-mpc-service
    // MessageBox transport — composes wrap_round_message +
    // unwrap_envelope_to_round_message with the existing envelope-level
    // send/subscribe). The dispatcher in `bsv-mpc-service` consumes these.
    // ---------------------------------------------------------------------

    /// Wrap `round_msg` as a canonical `MessageEnvelope` and send it to
    /// `recipient_pub_hex` on `message_box`. Auto-generates a fresh
    /// message_id. Returns the relay-echoed message_id (for
    /// [`acknowledge`]).
    ///
    /// `params` provides the envelope metadata the `RoundMessage`
    /// itself doesn't carry: `to_party`, `joint_pubkey`, `phase`,
    /// `execution_id_prefix`, and optional `correlation_id` /
    /// `traceparent` — see [`bsv_mpc_core::envelope::WrapParams`].
    ///
    /// For broadcast `RoundMessage`s (per §05.4.7), the caller is
    /// responsible for the N-unicast expansion: call `send_round_message`
    /// once per recipient with the right `to_party` in `params`.
    pub async fn send_round_message(
        &self,
        recipient_pub_hex: &str,
        message_box: &str,
        round_msg: &RoundMessage,
        params: WrapParams,
    ) -> Result<String> {
        let recipient_pub = PublicKey::from_hex(recipient_pub_hex)
            .map_err(|e| MessageBoxError::Protocol(format!("recipient pub hex: {e:?}")))?;
        let envelope = wrap_round_message(round_msg, params, &recipient_pub, &self.identity_priv)
            .map_err(MessageBoxError::Envelope)?;
        self.send(recipient_pub_hex, message_box, &envelope).await
    }

    /// Subscribe to one mailbox and yield typed [`DecodedRoundMessage`]s —
    /// each envelope's BRC-78 inner has been decrypted with our identity
    /// priv, the BRC-31 sender signature verified against the
    /// relay-asserted sender pub (defense in depth), and the round-number
    /// translated back to coordinator-form 0-indexed.
    ///
    /// On shutdown, sends `leaveRoom` like
    /// [`MessageBoxClient::subscribe`].
    pub async fn subscribe_round_messages(
        &self,
        message_box: &str,
    ) -> Result<RoundMessageSubscription> {
        let env_sub = self.subscribe(message_box).await?;
        Ok(RoundMessageSubscription::new(
            env_sub,
            self.identity_priv.clone(),
            message_box.to_string(),
        ))
    }

    /// Like [`subscribe_round_messages`] but over MULTIPLE mailboxes on a
    /// SINGLE connection. Required when one party must receive traffic from two
    /// boxes for the same ceremony (e.g. the presign coordinator listening on
    /// both `mpc_{sid}` and `presig_return_{sid}` per §06.17.2): two separate
    /// subscriptions would compete for the identity's relay queue and split
    /// messages non-deterministically. One connection over both boxes avoids
    /// that race. Dispatchers MUST route by an in-`RoundMessage` discriminator
    /// (not `message_box`, which only reflects the subscribed set).
    pub async fn subscribe_round_messages_many(
        &self,
        message_boxes: Vec<String>,
    ) -> Result<RoundMessageSubscription> {
        let label = message_boxes.join("+");
        let env_sub = self.subscribe_many(message_boxes).await?;
        Ok(RoundMessageSubscription::new(
            env_sub,
            self.identity_priv.clone(),
            label,
        ))
    }
}

/// One typed inbound `RoundMessage` event surfaced by
/// [`MessageBoxClient::subscribe_round_messages`]. Carries the
/// relay-assigned `message_id` (for `acknowledge`), the verified sender
/// pub (BRC-31 already checked), the path (`WsPush`/`Backfill`), and
/// the message_box the envelope arrived on (for dispatchers that
/// listen on multiple boxes).
#[derive(Debug, Clone)]
pub struct DecodedRoundMessage {
    pub message_id: String,
    pub message_box: String,
    pub sender_pub: PublicKey,
    pub round_msg: RoundMessage,
    pub via: InboundVia,
}

/// Typed subscription handle. Holds the underlying envelope
/// subscription + an adapter task that decodes each `DecodedEnvelope`
/// into a `DecodedRoundMessage`.
pub struct RoundMessageSubscription {
    inbound: mpsc::Receiver<Result<DecodedRoundMessage>>,
    env_sub: Option<EnvelopeSubscription>,
    adapter: Option<JoinHandle<()>>,
    adapter_shutdown: Option<oneshot::Sender<()>>,
}

impl RoundMessageSubscription {
    fn new(mut env_sub: EnvelopeSubscription, our_priv: PrivateKey, message_box: String) -> Self {
        let (tx, rx) = mpsc::channel::<Result<DecodedRoundMessage>>(64);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        // Move the inner mpsc out so the adapter task owns it. Replace
        // with a closed-by-default placeholder so the wrapper Drop is
        // still safe.
        let (placeholder_tx, placeholder_rx) = mpsc::channel::<Result<DecodedEnvelope>>(1);
        drop(placeholder_tx);
        let mut real_inbound = std::mem::replace(&mut env_sub.inbound, placeholder_rx);

        let adapter = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => return,
                    item = real_inbound.recv() => {
                        let Some(item) = item else { return; };
                        let forwarded = match item {
                            Ok(decoded) => decode_round_message(decoded, &our_priv, &message_box),
                            Err(e) => Err(e),
                        };
                        if tx.send(forwarded).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });

        Self {
            inbound: rx,
            env_sub: Some(env_sub),
            adapter: Some(adapter),
            adapter_shutdown: Some(shutdown_tx),
        }
    }

    /// Pull the next typed inbound RoundMessage (or error). Returns
    /// `None` on graceful shutdown / consumer drop.
    pub async fn next(&mut self) -> Option<Result<DecodedRoundMessage>> {
        self.inbound.recv().await
    }

    /// Gracefully shut down — propagates through to the underlying
    /// `EnvelopeSubscription::shutdown` (which sends `leaveRoom` per
    /// room before closing).
    pub async fn shutdown(mut self) {
        if let Some(env_sub) = self.env_sub.take() {
            env_sub.shutdown().await;
        }
        if let Some(tx) = self.adapter_shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.adapter.take() {
            let _ = h.await;
        }
    }
}

impl Drop for RoundMessageSubscription {
    fn drop(&mut self) {
        if let Some(tx) = self.adapter_shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.adapter.take() {
            h.abort();
        }
    }
}

/// Convert one decoded envelope into a typed RoundMessage event.
/// Parses the relay-asserted `sender` hex as a `PublicKey`, runs BRC-31
/// verify + BRC-78 decrypt via `unwrap_envelope_to_round_message`,
/// surfaces the result.
fn decode_round_message(
    decoded: DecodedEnvelope,
    our_priv: &PrivateKey,
    message_box: &str,
) -> Result<DecodedRoundMessage> {
    let sender_pub = PublicKey::from_hex(&decoded.sender).map_err(|e| {
        MessageBoxError::Protocol(format!(
            "relay-asserted sender hex isn't a valid pubkey ({}): {e:?}",
            decoded.sender
        ))
    })?;
    let round_msg =
        unwrap_envelope_to_round_message(&decoded.envelope, our_priv, Some(&sender_pub))
            .map_err(MessageBoxError::Envelope)?;
    Ok(DecodedRoundMessage {
        message_id: decoded.message_id,
        message_box: message_box.to_string(),
        sender_pub,
        round_msg,
        via: decoded.via,
    })
}

// ---------------------------------------------------------------------------
// EnvelopeSubscription — adapter over ws::WsSubscription that decodes
// each inbound body into a typed MessageEnvelope before yielding it.
// ---------------------------------------------------------------------------

/// Typed subscription handle returned by [`MessageBoxClient::subscribe`].
/// Holds an mpsc of [`DecodedEnvelope`]s + the underlying
/// [`ws::WsSubscription`] (which owns the WS task).
pub struct EnvelopeSubscription {
    inbound: mpsc::Receiver<Result<DecodedEnvelope>>,
    /// Underlying WS subscription. Held so shutdown signals propagate
    /// to it; `Drop` on the wrapper triggers `Drop` on the inner WS
    /// subscription which aborts the pump.
    ws_sub: Option<WsSubscription>,
    /// Handle to the adapter task that converts InboundEnvelopeEvent →
    /// DecodedEnvelope.
    adapter: Option<JoinHandle<()>>,
    /// Signal the adapter task to stop forwarding (we drop the ws_sub
    /// first to close the upstream channel; the adapter exits cleanly
    /// once its source is gone).
    adapter_shutdown: Option<oneshot::Sender<()>>,
}

impl EnvelopeSubscription {
    fn new(mut ws_sub: WsSubscription) -> Self {
        // Channel sized to match WsSubscription's buffer so we don't
        // become the bottleneck on the relay → consumer path.
        let (tx, rx) = mpsc::channel::<Result<DecodedEnvelope>>(64);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        // Take the ws_sub.inbound receiver into the adapter task. We
        // can't `&mut` borrow across the spawn boundary, so swap a
        // closed-by-default placeholder back in. The adapter owns
        // the real receiver.
        let (placeholder_tx, placeholder_rx) = mpsc::channel::<Result<InboundEnvelopeEvent>>(1);
        drop(placeholder_tx); // close immediately so any future recv() returns None
        let mut real_inbound = std::mem::replace(&mut ws_sub.inbound, placeholder_rx);

        let adapter = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => return,
                    item = real_inbound.recv() => {
                        let Some(item) = item else { return; };
                        let forwarded = match item {
                            Ok(event) => match decode_event(event) {
                                Ok(decoded) => Ok(decoded),
                                Err(e) => Err(e),
                            },
                            Err(e) => Err(e),
                        };
                        if tx.send(forwarded).await.is_err() {
                            return; // consumer dropped
                        }
                    }
                }
            }
        });

        Self {
            inbound: rx,
            ws_sub: Some(ws_sub),
            adapter: Some(adapter),
            adapter_shutdown: Some(shutdown_tx),
        }
    }

    /// Pull the next decoded envelope (or error). Returns `None` after
    /// the subscription is gracefully shut down or the consumer drops
    /// the handle.
    pub async fn next(&mut self) -> Option<Result<DecodedEnvelope>> {
        self.inbound.recv().await
    }

    /// Gracefully shut down — sends `leaveRoom` for each joined room
    /// (best-effort, ≤500ms ack timeout per room), closes the WS,
    /// stops the adapter. Always completes; failures in the leave path
    /// are logged but don't propagate.
    pub async fn shutdown(mut self) {
        if let Some(ws_sub) = self.ws_sub.take() {
            ws_sub.shutdown().await;
        }
        if let Some(tx) = self.adapter_shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.adapter.take() {
            let _ = h.await;
        }
    }
}

impl Drop for EnvelopeSubscription {
    fn drop(&mut self) {
        // Best-effort cancellation. Graceful shutdown should go via
        // `shutdown().await` because Drop can't await the leaveRoom
        // round-trips.
        if let Some(tx) = self.adapter_shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.adapter.take() {
            h.abort();
        }
        // ws_sub's Drop also aborts the WS pump.
    }
}

/// 32-character hex id (16 random bytes). Collision-resistant for the
/// per-(recipient, box) dedup window the relay maintains.
fn generate_message_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn decode_event(event: InboundEnvelopeEvent) -> Result<DecodedEnvelope> {
    let envelope = wire::unwrap_inbound_body(&event.body).map_err(|e| {
        warn!(
            "drop event with un-decodable body (sender={}, via={:?}): {e}",
            event.sender, event.via
        );
        e
    })?;
    Ok(DecodedEnvelope {
        message_id: event.message_id,
        sender: event.sender,
        envelope,
        via: event.via,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn fresh_priv() -> PrivateKey {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b[0] |= 0x01;
        PrivateKey::from_bytes(&b).expect("fresh priv must be valid")
    }

    #[test]
    fn construct_does_not_panic_and_carries_relay_url() {
        let client = MessageBoxClient::new("https://relay.example/", fresh_priv()).unwrap();
        assert_eq!(client.relay_url(), "https://relay.example/");
    }

    #[tokio::test]
    async fn identity_hex_matches_underlying_wallet() {
        let priv_ = fresh_priv();
        let expected_pub = priv_.public_key().to_hex();
        let client = MessageBoxClient::new("https://relay.example/", priv_).unwrap();
        let got = client.identity_hex().await.unwrap();
        assert_eq!(got, expected_pub);
    }

    #[test]
    fn client_is_clone_and_arc_shared() {
        // Demonstrates that MessageBoxClient is cheap to clone — the
        // underlying auth + Peer are Arc-shared, so this is a copy of
        // the Arc not a re-handshake.
        let c1 = MessageBoxClient::new("https://relay.example/", fresh_priv()).unwrap();
        let c2 = c1.clone();
        assert_eq!(c1.relay_url(), c2.relay_url());
        assert!(Arc::ptr_eq(c1.auth(), c2.auth()));
    }

    #[test]
    fn decode_event_round_trips_canonical_envelope_byte_exact() {
        // Vector check on the adapter that turns a wire-level
        // InboundEnvelopeEvent into a typed DecodedEnvelope. Build a
        // canonical envelope, wrap to the relay's body shape, feed it
        // through decode_event, assert byte-exact round trip + metadata
        // forwarding.
        use bsv_mpc_core::envelope::{MessageEnvelope, ENVELOPE_VERSION_V1};
        use bsv_mpc_core::types::SessionId;
        use serde_json::json;

        let envelope = MessageEnvelope {
            version: ENVELOPE_VERSION_V1,
            session_id: SessionId([0x42; 32]),
            joint_pubkey: {
                let mut p = [0u8; 33];
                p[0] = 0x02;
                p[32] = 0xee;
                p
            },
            phase: "sign".into(),
            round: 2,
            from_party: 1,
            to_party: 0,
            inner: b"unit-vector-decode-event".to_vec(),
            sender_sig_brc31: vec![0x30, 0x44, 0x02, 0x20],
            execution_id_prefix: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11],
            correlation_id: Some("unit-decode".into()),
            traceparent: None,
        };
        let envelope_bytes = envelope.encode_canonical();

        // Replicate the relay's /listMessages body wrap (the same
        // shape ws.rs normalizes WS-pushed bodies into, so this
        // exercises the consumer-facing decode path uniformly).
        let body = json!({ "message": hex::encode(&envelope_bytes) }).to_string();
        let event = InboundEnvelopeEvent {
            message_box: "mpc-sign".into(),
            sender: "02deadbeef".into(),
            message_id: "vector-fixture-1".into(),
            body,
            via: InboundVia::WsPush,
        };

        let decoded = decode_event(event).expect("decode_event MUST succeed on canonical");
        assert_eq!(decoded.message_id, "vector-fixture-1");
        assert_eq!(decoded.sender, "02deadbeef");
        assert_eq!(decoded.via, InboundVia::WsPush);
        assert_eq!(decoded.envelope, envelope);
        assert_eq!(decoded.envelope.encode_canonical(), envelope_bytes);
    }

    #[test]
    fn generate_message_id_is_32_char_lowercase_hex_and_unique() {
        let a = generate_message_id();
        let b = generate_message_id();
        assert_eq!(a.len(), 32, "must be 32 hex chars (16 bytes)");
        assert!(
            a.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "must be lowercase hex"
        );
        assert_ne!(a, b, "must be unique per call");
    }

    #[test]
    fn decode_round_message_round_trips_full_envelope_path() {
        // Vector test for the typed RoundMessage adapter: build a
        // canonical envelope from a known RoundMessage via
        // wrap_round_message_deterministic, then run it through the
        // adapter `decode_round_message` (which composes BRC-31 verify +
        // BRC-78 decrypt + round-translation). Byte-exact recovery is
        // the gate.
        use bsv_mpc_core::envelope::wrap_round_message_deterministic;
        use bsv_mpc_core::types::{SessionId, ShareIndex};

        let sender_priv = PrivateKey::from_bytes(&[0x11; 32]).unwrap();
        let sender_pub = sender_priv.public_key();
        let recipient_priv = PrivateKey::from_bytes(&[0x22; 32]).unwrap();
        let recipient_pub = recipient_priv.public_key();
        let eph_priv = PrivateKey::from_bytes(&[0x33; 32]).unwrap();
        let iv = [0x44u8; 12];

        let rm = RoundMessage {
            session_id: SessionId([0x55; 32]),
            round: 1,
            from: ShareIndex(0),
            to: Some(ShareIndex(1)),
            payload: b"round-msg-adapter-vector".to_vec(),
        };
        let params = WrapParams {
            to_party: 1,
            joint_pubkey: {
                let mut p = [0u8; 33];
                p[0] = 0x02;
                p
            },
            phase: "dkg".into(),
            execution_id_prefix: [0u8; 8],
            correlation_id: None,
            traceparent: None,
        };
        let envelope = wrap_round_message_deterministic(
            &rm,
            params,
            &recipient_pub,
            &sender_priv,
            &eph_priv,
            &iv,
        )
        .unwrap();

        // Construct the DecodedEnvelope that subscribe() would surface
        // (sender = relay-verified hex of sender pub).
        let decoded_env = DecodedEnvelope {
            message_id: "adapter-fixture-1".into(),
            sender: sender_pub.to_hex(),
            envelope,
            via: InboundVia::WsPush,
        };

        let decoded = decode_round_message(decoded_env, &recipient_priv, "mpc-dkg").unwrap();
        assert_eq!(decoded.message_id, "adapter-fixture-1");
        assert_eq!(decoded.sender_pub.to_hex(), sender_pub.to_hex());
        assert_eq!(decoded.message_box, "mpc-dkg");
        assert_eq!(decoded.via, InboundVia::WsPush);
        assert_eq!(decoded.round_msg.session_id, rm.session_id);
        assert_eq!(decoded.round_msg.round, rm.round);
        assert_eq!(decoded.round_msg.from, rm.from);
        assert_eq!(decoded.round_msg.to, rm.to);
        assert_eq!(decoded.round_msg.payload, rm.payload);
    }

    #[test]
    fn decode_round_message_propagates_decode_error_on_wrong_recipient() {
        // The adapter MUST propagate BRC-78 decryption failures (wrong
        // recipient priv) as an Err — not silently drop the message.
        use bsv_mpc_core::envelope::wrap_round_message_deterministic;
        use bsv_mpc_core::types::{SessionId, ShareIndex};

        let sender_priv = PrivateKey::from_bytes(&[0x11; 32]).unwrap();
        let intended_recipient_priv = PrivateKey::from_bytes(&[0x22; 32]).unwrap();
        let envelope = wrap_round_message_deterministic(
            &RoundMessage {
                session_id: SessionId([0x99; 32]),
                round: 0,
                from: ShareIndex(0),
                to: Some(ShareIndex(1)),
                payload: vec![0x01, 0x02, 0x03],
            },
            WrapParams {
                to_party: 1,
                joint_pubkey: [0u8; 33],
                phase: "sign".into(),
                execution_id_prefix: [0u8; 8],
                correlation_id: None,
                traceparent: None,
            },
            &intended_recipient_priv.public_key(),
            &sender_priv,
            &PrivateKey::from_bytes(&[0x33; 32]).unwrap(),
            &[0x44u8; 12],
        )
        .unwrap();

        let decoded_env = DecodedEnvelope {
            message_id: "err-fixture".into(),
            sender: sender_priv.public_key().to_hex(),
            envelope,
            via: InboundVia::WsPush,
        };
        let attacker_priv = PrivateKey::from_bytes(&[0xee; 32]).unwrap();
        let err = decode_round_message(decoded_env, &attacker_priv, "mpc-sign").unwrap_err();
        // Wrapped via MessageBoxError::Envelope(MpcError::Encryption(...))
        assert!(matches!(err, MessageBoxError::Envelope(_)));
    }

    #[test]
    fn decode_event_propagates_envelope_decode_errors() {
        // Garbage body must surface as MessageBoxError (not panic, not
        // silently drop). The exact variant comes from wire::
        // unwrap_inbound_body — we just assert it's an Err.
        let event = InboundEnvelopeEvent {
            message_box: "mpc-sign".into(),
            sender: "02deadbeef".into(),
            message_id: "broken-fixture".into(),
            body: r#"{"message":"not-hex-at-all"}"#.into(),
            via: InboundVia::WsPush,
        };
        let err = decode_event(event).unwrap_err();
        // The wire layer rejects malformed hex as MessageBoxError::Hex.
        assert!(matches!(err, MessageBoxError::Hex(_)));
    }
}
