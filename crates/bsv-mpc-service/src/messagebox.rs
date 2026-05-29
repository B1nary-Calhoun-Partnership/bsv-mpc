//! MessageBox-driven inbox listener for the KSS — Phase C of the
//! MPC-Spec §06.14 normative "MUST add MessageBox transport client to
//! participate in cross-impl ceremonies" requirement.
//!
//! ## What this module is
//!
//! A thin orchestration layer that:
//!
//! 1. Subscribes to one MessageBox mailbox via
//!    [`MessageBoxClient::subscribe_round_messages`] (typed
//!    `RoundMessage` stream from Phase B).
//! 2. On each inbound message, feeds it to a caller-supplied async
//!    closure (the "handler") that decides what response messages, if
//!    any, to ship.
//! 3. Wraps each handler-returned outgoing message in a canonical
//!    envelope (via [`MessageBoxClient::send_round_message`]) and
//!    sends it back to the recipient.
//!
//! ## What this module is NOT
//!
//! Not the cggmp24 coordinator integration — Phase C is explicitly the
//! *dispatcher primitive* without ceremony plumbing. Phase D wires the
//! real [`bsv_mpc_core::dkg::DkgCoordinator`] /
//! [`bsv_mpc_core::signing::SigningCoordinator`] /
//! [`bsv_mpc_core::presigning::PresigningManager`] in as handlers.
//!
//! ## Handler shape
//!
//! Closure-based instead of trait-object (`async_trait` avoided): the
//! handler is `Fn(DecodedRoundMessage) -> Future<Output =
//! Result<Vec<OutgoingRoundMessage>>>`. The closure captures whatever
//! state it needs (coordinator handles, locks, channels) and returns
//! zero or more outbound messages to ship in response. Returning an
//! empty `Vec` is fine — the ceremony may be complete, or this is a
//! "broadcast received, nothing to say back" branch.
//!
//! ## Lifecycle
//!
//! - [`MessageBoxListener::start`] does the inbox subscription inline
//!   so `Ok(_)` means we're really listening.
//! - The background pump runs until [`shutdown`](MessageBoxListener::shutdown)
//!   or until the listener handle is dropped.
//! - On shutdown, the inner `RoundMessageSubscription::shutdown` runs
//!   the §06.4 graceful `leaveRoom` path before closing the WS.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bsv_mpc_core::envelope::WrapParams;
use bsv_mpc_core::types::RoundMessage;
use bsv_mpc_messagebox::{DecodedRoundMessage, MessageBoxClient};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// Bounded idempotent retry count for shipping a round message. A round message
/// dropped on a transient `/sendMessage` blip stalls the recipient until the
/// ceremony times out; the re-send is a relay no-op (stable message_id) so a
/// retry never delivers a duplicate. 4 attempts (200/400/800ms backoff) clears
/// the brief connection contention seen under heavy concurrent send load.
const SEND_ROUND_MSG_MAX_ATTEMPTS: u32 = 4;

/// One outbound RoundMessage the handler wants to ship in response to
/// an inbound message. The listener wraps it as a canonical envelope
/// (BRC-78 encrypt to `recipient_pub_hex`, BRC-31 sign with our
/// identity) and ships via [`MessageBoxClient::send_round_message`].
#[derive(Debug, Clone)]
pub struct OutgoingRoundMessage {
    /// Recipient's BRC-31 identity-key hex (compressed pub).
    pub recipient_pub_hex: String,
    /// MessageBox mailbox to land on. Typically the same box the
    /// inbound message arrived on — the listener does NOT auto-route
    /// to the inbound box because some handlers may want to fan out to
    /// other boxes (e.g., the `presig_return_{session_id}` mailbox per
    /// §06.17.2).
    pub message_box: String,
    /// The cggmp24-level message to ship.
    pub round_msg: RoundMessage,
    /// Envelope metadata (to_party, joint_pubkey, phase,
    /// execution_id_prefix, correlation_id, traceparent).
    pub params: WrapParams,
}

/// Boxed async-returning closure type that the listener feeds inbound
/// messages to. Returns the list of outbound messages to ship in
/// response. Type alias keeps signatures readable.
pub type HandlerFuture =
    Pin<Box<dyn Future<Output = anyhow::Result<Vec<OutgoingRoundMessage>>> + Send>>;

/// Listener handle. Hold to keep the background pump alive; drop or
/// `shutdown().await` to stop.
pub struct MessageBoxListener {
    handle: Option<JoinHandle<()>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl MessageBoxListener {
    /// Subscribe to `message_box`, run `handler` on each inbound
    /// `DecodedRoundMessage`, ship handler responses via `client`.
    ///
    /// The subscription handshake happens inline (per Phase B), so
    /// `Ok` guarantees the listener is live on the relay. Subsequent
    /// reconnects after a drop are handled by the underlying
    /// `RoundMessageSubscription` per §06.12.
    ///
    /// `handler` must be `Send + Sync + 'static` so it can run in the
    /// background pump task; it gets cheaply cloned (via the boxed
    /// `Arc` indirection) on each dispatch.
    pub async fn start<F>(
        client: MessageBoxClient,
        message_box: &str,
        handler: F,
    ) -> anyhow::Result<Self>
    where
        F: Fn(DecodedRoundMessage) -> HandlerFuture + Send + Sync + 'static,
    {
        let sub = client
            .subscribe_round_messages(message_box)
            .await
            .map_err(|e| anyhow::anyhow!("subscribe_round_messages({message_box}): {e}"))?;

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handler: Arc<F> = Arc::new(handler);
        let client_for_task = client.clone();
        let handle = tokio::spawn(async move {
            run_loop(client_for_task, sub, handler, shutdown_rx).await;
        });

        Ok(Self {
            handle: Some(handle),
            shutdown_tx: Some(shutdown_tx),
        })
    }

    /// Like [`start`](Self::start) but subscribes to MULTIPLE mailboxes on a
    /// single connection (one pump task). Use when one party must receive two
    /// boxes for a ceremony (e.g. the presign coordinator on `mpc_{sid}` +
    /// `presig_return_{sid}`): a single connection avoids the message-split race
    /// two competing subscriptions would create. The `handler` MUST route by an
    /// in-`RoundMessage` discriminator, not `message_box`.
    pub async fn start_many<F>(
        client: MessageBoxClient,
        message_boxes: Vec<String>,
        handler: F,
    ) -> anyhow::Result<Self>
    where
        F: Fn(DecodedRoundMessage) -> HandlerFuture + Send + Sync + 'static,
    {
        let sub = client
            .subscribe_round_messages_many(message_boxes.clone())
            .await
            .map_err(|e| {
                anyhow::anyhow!("subscribe_round_messages_many({message_boxes:?}): {e}")
            })?;

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handler: Arc<F> = Arc::new(handler);
        let client_for_task = client.clone();
        let handle = tokio::spawn(async move {
            run_loop(client_for_task, sub, handler, shutdown_rx).await;
        });

        Ok(Self {
            handle: Some(handle),
            shutdown_tx: Some(shutdown_tx),
        })
    }

    /// Gracefully shut down — signals the pump, the pump runs
    /// `RoundMessageSubscription::shutdown` (which cascades to the
    /// underlying §06.4 `leaveRoom` path), then awaits the task exit.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

impl Drop for MessageBoxListener {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

/// Best-effort `acknowledgeMessage` (the canonical drain — see the TS
/// `message-box-client`/`-server`: read → process → acknowledge → server
/// DELETEs). Without this, every relayed round message persists in the box
/// forever; a long-lived cosigner identity's box then grows until the relay
/// (a 128 MB CF Worker) OOMs `/listMessages` and breaks reshare-over-relay.
/// Failure is non-fatal: the message is already consumed (the dedup set below
/// blocks reprocessing) and the relay's own GC is the backstop.
async fn ack_best_effort(client: &MessageBoxClient, message_id: &str) {
    if message_id.is_empty() {
        return;
    }
    if let Err(e) = client.acknowledge(&[message_id.to_string()]).await {
        debug!("acknowledge(message_id={message_id}) failed (best-effort): {e}");
    }
}

async fn run_loop<F>(
    client: MessageBoxClient,
    mut sub: bsv_mpc_messagebox::RoundMessageSubscription,
    handler: Arc<F>,
    mut shutdown: oneshot::Receiver<()>,
) where
    F: Fn(DecodedRoundMessage) -> HandlerFuture + Send + Sync + 'static,
{
    // §06.17 reliability: the relay's `/listMessages` is non-destructive and we
    // deliberately re-drain backfill (initial subscribe + every reconnect, and the
    // post-join window drain in `subscribe`), so the SAME message can arrive more
    // than once (backfill ∩ live-push ∩ re-drain). Feeding a duplicate round
    // message to a cggmp24 SM would error and abort the ceremony, so we dedup by
    // the relay's unique `message_id` here — at-least-once transport + dedup =
    // exactly-once delivery to the handler. Scope is this listener (one ceremony
    // phase), so the set stays small and is dropped when the phase ends.
    let mut seen_message_ids: HashSet<String> = HashSet::new();
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                sub.shutdown().await;
                return;
            }
            item = sub.next() => {
                let Some(item) = item else {
                    debug!("RoundMessageSubscription closed — listener exiting");
                    return;
                };
                let inbound = match item {
                    Ok(m) => m,
                    Err(e) => {
                        warn!("inbound subscription error (continuing): {e}");
                        continue;
                    }
                };
                // Drop duplicates (re-drained / re-pushed) before they reach the SM.
                if !inbound.message_id.is_empty()
                    && !seen_message_ids.insert(inbound.message_id.clone())
                {
                    debug!(
                        "skipping duplicate inbound message_id={} (session={} round={})",
                        inbound.message_id,
                        hex::encode(inbound.round_msg.session_id.as_bytes()),
                        inbound.round_msg.round,
                    );
                    // Already consumed on first delivery — drain the duplicate too.
                    ack_best_effort(&client, &inbound.message_id).await;
                    continue;
                }
                let inbound_summary = format!(
                    "session={} round={} from_party={} via={:?} message_box={}",
                    hex::encode(inbound.round_msg.session_id.as_bytes()),
                    inbound.round_msg.round,
                    inbound.round_msg.from.0,
                    inbound.via,
                    inbound.message_box,
                );
                debug!("dispatching inbound: {inbound_summary}");
                let message_id = inbound.message_id.clone();
                let result = (handler)(inbound).await;
                // Drain regardless of Ok/Err: the SM has seen it and the dedup
                // set blocks reprocessing, so retaining it on the relay only
                // bloats the box (the canonical read→process→acknowledge cycle).
                ack_best_effort(&client, &message_id).await;
                let outgoing = match result {
                    Ok(o) => o,
                    Err(e) => {
                        warn!("handler returned error ({inbound_summary}): {e:#}");
                        continue;
                    }
                };
                if outgoing.is_empty() {
                    debug!("handler returned no outbound messages ({inbound_summary})");
                    continue;
                }
                for out in outgoing {
                    let send_summary = format!(
                        "to={}... box={} round={} to_party={}",
                        &out.recipient_pub_hex[..out.recipient_pub_hex.len().min(8)],
                        out.message_box,
                        out.round_msg.round,
                        out.params.to_party,
                    );
                    // Bounded IDEMPOTENT retry: a transient `/sendMessage` blip
                    // must not silently drop a round message (→ recipient stalls
                    // until ceremony timeout). The stable-message_id re-send is a
                    // relay no-op if the first attempt actually landed, so a retry
                    // never duplicates a round message (which would abort the SM).
                    if let Err(e) = client
                        .send_round_message_reliable(
                            &out.recipient_pub_hex,
                            &out.message_box,
                            &out.round_msg,
                            out.params,
                            SEND_ROUND_MSG_MAX_ATTEMPTS,
                        )
                        .await
                    {
                        warn!(
                            "send_round_message failed after {SEND_ROUND_MSG_MAX_ATTEMPTS} attempts ({send_summary}): {e}"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::primitives::ec::PrivateKey;
    use bsv_mpc_core::types::{SessionId, ShareIndex};
    use bsv_mpc_messagebox::InboundVia;
    use rand::RngCore;

    fn fresh_priv() -> PrivateKey {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b[0] |= 0x01;
        PrivateKey::from_bytes(&b).unwrap()
    }

    #[test]
    fn outgoing_round_message_constructs() {
        let sender = fresh_priv();
        let out = OutgoingRoundMessage {
            recipient_pub_hex: sender.public_key().to_hex(),
            message_box: "mpc-dkg".into(),
            round_msg: RoundMessage {
                session_id: SessionId([0xaa; 32]),
                round: 0,
                from: ShareIndex(0),
                to: Some(ShareIndex(1)),
                payload: vec![1, 2, 3],
            },
            params: WrapParams {
                to_party: 1,
                joint_pubkey: [0u8; 33],
                phase: "dkg".into(),
                execution_id_prefix: [0u8; 8],
                correlation_id: None,
                traceparent: None,
            },
        };
        assert_eq!(out.message_box, "mpc-dkg");
        assert_eq!(out.round_msg.from.0, 0);
        assert_eq!(out.params.phase, "dkg");
    }

    /// Sanity test that the handler closure signature + dispatch path
    /// compiles + that `MessageBoxListener::start` is the right shape
    /// without requiring a live relay.
    #[test]
    fn handler_closure_type_compiles() {
        let _: Box<dyn Fn(DecodedRoundMessage) -> HandlerFuture + Send + Sync + 'static> =
            Box::new(|_inbound: DecodedRoundMessage| -> HandlerFuture {
                Box::pin(async move { Ok(Vec::<OutgoingRoundMessage>::new()) })
            });
    }

    #[test]
    fn handler_can_capture_state_and_emit_response() {
        // Demonstrates the typical pattern: a closure captures an Arc
        // around shared state (here a counter), inspects the inbound,
        // and returns an outbound. Exercised end-to-end against the
        // live relay in tests/messagebox_listener_e2e.rs.
        use std::sync::atomic::{AtomicU32, Ordering};

        let counter = Arc::new(AtomicU32::new(0));
        let recipient_hex = fresh_priv().public_key().to_hex();

        let counter_for_handler = counter.clone();
        let recipient_for_handler = recipient_hex.clone();
        let handler = move |inbound: DecodedRoundMessage| -> HandlerFuture {
            let counter = counter_for_handler.clone();
            let recipient = recipient_for_handler.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(vec![OutgoingRoundMessage {
                    recipient_pub_hex: recipient,
                    message_box: inbound.message_box.clone(),
                    round_msg: inbound.round_msg.clone(),
                    params: WrapParams {
                        to_party: inbound.round_msg.from.0,
                        joint_pubkey: [0u8; 33],
                        phase: "dkg".into(),
                        execution_id_prefix: [0u8; 8],
                        correlation_id: None,
                        traceparent: None,
                    },
                }])
            })
        };

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let sender_pub = PrivateKey::from_bytes(&[0x11; 32]).unwrap().public_key();
        let synthetic = DecodedRoundMessage {
            message_id: "fixture".into(),
            message_box: "mpc-dkg".into(),
            sender_pub,
            round_msg: RoundMessage {
                session_id: SessionId([0xbb; 32]),
                round: 0,
                from: ShareIndex(1),
                to: Some(ShareIndex(0)),
                payload: b"hello".to_vec(),
            },
            via: InboundVia::WsPush,
        };
        let outgoing = runtime
            .block_on(async move { handler(synthetic).await })
            .unwrap();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].round_msg.payload, b"hello");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
