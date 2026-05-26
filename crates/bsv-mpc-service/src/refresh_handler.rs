//! Refresh handler — MessageBox-driven wiring for the §18.2 distributed
//! key-refresh ceremony, mirroring [`DkgHandler`](crate::dkg_handler::DkgHandler)
//! / [`PresignHandler`](crate::presign_handler::PresignHandler).
//!
//! Each party runs one [`RefreshHandler`]; both sides drive the same
//! [`RefreshCoordinator`](bsv_mpc_core::RefreshCoordinator) (refresh is symmetric
//! — there is no coordinator/cosigner split as in presign). On completion each
//! side independently obtains its OWN **rotated** key share for the **unchanged**
//! joint public key.
//!
//! ## Lifecycle
//!
//! 1. Each party calls [`initiate`](RefreshHandler::initiate) with its current
//!    share + the peer routing table; it runs `coord.init()` and returns the
//!    round-1 outbound messages + a completion receiver.
//! 2. Round-1 contributions (p2p) ship to peers. As inbound envelopes arrive on
//!    the listener, the handler feeds them to the coordinator and ships any
//!    next-round output (the round-2 public-share broadcast).
//! 3. On [`RefreshRoundResult::Complete`], the handler fires the completion
//!    sender with the [`RefreshCommit`] and drops the coordinator.
//!
//! ## Rotation-on-commit is the CALLER's job
//!
//! Unlike `DkgHandler` (which persists internally), this handler only *yields*
//! the [`RefreshCommit`]. The container endpoint and the proxy coordinator
//! persist to different stores, and each must rotate the stored share atomically
//! with the commit AND fire the §06.18 presig invalidation. Keeping persistence
//! at the call site makes that atomicity explicit (see the service
//! `/refresh-relay/*` routes and the proxy refresh coordinator).
//!
//! The refresh math is cheap (no Paillier / no ZK), so rounds are driven inline
//! on the async runtime — no `spawn_blocking` is needed (the DKG handler needs it
//! only for aux-info safe-prime generation, which refresh does not perform).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bsv_mpc_core::canonical::{canonical_execution_id, ExecutionParams, PhaseTag};
use bsv_mpc_core::envelope::WrapParams;
use bsv_mpc_core::types::{EncryptedShare, RoundMessage, SessionId, ShareIndex};
use bsv_mpc_core::{RefreshCommit, RefreshCoordinator, RefreshRoundResult};
use bsv_mpc_messagebox::types::BOX_REFRESH;
use bsv_mpc_messagebox::DecodedRoundMessage;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::messagebox::{HandlerFuture, OutgoingRoundMessage};

/// One live refresh ceremony — the coordinator + peer routing + the joint pubkey
/// (known throughout: refresh preserves it).
struct CoordinatorSlot {
    coord: RefreshCoordinator,
    /// All OTHER parties: `(party_index, identity_pub_hex)`.
    peers: Vec<(u16, String)>,
    /// The 33-byte joint pubkey (unchanged) — used for the canonical §02
    /// ExecutionId prefix + the §05 envelope binding.
    joint_pubkey: [u8; 33],
}

struct RefreshHandlerInner {
    /// Cosigner subset in canonical ascending order (the full party set for v1).
    /// This party's own index is read from the share by the coordinator
    /// (`KeyShare.core.i`), so it is not stored separately here.
    parties_at_keygen: Vec<u16>,
    coordinators: Mutex<HashMap<SessionId, CoordinatorSlot>>,
    completion_tx: Mutex<HashMap<SessionId, oneshot::Sender<RefreshCommit>>>,
}

/// Clone-able handle (`Arc`-shared inside).
#[derive(Clone)]
pub struct RefreshHandler {
    inner: Arc<RefreshHandlerInner>,
}

impl RefreshHandler {
    /// Build a refresh handler for a party at `my_party_index` participating in a
    /// `parties_at_keygen` reshare (the full party set, canonical ascending).
    pub fn new(my_party_index: u16, parties_at_keygen: Vec<u16>) -> Self {
        assert!(
            parties_at_keygen.contains(&my_party_index),
            "my_party_index {my_party_index} not in parties_at_keygen {parties_at_keygen:?}"
        );
        let _ = my_party_index; // validated above; coordinator reads it from the share
        Self {
            inner: Arc::new(RefreshHandlerInner {
                parties_at_keygen,
                coordinators: Mutex::new(HashMap::new()),
                completion_tx: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Pre-create the coordinator for `session_id`, run `init()`, and return the
    /// round-1 outbound messages + a receiver that fires with this party's
    /// [`RefreshCommit`] when its ceremony completes.
    ///
    /// `share.ciphertext` MUST be the serialized cggmp24 `KeyShare` JSON and
    /// `share.joint_pubkey_compressed` MUST be the 33-byte joint pubkey.
    pub async fn initiate(
        &self,
        session_id: SessionId,
        share: EncryptedShare,
        peers: Vec<(u16, String)>,
    ) -> anyhow::Result<(oneshot::Receiver<RefreshCommit>, Vec<OutgoingRoundMessage>)> {
        let joint_pubkey: [u8; 33] = share
            .joint_pubkey_compressed
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("refresh: share must carry a 33-byte joint pubkey"))?;

        let mut coord =
            RefreshCoordinator::new(session_id, share, self.inner.parties_at_keygen.clone())
                .map_err(|e| anyhow::anyhow!("RefreshCoordinator::new failed: {e}"))?;
        let initial = coord
            .init()
            .map_err(|e| anyhow::anyhow!("RefreshCoordinator::init failed: {e}"))?;

        let (completion_tx, completion_rx) = oneshot::channel::<RefreshCommit>();
        let outgoing = wrap_outgoing(&initial, session_id, &peers, &joint_pubkey);
        {
            let mut coords = self
                .inner
                .coordinators
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            coords.insert(
                session_id,
                CoordinatorSlot {
                    coord,
                    peers,
                    joint_pubkey,
                },
            );
        }
        {
            let mut tx = self
                .inner
                .completion_tx
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            tx.insert(session_id, completion_tx);
        }
        Ok((completion_rx, outgoing))
    }

    /// Returns the closure to hand to
    /// [`MessageBoxListener::start`](crate::messagebox::MessageBoxListener::start).
    pub fn handler_fn(
        &self,
    ) -> impl Fn(DecodedRoundMessage) -> HandlerFuture + Send + Sync + 'static {
        let inner = self.inner.clone();
        move |inbound: DecodedRoundMessage| -> HandlerFuture {
            let inner = inner.clone();
            Box::pin(async move { dispatch_one(inner, inbound).await })
        }
    }

    /// Test/inspect — number of live ceremonies the handler is tracking.
    pub fn live_session_count(&self) -> usize {
        self.inner
            .coordinators
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }
}

async fn dispatch_one(
    inner: Arc<RefreshHandlerInner>,
    inbound: DecodedRoundMessage,
) -> anyhow::Result<Vec<OutgoingRoundMessage>> {
    let session_id = inbound.round_msg.session_id;

    // Take the slot out so the lock isn't held across the (cheap, sync) round.
    let slot = {
        let mut coords = inner.coordinators.lock().unwrap_or_else(|p| p.into_inner());
        coords.remove(&session_id)
    };
    let Some(mut slot) = slot else {
        warn!(
            "RefreshHandler: inbound for unknown session_id {} (no coordinator); dropping.",
            hex::encode(session_id.as_bytes())
        );
        return Ok(vec![]);
    };

    let round_result = slot
        .coord
        .process_round(vec![inbound.round_msg])
        .map_err(|e| anyhow::anyhow!("RefreshCoordinator::process_round failed: {e}"))?;

    match round_result {
        RefreshRoundResult::NextRound(next_msgs) => {
            let outgoing = wrap_outgoing(&next_msgs, session_id, &slot.peers, &slot.joint_pubkey);
            let n = next_msgs.len();
            // Re-insert the slot to await further rounds.
            let mut coords = inner.coordinators.lock().unwrap_or_else(|p| p.into_inner());
            coords.insert(session_id, slot);
            drop(coords);
            debug!(
                "RefreshHandler: session={} produced {} outbound msgs",
                hex::encode(session_id.as_bytes()),
                n
            );
            Ok(outgoing)
        }
        RefreshRoundResult::Complete(commit) => {
            info!(
                "RefreshHandler: ceremony complete — session={} joint_pubkey={} (UNCHANGED)",
                hex::encode(session_id.as_bytes()),
                hex::encode(&commit.joint_pubkey_compressed),
            );
            let tx = {
                let mut txs = inner
                    .completion_tx
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                txs.remove(&session_id)
            };
            if let Some(tx) = tx {
                let _ = tx.send(*commit);
            }
            // slot (coord) dropped here.
            Ok(vec![])
        }
    }
}

/// Wrap `RoundMessage`s as `OutgoingRoundMessage`s on the `mpc-refresh` box with
/// the canonical §02 ExecutionId prefix (PhaseTag::Refresh + the real, unchanged
/// joint pubkey — no DKG zero carve-out, since the key is known throughout).
fn wrap_outgoing(
    round_msgs: &[RoundMessage],
    session_id: SessionId,
    peers: &[(u16, String)],
    joint_pubkey: &[u8; 33],
) -> Vec<OutgoingRoundMessage> {
    let eid = canonical_execution_id(&ExecutionParams::new_v1(
        PhaseTag::Refresh,
        session_id,
        *joint_pubkey,
    ));
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&eid[..8]);

    let mut out = Vec::new();
    for rm in round_msgs {
        // `None` = broadcast (round-2 public shares) → every peer; `Some(idx)` =
        // p2p (round-1 contribution) → the matching peer only.
        let targets: Vec<&(u16, String)> = match rm.to {
            None => peers.iter().collect(),
            Some(ShareIndex(idx)) => peers.iter().filter(|(p, _)| *p == idx).collect(),
        };
        if targets.is_empty() {
            warn!(
                "RefreshHandler: outgoing p2p to party {:?} not in peer set {:?}; dropping",
                rm.to,
                peers.iter().map(|(p, _)| *p).collect::<Vec<_>>()
            );
            continue;
        }
        for (idx, hex) in targets {
            out.push(OutgoingRoundMessage {
                recipient_pub_hex: hex.clone(),
                message_box: BOX_REFRESH.to_string(),
                round_msg: rm.clone(),
                params: WrapParams {
                    to_party: *idx,
                    joint_pubkey: *joint_pubkey,
                    phase: "refresh".into(),
                    execution_id_prefix: prefix,
                    correlation_id: None,
                    traceparent: None,
                },
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_mpc_core::types::{SessionId, ShareIndex};

    #[test]
    fn handler_constructs_with_valid_party_index() {
        let h = RefreshHandler::new(0, vec![0, 1]);
        assert_eq!(h.live_session_count(), 0);
    }

    #[test]
    #[should_panic(expected = "not in parties_at_keygen")]
    fn handler_rejects_party_not_in_set() {
        let _ = RefreshHandler::new(5, vec![0, 1]);
    }

    #[test]
    fn wrap_outgoing_uses_refresh_box_and_real_joint_pubkey() {
        let jpk = [0x02u8; 33];
        let rm_p2p = RoundMessage {
            session_id: SessionId([0xaa; 32]),
            round: 1,
            from: ShareIndex(0),
            to: Some(ShareIndex(1)),
            payload: vec![1, 2, 3],
        };
        let rm_broadcast = RoundMessage {
            session_id: SessionId([0xaa; 32]),
            round: 2,
            from: ShareIndex(0),
            to: None,
            payload: vec![4, 5, 6],
        };
        let peers = vec![(1u16, "02deadbeef".to_string())];

        let a = wrap_outgoing(
            std::slice::from_ref(&rm_p2p),
            SessionId([0xaa; 32]),
            &peers,
            &jpk,
        );
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].message_box, "mpc-refresh");
        assert_eq!(a[0].params.phase, "refresh");
        assert_eq!(
            a[0].params.joint_pubkey, jpk,
            "refresh binds the real joint key"
        );
        assert_eq!(a[0].params.to_party, 1);

        // Different session → different ExecutionId prefix (binding property §02).
        let c = wrap_outgoing(
            std::slice::from_ref(&rm_p2p),
            SessionId([0xbb; 32]),
            &peers,
            &jpk,
        );
        assert_ne!(
            a[0].params.execution_id_prefix,
            c[0].params.execution_id_prefix
        );

        // Broadcast fans to every peer.
        let b = wrap_outgoing(
            std::slice::from_ref(&rm_broadcast),
            SessionId([0xaa; 32]),
            &peers,
            &jpk,
        );
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].params.to_party, 1);
    }
}
