//! Reshar handler — MessageBox-driven wiring for the §18.2 **cross-(t,n)** PSS
//! reshare phase (issue #35c), mirroring [`RefreshHandler`](crate::refresh_handler).
//!
//! Each party runs one [`ResharHandler`] driving a
//! [`ResharCoordinator`](bsv_mpc_core::ResharCoordinator) over the canonical
//! `mpc-refresh` box. The PSS phase yields each party's **`IncompleteKeyShare`**
//! for the new `(t', n')` set, bound to the UNCHANGED joint pubkey. The caller
//! then obtains fresh aux for the new set (the aux is key-independent — it can be
//! taken from a throwaway new-set DKG) and `KeyShare::from_parts` to get a
//! signing-ready share.
//!
//! Only the PSS evaluations cross the wire; no party reveals its old secret.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bsv_mpc_core::canonical::{canonical_execution_id, ExecutionParams, PhaseTag};
use bsv_mpc_core::envelope::WrapParams;
use bsv_mpc_core::types::{RoundMessage, SessionId, ShareIndex};
use bsv_mpc_core::{ResharCommit, ResharConfig, ResharCoordinator, ResharRoundResult};
use bsv_mpc_messagebox::types::BOX_REFRESH;
use bsv_mpc_messagebox::DecodedRoundMessage;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::messagebox::{HandlerFuture, OutgoingRoundMessage};

struct CoordinatorSlot {
    coord: ResharCoordinator,
    /// All OTHER parties in the NEW set: `(new_index, identity_pub_hex)`.
    peers: Vec<(u16, String)>,
    joint_pubkey: [u8; 33],
}

struct ResharHandlerInner {
    coordinators: Mutex<HashMap<SessionId, CoordinatorSlot>>,
    completion_tx: Mutex<HashMap<SessionId, oneshot::Sender<ResharCommit>>>,
}

/// Clone-able handle.
#[derive(Clone)]
pub struct ResharHandler {
    inner: Arc<ResharHandlerInner>,
}

impl Default for ResharHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ResharHandler {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ResharHandlerInner {
                coordinators: Mutex::new(HashMap::new()),
                completion_tx: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Pre-create the coordinator from `config`, run `init()`, and return the
    /// round-1 outbound + a receiver that fires with this party's [`ResharCommit`]
    /// (its new-set `IncompleteKeyShare`) when the PSS completes.
    ///
    /// `peers` is every OTHER party in the NEW set as `(new_index, identity_hex)`.
    pub async fn initiate(
        &self,
        config: ResharConfig,
        peers: Vec<(u16, String)>,
    ) -> anyhow::Result<(oneshot::Receiver<ResharCommit>, Vec<OutgoingRoundMessage>)> {
        let session_id = config.session_id;
        let joint_pubkey: [u8; 33] = config
            .original_joint_pubkey
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("reshar: joint pubkey must be 33 bytes"))?;

        let mut coord = ResharCoordinator::new(config)
            .map_err(|e| anyhow::anyhow!("ResharCoordinator::new failed: {e}"))?;
        let initial = coord
            .init()
            .map_err(|e| anyhow::anyhow!("ResharCoordinator::init failed: {e}"))?;

        let (completion_tx, completion_rx) = oneshot::channel::<ResharCommit>();
        let outgoing = wrap_outgoing(&initial, session_id, &peers, &joint_pubkey);
        {
            let mut coords = self.inner.coordinators.lock().unwrap_or_else(|p| p.into_inner());
            coords.insert(session_id, CoordinatorSlot { coord, peers, joint_pubkey });
        }
        {
            let mut tx = self.inner.completion_tx.lock().unwrap_or_else(|p| p.into_inner());
            tx.insert(session_id, completion_tx);
        }
        Ok((completion_rx, outgoing))
    }

    pub fn handler_fn(
        &self,
    ) -> impl Fn(DecodedRoundMessage) -> HandlerFuture + Send + Sync + 'static {
        let inner = self.inner.clone();
        move |inbound: DecodedRoundMessage| -> HandlerFuture {
            let inner = inner.clone();
            Box::pin(async move { dispatch_one(inner, inbound).await })
        }
    }

    pub fn live_session_count(&self) -> usize {
        self.inner.coordinators.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

async fn dispatch_one(
    inner: Arc<ResharHandlerInner>,
    inbound: DecodedRoundMessage,
) -> anyhow::Result<Vec<OutgoingRoundMessage>> {
    let session_id = inbound.round_msg.session_id;
    let slot = {
        let mut coords = inner.coordinators.lock().unwrap_or_else(|p| p.into_inner());
        coords.remove(&session_id)
    };
    let Some(mut slot) = slot else {
        warn!(
            "ResharHandler: inbound for unknown session {} — dropping",
            hex::encode(session_id.as_bytes())
        );
        return Ok(vec![]);
    };

    let result = slot
        .coord
        .process_round(vec![inbound.round_msg])
        .map_err(|e| anyhow::anyhow!("ResharCoordinator::process_round failed: {e}"))?;

    match result {
        ResharRoundResult::NextRound(next) => {
            let outgoing = wrap_outgoing(&next, session_id, &slot.peers, &slot.joint_pubkey);
            let n = next.len();
            let mut coords = inner.coordinators.lock().unwrap_or_else(|p| p.into_inner());
            coords.insert(session_id, slot);
            drop(coords);
            debug!(
                "ResharHandler: session={} produced {n} outbound",
                hex::encode(session_id.as_bytes())
            );
            Ok(outgoing)
        }
        ResharRoundResult::Complete(commit) => {
            info!(
                "ResharHandler: PSS complete — session={} joint_pubkey={} (UNCHANGED)",
                hex::encode(session_id.as_bytes()),
                hex::encode(&commit.joint_pubkey_compressed)
            );
            let tx = {
                let mut txs = inner.completion_tx.lock().unwrap_or_else(|p| p.into_inner());
                txs.remove(&session_id)
            };
            if let Some(tx) = tx {
                let _ = tx.send(*commit);
            }
            Ok(vec![])
        }
    }
}

/// Wrap on the `mpc-refresh` box with the canonical §02 ExecutionId (PhaseTag::Refresh
/// + the unchanged joint pubkey).
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
        let targets: Vec<&(u16, String)> = match rm.to {
            None => peers.iter().collect(),
            Some(ShareIndex(idx)) => peers.iter().filter(|(p, _)| *p == idx).collect(),
        };
        if targets.is_empty() {
            warn!("ResharHandler: outgoing to party {:?} not in peer set; dropping", rm.to);
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

    #[test]
    fn handler_constructs_empty() {
        let h = ResharHandler::new();
        assert_eq!(h.live_session_count(), 0);
    }
}
