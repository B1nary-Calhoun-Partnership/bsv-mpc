//! Signing handler — Phase E wiring between the `MessageBoxListener`
//! dispatcher primitive (Phase C) and the real `SigningCoordinator`
//! from `bsv-mpc-core`. Drives a 2-of-N CGGMP'24 signing ceremony
//! across the canonical MessageBox wire to produce a DER ECDSA
//! signature ready for a BSV unlocking script.
//!
//! ## Lifecycle (mirrors [`crate::dkg_handler::DkgHandler`])
//!
//! 1. Caller pre-creates the coordinator via [`SigningHandler::initiate`]
//!    with `(agent_id, signing_session_id, peer_pub_hex,
//!    peer_party_index, sighash, joint_pubkey, hmac_offset?)`. This
//!    loads the share from storage, calls `coord.sign(sighash, None,
//!    hmac_offset)`, and returns the round-1 outbound messages + a
//!    completion receiver that yields a `SigningResult`.
//! 2. Caller ships the round-1 messages once per peer.
//! 3. As inbound envelopes arrive on the listener, the handler closure
//!    runs `process_round` on a `spawn_blocking` thread, ships any
//!    `NextRound` outbound back to the peer.
//! 4. On `SigningRoundResult::Complete`, the handler fires the
//!    completion sender with the `SigningResult` (DER signature + raw
//!    r/s + recovery id + participation proof), drops the coordinator.
//!
//! ## What's different from DkgHandler
//!
//! - **Share lookup**: signing requires the share previously persisted
//!   by DKG; `initiate` loads it from `SqliteShareStorage::get_share`.
//! - **Joint pubkey is known**: unlike DKG (keygen carve-out
//!   joint_pubkey=all-zero per §05.4.3), signing envelopes carry the
//!   real joint pubkey. Caller supplies it explicitly.
//! - **Phase tag**: envelopes are tagged `"sign"` and routed via
//!   `BOX_SIGN`, so DKG vs sign listeners don't collide even on the
//!   same session_id.
//! - **No persistence on Complete**: a signature is the output, not
//!   long-lived state. Storage isn't touched on completion.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bsv_mpc_core::canonical::{canonical_execution_id, ExecutionParams, PhaseTag};
use bsv_mpc_core::envelope::WrapParams;
use bsv_mpc_core::signing::{SigningCoordinator, SigningRoundResult};
use bsv_mpc_core::types::{RoundMessage, SessionId, SigningResult, ThresholdConfig};
use bsv_mpc_messagebox::DecodedRoundMessage;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::messagebox::{HandlerFuture, OutgoingRoundMessage};
use crate::storage::SqliteShareStorage;

/// One live signing ceremony — coordinator + peer routing + the joint
/// pubkey the envelope wrap needs.
struct CoordinatorSlot {
    coord: SigningCoordinator,
    peer_pub_hex: String,
    peer_party_index: u16,
    joint_pubkey: [u8; 33],
}

struct SigningHandlerInner {
    config: ThresholdConfig,
    /// Party indices participating in this signing ceremony (e.g.
    /// `[0, 1]` for 2-of-2). Passed to every `SigningCoordinator::new`.
    participants: Vec<u16>,
    storage: Arc<std::sync::RwLock<SqliteShareStorage>>,
    coordinators: Mutex<HashMap<SessionId, CoordinatorSlot>>,
    completion_tx: Mutex<HashMap<SessionId, oneshot::Sender<SigningResult>>>,
}

/// Clone-able handle. Same shape as [`crate::dkg_handler::DkgHandler`].
#[derive(Clone)]
pub struct SigningHandler {
    inner: Arc<SigningHandlerInner>,
}

impl SigningHandler {
    /// Build a fresh handler for a service that will sign with the
    /// `config`-threshold quorum identified by `participants`.
    pub fn new(
        config: ThresholdConfig,
        participants: Vec<u16>,
        storage: Arc<std::sync::RwLock<SqliteShareStorage>>,
    ) -> Self {
        assert!(
            participants.len() == config.threshold as usize,
            "participants len {} != threshold {}",
            participants.len(),
            config.threshold
        );
        Self {
            inner: Arc::new(SigningHandlerInner {
                config,
                participants,
                storage,
                coordinators: Mutex::new(HashMap::new()),
                completion_tx: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Load the share previously persisted by DKG (keyed by
    /// `agent_id`, which by convention is the DKG `session_id.hex()`),
    /// create a fresh `SigningCoordinator` for `signing_session_id`,
    /// call `sign(sighash, None, hmac_offset)`, and return the round-1
    /// outbound messages + a completion receiver.
    ///
    /// `joint_pubkey` is supplied by the caller — the DKG result on
    /// hand carries it, and the envelope wrap needs it (signing phase
    /// envelopes carry the real joint pubkey per §05.4.3, unlike DKG
    /// keygen which has the all-zero carve-out).
    #[allow(clippy::too_many_arguments)]
    pub async fn initiate(
        &self,
        agent_id: String,
        signing_session_id: SessionId,
        peer_pub_hex: String,
        peer_party_index: u16,
        sighash: [u8; 32],
        joint_pubkey: [u8; 33],
        hmac_offset: Option<[u8; 32]>,
    ) -> anyhow::Result<(oneshot::Receiver<SigningResult>, Vec<OutgoingRoundMessage>)> {
        // Load share synchronously — it's a quick SQLite read.
        let share = {
            let storage = self
                .inner
                .storage
                .read()
                .map_err(|e| anyhow::anyhow!("storage RwLock poisoned: {e}"))?;
            storage
                .get_share(&agent_id)
                .map_err(|e| anyhow::anyhow!("get_share({agent_id}): {e}"))?
                .ok_or_else(|| anyhow::anyhow!("no share for agent_id {agent_id}"))?
        };

        let config = self.inner.config;
        let participants = self.inner.participants.clone();

        let (coord, initial_round_msgs) = tokio::task::spawn_blocking(
            move || -> anyhow::Result<(SigningCoordinator, Vec<RoundMessage>)> {
                let mut coord =
                    SigningCoordinator::new(signing_session_id, share, config, participants);
                let initial = coord
                    .sign(&sighash, None, hmac_offset)
                    .map_err(|e| anyhow::anyhow!("SigningCoordinator::sign failed: {e}"))?;
                Ok((coord, initial))
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("sign init task panicked: {e}"))??;

        let (completion_tx, completion_rx) = oneshot::channel::<SigningResult>();
        {
            let mut coords = self
                .inner
                .coordinators
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            coords.insert(
                signing_session_id,
                CoordinatorSlot {
                    coord,
                    peer_pub_hex: peer_pub_hex.clone(),
                    peer_party_index,
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
            tx.insert(signing_session_id, completion_tx);
        }

        let outgoing = wrap_outgoing(
            &initial_round_msgs,
            signing_session_id,
            joint_pubkey,
            peer_pub_hex,
            peer_party_index,
        );
        Ok((completion_rx, outgoing))
    }

    /// Returns the closure to hand to
    /// [`crate::messagebox::MessageBoxListener::start`].
    pub fn handler_fn(
        &self,
    ) -> impl Fn(DecodedRoundMessage) -> HandlerFuture + Send + Sync + 'static {
        let inner = self.inner.clone();
        move |inbound: DecodedRoundMessage| -> HandlerFuture {
            let inner = inner.clone();
            Box::pin(async move { dispatch_one(inner, inbound).await })
        }
    }

    /// Test/inspect — number of live signing ceremonies.
    pub fn live_session_count(&self) -> usize {
        self.inner
            .coordinators
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }
}

async fn dispatch_one(
    inner: Arc<SigningHandlerInner>,
    inbound: DecodedRoundMessage,
) -> anyhow::Result<Vec<OutgoingRoundMessage>> {
    let session_id = inbound.round_msg.session_id;

    let slot = {
        let mut coords = inner.coordinators.lock().unwrap_or_else(|p| p.into_inner());
        coords.remove(&session_id)
    };
    let Some(slot) = slot else {
        warn!(
            "SigningHandler: inbound for unknown session_id {} (no coordinator); dropping.",
            hex::encode(session_id.as_bytes())
        );
        return Ok(vec![]);
    };

    let CoordinatorSlot {
        mut coord,
        peer_pub_hex,
        peer_party_index,
        joint_pubkey,
    } = slot;
    let inbound_round_msg = inbound.round_msg;

    let (round_result, coord) = tokio::task::spawn_blocking(move || {
        let result = coord
            .process_round(vec![inbound_round_msg])
            .map_err(|e| anyhow::anyhow!("SigningCoordinator::process_round failed: {e}"))?;
        Ok::<_, anyhow::Error>((result, coord))
    })
    .await
    .map_err(|e| anyhow::anyhow!("process_round task panicked: {e}"))??;

    match round_result {
        SigningRoundResult::NextRound(next_msgs) => {
            let mut coords = inner.coordinators.lock().unwrap_or_else(|p| p.into_inner());
            coords.insert(
                session_id,
                CoordinatorSlot {
                    coord,
                    peer_pub_hex: peer_pub_hex.clone(),
                    peer_party_index,
                    joint_pubkey,
                },
            );
            drop(coords);
            debug!(
                "SigningHandler: session={} round {} → {} outbound",
                hex::encode(session_id.as_bytes()),
                next_msgs.first().map(|m| m.round).unwrap_or(0),
                next_msgs.len(),
            );
            Ok(wrap_outgoing(
                &next_msgs,
                session_id,
                joint_pubkey,
                peer_pub_hex,
                peer_party_index,
            ))
        }
        SigningRoundResult::Complete(sig_result) => {
            info!(
                "SigningHandler: ceremony complete — session={} sig_der_len={}",
                hex::encode(session_id.as_bytes()),
                sig_result.signature.len(),
            );
            let tx = {
                let mut txs = inner
                    .completion_tx
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                txs.remove(&session_id)
            };
            if let Some(tx) = tx {
                let _ = tx.send(sig_result);
            }
            drop(coord);
            Ok(vec![])
        }
    }
}

/// Wrap signing-round outbound messages. Per §05.4.3 the signing phase
/// uses the REAL joint pubkey (unlike DKG's all-zero carve-out).
/// Canonical execution_id is computed with `PhaseTag::Sign`.
fn wrap_outgoing(
    round_msgs: &[RoundMessage],
    session_id: SessionId,
    joint_pubkey: [u8; 33],
    peer_pub_hex: String,
    peer_party_index: u16,
) -> Vec<OutgoingRoundMessage> {
    let eid = canonical_execution_id(&ExecutionParams::new_v1(
        PhaseTag::Sign,
        session_id,
        joint_pubkey,
    ));
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&eid[..8]);

    round_msgs
        .iter()
        .map(|rm| OutgoingRoundMessage {
            recipient_pub_hex: peer_pub_hex.clone(),
            message_box: bsv_mpc_messagebox::types::BOX_SIGN.to_string(),
            round_msg: rm.clone(),
            params: WrapParams {
                to_party: peer_party_index,
                joint_pubkey,
                phase: "sign".into(),
                execution_id_prefix: prefix,
                correlation_id: None,
                traceparent: None,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fresh_storage() -> Arc<std::sync::RwLock<SqliteShareStorage>> {
        let dir = tempdir().expect("tempdir");
        let storage = SqliteShareStorage::open(dir.path().to_str().unwrap()).expect("open");
        std::mem::forget(dir);
        Arc::new(std::sync::RwLock::new(storage))
    }

    #[test]
    fn handler_constructs_with_valid_quorum() {
        let h = SigningHandler::new(
            ThresholdConfig::new(2, 2).unwrap(),
            vec![0, 1],
            fresh_storage(),
        );
        assert_eq!(h.live_session_count(), 0);
    }

    #[test]
    #[should_panic(expected = "participants len 1 != threshold 2")]
    fn handler_rejects_wrong_size_quorum() {
        let _ = SigningHandler::new(
            ThresholdConfig::new(2, 2).unwrap(),
            vec![0], // only 1 participant in a 2-of-2 quorum
            fresh_storage(),
        );
    }

    #[test]
    fn wrap_outgoing_uses_real_joint_pubkey_and_sign_phase() {
        let rm = RoundMessage {
            session_id: SessionId([0x77; 32]),
            round: 0,
            from: bsv_mpc_core::types::ShareIndex(0),
            to: Some(bsv_mpc_core::types::ShareIndex(1)),
            payload: vec![1, 2, 3],
        };
        let mut jp = [0u8; 33];
        jp[0] = 0x02;
        jp[32] = 0x55;

        let out = wrap_outgoing(
            std::slice::from_ref(&rm),
            SessionId([0x77; 32]),
            jp,
            "02deadbeef".into(),
            1,
        );
        assert_eq!(out[0].params.phase, "sign", "phase MUST be 'sign'");
        assert_eq!(
            out[0].params.joint_pubkey, jp,
            "signing envelopes carry the real joint pubkey (§05.4.3)"
        );
        assert_eq!(out[0].message_box, "mpc-sign");
        assert_eq!(out[0].params.to_party, 1);

        // Determinism: same input → same EID prefix; different
        // joint_pubkey → different prefix.
        let out2 = wrap_outgoing(
            std::slice::from_ref(&rm),
            SessionId([0x77; 32]),
            jp,
            "02deadbeef".into(),
            1,
        );
        assert_eq!(
            out[0].params.execution_id_prefix,
            out2[0].params.execution_id_prefix
        );

        let mut jp_other = jp;
        jp_other[32] = 0x99;
        let out3 = wrap_outgoing(
            std::slice::from_ref(&rm),
            SessionId([0x77; 32]),
            jp_other,
            "02deadbeef".into(),
            1,
        );
        assert_ne!(
            out[0].params.execution_id_prefix,
            out3[0].params.execution_id_prefix,
            "different joint_pubkey MUST produce different EID prefix (binds signing ceremony to key)"
        );
    }
}
