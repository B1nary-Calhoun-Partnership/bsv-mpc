//! DKG handler — Phase D wiring between the `MessageBoxListener`
//! dispatcher primitive (Phase C) and the real `DkgCoordinator` from
//! `bsv-mpc-core`. Drives a 2-of-N CGGMP'24 DKG ceremony across the
//! canonical MessageBox wire.
//!
//! ## Lifecycle
//!
//! 1. Caller pre-creates a coordinator via [`DkgHandler::initiate`]
//!    with `(session_id, peer_pub_hex, peer_party_index)`. This calls
//!    `coord.init()` and returns the initial round-1 outbound messages
//!    + a completion receiver.
//! 2. Caller ships the round-1 messages once per peer (one for 2-of-2).
//! 3. As inbound envelopes arrive on the listener, the handler closure
//!    looks up the coordinator, feeds the message via `process_round`
//!    on a `spawn_blocking` thread, ships any `NextRound` outbound
//!    back to the peer.
//! 4. On `DkgRoundResult::Complete`, the handler persists the share to
//!    storage, fires the completion sender, drops the coordinator.
//!
//! ## Pregenerated primes
//!
//! Auxinfo's Paillier safe-prime generation dominates DKG wall-clock
//! (~30-60s per party). [`DkgHandler::seed_primes_for`] lets the caller
//! inject primes generated ahead of time; typical pattern is one set
//! per `(session_id, party)` generated at process start.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bsv_mpc_core::canonical::{canonical_execution_id, ExecutionParams, PhaseTag};
use bsv_mpc_core::dkg::{DkgCoordinator, DkgRoundResult};
use bsv_mpc_core::envelope::WrapParams;
use bsv_mpc_core::types::{DkgResult, RoundMessage, SessionId, ShareIndex, ThresholdConfig};
use bsv_mpc_messagebox::DecodedRoundMessage;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::PregeneratedPrimes;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::messagebox::{HandlerFuture, OutgoingRoundMessage};
use crate::storage::SqliteShareStorage;

/// One live DKG ceremony — the coordinator, the peer routing info, and
/// (separately) the completion notifier. Pulled out of
/// `DkgHandlerInner::coordinators` for the duration of `process_round`
/// so the lock isn't held across a `spawn_blocking` boundary.
struct CoordinatorSlot {
    coord: DkgCoordinator,
    peer_pub_hex: String,
    peer_party_index: u16,
}

struct DkgHandlerInner {
    config: ThresholdConfig,
    my_party_index: u16,
    storage: Arc<std::sync::RwLock<SqliteShareStorage>>,
    coordinators: Mutex<HashMap<SessionId, CoordinatorSlot>>,
    completion_tx: Mutex<HashMap<SessionId, oneshot::Sender<DkgResult>>>,
    /// One-shot primes keyed by `session_id`. Consumed at coordinator
    /// instantiation; populated via [`DkgHandler::seed_primes_for`].
    primes_pool: Mutex<HashMap<SessionId, PregeneratedPrimes<SecurityLevel128>>>,
}

/// Clone-able handle. Cheap (`Arc`-shared inside); the handler closure
/// captures it and mutates the inner maps under fine-grained locks.
#[derive(Clone)]
pub struct DkgHandler {
    inner: Arc<DkgHandlerInner>,
}

impl DkgHandler {
    /// Build a fresh handler for a service that will participate in
    /// `config`-threshold ceremonies as party `my_party_index`.
    pub fn new(
        config: ThresholdConfig,
        my_party_index: u16,
        storage: Arc<std::sync::RwLock<SqliteShareStorage>>,
    ) -> Self {
        assert!(
            my_party_index < config.parties,
            "my_party_index {my_party_index} >= parties {}",
            config.parties
        );
        Self {
            inner: Arc::new(DkgHandlerInner {
                config,
                my_party_index,
                storage,
                coordinators: Mutex::new(HashMap::new()),
                completion_tx: Mutex::new(HashMap::new()),
                primes_pool: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Pre-stash a set of pregenerated primes for a specific session.
    /// Consumed at the first [`initiate`](Self::initiate) for that
    /// session_id. If absent, the cggmp24 SM falls back to on-the-fly
    /// safe prime generation (~30-60s/party).
    pub fn seed_primes_for(
        &self,
        session_id: SessionId,
        primes: PregeneratedPrimes<SecurityLevel128>,
    ) {
        self.inner
            .primes_pool
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(session_id, primes);
    }

    /// Pre-create the coordinator for `session_id`, run `init()`, and
    /// return the initial round-1 outbound messages + a receiver that
    /// fires with the `DkgResult` the moment this party's ceremony
    /// completes.
    ///
    /// Both parties in a 2-of-2 call `initiate` before any traffic
    /// flows; the round-1 sends happen in parallel.
    pub async fn initiate(
        &self,
        session_id: SessionId,
        peer_pub_hex: String,
        peer_party_index: u16,
    ) -> anyhow::Result<(oneshot::Receiver<DkgResult>, Vec<OutgoingRoundMessage>)> {
        let inner = self.inner.clone();
        let coord_session = session_id;

        let (coord, initial_round_msgs) = tokio::task::spawn_blocking(
            move || -> anyhow::Result<(DkgCoordinator, Vec<RoundMessage>)> {
                let mut coord = DkgCoordinator::new(
                    coord_session,
                    inner.config,
                    ShareIndex(inner.my_party_index),
                );
                if let Some(primes) = inner
                    .primes_pool
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&coord_session)
                {
                    coord.set_pregenerated_primes(primes);
                }
                let initial = coord
                    .init()
                    .map_err(|e| anyhow::anyhow!("DkgCoordinator::init failed: {e}"))?;
                Ok((coord, initial))
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("init task panicked: {e}"))??;

        let (completion_tx, completion_rx) = oneshot::channel::<DkgResult>();
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
                    peer_pub_hex: peer_pub_hex.clone(),
                    peer_party_index,
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

        let outgoing = wrap_outgoing(
            &initial_round_msgs,
            session_id,
            peer_pub_hex,
            peer_party_index,
        );
        Ok((completion_rx, outgoing))
    }

    /// Returns the closure to hand to
    /// [`crate::messagebox::MessageBoxListener::start`]. Captures an
    /// `Arc` to the handler state — cheap per call.
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
    inner: Arc<DkgHandlerInner>,
    inbound: DecodedRoundMessage,
) -> anyhow::Result<Vec<OutgoingRoundMessage>> {
    let session_id = inbound.round_msg.session_id;

    // Take the slot out — process_round is sync-blocking and we don't
    // want to hold the lock across an await.
    let slot = {
        let mut coords = inner.coordinators.lock().unwrap_or_else(|p| p.into_inner());
        coords.remove(&session_id)
    };
    let Some(slot) = slot else {
        warn!(
            "DkgHandler: inbound for unknown session_id {} (no coordinator); dropping. \
             Per-spec lazy init for unsolicited inbounds is a follow-up.",
            hex::encode(session_id.as_bytes())
        );
        return Ok(vec![]);
    };

    let CoordinatorSlot {
        mut coord,
        peer_pub_hex,
        peer_party_index,
    } = slot;
    let inbound_round_msg = inbound.round_msg;

    let (round_result, coord) = tokio::task::spawn_blocking(move || {
        let result = coord
            .process_round(vec![inbound_round_msg])
            .map_err(|e| anyhow::anyhow!("DkgCoordinator::process_round failed: {e}"))?;
        Ok::<_, anyhow::Error>((result, coord))
    })
    .await
    .map_err(|e| anyhow::anyhow!("process_round task panicked: {e}"))??;

    match round_result {
        DkgRoundResult::NextRound(next_msgs) => {
            let mut coords = inner.coordinators.lock().unwrap_or_else(|p| p.into_inner());
            coords.insert(
                session_id,
                CoordinatorSlot {
                    coord,
                    peer_pub_hex: peer_pub_hex.clone(),
                    peer_party_index,
                },
            );
            drop(coords);
            debug!(
                "DkgHandler: session={} round {} produced {} outbound msgs",
                hex::encode(session_id.as_bytes()),
                next_msgs.first().map(|m| m.round).unwrap_or(0),
                next_msgs.len()
            );
            Ok(wrap_outgoing(
                &next_msgs,
                session_id,
                peer_pub_hex,
                peer_party_index,
            ))
        }
        DkgRoundResult::Complete(dkg_result) => {
            let share_session_hex = dkg_result.session_id.hex();
            if let Ok(mut storage) = inner.storage.write() {
                if let Err(e) = storage.store_share(&share_session_hex, &dkg_result.share) {
                    warn!(
                        "DkgHandler: failed to persist share for session {share_session_hex}: {e}"
                    );
                }
            } else {
                warn!("DkgHandler: storage RwLock poisoned; share not persisted");
            }
            info!(
                "DkgHandler: ceremony complete — session={} joint_pubkey={}",
                hex::encode(session_id.as_bytes()),
                hex::encode(&dkg_result.joint_key.compressed)
            );
            let tx = {
                let mut txs = inner
                    .completion_tx
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                txs.remove(&session_id)
            };
            if let Some(tx) = tx {
                let _ = tx.send(dkg_result);
            }
            // coord dropped here — its SM thread joins.
            drop(coord);
            Ok(vec![])
        }
    }
}

/// Wrap one or more `RoundMessage`s as `OutgoingRoundMessage`s
/// addressed to the same peer. Computes the canonical
/// execution_id_prefix per §02.4 with the keygen carve-out
/// (joint_pubkey=all-zero before DKG completes, per §02.4 + §05.4.3).
fn wrap_outgoing(
    round_msgs: &[RoundMessage],
    session_id: SessionId,
    peer_pub_hex: String,
    peer_party_index: u16,
) -> Vec<OutgoingRoundMessage> {
    let eid = canonical_execution_id(&ExecutionParams::new_v1(
        PhaseTag::DkgKeygen,
        session_id,
        [0u8; 33],
    ));
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&eid[..8]);

    round_msgs
        .iter()
        .map(|rm| OutgoingRoundMessage {
            recipient_pub_hex: peer_pub_hex.clone(),
            message_box: bsv_mpc_messagebox::types::BOX_DKG.to_string(),
            round_msg: rm.clone(),
            params: WrapParams {
                to_party: peer_party_index,
                joint_pubkey: [0u8; 33], // §05.4.3 — DKG keygen, no joint key yet
                phase: "dkg".into(),
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
        // Leak the dir handle so the path stays valid for the test's
        // lifetime (cargo test runs are short-lived; OS cleanup wins).
        std::mem::forget(dir);
        Arc::new(std::sync::RwLock::new(storage))
    }

    #[test]
    fn handler_constructs_with_valid_party_index() {
        let h = DkgHandler::new(ThresholdConfig::new(2, 2).unwrap(), 0, fresh_storage());
        assert_eq!(h.live_session_count(), 0);
    }

    #[test]
    #[should_panic(expected = "my_party_index 2 >= parties 2")]
    fn handler_rejects_out_of_range_party_index() {
        let _ = DkgHandler::new(
            ThresholdConfig::new(2, 2).unwrap(),
            2, // parties=2 means valid indices are 0..2
            fresh_storage(),
        );
    }

    #[test]
    fn wrap_outgoing_computes_canonical_eid_prefix() {
        let rm = RoundMessage {
            session_id: SessionId([0xaa; 32]),
            round: 0,
            from: ShareIndex(0),
            to: Some(ShareIndex(1)),
            payload: vec![1, 2, 3],
        };
        let a = wrap_outgoing(
            std::slice::from_ref(&rm),
            SessionId([0xaa; 32]),
            "02deadbeef".into(),
            1,
        );
        let b = wrap_outgoing(
            std::slice::from_ref(&rm),
            SessionId([0xaa; 32]),
            "02deadbeef".into(),
            1,
        );
        let c = wrap_outgoing(
            std::slice::from_ref(&rm),
            SessionId([0xbb; 32]), // different session
            "02deadbeef".into(),
            1,
        );
        // Determinism + session-binding properties of canonical
        // ExecutionId (§02): same input → same prefix; different
        // session → different prefix.
        assert_eq!(
            a[0].params.execution_id_prefix,
            b[0].params.execution_id_prefix
        );
        assert_ne!(
            a[0].params.execution_id_prefix,
            c[0].params.execution_id_prefix
        );
        assert_eq!(a[0].params.phase, "dkg");
        assert_eq!(
            a[0].params.joint_pubkey, [0u8; 33],
            "§05.4.3 keygen carve-out"
        );
        assert_eq!(a[0].params.to_party, 1);
        assert_eq!(a[0].message_box, "mpc-dkg");
    }

    #[test]
    fn primes_pool_starts_empty() {
        let h = DkgHandler::new(ThresholdConfig::new(2, 2).unwrap(), 0, fresh_storage());
        assert_eq!(h.inner.primes_pool.lock().unwrap().len(), 0);
    }
}
