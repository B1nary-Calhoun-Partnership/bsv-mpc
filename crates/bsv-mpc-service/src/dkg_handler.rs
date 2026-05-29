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

use std::collections::{HashMap, VecDeque};
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
    /// All OTHER parties: `(party_index, identity_pub_hex)`. A broadcast
    /// `RoundMessage` (`to == None`) fans out to every peer; a p2p one
    /// (`to == Some(idx)`, e.g. a threshold-keygen VSS share) routes only to
    /// the peer whose index matches. For 2-party this is a 1-element vec.
    peers: Vec<(u16, String)>,
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
    /// Per-session **late-prime cells**, shared with the live coordinator. An
    /// [`initiate`](DkgHandler::initiate) installs one per session and hands a
    /// clone to the coordinator via `set_late_prime_cell`; the caller fills it
    /// later via [`seed_primes_late`](DkgHandler::seed_primes_late). This is the
    /// §06.17 ordering fix: subscribe + initiate + ship keygen round-1 FIRST
    /// (no late relay join), then generate the slow safe primes and drop them
    /// in — the coordinator pulls them at the keygen→auxinfo transition.
    late_prime_cells: Mutex<HashMap<SessionId, bsv_mpc_core::dkg::SharedPrimeCell>>,
    /// **Early-inbound buffer** for messages that arrive BEFORE this party has
    /// [`initiate`](DkgHandler::initiate)d its coordinator for that session.
    ///
    /// In a multi-party ceremony over the relay, parties subscribe + initiate +
    /// ship round-1 concurrently (and across process boundaries — proxy +
    /// container — there is NO global "all-initiate-before-any-ship" barrier).
    /// So a peer's round-1 can be delivered (live OR via backfill) to a party
    /// whose coordinator is not yet registered. The old code DROPPED such
    /// messages — and the relay never re-delivers them, so the joint DKG could
    /// never gather all round-1 commitments and stalled (the deployed
    /// `party N timed out awaiting throwaway DKG aux` bug). We instead BUFFER
    /// them here, keyed by session, and replay them the moment that session's
    /// coordinator is registered in `initiate`. cggmp24's SM already buffers
    /// out-of-order rounds internally, so replay order across rounds is safe.
    pending_inbound: Mutex<HashMap<SessionId, Vec<DecodedRoundMessage>>>,
    /// Composite-persist override (ADR-0052). `None` → the completed share is
    /// persisted under the legacy session-hex key (the HTTP `/dkg` path). `Some(owner)`
    /// → it is persisted under the composite key `"{joint_pubkey_hex}#{share_index}"`
    /// recording `owner` (§08.1), so a cosigner holding `w > 1` indices of one
    /// ceremony does not overwrite. Set via [`DkgHandler::use_composite_persist`]
    /// by the `/dkg-relay/init` route before `initiate`.
    persist_override: Mutex<Option<String>>,
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
                late_prime_cells: Mutex::new(HashMap::new()),
                pending_inbound: Mutex::new(HashMap::new()),
                persist_override: Mutex::new(None),
            }),
        }
    }

    /// Persist completed shares under the COMPOSITE key
    /// `"{joint_pubkey_hex}#{share_index}"` recording `owner` (§08.1), instead of
    /// the legacy session-hex key (ADR-0052). This is what lets a cosigner — or
    /// the device — hold `w > 1` indices of ONE ceremony without overwriting
    /// (every held share has the same joint pubkey, hence the same `agent_id`).
    /// Call BEFORE [`initiate`](Self::initiate); used by the `/dkg-relay/init`
    /// route. The legacy HTTP `/dkg` path leaves it unset (session-hex keying).
    pub fn use_composite_persist(&self, owner: String) {
        *self
            .inner
            .persist_override
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(owner);
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

    /// **Late-seed** primes for a session that has already been
    /// [`initiate`](Self::initiate)d. Unlike [`seed_primes_for`](Self::seed_primes_for)
    /// (which MUST run before `initiate` because it is consumed at coordinator
    /// instantiation), this drops primes into the per-session shared cell the
    /// live coordinator consults at its keygen→auxinfo transition.
    ///
    /// This is what lets a party `initiate` + ship keygen round-1 immediately —
    /// BEFORE the ~30-90s safe-prime generation finishes — so it never joins the
    /// relay late (the §06.17 ordering invariant). Call it as soon as prime
    /// generation completes. If the keygen phase happens to outrun prime gen,
    /// the auxinfo phase falls back to inline generation (slow but correct);
    /// seeding after that point is a harmless no-op.
    ///
    /// No-op if `initiate` was never called for `session_id` (no cell exists).
    pub fn seed_primes_late(
        &self,
        session_id: SessionId,
        primes: PregeneratedPrimes<SecurityLevel128>,
    ) {
        let cell = self
            .inner
            .late_prime_cells
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&session_id)
            .cloned();
        if let Some(cell) = cell {
            *cell.lock().unwrap_or_else(|p| p.into_inner()) = Some(primes);
            debug!(
                "DkgHandler: late-seeded primes for session {}",
                hex::encode(session_id.as_bytes())
            );
        } else {
            warn!(
                "DkgHandler: seed_primes_late for session {} with no live cell (initiate not called?); dropping",
                hex::encode(session_id.as_bytes())
            );
        }
    }

    /// Pre-create the coordinator for `session_id`, run `init()`, and
    /// return the initial round-1 outbound messages + a receiver that
    /// fires with the `DkgResult` the moment this party's ceremony
    /// completes.
    ///
    /// Every party calls `initiate` before any traffic flows; the round-1
    /// sends happen in parallel. `peers` is every OTHER party as
    /// `(party_index, identity_pub_hex)` — one entry for 2-of-2, two for
    /// 2-of-3, etc. Broadcast round-1 messages fan out to all of them.
    pub async fn initiate(
        &self,
        session_id: SessionId,
        peers: Vec<(u16, String)>,
    ) -> anyhow::Result<(oneshot::Receiver<DkgResult>, Vec<OutgoingRoundMessage>)> {
        let inner = self.inner.clone();
        let coord_session = session_id;

        // Install (or reuse) the per-session late-prime cell BEFORE init, and
        // hand a clone to the coordinator. This lets the caller `initiate` +
        // ship round-1 now and `seed_primes_late` afterwards (§06.17 ordering).
        let late_cell: bsv_mpc_core::dkg::SharedPrimeCell = {
            let mut cells = inner
                .late_prime_cells
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            cells
                .entry(coord_session)
                .or_insert_with(|| std::sync::Arc::new(std::sync::Mutex::new(None)))
                .clone()
        };
        let coord_late_cell = late_cell.clone();

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
                // Fallback prime source for late-seeded primes (filled after
                // init via `seed_primes_late`). Harmless when primes were
                // already set eagerly above — the eager set takes precedence.
                coord.set_late_prime_cell(coord_late_cell);
                let initial = coord
                    .init()
                    .map_err(|e| anyhow::anyhow!("DkgCoordinator::init failed: {e}"))?;
                Ok((coord, initial))
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("init task panicked: {e}"))??;

        let (completion_tx, completion_rx) = oneshot::channel::<DkgResult>();
        let mut outgoing = wrap_outgoing(&initial_round_msgs, session_id, &peers);

        // Register the completion notifier, then the coordinator, then drain any
        // EARLY-INBOUND messages buffered before this `initiate` (peer round-1
        // that raced ahead of us). Lock order is `coordinators` → `pending_inbound`
        // (same as the dispatch buffering path) so no buffered message is lost
        // between the coordinator insert and the drain.
        {
            let mut tx = self
                .inner
                .completion_tx
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            tx.insert(session_id, completion_tx);
        }
        let buffered: Vec<DecodedRoundMessage> = {
            let mut coords = self
                .inner
                .coordinators
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            coords.insert(session_id, CoordinatorSlot { coord, peers });
            self.inner
                .pending_inbound
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&session_id)
                .unwrap_or_default()
        };

        // Replay buffered inbounds through the normal dispatch path. Each call
        // re-inserts the (advanced) coordinator, so sequential replay is safe;
        // accumulate any outbound the SM produces so the caller ships it
        // alongside round-1.
        if !buffered.is_empty() {
            debug!(
                "DkgHandler: replaying {} buffered inbound(s) for session {} after initiate",
                buffered.len(),
                hex::encode(session_id.as_bytes())
            );
            for msg in buffered {
                match dispatch_one(self.inner.clone(), msg).await {
                    Ok(mut more) => outgoing.append(&mut more),
                    Err(e) => warn!(
                        "DkgHandler: replay of buffered inbound for session {} failed: {e}",
                        hex::encode(session_id.as_bytes())
                    ),
                }
            }
        }

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
    let mut all_outgoing: Vec<OutgoingRoundMessage> = Vec::new();
    // Work queue: the triggering inbound, then any messages drained from the
    // pending buffer as we make progress (closes the race where a peer message
    // arrives while the coordinator slot is checked-out for processing).
    let mut queue: VecDeque<DecodedRoundMessage> = VecDeque::new();
    queue.push_back(inbound);

    while let Some(next) = queue.pop_front() {
        // Take the slot out — process_round is sync-blocking and we don't want
        // to hold the lock across an await. If the coordinator is not yet
        // registered (peer round-1 raced ahead of our own `initiate`), BUFFER
        // the inbound under the pending map instead of dropping it — `initiate`
        // (or a later drain below) replays it once the coordinator exists. Lock
        // order is `coordinators` → `pending_inbound` (same as `initiate`) so a
        // concurrent register-then-drain cannot lose a message buffered here.
        let slot = {
            let mut coords = inner.coordinators.lock().unwrap_or_else(|p| p.into_inner());
            match coords.remove(&session_id) {
                Some(s) => s,
                None => {
                    let mut pend = inner
                        .pending_inbound
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    let buf = pend.entry(session_id).or_default();
                    // `next` first, then any items we'd drained ahead of it, so
                    // FIFO order is preserved for the eventual replay.
                    buf.push(next);
                    buf.extend(queue.drain(..));
                    debug!(
                        "DkgHandler: inbound for session {} buffered (coordinator checked-out or \
                         not yet initiated); will replay",
                        hex::encode(session_id.as_bytes())
                    );
                    return Ok(all_outgoing);
                }
            }
        };

        let CoordinatorSlot { mut coord, peers } = slot;
        let inbound_round_msg = next.round_msg;

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
                let mut outgoing = wrap_outgoing(&next_msgs, session_id, &peers);
                {
                    let mut coords = inner.coordinators.lock().unwrap_or_else(|p| p.into_inner());
                    coords.insert(session_id, CoordinatorSlot { coord, peers });
                }
                debug!(
                    "DkgHandler: session={} round {} produced {} outbound msgs",
                    hex::encode(session_id.as_bytes()),
                    next_msgs.first().map(|m| m.round).unwrap_or(0),
                    next_msgs.len()
                );
                all_outgoing.append(&mut outgoing);
                // Drain any messages that buffered while the slot was checked
                // out (or earlier) and keep processing them in this same call.
                let drained: Vec<DecodedRoundMessage> = inner
                    .pending_inbound
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&session_id)
                    .unwrap_or_default();
                queue.extend(drained);
            }
            DkgRoundResult::Complete(dkg_result) => {
                return finish_complete(&inner, session_id, coord, dkg_result, all_outgoing);
            }
        }
    }

    Ok(all_outgoing)
}

/// Persist a completed DKG share, honoring the composite-persist override
/// (ADR-0052). When set (via [`DkgHandler::use_composite_persist`], the
/// `/dkg-relay` path), the share is stored under `"{joint_pubkey_hex}#{index}"`
/// with the recorded owner (§08.1) so a multi-index cosigner never overwrites;
/// otherwise it falls back to the legacy session-hex key (the HTTP `/dkg` path),
/// byte-for-byte unchanged.
fn persist_completed_share(inner: &Arc<DkgHandlerInner>, dkg_result: &DkgResult) {
    let override_owner = inner
        .persist_override
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let Ok(mut storage) = inner.storage.write() else {
        warn!("DkgHandler: storage RwLock poisoned; share not persisted");
        return;
    };
    let result = match override_owner {
        Some(owner) => {
            // FRESH DKG: the joint pubkey is the agent_id, known now at completion
            // (user-decision: re-key at completion). Index = this party's held index.
            let agent_id = hex::encode(&dkg_result.joint_key.compressed);
            let index = dkg_result.share.share_index.0;
            storage.store_share_at_index(&agent_id, index, &dkg_result.share, &owner)
        }
        None => storage.store_share(&dkg_result.session_id.hex(), &dkg_result.share),
    };
    if let Err(e) = result {
        warn!("DkgHandler: failed to persist completed share: {e}");
    }
}

/// Finalize a completed DKG ceremony: persist the share, clean up per-session
/// state, fire the completion notifier, and drop the coordinator.
fn finish_complete(
    inner: &Arc<DkgHandlerInner>,
    session_id: SessionId,
    coord: DkgCoordinator,
    dkg_result: DkgResult,
    all_outgoing: Vec<OutgoingRoundMessage>,
) -> anyhow::Result<Vec<OutgoingRoundMessage>> {
    persist_completed_share(inner, &dkg_result);
    info!(
        "DkgHandler: ceremony complete — session={} joint_pubkey={}",
        hex::encode(session_id.as_bytes()),
        hex::encode(&dkg_result.joint_key.compressed)
    );
    // Drop the per-session late-prime cell + pending buffer — primes (if any)
    // were consumed at the keygen→auxinfo transition; no further inbound is
    // meaningful after completion.
    inner
        .late_prime_cells
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&session_id);
    inner
        .pending_inbound
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&session_id);
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
    Ok(all_outgoing)
}

/// Wrap one or more `RoundMessage`s as `OutgoingRoundMessage`s
/// addressed to the same peer. Computes the canonical
/// execution_id_prefix per §02.4 with the keygen carve-out
/// (joint_pubkey=all-zero before DKG completes, per §02.4 + §05.4.3).
fn wrap_outgoing(
    round_msgs: &[RoundMessage],
    session_id: SessionId,
    peers: &[(u16, String)],
) -> Vec<OutgoingRoundMessage> {
    let eid = canonical_execution_id(&ExecutionParams::new_v1(
        PhaseTag::DkgKeygen,
        session_id,
        [0u8; 33],
    ));
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&eid[..8]);

    let mut out = Vec::new();
    for rm in round_msgs {
        // Route by the cggmp24 recipient surfaced on `RoundMessage.to`:
        // `None` = broadcast → ship to every peer; `Some(idx)` = p2p (e.g. a
        // threshold-keygen VSS share) → ship only to the matching peer.
        let targets: Vec<&(u16, String)> = match rm.to {
            None => peers.iter().collect(),
            Some(ShareIndex(idx)) => peers.iter().filter(|(p, _)| *p == idx).collect(),
        };
        if targets.is_empty() {
            warn!(
                "DkgHandler: outgoing p2p message to party {:?} not in peer set {:?}; dropping",
                rm.to,
                peers.iter().map(|(p, _)| *p).collect::<Vec<_>>()
            );
            continue;
        }
        for (idx, hex) in targets {
            out.push(OutgoingRoundMessage {
                recipient_pub_hex: hex.clone(),
                message_box: bsv_mpc_messagebox::types::BOX_DKG.to_string(),
                round_msg: rm.clone(),
                params: WrapParams {
                    to_party: *idx,
                    joint_pubkey: [0u8; 33], // §05.4.3 — DKG keygen, no joint key yet
                    phase: "dkg".into(),
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

    use bsv_mpc_core::types::{EncryptedShare, JointPublicKey};

    /// Fabricate a completed-DKG result for the persist-keying tests (no relay).
    fn fake_result(joint_byte: u8, idx: u16, ct: u8, sess: u8) -> DkgResult {
        let joint = vec![joint_byte; 33];
        DkgResult {
            joint_key: JointPublicKey {
                compressed: joint.clone(),
                address: "1Test".into(),
            },
            share: EncryptedShare {
                nonce: vec![0u8; 12],
                ciphertext: vec![ct; 8],
                session_id: SessionId([sess; 32]),
                share_index: ShareIndex(idx),
                config: ThresholdConfig::new(4, 6).unwrap(),
                joint_pubkey_compressed: joint,
            },
            session_id: SessionId([sess; 32]),
        }
    }

    /// ADR-0052: with the composite-persist override set, a completed share lands
    /// under `"{joint_pubkey_hex}#{index}"` with the recorded owner — NOT the
    /// legacy session-hex key — so a cosigner holding >1 index never overwrites.
    #[test]
    fn composite_persist_override_keys_by_joint_pubkey_and_index() {
        let storage = fresh_storage();
        let h = DkgHandler::new(ThresholdConfig::new(4, 6).unwrap(), 4, storage.clone());
        h.use_composite_persist("owner-XYZ".to_string());

        let result = fake_result(0x02, 4, 0x44, 0x99);
        let agent_id = hex::encode(&result.joint_key.compressed);
        persist_completed_share(&h.inner, &result);

        let st = storage.read().unwrap_or_else(|p| p.into_inner());
        let got = st
            .get_share_at_index(&agent_id, 4)
            .unwrap()
            .expect("composite (agent_id,4) share present");
        assert_eq!(got.share_index, ShareIndex(4));
        assert_eq!(got.ciphertext, vec![0x44u8; 8]);
        assert_eq!(
            st.get_share_owner_at_index(&agent_id, 4)
                .unwrap()
                .as_deref(),
            Some("owner-XYZ"),
        );
        // MUST NOT also write the legacy session-hex key (no double-key).
        assert!(
            st.get_share(&result.session_id.hex()).unwrap().is_none(),
            "composite-persist must not also write the legacy session-hex key"
        );
    }

    /// Without the override (legacy HTTP `/dkg` path) the share persists under the
    /// session-hex key exactly as before — byte-for-byte unchanged.
    #[test]
    fn legacy_persist_unchanged_when_override_unset() {
        let storage = fresh_storage();
        let h = DkgHandler::new(ThresholdConfig::new(2, 2).unwrap(), 1, storage.clone());
        // no use_composite_persist() → legacy path.
        let result = fake_result(0x03, 1, 0x77, 0x88);
        persist_completed_share(&h.inner, &result);

        let st = storage.read().unwrap_or_else(|p| p.into_inner());
        assert!(
            st.get_share(&result.session_id.hex()).unwrap().is_some(),
            "legacy persist must write the session-hex key (unchanged)"
        );
        let agent_id = hex::encode(&result.joint_key.compressed);
        assert!(
            st.get_share_at_index(&agent_id, 1).unwrap().is_none(),
            "legacy path must not touch the composite namespace"
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
            &[(1u16, "02deadbeef".to_string())],
        );
        let b = wrap_outgoing(
            std::slice::from_ref(&rm),
            SessionId([0xaa; 32]),
            &[(1u16, "02deadbeef".to_string())],
        );
        let c = wrap_outgoing(
            std::slice::from_ref(&rm),
            SessionId([0xbb; 32]), // different session
            &[(1u16, "02deadbeef".to_string())],
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
