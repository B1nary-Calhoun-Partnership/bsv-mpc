//! Presign handler — drives a 2-of-N CGGMP'24 presignature ceremony over the
//! canonical MessageBox wire and assembles the §06.17.1 `PresigBundle`
//! (MPC-Spec #4 item 3, §06.16 + §06.17.2). Mirrors [`crate::dkg_handler`] /
//! [`crate::signing_handler`].
//!
//! ## Two transient mailboxes (§06.17.2)
//!
//! Mailboxes are IMPLICIT on the relay (created on first `send`, no
//! create/delete API). For each presign session the coordinator uses two,
//! both scoped by the canonical SessionId hex (§04):
//!
//!   - `mpc_{session_id}`           — round-trip channel for the 3-round
//!     protocol traffic ([`bsv_mpc_messagebox::types::presign_protocol_box`]).
//!   - `presig_return_{session_id}` — one-way return channel for the
//!     cosigner-encrypted presig-share ciphertexts
//!     ([`bsv_mpc_messagebox::types::presig_return_box`]).
//!
//! "Allocate" = use the name (first send creates it). "Delete after persist" =
//! `acknowledge()` the consumed messages + rely on best-effort relay GC (§06.13
//! / §06.17.2 stranded-mailbox expiry).
//!
//! ## Roles
//!
//! Both parties run a [`PresigningManager`] and drive the 3-round SM over the
//! protocol box. After round 3 completes (§06.16):
//!
//!   - **Cosigner** (`party != coordinator_party`): serializes its presig share
//!     ([`serialize_party_presignature`]), BRC-2 self-encrypts it
//!     ([`encrypt_presig_share`]), and sends the opaque ciphertext to the
//!     coordinator on the return box.
//!   - **Coordinator** (`party == coordinator_party`, typically party 0):
//!     keeps its OWN serialized presig share (sealed at-rest per §06.17.1),
//!     collects each cosigner ciphertext into `cosigner_encrypted_shares`
//!     **indexed positionally by party order in `parties_at_keygen`**, then
//!     assembles + persists the [`PresigBundle`] and acknowledges.
//!
//! ## Lifecycle
//!
//! 1. Caller builds the handler with [`PresignHandler::new`] (role, binding
//!    triple, at-rest root key).
//! 2. Caller starts a [`MessageBoxListener`] on the protocol box AND, for the
//!    coordinator, a second listener on the return box (both feed
//!    [`PresignHandler::handler_fn`]).
//! 3. Caller [`initiate`](PresignHandler::initiate)s — runs `init_generate` and
//!    returns round-1 outbound + a completion receiver. The coordinator's
//!    receiver fires with the persisted [`PresigBundle`]; a cosigner's fires
//!    once it has shipped its return ciphertext.
//! 4. Inbound protocol messages drive the SM; on `Complete` the role-specific
//!    path above runs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::canonical::{canonical_execution_id, ExecutionParams, PhaseTag};
use bsv_mpc_core::envelope::WrapParams;
use bsv_mpc_core::presig_at_rest::{derive_presig_at_rest_key, seal_presig_bytes};
use bsv_mpc_core::presig_encryption::{encrypt_presig_share, wallet_from_identity};
use bsv_mpc_core::presigning::{
    serialize_party_presig_with_public_data, serialize_party_presignature, PresigningManager,
    PresigningRoundResult,
};
use bsv_mpc_core::types::{
    EncryptedShare, PolicyId, PresigBundle, RoundMessage, SessionId, ShareIndex,
};
use bsv_mpc_messagebox::types::{presig_return_box, presign_protocol_box};
use bsv_mpc_messagebox::DecodedRoundMessage;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::messagebox::{HandlerFuture, OutgoingRoundMessage};

/// Sentinel `RoundMessage.round` marking a return-channel ciphertext.
///
/// The dispatcher routes on THIS, not on `message_box`: the relay delivers by
/// recipient identity and `DecodedRoundMessage.message_box` only reflects the
/// subscribed set, so it cannot reliably distinguish a return ciphertext from
/// protocol traffic when one party subscribes to both boxes. The 3-round presign
/// emits coordinator rounds 1..=3, so `200` is unambiguous (and `200 + 1 = 201`
/// stays within the envelope's `round + 1` wire encoding, u8-safe).
const RETURN_SHARE_ROUND: u8 = 200;

/// One live presign ceremony.
struct CeremonySlot {
    mgr: PresigningManager,
    /// Joint pubkey (33-byte compressed) this presig is bound to. Empty during
    /// keygen only; presign always has it.
    joint_pubkey: [u8; 33],
    /// All OTHER parties: `(party_index, identity_pub_hex)`.
    peers: Vec<(u16, String)>,
}

/// Per-session coordinator collection state for the return channel.
struct CollectionSlot {
    /// Coordinator's OWN serialized presig share, sealed at-rest (§06.17.1).
    own_presig_sealed: Vec<u8>,
    /// Durable CBOR of the shared `PresignaturePublicData` (§06.17.1
    /// `commitments`) — lets the coordinator reconstruct + combine after a
    /// restart (#25a), not just from an in-memory pool.
    public_data_cbor: Vec<u8>,
    /// `Gamma` commitment hex (§06.17.1 `gamma_hex`).
    gamma_hex: String,
    /// canonical `presig_id` (= presign session_id hex).
    presig_id: String,
    /// Joint pubkey (33-byte compressed) the bundle binds to. Stashed at
    /// round-3 complete so a return share arriving AFTER the ceremony slot is
    /// gone can still drive `try_finalize_bundle`.
    joint_pubkey: [u8; 33],
    /// One slot per party in `parties_at_keygen`, positional. `None` until that
    /// party's ciphertext arrives; the coordinator's own slot stays `None`
    /// (coordinator keeps plaintext in `presig_bytes`, not a self-ciphertext).
    cosigner_shares: Vec<Option<Vec<u8>>>,
    /// Relay message_ids to `acknowledge()` once the bundle is persisted
    /// (best-effort GC per §06.13 / §06.17.2).
    ack_ids: Vec<String>,
}

struct PresignHandlerInner {
    /// This party's 0-based index.
    my_party_index: u16,
    /// The coordinator's party index (collects + persists the bundle).
    coordinator_party: u16,
    /// Cosigner subset (party indices) in canonical ascending order — the
    /// binding triple's `parties_at_keygen` and the positional index basis for
    /// `cosigner_encrypted_shares`.
    parties_at_keygen: Vec<u16>,
    /// Policy hash this presig binds to (§09 / §06.17.1 binding triple).
    policy_id: PolicyId,
    /// Identity priv — the BRC-2 self-encryption key for the cosigner's return
    /// ciphertext (and, for the coordinator, the at-rest root key source).
    identity_priv: PrivateKey,
    /// At-rest root key for sealing the coordinator's own presig share (§06.17.1).
    at_rest_root: [u8; 32],
    /// Where the coordinator persists assembled bundles.
    bundle_store: Arc<dyn BundleStore>,

    ceremonies: Mutex<HashMap<SessionId, CeremonySlot>>,
    collections: Mutex<HashMap<SessionId, CollectionSlot>>,
    completion_tx: Mutex<HashMap<SessionId, oneshot::Sender<PresignOutcome>>>,
}

/// What a party's completion receiver yields.
#[derive(Debug, Clone)]
pub enum PresignOutcome {
    /// Coordinator: the assembled + persisted bundle.
    BundlePersisted(Box<PresigBundle>),
    /// Cosigner: it finished the 3 rounds and shipped its return ciphertext.
    ReturnShipped,
}

/// Pluggable persistence sink for assembled bundles. The relay e2e uses an
/// in-memory implementation; production wires the worker DO / SQLite store.
pub trait BundleStore: Send + Sync {
    fn persist(&self, bundle: &PresigBundle) -> anyhow::Result<()>;
}

/// In-memory bundle store (tests / single-process demos). Keyed by `presig_id`.
#[derive(Default, Clone)]
pub struct InMemoryBundleStore {
    inner: Arc<Mutex<HashMap<String, PresigBundle>>>,
}

impl InMemoryBundleStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fetch a persisted bundle by `presig_id` (clone).
    pub fn get(&self, presig_id: &str) -> Option<PresigBundle> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(presig_id)
            .cloned()
    }

    /// Count of persisted bundles.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl BundleStore for InMemoryBundleStore {
    fn persist(&self, bundle: &PresigBundle) -> anyhow::Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(bundle.presig_id.clone(), bundle.clone());
        Ok(())
    }
}

/// **Durable file-backed bundle store (§06.17.1).** One JSON file per
/// `presig_id` under `root`, so an assembled [`PresigBundle`] survives a
/// coordinator restart — the property the in-memory store cannot prove. The
/// `PresigBundle` is fully `Serialize`/`Deserialize` (its `commitments`/
/// `gamma_hex` carry the public data per #25a), so a coordinator that reloads a
/// bundle from disk can reconstruct `PresignaturePublicData` and combine via
/// [`SigningCoordinator::sign_from_bundle`](bsv_mpc_core::signing::SigningCoordinator::sign_from_bundle)
/// — no live in-memory presig tuple required.
///
/// This is the interface the worker DO / SQLite store slots behind in
/// production; the file impl is the hermetically-provable durable backing.
#[derive(Clone)]
pub struct FileBundleStore {
    root: std::path::PathBuf,
}

impl FileBundleStore {
    /// Open (creating if needed) a bundle store rooted at `root`.
    pub fn new(root: impl Into<std::path::PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)
            .map_err(|e| anyhow::anyhow!("create bundle store dir {}: {e}", root.display()))?;
        Ok(Self { root })
    }

    /// Filesystem-safe path for a `presig_id` (hex/ascii ids only — the
    /// canonical presig_id is a SessionId hex string, so this is total).
    fn path_for(&self, presig_id: &str) -> std::path::PathBuf {
        let safe: String = presig_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        self.root.join(format!("{safe}.json"))
    }

    /// Load a persisted bundle by `presig_id`, or `None` if absent.
    pub fn get(&self, presig_id: &str) -> Option<PresigBundle> {
        let path = self.path_for(presig_id);
        let bytes = std::fs::read(&path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
}

impl BundleStore for FileBundleStore {
    fn persist(&self, bundle: &PresigBundle) -> anyhow::Result<()> {
        let path = self.path_for(&bundle.presig_id);
        let bytes = serde_json::to_vec(bundle)
            .map_err(|e| anyhow::anyhow!("serialize PresigBundle {}: {e}", bundle.presig_id))?;
        // Write to a temp sibling then rename for atomic, restart-safe durability.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes)
            .map_err(|e| anyhow::anyhow!("write bundle {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .map_err(|e| anyhow::anyhow!("rename bundle into place {}: {e}", path.display()))?;
        Ok(())
    }
}

/// Clone-able handle. `Arc`-shared inside; the handler closure captures it.
#[derive(Clone)]
pub struct PresignHandler {
    inner: Arc<PresignHandlerInner>,
}

/// Construction parameters for [`PresignHandler::new`].
pub struct PresignHandlerConfig {
    pub my_party_index: u16,
    pub coordinator_party: u16,
    /// Cosigner subset in canonical ascending order (binding triple).
    pub parties_at_keygen: Vec<u16>,
    pub policy_id: PolicyId,
    /// This party's BRC-31 identity priv (BRC-2 self-encryption key / at-rest
    /// root source).
    pub identity_priv: PrivateKey,
    /// At-rest root key for sealing the coordinator's own presig share.
    pub at_rest_root: [u8; 32],
    pub bundle_store: Arc<dyn BundleStore>,
}

impl PresignHandler {
    /// Build a fresh presign handler.
    pub fn new(config: PresignHandlerConfig) -> Self {
        assert!(
            config.parties_at_keygen.contains(&config.my_party_index),
            "my_party_index {} not in parties_at_keygen {:?}",
            config.my_party_index,
            config.parties_at_keygen
        );
        assert!(
            config.parties_at_keygen.contains(&config.coordinator_party),
            "coordinator_party {} not in parties_at_keygen {:?}",
            config.coordinator_party,
            config.parties_at_keygen
        );
        // Ascending-order invariant (positional indexing depends on it).
        let mut sorted = config.parties_at_keygen.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted, config.parties_at_keygen,
            "parties_at_keygen MUST be in canonical ascending order"
        );
        Self {
            inner: Arc::new(PresignHandlerInner {
                my_party_index: config.my_party_index,
                coordinator_party: config.coordinator_party,
                parties_at_keygen: config.parties_at_keygen,
                policy_id: config.policy_id,
                identity_priv: config.identity_priv,
                at_rest_root: config.at_rest_root,
                bundle_store: config.bundle_store,
                ceremonies: Mutex::new(HashMap::new()),
                collections: Mutex::new(HashMap::new()),
                completion_tx: Mutex::new(HashMap::new()),
            }),
        }
    }

    fn is_coordinator(&self) -> bool {
        self.inner.my_party_index == self.inner.coordinator_party
    }

    /// Pre-create the `PresigningManager` for `session_id`, run `init_generate`,
    /// and return the round-1 outbound + a completion receiver.
    ///
    /// `share` is this party's DKG key share (with `joint_pubkey_compressed`
    /// filled). `peers` is every OTHER party as `(party_index, identity_hex)`.
    pub async fn initiate(
        &self,
        session_id: SessionId,
        share: EncryptedShare,
        peers: Vec<(u16, String)>,
    ) -> anyhow::Result<(oneshot::Receiver<PresignOutcome>, Vec<OutgoingRoundMessage>)> {
        let joint_pubkey = share_joint_pubkey(&share)?;
        let participants = self.inner.parties_at_keygen.clone();
        let pool = participants.len(); // generate one presig per initiate is plenty for the SM

        let (mgr, initial) = tokio::task::spawn_blocking(
            move || -> anyhow::Result<(PresigningManager, Vec<RoundMessage>)> {
                let mut mgr = PresigningManager::new(session_id, share, participants, pool.max(1));
                let initial = mgr
                    .init_generate()
                    .map_err(|e| anyhow::anyhow!("PresigningManager::init_generate: {e}"))?;
                Ok((mgr, initial))
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("init_generate task panicked: {e}"))??;

        let (tx, rx) = oneshot::channel::<PresignOutcome>();
        let outgoing = wrap_protocol(&initial, session_id, joint_pubkey, &peers);
        {
            let mut c = self.inner.ceremonies.lock().unwrap_or_else(|p| p.into_inner());
            c.insert(
                session_id,
                CeremonySlot {
                    mgr,
                    joint_pubkey,
                    peers,
                },
            );
        }
        {
            let mut t = self
                .inner
                .completion_tx
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            t.insert(session_id, tx);
        }
        Ok((rx, outgoing))
    }

    /// Returns the closure to hand to [`MessageBoxListener::start`]. The same
    /// closure handles BOTH the protocol box and the return box (it routes on
    /// `inbound.message_box`).
    pub fn handler_fn(
        &self,
    ) -> impl Fn(DecodedRoundMessage) -> HandlerFuture + Send + Sync + 'static {
        let handler = self.clone();
        move |inbound: DecodedRoundMessage| -> HandlerFuture {
            let handler = handler.clone();
            Box::pin(async move { handler.dispatch_one(inbound).await })
        }
    }

    /// Test/inspect — number of live ceremonies.
    pub fn live_session_count(&self) -> usize {
        self.inner
            .ceremonies
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    async fn dispatch_one(
        &self,
        inbound: DecodedRoundMessage,
    ) -> anyhow::Result<Vec<OutgoingRoundMessage>> {
        // Route by the in-RoundMessage sentinel, NOT message_box: the relay
        // delivers by identity and a single connection subscribes to both
        // `mpc_{sid}` and `presig_return_{sid}`, so message_box can't tell them
        // apart. A return ciphertext is marked by round == RETURN_SHARE_ROUND.
        if inbound.round_msg.round == RETURN_SHARE_ROUND {
            self.collect_return_share(inbound).await?;
            return Ok(vec![]);
        }

        // Otherwise it's protocol traffic for the SM.
        self.drive_protocol(inbound).await
    }

    async fn drive_protocol(
        &self,
        inbound: DecodedRoundMessage,
    ) -> anyhow::Result<Vec<OutgoingRoundMessage>> {
        let session_id = inbound.round_msg.session_id;

        let slot = {
            let mut c = self.inner.ceremonies.lock().unwrap_or_else(|p| p.into_inner());
            c.remove(&session_id)
        };
        let Some(slot) = slot else {
            warn!(
                "PresignHandler: protocol inbound for unknown session_id {} (no manager); dropping",
                session_id.hex()
            );
            return Ok(vec![]);
        };

        let CeremonySlot {
            mut mgr,
            joint_pubkey,
            peers,
        } = slot;
        let inbound_round_msg = inbound.round_msg;

        let (result, mgr) = tokio::task::spawn_blocking(move || {
            let r = mgr
                .process_generate_round(vec![inbound_round_msg])
                .map_err(|e| anyhow::anyhow!("PresigningManager::process_generate_round: {e}"));
            (r, mgr)
        })
        .await
        .map_err(|e| anyhow::anyhow!("process_generate_round task panicked: {e}"))?;

        let result = result?;

        match result {
            PresigningRoundResult::NextRound(next_msgs) => {
                let outgoing = wrap_protocol(&next_msgs, session_id, joint_pubkey, &peers);
                let mut c = self.inner.ceremonies.lock().unwrap_or_else(|p| p.into_inner());
                c.insert(
                    session_id,
                    CeremonySlot {
                        mgr,
                        joint_pubkey,
                        peers,
                    },
                );
                drop(c);
                debug!(
                    "PresignHandler: session={} produced {} outbound",
                    session_id.hex(),
                    outgoing.len()
                );
                Ok(outgoing)
            }
            PresigningRoundResult::Complete => {
                self.on_presign_complete(session_id, joint_pubkey, peers, mgr)
                    .await
            }
        }
    }

    /// Round-3 complete (§06.16): extract this party's presig share and run the
    /// role-specific path.
    async fn on_presign_complete(
        &self,
        session_id: SessionId,
        joint_pubkey: [u8; 33],
        peers: Vec<(u16, String)>,
        mut mgr: PresigningManager,
    ) -> anyhow::Result<Vec<OutgoingRoundMessage>> {
        let presig_id = session_id.hex();

        let (meta, raw) = mgr
            .take_raw()
            .ok_or_else(|| anyhow::anyhow!("presign complete but pool empty (no raw presig)"))?;
        let _ = meta;

        if self.is_coordinator() {
            // Coordinator keeps its OWN share (sealed at-rest, §06.17.1) + the
            // shared public data (durable CBOR for cross-restart combine, #25a)
            // and opens the collection slot. Cosigner ciphertexts arrive on the
            // return box.
            let (serialized, public_data_cbor, gamma_hex) =
                serialize_party_presig_with_public_data(raw).map_err(|e| {
                    anyhow::anyhow!("serialize coordinator presig + public data: {e}")
                })?;
            let at_rest_key = derive_presig_at_rest_key(&self.inner.at_rest_root, &presig_id);
            let sealed = seal_presig_bytes(&serialized, &at_rest_key)
                .map_err(|e| anyhow::anyhow!("seal coordinator presig: {e}"))?;

            let n = self.inner.parties_at_keygen.len();
            {
                let mut col = self.inner.collections.lock().unwrap_or_else(|p| p.into_inner());
                col.entry(session_id).or_insert_with(|| CollectionSlot {
                    own_presig_sealed: sealed,
                    public_data_cbor,
                    gamma_hex,
                    presig_id: presig_id.clone(),
                    joint_pubkey,
                    cosigner_shares: vec![None; n],
                    ack_ids: Vec::new(),
                });
            }
            info!(
                "PresignHandler[coord]: session={} round-3 done, awaiting {} cosigner return share(s)",
                presig_id,
                n - 1
            );
            // Maybe everything already arrived (return shares can race ahead).
            self.try_finalize_bundle(session_id, joint_pubkey).await?;
            Ok(vec![])
        } else {
            // Cosigner: BRC-2 self-encrypt the share and ship it to the
            // coordinator on the return box (§06.16 step 3). It keeps no
            // plaintext and no public data (the coordinator holds those).
            let serialized = serialize_party_presignature(raw)
                .map_err(|e| anyhow::anyhow!("serialize_party_presignature: {e}"))?;
            let wallet = wallet_from_identity(&self.inner.identity_priv);
            let ciphertext = encrypt_presig_share(&wallet, &presig_id, &serialized)
                .map_err(|e| anyhow::anyhow!("encrypt_presig_share: {e}"))?;

            let coordinator = peers
                .iter()
                .find(|(idx, _)| *idx == self.inner.coordinator_party)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "coordinator party {} not in peer set {:?}",
                        self.inner.coordinator_party,
                        peers.iter().map(|(p, _)| *p).collect::<Vec<_>>()
                    )
                })?;

            let return_msg = RoundMessage {
                session_id,
                round: RETURN_SHARE_ROUND,
                from: ShareIndex(self.inner.my_party_index),
                to: Some(ShareIndex(self.inner.coordinator_party)),
                payload: ciphertext,
            };
            let out = OutgoingRoundMessage {
                recipient_pub_hex: coordinator.1.clone(),
                message_box: presig_return_box(&presig_id),
                round_msg: return_msg,
                params: presign_wrap_params(
                    session_id,
                    joint_pubkey,
                    self.inner.coordinator_party,
                ),
            };
            info!(
                "PresignHandler[cosigner {}]: shipping return ciphertext to coordinator {}",
                self.inner.my_party_index, self.inner.coordinator_party
            );
            self.fire_completion(session_id, PresignOutcome::ReturnShipped);
            Ok(vec![out])
        }
    }

    /// Coordinator: a return ciphertext arrived. Store it positionally and try
    /// to finalize.
    async fn collect_return_share(&self, inbound: DecodedRoundMessage) -> anyhow::Result<()> {
        if !self.is_coordinator() {
            warn!("PresignHandler: non-coordinator received a return-box message; ignoring");
            return Ok(());
        }
        let session_id = inbound.round_msg.session_id;
        let from_party = inbound.round_msg.from.0;
        let ciphertext = inbound.round_msg.payload;

        let pos = self
            .inner
            .parties_at_keygen
            .iter()
            .position(|&p| p == from_party)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "return share from party {from_party} not in parties_at_keygen {:?}",
                    self.inner.parties_at_keygen
                )
            })?;

        let joint_pubkey = {
            let mut col = self.inner.collections.lock().unwrap_or_else(|p| p.into_inner());
            let Some(slot) = col.get_mut(&session_id) else {
                // Round-3 hasn't completed on the coordinator yet (return share
                // raced ahead of the coordinator's own SM completion). The
                // collection slot — which holds the sealed own-share — doesn't
                // exist yet, so we can't store this ciphertext positionally.
                // Re-deliver: surface as an error so the listener logs + the
                // relay leaves the message un-acked for redelivery on the next
                // backfill (§06.12). In practice the coordinator (party 0) drives
                // round-3 to completion before the cosigner ships, so this is
                // rare.
                warn!(
                    "PresignHandler[coord]: return share for session {} arrived before \
                     coordinator round-3 complete; leaving un-acked for redelivery",
                    session_id.hex()
                );
                return Ok(());
            };
            slot.cosigner_shares[pos] = Some(ciphertext);
            slot.ack_ids.push(inbound.message_id);
            slot.joint_pubkey
        };

        self.try_finalize_bundle(session_id, joint_pubkey).await?;
        Ok(())
    }

    /// Assemble + persist the bundle iff the coordinator's own share is sealed
    /// AND every cosigner ciphertext has arrived.
    async fn try_finalize_bundle(
        &self,
        session_id: SessionId,
        joint_pubkey: [u8; 33],
    ) -> anyhow::Result<()> {
        let bundle = {
            let mut col = self.inner.collections.lock().unwrap_or_else(|p| p.into_inner());
            let Some(slot) = col.get(&session_id) else {
                return Ok(());
            };
            // All cosigner slots (every party except the coordinator) filled?
            let all_filled = self
                .inner
                .parties_at_keygen
                .iter()
                .enumerate()
                .all(|(pos, &party)| {
                    party == self.inner.coordinator_party || slot.cosigner_shares[pos].is_some()
                });
            if !all_filled {
                return Ok(());
            }

            // Build positional cosigner_encrypted_shares: the coordinator's own
            // slot is the empty ciphertext (its plaintext lives in presig_bytes);
            // every cosigner slot is its BRC-2 ciphertext.
            let cosigner_encrypted_shares = self
                .inner
                .parties_at_keygen
                .iter()
                .enumerate()
                .map(|(pos, _party)| {
                    serde_bytes::ByteBuf::from(slot.cosigner_shares[pos].clone().unwrap_or_default())
                })
                .collect::<Vec<_>>();

            let bundle = PresigBundle {
                presig_id: slot.presig_id.clone(),
                presig_bytes: slot.own_presig_sealed.clone(),
                cosigner_encrypted_shares,
                gamma_hex: slot.gamma_hex.clone(),
                commitments: slot.public_data_cbor.clone(),
                policy_id: self.inner.policy_id,
                joint_pubkey: joint_pubkey.to_vec(),
                parties_at_keygen: self.inner.parties_at_keygen.clone(),
                generated_at: now_unix(),
            };
            let ack_ids = slot.ack_ids.clone();
            // Remove the collection slot atomically with the read so a racing
            // duplicate finalize is a no-op.
            col.remove(&session_id);
            (bundle, ack_ids)
        };
        let (bundle, ack_ids) = bundle;

        self.inner
            .bundle_store
            .persist(&bundle)
            .map_err(|e| anyhow::anyhow!("persist PresigBundle: {e}"))?;
        info!(
            "PresignHandler[coord]: PresigBundle persisted — presig_id={} cosigner_shares={} parties={:?}",
            bundle.presig_id,
            bundle.cosigner_encrypted_shares.len(),
            bundle.parties_at_keygen
        );

        // Best-effort: acknowledge the consumed return messages so the relay can
        // GC the transient mailbox (§06.13 / §06.17.2). The listener already
        // owns the client; acks here would need it too — defer to the caller via
        // the completion signal (it has the client). We surface the ids isn't
        // necessary for correctness, so we just log the count.
        debug!(
            "PresignHandler[coord]: {} return message(s) ready to acknowledge for relay GC",
            ack_ids.len()
        );

        self.fire_completion(session_id, PresignOutcome::BundlePersisted(Box::new(bundle)));
        Ok(())
    }

    fn fire_completion(&self, session_id: SessionId, outcome: PresignOutcome) {
        let tx = {
            let mut t = self
                .inner
                .completion_tx
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            t.remove(&session_id)
        };
        if let Some(tx) = tx {
            let _ = tx.send(outcome);
        }
    }
}

/// Compute the canonical presign execution_id_prefix (§02, phase=Presign) and
/// wrap protocol-traffic round messages addressed to peers (broadcast → all,
/// p2p → matching peer).
fn wrap_protocol(
    round_msgs: &[RoundMessage],
    session_id: SessionId,
    joint_pubkey: [u8; 33],
    peers: &[(u16, String)],
) -> Vec<OutgoingRoundMessage> {
    let prefix = presign_eid_prefix(session_id, joint_pubkey);
    let box_name = presign_protocol_box(&session_id.hex());

    let mut out = Vec::new();
    for rm in round_msgs {
        let targets: Vec<&(u16, String)> = match rm.to {
            None => peers.iter().collect(),
            Some(ShareIndex(idx)) => peers.iter().filter(|(p, _)| *p == idx).collect(),
        };
        if targets.is_empty() {
            warn!(
                "PresignHandler: outgoing p2p to party {:?} not in peers {:?}; dropping",
                rm.to,
                peers.iter().map(|(p, _)| *p).collect::<Vec<_>>()
            );
            continue;
        }
        for (idx, hex) in targets {
            out.push(OutgoingRoundMessage {
                recipient_pub_hex: hex.clone(),
                message_box: box_name.clone(),
                round_msg: rm.clone(),
                params: WrapParams {
                    to_party: *idx,
                    joint_pubkey,
                    phase: PhaseTag::Presign.envelope_str().to_string(),
                    execution_id_prefix: prefix,
                    correlation_id: None,
                    traceparent: None,
                },
            });
        }
    }
    out
}

fn presign_wrap_params(
    session_id: SessionId,
    joint_pubkey: [u8; 33],
    to_party: u16,
) -> WrapParams {
    WrapParams {
        to_party,
        joint_pubkey,
        phase: PhaseTag::Presign.envelope_str().to_string(),
        execution_id_prefix: presign_eid_prefix(session_id, joint_pubkey),
        correlation_id: None,
        traceparent: None,
    }
}

fn presign_eid_prefix(session_id: SessionId, joint_pubkey: [u8; 33]) -> [u8; 8] {
    let eid = canonical_execution_id(&ExecutionParams::new_v1(
        PhaseTag::Presign,
        session_id,
        joint_pubkey,
    ));
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&eid[..8]);
    prefix
}

fn share_joint_pubkey(share: &EncryptedShare) -> anyhow::Result<[u8; 33]> {
    let jpk = &share.joint_pubkey_compressed;
    if jpk.len() != 33 {
        anyhow::bail!(
            "share.joint_pubkey_compressed is {} bytes (need 33) — presign requires the joint key",
            jpk.len()
        );
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(jpk);
    Ok(out)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_priv() -> PrivateKey {
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b[0] |= 0x01;
        PrivateKey::from_bytes(&b).unwrap()
    }

    fn handler(my: u16, coord: u16, store: Arc<dyn BundleStore>) -> PresignHandler {
        PresignHandler::new(PresignHandlerConfig {
            my_party_index: my,
            coordinator_party: coord,
            parties_at_keygen: vec![0, 1],
            policy_id: PolicyId([0x11; 32]),
            identity_priv: fresh_priv(),
            at_rest_root: [0x42; 32],
            bundle_store: store,
        })
    }

    #[test]
    fn constructs_and_reports_role() {
        let store = Arc::new(InMemoryBundleStore::new());
        let coord = handler(0, 0, store.clone());
        assert!(coord.is_coordinator());
        assert_eq!(coord.live_session_count(), 0);
        let cosigner = handler(1, 0, store);
        assert!(!cosigner.is_coordinator());
    }

    #[test]
    #[should_panic(expected = "not in parties_at_keygen")]
    fn rejects_party_outside_subset() {
        let store = Arc::new(InMemoryBundleStore::new());
        let _ = PresignHandler::new(PresignHandlerConfig {
            my_party_index: 5,
            coordinator_party: 0,
            parties_at_keygen: vec![0, 1],
            policy_id: PolicyId([0x11; 32]),
            identity_priv: fresh_priv(),
            at_rest_root: [0x42; 32],
            bundle_store: store,
        });
    }

    #[test]
    #[should_panic(expected = "ascending order")]
    fn rejects_unsorted_subset() {
        let store = Arc::new(InMemoryBundleStore::new());
        let _ = PresignHandler::new(PresignHandlerConfig {
            my_party_index: 1,
            coordinator_party: 0,
            parties_at_keygen: vec![1, 0],
            policy_id: PolicyId([0x11; 32]),
            identity_priv: fresh_priv(),
            at_rest_root: [0x42; 32],
            bundle_store: store,
        });
    }

    #[test]
    fn presign_eid_prefix_is_deterministic_and_key_bound() {
        let sid = SessionId([0xaa; 32]);
        let mut jpk = [0u8; 33];
        jpk[0] = 0x02;
        let a = presign_eid_prefix(sid, jpk);
        let b = presign_eid_prefix(sid, jpk);
        assert_eq!(a, b, "deterministic");
        let mut jpk2 = jpk;
        jpk2[32] = 0x01;
        assert_ne!(
            a,
            presign_eid_prefix(sid, jpk2),
            "different joint pubkey → different prefix"
        );
        let sid2 = SessionId([0xbb; 32]);
        assert_ne!(
            a,
            presign_eid_prefix(sid2, jpk),
            "different session → different prefix"
        );
    }

    #[test]
    fn wrap_protocol_uses_session_scoped_box_and_presign_phase() {
        let sid = SessionId([0x77; 32]);
        let mut jpk = [0u8; 33];
        jpk[0] = 0x02;
        let rm = RoundMessage {
            session_id: sid,
            round: 0,
            from: ShareIndex(0),
            to: None, // broadcast
            payload: vec![1, 2, 3],
        };
        let out = wrap_protocol(
            std::slice::from_ref(&rm),
            sid,
            jpk,
            &[(1u16, "02deadbeef".to_string())],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].params.phase, "presign");
        assert_eq!(out[0].params.joint_pubkey, jpk);
        assert_eq!(out[0].params.to_party, 1);
        // §06.17.2 spelling: mpc_{session_id_hex}
        assert_eq!(out[0].message_box, format!("mpc_{}", sid.hex()));
    }

    #[test]
    fn in_memory_bundle_store_persists_and_fetches() {
        let store = InMemoryBundleStore::new();
        assert!(store.is_empty());
        let bundle = PresigBundle {
            presig_id: "presig-xyz".to_string(),
            presig_bytes: vec![0xaa; 16],
            cosigner_encrypted_shares: vec![
                serde_bytes::ByteBuf::from(vec![]),
                serde_bytes::ByteBuf::from(vec![0x01, 0x02]),
            ],
            gamma_hex: String::new(),
            commitments: Vec::new(),
            policy_id: PolicyId([0x11; 32]),
            joint_pubkey: vec![0x02; 33],
            parties_at_keygen: vec![0, 1],
            generated_at: 1,
        };
        store.persist(&bundle).unwrap();
        assert_eq!(store.len(), 1);
        let got = store.get("presig-xyz").unwrap();
        assert_eq!(got, bundle);
    }

    /// **§06.17.1 durability** — the file-backed store survives a "restart":
    /// persist with one handle, reopen a fresh handle on the same dir, and the
    /// bundle reloads byte-identical. Also proves overwrite (re-persist) works.
    #[test]
    fn file_bundle_store_persists_reloads_and_overwrites() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Canonical presig_id = a 64-char session_id hex (the real shape).
        let presig_id = "ab".repeat(32);
        let bundle = PresigBundle {
            presig_id: presig_id.clone(),
            presig_bytes: vec![0xaa; 16],
            cosigner_encrypted_shares: vec![
                serde_bytes::ByteBuf::from(vec![]),
                serde_bytes::ByteBuf::from(vec![0x01, 0x02, 0x03]),
            ],
            gamma_hex: "deadbeef".to_string(),
            commitments: vec![0xc0, 0x1d],
            policy_id: PolicyId([0x22; 32]),
            joint_pubkey: vec![0x03; 33],
            parties_at_keygen: vec![0, 1],
            generated_at: 42,
        };

        {
            let store = FileBundleStore::new(dir.path()).expect("open store");
            assert!(store.get(&presig_id).is_none(), "empty before persist");
            store.persist(&bundle).expect("persist");
        }
        // Fresh handle on the same dir = a coordinator restart.
        let reopened = FileBundleStore::new(dir.path()).expect("reopen store");
        let got = reopened.get(&presig_id).expect("reload after restart");
        assert_eq!(got, bundle, "durable bundle reloads byte-identical");

        // Overwrite (atomic rename) with a mutated bundle.
        let mut bundle2 = bundle.clone();
        bundle2.generated_at = 99;
        reopened.persist(&bundle2).expect("re-persist");
        assert_eq!(
            reopened.get(&presig_id).expect("reload after overwrite"),
            bundle2,
            "re-persist overwrites in place"
        );

        // Unknown id → None.
        assert!(reopened.get("nope").is_none());
    }

    /// **Item-1 gate** — PresigBundle assembly produces positional
    /// `cosigner_encrypted_shares` (the §06.17.1 "indexed positionally by party
    /// order in parties_at_keygen" requirement). Coordinator = party 0; its own
    /// slot is the empty ciphertext (plaintext in `presig_bytes`); party 1's
    /// ciphertext lands at index 1.
    #[tokio::test]
    async fn assembles_bundle_with_positional_cosigner_shares() {
        let store = Arc::new(InMemoryBundleStore::new());
        let coord = handler(0, 0, store.clone());
        let sid = SessionId([0x33; 32]);
        let mut jpk = [0u8; 33];
        jpk[0] = 0x02;
        jpk[32] = 0xcd;

        // Simulate coordinator round-3 completing: seal a stand-in own share +
        // open the collection slot.
        let presig_id = sid.hex();
        let at_rest_key = derive_presig_at_rest_key(&[0x42; 32], &presig_id);
        let sealed = seal_presig_bytes(b"coordinator-own-presig-share", &at_rest_key).unwrap();
        {
            let mut col = coord
                .inner
                .collections
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            col.insert(
                sid,
                CollectionSlot {
                    own_presig_sealed: sealed.clone(),
                    public_data_cbor: b"stub-public-data-cbor".to_vec(),
                    gamma_hex: "02deadbeef".to_string(),
                    presig_id: presig_id.clone(),
                    joint_pubkey: jpk,
                    cosigner_shares: vec![None, None],
                    ack_ids: Vec::new(),
                },
            );
        }
        // Not finalizable yet (party 1 share missing).
        coord.try_finalize_bundle(sid, jpk).await.unwrap();
        assert!(store.is_empty(), "must NOT finalize before all shares arrive");

        // Party 1's return ciphertext arrives.
        let p1_ciphertext = b"party-1-brc2-ciphertext".to_vec();
        coord
            .collect_return_share(DecodedRoundMessage {
                message_id: "ret-1".into(),
                message_box: presig_return_box(&presig_id),
                sender_pub: fresh_priv().public_key(),
                round_msg: RoundMessage {
                    session_id: sid,
                    round: RETURN_SHARE_ROUND,
                    from: ShareIndex(1),
                    to: Some(ShareIndex(0)),
                    payload: p1_ciphertext.clone(),
                },
                via: bsv_mpc_messagebox::InboundVia::WsPush,
            })
            .await
            .unwrap();
        // collect_return_share can't see joint_pubkey (ceremony slot gone), so it
        // doesn't auto-finalize; drive the finalize explicitly as the complete
        // path would.
        coord.try_finalize_bundle(sid, jpk).await.unwrap();

        let bundle = store.get(&presig_id).expect("bundle MUST be persisted");
        assert_eq!(bundle.presig_id, presig_id);
        assert_eq!(bundle.presig_bytes, sealed, "coordinator's own sealed share");
        assert_eq!(bundle.parties_at_keygen, vec![0, 1]);
        assert_eq!(bundle.cosigner_encrypted_shares.len(), 2);
        // Positional: index 0 = coordinator (empty), index 1 = party-1 ciphertext.
        assert!(
            bundle.cosigner_encrypted_shares[0].is_empty(),
            "coordinator's positional slot is empty (its plaintext is in presig_bytes)"
        );
        assert_eq!(
            bundle.cosigner_encrypted_shares[1].as_slice(),
            p1_ciphertext.as_slice(),
            "party-1 ciphertext MUST land at positional index 1"
        );
        assert_eq!(bundle.joint_pubkey, jpk.to_vec());
        assert_eq!(bundle.policy_id, PolicyId([0x11; 32]));
    }
}
