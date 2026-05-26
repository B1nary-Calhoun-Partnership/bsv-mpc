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

use std::collections::{HashMap, VecDeque};
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
    EncryptedShare, InvalidationTrigger, PolicyId, PresigBundle, RoundMessage, SessionId,
    ShareIndex,
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
    /// **Early-inbound / out-of-order buffer** (mirrors [`crate::dkg_handler`] and
    /// [`crate::reshar_handler`], the §06.17 ordering discipline). With the
    /// WS-live-push ordering — every party subscribes BEFORE any party ships
    /// round-1 (see `relay_presign::coordinate_presign_over_relay` /
    /// [`crate::relay_handlers::handle_presign_relay_init`]) — a peer's protocol
    /// round message can still be delivered (live OR via backfill) to a party
    /// whose `CeremonySlot` is momentarily checked-out for processing, or before
    /// `initiate` has registered it. Dropping such a message stalls the presign:
    /// the relay does not re-deliver, the cosigner never advances, and the
    /// coordinator times out "awaiting PresigBundle assembly". So we BUFFER here,
    /// keyed by session, and replay the moment the slot is (re)registered. The
    /// cggmp24 presigning SM already buffers out-of-order rounds internally
    /// (`presigning.rs` `wire_buffer`), so replay order across rounds is safe.
    pending_inbound: Mutex<HashMap<SessionId, Vec<DecodedRoundMessage>>>,
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

    /// §06.18 **mandatory invalidation**: delete every stored bundle the
    /// `trigger` fires on (per [`PresigBundle::invalidated_by`]), best-effort
    /// **zeroizing** the bytes (overwrite-then-remove). Returns the count purged.
    ///
    /// A bundle MUST NOT be consumable across an invalidation boundary, so this
    /// is called atomically with the trigger event (share refresh, policy update,
    /// cosigner-subset change, joint-pubkey rekey) before any sign request that
    /// could use a now-stale bundle.
    fn invalidate(&self, trigger: &InvalidationTrigger) -> anyhow::Result<u64>;

    /// §06.17.3 **single-use consume**: atomically remove the bundle for
    /// `presig_id` and return it, or `None` if it is absent / already consumed.
    /// The removal MUST be atomic so a bundle can be consumed **at most once**
    /// even under concurrent sign requests — this is the spec-level mitigation for
    /// the CVE-2025-66017 presignature-forgery class. Removal zeroizes the bytes
    /// (same erase semantics as [`invalidate`](Self::invalidate)).
    fn consume(&self, presig_id: &str) -> anyhow::Result<Option<PresigBundle>>;
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

    fn invalidate(&self, trigger: &InvalidationTrigger) -> anyhow::Result<u64> {
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let doomed: Vec<String> = map
            .iter()
            .filter(|(_, b)| b.invalidated_by(trigger))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &doomed {
            // In-memory drop is the zeroize analogue (no on-disk bytes to scrub).
            map.remove(id);
        }
        Ok(doomed.len() as u64)
    }

    fn consume(&self, presig_id: &str) -> anyhow::Result<Option<PresigBundle>> {
        // `HashMap::remove` under the lock is atomic — a second consume returns None.
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(presig_id))
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

    /// All persisted bundles' `(path, bundle)` pairs (skips unreadable / non-JSON
    /// entries). Used by [`BundleStore::invalidate`] to scan the pool.
    fn all_bundles(&self) -> Vec<(std::path::PathBuf, PresigBundle)> {
        let Ok(rd) = std::fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(b) = serde_json::from_slice::<PresigBundle>(&bytes) {
                    out.push((path, b));
                }
            }
        }
        out
    }

    /// Best-effort **zeroizing** delete of a bundle file (§06.18): overwrite the
    /// bytes with zeros + flush before removing, so the secret-bearing JSON is not
    /// merely unlinked. Filesystems without erase semantics still get the
    /// overwrite (the spec's truncate-and-rewrite floor).
    fn zeroize_and_remove(path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        if let Ok(meta) = std::fs::metadata(path) {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                let zeros = vec![0u8; meta.len() as usize];
                let _ = f.write_all(&zeros);
                let _ = f.flush();
                let _ = f.sync_all();
            }
        }
        std::fs::remove_file(path)
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

    fn invalidate(&self, trigger: &InvalidationTrigger) -> anyhow::Result<u64> {
        let mut purged = 0u64;
        for (path, bundle) in self.all_bundles() {
            if bundle.invalidated_by(trigger) {
                Self::zeroize_and_remove(&path).map_err(|e| {
                    anyhow::anyhow!("zeroize bundle {}: {e}", path.display())
                })?;
                purged += 1;
            }
        }
        Ok(purged)
    }

    fn consume(&self, presig_id: &str) -> anyhow::Result<Option<PresigBundle>> {
        let path = self.path_for(presig_id);
        // Atomic claim: rename the bundle file to a unique sibling. `rename` is
        // atomic on POSIX, so exactly one concurrent consumer wins; the loser's
        // rename fails with NotFound → None. This makes single-use race-free
        // (§06.17.3) without a lock spanning the read.
        static CLAIM_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = CLAIM_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let claim = path.with_extension(format!(
            "consuming.{}.{nanos}.{seq}",
            std::process::id()
        ));
        match std::fs::rename(&path, &claim) {
            Ok(()) => {
                let bytes = std::fs::read(&claim)
                    .map_err(|e| anyhow::anyhow!("read claimed bundle {}: {e}", claim.display()))?;
                let bundle: PresigBundle = serde_json::from_slice(&bytes).map_err(|e| {
                    anyhow::anyhow!("parse claimed bundle {}: {e}", claim.display())
                })?;
                // Zeroize the claimed copy (overwrite-then-remove) per §06.18.
                Self::zeroize_and_remove(&claim).map_err(|e| {
                    anyhow::anyhow!("zeroize consumed bundle {}: {e}", claim.display())
                })?;
                Ok(Some(bundle))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::anyhow!("claim bundle {}: {e}", path.display())),
        }
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
                pending_inbound: Mutex::new(HashMap::new()),
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
        let mut outgoing =
            wrap_protocol(&initial, session_id, joint_pubkey, &peers, &self.inner.parties_at_keygen);
        {
            let mut t = self
                .inner
                .completion_tx
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            t.insert(session_id, tx);
        }
        // Register the slot, then drain any EARLY-INBOUND buffered before this
        // `initiate` (a peer round-1 that raced ahead of us under WS live-push).
        // Hold the `ceremonies` lock across the `pending_inbound` drain so no
        // buffered message is lost between the insert and the drain (same lock
        // discipline as `DkgHandler::initiate`).
        let buffered: Vec<DecodedRoundMessage> = {
            let mut c = self.inner.ceremonies.lock().unwrap_or_else(|p| p.into_inner());
            c.insert(
                session_id,
                CeremonySlot {
                    mgr,
                    joint_pubkey,
                    peers,
                },
            );
            self.inner
                .pending_inbound
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&session_id)
                .unwrap_or_default()
        };
        // Replay buffered inbounds through the normal dispatch path; accumulate
        // any outbound the SM produces so the caller ships it alongside round-1.
        if !buffered.is_empty() {
            debug!(
                "PresignHandler: replaying {} buffered inbound(s) for session {} after initiate",
                buffered.len(),
                session_id.hex()
            );
            for msg in buffered {
                // Buffered messages are already position-space (translated in
                // `dispatch_one` before they were buffered), so replay via
                // `drive_protocol` — NOT `dispatch_one`, which would translate again.
                match self.drive_protocol(msg).await {
                    Ok(mut more) => outgoing.append(&mut more),
                    Err(e) => warn!(
                        "PresignHandler: replay of buffered inbound for session {} failed: {e}",
                        session_id.hex()
                    ),
                }
            }
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
        mut inbound: DecodedRoundMessage,
    ) -> anyhow::Result<Vec<OutgoingRoundMessage>> {
        // Route by the in-RoundMessage sentinel, NOT message_box: the relay
        // delivers by identity and a single connection subscribes to both
        // `mpc_{sid}` and `presig_return_{sid}`, so message_box can't tell them
        // apart. A return ciphertext is marked by round == RETURN_SHARE_ROUND.
        // The return channel uses ABSOLUTE indices end-to-end (see
        // `collect_return_share`), so it is NOT index-translated.
        if inbound.round_msg.round == RETURN_SHARE_ROUND {
            self.collect_return_share(inbound).await?;
            return Ok(vec![]);
        }

        // Protocol traffic: the wire carries ABSOLUTE keygen indices (§05.4.6,
        // see `wrap_protocol`), but the cggmp24 SM works in subset-POSITION space.
        // Translate from/to absolute → position so the SM sees exactly the
        // positions it emitted (inverse of `wrap_protocol`'s send-side translation;
        // a no-op for a contiguous subset). All downstream state — `drive_protocol`,
        // the `pending_inbound` buffer, and the `initiate` replay — is therefore
        // position-space, so buffered messages MUST be replayed via `drive_protocol`
        // (not `dispatch_one`) to avoid a double translation.
        let pak = &self.inner.parties_at_keygen;
        match pak.iter().position(|&p| p == inbound.round_msg.from.0) {
            Some(pos) => inbound.round_msg.from = ShareIndex(pos as u16),
            None => {
                warn!(
                    "PresignHandler: inbound from absolute index {} not in subset {:?}; dropping",
                    inbound.round_msg.from.0, pak
                );
                return Ok(vec![]);
            }
        }
        if let Some(ShareIndex(abs)) = inbound.round_msg.to {
            if let Some(pos) = pak.iter().position(|&p| p == abs) {
                inbound.round_msg.to = Some(ShareIndex(pos as u16));
            }
        }

        // Otherwise it's protocol traffic for the SM.
        self.drive_protocol(inbound).await
    }

    async fn drive_protocol(
        &self,
        inbound: DecodedRoundMessage,
    ) -> anyhow::Result<Vec<OutgoingRoundMessage>> {
        let session_id = inbound.round_msg.session_id;
        let mut all_outgoing: Vec<OutgoingRoundMessage> = Vec::new();
        // Work queue: the triggering inbound, then any messages drained from the
        // pending buffer as the SM advances (closes the race where a peer message
        // arrives while the slot is checked out for processing).
        let mut queue: VecDeque<DecodedRoundMessage> = VecDeque::new();
        queue.push_back(inbound);

        while let Some(next) = queue.pop_front() {
            // Take the slot out — `process_generate_round` is sync-blocking and we
            // don't hold the lock across the await. If the slot is not registered
            // (peer round raced ahead of `initiate`, or it is checked-out for a
            // concurrent step), BUFFER the inbound instead of DROPPING it — the
            // relay never re-delivers, so a drop deadlocks the presign. `initiate`
            // (or the post-advance drain below) replays it once the slot exists.
            // Lock order `ceremonies` → `pending_inbound` matches `initiate`.
            let slot = {
                let mut c = self.inner.ceremonies.lock().unwrap_or_else(|p| p.into_inner());
                match c.remove(&session_id) {
                    Some(s) => s,
                    None => {
                        let mut pend =
                            self.inner.pending_inbound.lock().unwrap_or_else(|p| p.into_inner());
                        let buf = pend.entry(session_id).or_default();
                        buf.push(next);
                        buf.extend(queue.drain(..));
                        debug!(
                            "PresignHandler: protocol inbound for session {} buffered (slot \
                             checked-out or not yet initiated); will replay",
                            session_id.hex()
                        );
                        return Ok(all_outgoing);
                    }
                }
            };

            let CeremonySlot {
                mut mgr,
                joint_pubkey,
                peers,
            } = slot;
            let inbound_round_msg = next.round_msg;

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
                    let mut outgoing = wrap_protocol(
                        &next_msgs,
                        session_id,
                        joint_pubkey,
                        &peers,
                        &self.inner.parties_at_keygen,
                    );
                    {
                        let mut c =
                            self.inner.ceremonies.lock().unwrap_or_else(|p| p.into_inner());
                        c.insert(
                            session_id,
                            CeremonySlot {
                                mgr,
                                joint_pubkey,
                                peers,
                            },
                        );
                    }
                    debug!(
                        "PresignHandler: session={} produced {} outbound",
                        session_id.hex(),
                        outgoing.len()
                    );
                    all_outgoing.append(&mut outgoing);
                    // Drain anything buffered while the slot was checked out and
                    // keep processing it in this same call.
                    let drained: Vec<DecodedRoundMessage> = self
                        .inner
                        .pending_inbound
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(&session_id)
                        .unwrap_or_default();
                    queue.extend(drained);
                }
                PresigningRoundResult::Complete => {
                    let mut more = self
                        .on_presign_complete(session_id, joint_pubkey, peers, mgr)
                        .await?;
                    all_outgoing.append(&mut more);
                    // Ceremony slot is consumed (the coordinator's moves to a
                    // collection slot; the cosigner shipped its return). Drop any
                    // late protocol buffer for this session — nothing more to drive.
                    self.inner
                        .pending_inbound
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(&session_id);
                    return Ok(all_outgoing);
                }
            }
        }

        Ok(all_outgoing)
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
///
/// **Index spaces (MPC-Spec §05.4.6).** The cggmp24 presigning/signing SM
/// identifies parties by their 0-based POSITION within the signing subset
/// (`[0, t)`), so the `RoundMessage.{from,to}` produced by [`drive_inline`] carry
/// positions. But `peers` and the canonical wire `from_party`/`to_party` are
/// keyed by the ABSOLUTE keygen party index (the entries of `parties_at_keygen`,
/// which a BRC-52 cert lookup keys on). `parties_at_keygen[pos] == absolute`, so
/// we translate position → absolute here before routing + emitting. Without this,
/// a NON-CONTIGUOUS subset (e.g. `{0,2}`: party 2 is SM-position 1) mis-addresses
/// every p2p message — `wrap_protocol` finds no peer with absolute index 1, drops
/// it, and the ceremony deadlocks ("awaiting PresigBundle assembly"). A CONTIGUOUS
/// subset (`{0,1}`) is unaffected because position == absolute. The receive side
/// ([`PresignHandler::dispatch_one`]) performs the inverse absolute → position
/// translation, so the SM only ever sees positions.
fn wrap_protocol(
    round_msgs: &[RoundMessage],
    session_id: SessionId,
    joint_pubkey: [u8; 33],
    peers: &[(u16, String)],
    parties_at_keygen: &[u16],
) -> Vec<OutgoingRoundMessage> {
    let prefix = presign_eid_prefix(session_id, joint_pubkey);
    let box_name = presign_protocol_box(&session_id.hex());
    let pos_to_abs = |pos: u16| -> Option<u16> { parties_at_keygen.get(pos as usize).copied() };

    let mut out = Vec::new();
    for rm in round_msgs {
        // `from` is THIS party's SM position → its absolute keygen index.
        let Some(from_abs) = pos_to_abs(rm.from.0) else {
            warn!(
                "PresignHandler: outgoing from SM-position {} outside subset {:?}; dropping",
                rm.from.0, parties_at_keygen
            );
            continue;
        };
        // Resolve targets (by absolute index) + the absolute `to` for the wire.
        let (targets, to_abs): (Vec<&(u16, String)>, Option<u16>) = match rm.to {
            None => (peers.iter().collect(), None),
            Some(ShareIndex(pos)) => match pos_to_abs(pos) {
                Some(abs) => (peers.iter().filter(|(p, _)| *p == abs).collect(), Some(abs)),
                None => (Vec::new(), None),
            },
        };
        if targets.is_empty() {
            warn!(
                "PresignHandler: outgoing p2p to SM-position {:?} (abs {:?}) not in peers {:?}; dropping",
                rm.to,
                to_abs,
                peers.iter().map(|(p, _)| *p).collect::<Vec<_>>()
            );
            continue;
        }
        // Emit with ABSOLUTE from/to on the wire (§05.4.6).
        let mut wire_msg = rm.clone();
        wire_msg.from = ShareIndex(from_abs);
        wire_msg.to = to_abs.map(ShareIndex);
        for (idx, hex) in targets {
            out.push(OutgoingRoundMessage {
                recipient_pub_hex: hex.clone(),
                message_box: box_name.clone(),
                round_msg: wire_msg.clone(),
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
            &[0u16, 1u16],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].params.phase, "presign");
        assert_eq!(out[0].params.joint_pubkey, jpk);
        assert_eq!(out[0].params.to_party, 1);
        // §06.17.2 spelling: mpc_{session_id_hex}
        assert_eq!(out[0].message_box, format!("mpc_{}", sid.hex()));
    }

    /// **Regression for the deterministic `{0,2}` presign-over-relay timeout.** A
    /// NON-CONTIGUOUS subset must route p2p by ABSOLUTE keygen index, not the
    /// cggmp24 SM position. Party 2 is SM-position 1 in subset `[0,2]`; a p2p
    /// message the SM addresses to position 1 MUST reach the peer whose absolute
    /// index is 2, and the emitted wire `to`/`from` MUST be absolute (§05.4.6).
    /// Before the fix this dropped (no peer with absolute index 1) → deadlock.
    #[test]
    fn wrap_protocol_routes_noncontiguous_subset_by_absolute_index() {
        let sid = SessionId([0x99; 32]);
        let mut jpk = [0u8; 33];
        jpk[0] = 0x02;
        // This party is absolute 0 = position 0; the peer is absolute 2 = position 1.
        let parties_at_keygen = [0u16, 2u16];
        let peers = [(2u16, "02cafe".to_string())];
        // SM emits a p2p message from position 0 to position 1 (the "other signer").
        let rm = RoundMessage {
            session_id: sid,
            round: 1,
            from: ShareIndex(0),
            to: Some(ShareIndex(1)), // SM POSITION of party 2
            payload: vec![9, 9, 9],
        };
        let out = wrap_protocol(std::slice::from_ref(&rm), sid, jpk, &peers, &parties_at_keygen);
        assert_eq!(out.len(), 1, "p2p MUST route to the absolute-index-2 peer (not dropped)");
        assert_eq!(out[0].recipient_pub_hex, "02cafe");
        assert_eq!(out[0].params.to_party, 2, "envelope to_party = absolute index 2");
        // Wire carries ABSOLUTE indices (§05.4.6): from 0→0, to position 1→absolute 2.
        assert_eq!(out[0].round_msg.from, ShareIndex(0));
        assert_eq!(out[0].round_msg.to, Some(ShareIndex(2)));

        // And the inverse: a broadcast from position 1 (party 2) emits absolute from=2.
        let bcast = RoundMessage {
            session_id: sid,
            round: 1,
            from: ShareIndex(1), // SM position of party 2
            to: None,
            payload: vec![1],
        };
        let out2 = wrap_protocol(std::slice::from_ref(&bcast), sid, jpk, &peers, &parties_at_keygen);
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].round_msg.from, ShareIndex(2), "broadcast from = absolute index 2");
        assert_eq!(out2[0].round_msg.to, None);
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

    // ── §06.18 invalidation ──────────────────────────────────────────────

    fn bundle_with(
        presig_id: &str,
        policy_id: [u8; 32],
        joint_pubkey: Vec<u8>,
        parties: Vec<u16>,
    ) -> PresigBundle {
        PresigBundle {
            presig_id: presig_id.to_string(),
            presig_bytes: vec![0xaa; 16],
            cosigner_encrypted_shares: vec![
                serde_bytes::ByteBuf::from(vec![]),
                serde_bytes::ByteBuf::from(vec![0x07, 0x08]),
            ],
            gamma_hex: "ab".into(),
            commitments: vec![0x01],
            policy_id: PolicyId(policy_id),
            joint_pubkey,
            parties_at_keygen: parties,
            generated_at: 1,
        }
    }

    #[test]
    fn in_memory_invalidate_purges_only_matching_bundles() {
        let store = InMemoryBundleStore::new();
        // Two bundles for JPK-A, one for JPK-B.
        store
            .persist(&bundle_with("a1", [0x11; 32], vec![0x02; 33], vec![0, 1]))
            .unwrap();
        store
            .persist(&bundle_with("a2", [0x11; 32], vec![0x02; 33], vec![0, 1]))
            .unwrap();
        store
            .persist(&bundle_with("b1", [0x11; 32], vec![0x03; 33], vec![0, 1]))
            .unwrap();
        assert_eq!(store.len(), 3);

        // ShareRefresh on JPK-A purges exactly a1, a2; b1 survives.
        let jpk_a = vec![0x02; 33];
        let purged = store
            .invalidate(&InvalidationTrigger::ShareRefresh {
                joint_pubkey: &jpk_a,
            })
            .unwrap();
        assert_eq!(purged, 2, "both JPK-A bundles purged");
        assert_eq!(store.len(), 1);
        assert!(store.get("b1").is_some(), "JPK-B bundle survives");
        assert!(store.get("a1").is_none() && store.get("a2").is_none());
    }

    #[test]
    fn file_invalidate_purges_matching_and_zeroizes_on_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileBundleStore::new(dir.path()).expect("open");

        // Two policy-bound bundles: one under the CURRENT policy, one stale.
        let current_policy = [0x55; 32];
        let stale_policy = [0x66; 32];
        store
            .persist(&bundle_with(
                &"aa".repeat(32),
                current_policy,
                vec![0x02; 33],
                vec![0, 1],
            ))
            .unwrap();
        let stale_id = "bb".repeat(32);
        store
            .persist(&bundle_with(&stale_id, stale_policy, vec![0x02; 33], vec![0, 1]))
            .unwrap();
        let stale_path = store.path_for(&stale_id);
        assert!(stale_path.exists());

        // PolicyUpdate(current) MUST purge the stale-policy bundle only.
        let purged = store
            .invalidate(&InvalidationTrigger::PolicyUpdate {
                current_policy_id: PolicyId(current_policy),
            })
            .unwrap();
        assert_eq!(purged, 1, "only the stale-policy bundle is purged");
        assert!(!stale_path.exists(), "stale bundle file removed (zeroized first)");
        assert!(
            store.get(&"aa".repeat(32)).is_some(),
            "current-policy bundle survives"
        );

        // The purged bundle is unrecoverable + a stray .json.tmp is not left behind.
        assert!(store.get(&stale_id).is_none());
        let leftover_tmp = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("tmp"));
        assert!(!leftover_tmp, "no temp file left behind");
    }

    #[test]
    fn file_invalidate_subset_and_rekey_triggers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileBundleStore::new(dir.path()).expect("open");
        // subset [0,1] vs [0,2]; jpk A vs B.
        store
            .persist(&bundle_with(&"11".repeat(32), [0x11; 32], vec![0x02; 33], vec![0, 1]))
            .unwrap();
        store
            .persist(&bundle_with(&"22".repeat(32), [0x11; 32], vec![0x02; 33], vec![0, 2]))
            .unwrap();

        // CosignerSubsetChange(prior=[0,1]) purges only the [0,1] bundle.
        let purged = store
            .invalidate(&InvalidationTrigger::CosignerSubsetChange {
                prior_subset: &[0, 1],
            })
            .unwrap();
        assert_eq!(purged, 1);
        assert!(store.get(&"11".repeat(32)).is_none());
        assert!(store.get(&"22".repeat(32)).is_some());

        // JointPubkeyChange(prior=JPK-A) purges the remaining [0,2] bundle (JPK-A).
        let jpk_a = vec![0x02; 33];
        let purged = store
            .invalidate(&InvalidationTrigger::JointPubkeyChange {
                prior_joint_pubkey: &jpk_a,
            })
            .unwrap();
        assert_eq!(purged, 1);
        assert!(store.get(&"22".repeat(32)).is_none(), "pool now empty");
    }

    // ── §06.17.3 single-use consume ──────────────────────────────────────

    #[test]
    fn in_memory_consume_is_single_use() {
        let store = InMemoryBundleStore::new();
        store
            .persist(&bundle_with("c1", [0x11; 32], vec![0x02; 33], vec![0, 1]))
            .unwrap();
        // First consume returns the bundle; second yields None (single-use).
        let first = store.consume("c1").unwrap();
        assert!(first.is_some(), "first consume returns the bundle");
        assert_eq!(first.unwrap().presig_id, "c1");
        assert!(
            store.consume("c1").unwrap().is_none(),
            "a bundle MUST NOT be consumable twice (§06.17.3)"
        );
        assert!(store.get("c1").is_none(), "consumed bundle is gone");
    }

    #[test]
    fn file_consume_is_single_use_and_zeroizes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileBundleStore::new(dir.path()).expect("open");
        let id = "cc".repeat(32);
        store
            .persist(&bundle_with(&id, [0x11; 32], vec![0x02; 33], vec![0, 1]))
            .unwrap();
        let path = store.path_for(&id);
        assert!(path.exists());

        let first = store.consume(&id).unwrap();
        assert!(first.is_some(), "first consume returns the bundle");
        assert!(!path.exists(), "consumed bundle file removed (zeroized)");
        assert!(
            store.consume(&id).unwrap().is_none(),
            "second consume yields None (single-use §06.17.3)"
        );
        // No stray consuming.* claim files left behind.
        let leftovers = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .count();
        assert_eq!(leftovers, 0, "no claim/temp files left after consume");
    }

    #[test]
    fn file_consume_concurrent_yields_bundle_at_most_once() {
        // Two threads race to consume the same bundle; EXACTLY one wins.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(FileBundleStore::new(dir.path()).expect("open"));
        let id = "dd".repeat(32);
        store
            .persist(&bundle_with(&id, [0x11; 32], vec![0x02; 33], vec![0, 1]))
            .unwrap();

        let barrier = Arc::new(std::sync::Barrier::new(8));
        let wins = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let id = id.clone();
            let barrier = barrier.clone();
            let wins = wins.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                if store.consume(&id).unwrap().is_some() {
                    wins.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            wins.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "EXACTLY one concurrent consumer may win (atomic single-use)"
        );
    }
}
