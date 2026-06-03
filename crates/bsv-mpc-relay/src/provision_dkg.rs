//! **Genuine n-party DKG over the relay** — the CREATE side of the
//! device-holds-(t−1) model (ADR-0052 Model B / §06.22, #69 PR-2 step 5b).
//!
//! Mirrors [`coordinate_reshare_over_relay`](crate::reshare::coordinate_reshare_over_relay)'s
//! PHASE A (a fresh joint DKG over the `mpc-dkg` box), but **KEEPS** the resulting
//! shares — no PSS, no combine. Phase A *is* the wallet: the `DkgResult.share` of
//! each in-process party is a complete, signable cggmp24 `KeyShare`.
//!
//! The caller (device) drives `w = t−1` in-process keygen parties (fresh random
//! relay identities); the deployed container(s) drive the remaining `n − w`,
//! armed via `POST /dkg-relay/init` — **one arm per held index**, so a single
//! container can hold several indices (the "two Notaries, one holds two" topology).
//!
//! Each container index uses a ONE-WAY-derived per-index relay identity
//! ([`bsv_mpc_core::hd::derive_relay_index_privkey`]); since the derivation is
//! one-way, the device CANNOT recompute it and instead FETCHES each one read-only
//! via `GET /dkg-relay/peer-identity?session&index`. The arm response MUST echo
//! that same per-index pub — the coordinator asserts the equality, catching any
//! index-derivation drift before the (long) ceremony wait.
//!
//! The joint pubkey is byte-identical across all `n` parties (the DKG agreement —
//! the merge gate). The device-alone set `{0,1,2}` is `w = t−1 < t`, i.e.
//! sub-threshold: the two mandatory sides are structural, not policy.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv_mpc_core::error::{MpcError, Result};
use bsv_mpc_core::paillier_pool::{generate_serialized, PaillierPool, PrimePoolStorage};
use bsv_mpc_core::types::{DkgResult, JointPublicKey, SessionId, ThresholdConfig};
use bsv_mpc_messagebox::types::BOX_DKG;
use bsv_mpc_messagebox::MessageBoxClient;
use bsv_mpc_service::{DkgHandler, MessageBoxListener, OutgoingRoundMessage, SqliteShareStorage};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::PregeneratedPrimes;
use rand::RngCore;

use crate::reshare::{ArmRequestSigner, RequestSigner};

/// One deployed cosigner endpoint + the indices it drives + its arm signer.
///
/// `indices` may have length > 1 — that is the multi-index-on-one-container path
/// (e.g. one Notary holding `{3, 4}`). `arm_signer` is the BRC-31 request signer
/// for THIS cosigner's session (each cosigner has its own identity / session).
pub struct CosignerEndpoint {
    /// The cosigner's `/dkg-relay/init` URL (the peer-identity URL is derived from it).
    pub init_url: String,
    /// The absolute keygen indices this cosigner drives, ascending.
    pub indices: Vec<u16>,
    /// BRC-31 request signer for this cosigner's session (arms are POSTed signed).
    pub arm_signer: ArmRequestSigner,
    /// **#85 MITM gate.** The cosigner's MASTER identity pubkey hex, PINNED
    /// out-of-band (the device provisions a *named* Notary — it should already know
    /// its identity, not trust whatever an unauthenticated GET returns). When `Some`,
    /// every per-index relay pub fetched over `/dkg-relay/peer-identity` MUST carry a
    /// valid attestation by this master (else fail closed), and a post-DKG liveness
    /// challenge is verified against it before the wallet is returned. `None` =
    /// unpinned (hermetic tests / legacy dev only — NOT for funded production).
    pub expected_master_pub: Option<String>,
}

/// Inputs for the device side of a genuine n-party DKG over the relay.
pub struct DkgOverRelay {
    /// MessageBox relay URL.
    pub relay_url: String,
    /// The threshold `t`.
    pub threshold: u16,
    /// The party count `n`.
    pub parties: u16,
    /// The device's in-process keygen indices (`w = t−1` of them).
    pub local_indices: Vec<u16>,
    /// The cosigner endpoints driving the remaining `n − w` indices.
    pub cosigners: Vec<CosignerEndpoint>,
    /// A provisional ceremony handle for the arm body's `agent_id` (owner-authz
    /// §08.1 salt). The FINAL share key is `{joint_pubkey}#{index}`, re-keyed at
    /// completion — so this value is transient, not the storage key.
    pub provisional_agent_id: String,
    /// **Lever B (ADR-0041 / issue #99) — OPTIONAL device Paillier prime pool.**
    /// When `Some`, the device draws ONE pre-generated safe-prime set per local
    /// index from this on-device encrypted pool instead of grinding it inline
    /// (the ~250s 4-of-6 provision cost). A miss (empty pool / decrypt failure)
    /// FALLS BACK to inline `generate_serialized` per index, so this is strictly
    /// Pareto — never slower than `None` (today's always-inline behavior). The
    /// prime values fed into the DKG are byte-identical either way; only their
    /// SOURCE changes. The pool seals at rest with a key BRC-42-derived from
    /// [`Self::at_rest_root`] + [`Self::pool_id`] — see [`PaillierPool`].
    pub prime_pool: Option<Arc<dyn PrimePoolStorage>>,
    /// The device's 32-byte at-rest root, BRC-42-deriving the pool encryption key.
    /// Only consulted when [`Self::prime_pool`] is `Some`.
    pub at_rest_root: [u8; 32],
    /// Domain-separation bytes for the pool encryption key (e.g. the device
    /// identity pubkey). Only consulted when [`Self::prime_pool`] is `Some`.
    pub pool_id: Vec<u8>,
    /// **#101 (Shape B) — OPTIONAL keygen-done callback (the instant-address lever).**
    /// Invoked exactly ONCE, the instant all `w` device parties agree on a
    /// byte-identical keygen joint key — BEFORE the slow aux-info phase — and AFTER
    /// the #85 liveness gate has passed against that joint key. So the surfaced
    /// address is already #85-verified and safe to label fundable. The ceremony then
    /// CONTINUES to aux-info + completion in this SAME call (the relay listeners and
    /// cosigner arms are never torn down across the gap). `None` ⇒ byte-identical to
    /// today: no early surface, and the #85 gate runs at completion as before.
    pub on_keygen: Option<Box<dyn FnOnce(JointPublicKey, SessionId) + Send>>,

    /// **#104 aux-REUSE — OPTIONAL per-local-index pre-validated aux.** When
    /// `Some`, each `(index, aux_json_bytes)` entry is loaded into THIS device's
    /// in-process keygen party for `index` (`DkgHandler::set_loaded_aux_json`), so
    /// the device SKIPS the entire aux SM AND the device prime pre-seed for that
    /// index — the per-wallet time-to-sendable lever. The aux MUST already have
    /// passed `bsv_mpc_core::aux_binding::validate_aux_for_load` (the caller / FFI
    /// unseals + validates before threading it here). `None` ⇒ today's fresh-aux
    /// path (every index runs the ~180-300s aux SM). Each entry's index MUST be a
    /// member of [`Self::local_indices`].
    pub device_aux: Option<Vec<(u16, Vec<u8>)>>,
    /// **#104 aux-REUSE — the 32-byte group-id** this wallet's group belongs to.
    /// When `Some` (with [`Self::aux_epoch`]), it is shipped in every cosigner arm
    /// so each Notary loads + reuses ITS sealed aux for `(group_id, index)`. `None`
    /// ⇒ no group declared ⇒ Notaries run fresh aux.
    pub group_id: Option<[u8; 32]>,
    /// **#104 aux-REUSE — the pinned-Notary epoch** the reused aux must match
    /// (must-do #10). Shipped alongside [`Self::group_id`].
    pub aux_epoch: Option<u64>,
}

/// Output: the agreed joint key + this device's signable per-index shares.
pub struct DkgOverRelayOutput {
    /// The joint public key, byte-identical across all `n` parties (the merge gate).
    pub joint_key: JointPublicKey,
    /// The ceremony session id (carried on each share's metadata).
    pub session_id: SessionId,
    /// `(index, signable cggmp24 KeyShare JSON)` for each LOCAL index, ascending.
    pub local_shares: Vec<(u16, Vec<u8>)>,
}

#[derive(serde::Deserialize)]
pub(crate) struct PeerIdentityResponse {
    pub(crate) relay_pub_hex: String,
    /// #85: the cosigner's MASTER pub (what the device pins) + its attestation over
    /// (master, session, index, relay_pub). `Option` so an un-hardened/legacy
    /// container still parses — but a PINNED device rejects a missing attestation.
    #[serde(default)]
    pub(crate) master_pub_hex: Option<String>,
    #[serde(default)]
    pub(crate) attestation_hex: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct ArmResponse {
    pub(crate) peer_pub_hex: String,
}

/// Fresh isolated SQLite storage for an in-process device keygen party. The share
/// is read out of the completion channel (`DkgResult`) and sealed by the caller,
/// so this storage is incidental — a unique temp path avoids collisions.
pub(crate) fn fresh_storage() -> Arc<RwLock<SqliteShareStorage>> {
    let mut tag = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut tag);
    let dir = std::env::temp_dir().join(format!("mpc-provision-dkg-{}", hex::encode(tag)));
    let path = dir.to_string_lossy().to_string();
    let s = SqliteShareStorage::open(&path).expect("open provision-dkg storage");
    Arc::new(RwLock::new(s))
}

/// GET the cosigner's `/dkg-relay/peer-identity?session&index` → the per-index
/// relay pub (read-only; the device cannot recompute the one-way value itself).
///
/// **#85 MITM gate:** when `expected_master_pub` is `Some`, the response MUST carry
/// the PINNED master pub + a valid attestation over `(master, session, index,
/// relay_pub)` — else this fails closed (a network MITM cannot forge the master's
/// signature, so it cannot substitute an attacker relay identity).
async fn fetch_dkg_peer_identity(
    init_url: &str,
    session: &SessionId,
    index: u16,
    expected_master_pub: Option<&str>,
) -> Result<String> {
    let session_hex = session.hex();
    let base = init_url.replace("/dkg-relay/init", "/dkg-relay/peer-identity");
    let url = format!("{base}?session={session_hex}&index={index}");
    let resp = crate::bounded_http_client(crate::RELAY_HTTP_TIMEOUT)?
        .get(&url)
        .send()
        .await
        .map_err(|e| MpcError::Protocol(format!("fetch dkg peer identity (index {index}): {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "/dkg-relay/peer-identity (index {index}) returned {status}: {txt}"
        )));
    }
    let parsed: PeerIdentityResponse = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse dkg peer-identity response: {e}")))?;

    if let Some(pinned_hex) = expected_master_pub {
        // 1. The cosigner must claim to BE the pinned master.
        let claimed = parsed.master_pub_hex.as_deref().ok_or_else(|| {
            MpcError::Protocol(format!(
                "dkg peer-identity (index {index}) returned no master_pub_hex — cannot verify \
                 against the pinned master (#85); refusing"
            ))
        })?;
        if claimed != pinned_hex {
            return Err(MpcError::Protocol(format!(
                "dkg peer-identity (index {index}) master {claimed} != pinned {pinned_hex} (#85 MITM)"
            )));
        }
        // 2. The attestation must verify under the PINNED master.
        let att_hex = parsed.attestation_hex.as_deref().ok_or_else(|| {
            MpcError::Protocol(format!(
                "dkg peer-identity (index {index}) returned no attestation (#85); refusing"
            ))
        })?;
        let master = PublicKey::from_hex(pinned_hex)
            .map_err(|e| MpcError::Protocol(format!("pinned master pub hex: {e}")))?;
        let relay_pub = PublicKey::from_hex(&parsed.relay_pub_hex)
            .map_err(|e| MpcError::Protocol(format!("relay pub hex: {e}")))?;
        let att: [u8; 64] = hex::decode(att_hex)
            .map_err(|e| MpcError::Protocol(format!("attestation hex: {e}")))?
            .try_into()
            .map_err(|_| {
                MpcError::Protocol(format!("attestation (index {index}) must be 64 bytes"))
            })?;
        if !bsv_mpc_core::hd::verify_relay_identity_attestation(
            &master, session, index, &relay_pub, &att,
        ) {
            return Err(MpcError::Protocol(format!(
                "dkg peer-identity (index {index}) attestation FAILED under the pinned master \
                 (#85 MITM) — refusing to route to an unattested relay identity"
            )));
        }
    }
    Ok(parsed.relay_pub_hex)
}

/// POST `/dkg-relay/init`, BRC-31-signed over the canonical wire. Returns the
/// container's per-index relay pub (must equal the earlier `fetch_dkg_peer_identity`).
#[allow(clippy::too_many_arguments)]
async fn arm_dkg_container(
    init_url: &str,
    request_signer: RequestSigner<'_>,
    agent_id: &str,
    session_hex: &str,
    my_index: u16,
    threshold: u16,
    parties: u16,
    peers: &[(u16, String)],
    // #104: when set, the Notary loads + reuses its sealed aux for (group_id, idx).
    aux_reuse: Option<(String, u64)>,
    timeout: Duration,
) -> Result<String> {
    let peers_json: Vec<serde_json::Value> = peers
        .iter()
        .map(|(i, h)| serde_json::json!({ "index": i, "pub_hex": h }))
        .collect();
    let mut body = serde_json::json!({
        "agent_id": agent_id,
        "dkg_session": session_hex,
        "my_index": my_index,
        "threshold": threshold,
        "parties": parties,
        "peers": peers_json,
    });
    if let Some((group_id_hex, aux_epoch)) = aux_reuse {
        body["group_id"] = serde_json::Value::String(group_id_hex);
        body["aux_epoch"] = serde_json::Value::from(aux_epoch);
    }
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| MpcError::Serialization(format!("serialize dkg-relay/init: {e}")))?;
    let path = reqwest::Url::parse(init_url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| "/dkg-relay/init".to_string());

    let http = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| MpcError::Protocol(format!("build dkg http client: {e}")))?;
    let mut builder = http
        .post(init_url)
        .header("content-type", "application/json")
        .body(body_bytes.clone());
    for (name, value) in request_signer("POST", &path, &body_bytes)? {
        builder = builder.header(name, value);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| MpcError::Protocol(format!("arm dkg peer (index {my_index}): {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "container /dkg-relay/init (index {my_index}) returned {status}: {txt}"
        )));
    }
    let parsed: ArmResponse = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse dkg-relay/init response: {e}")))?;
    Ok(parsed.peer_pub_hex)
}

/// Run a genuine n-party DKG over the relay for the device's `local_indices`,
/// arming each cosigner index via `POST /dkg-relay/init`. Returns the agreed joint
/// key + the device's signable per-index shares (the caller seals them).
pub async fn coordinate_dkg_over_relay(
    mut p: DkgOverRelay,
    timeout: Duration,
) -> Result<DkgOverRelayOutput> {
    let proto = |e: bsv_mpc_messagebox::error::MessageBoxError| MpcError::Protocol(e.to_string());
    let cfg = ThresholdConfig::new(p.threshold, p.parties)?;
    let n = p.parties;
    // #8 DIAGNOSTIC: keygen-phase per-step timing (eprintln surfaces to the sim test log).
    let _kg = std::time::Instant::now();
    eprintln!("KGSTEP 0 start");

    // ── Topology validation: device + cosigner indices MUST partition 0..n exactly,
    //    and the device MUST hold w = t−1 (the device-holds invariant — anything
    //    else is a different product tier and is rejected, not silently accepted). ──
    if (p.local_indices.len() as u16) != p.threshold - 1 {
        return Err(MpcError::Protocol(format!(
            "dkg-over-relay: device must hold w = t−1 = {} indices, got {} ({:?})",
            p.threshold - 1,
            p.local_indices.len(),
            p.local_indices
        )));
    }
    let mut all_indices: Vec<u16> = p.local_indices.clone();
    for c in &p.cosigners {
        all_indices.extend(c.indices.iter().copied());
    }
    all_indices.sort_unstable();
    let expected: Vec<u16> = (0..n).collect();
    if all_indices != expected {
        return Err(MpcError::Protocol(format!(
            "dkg-over-relay: device + cosigner indices must be exactly 0..{n} (no gaps/dupes), got {all_indices:?}"
        )));
    }

    // ── Ceremony session (shared across all n parties). ──
    let session = {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        SessionId(b)
    };
    let session_hex = session.hex();

    // ── Device mints fresh relay identities for its local indices. ──
    let local_indices = p.local_indices.clone();
    let mut local_clients: Vec<MessageBoxClient> = Vec::new();
    let mut local_pubs: Vec<String> = Vec::new();
    for _ in 0..local_indices.len() {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b[0] |= 0x01;
        let priv_key = PrivateKey::from_bytes(&b)
            .map_err(|e| MpcError::Protocol(format!("dkg-over-relay: party identity: {e}")))?;
        let c = MessageBoxClient::new(&p.relay_url, priv_key).map_err(proto)?;
        let ph = c.identity_hex().await.map_err(proto)?;
        local_clients.push(c);
        local_pubs.push(ph);
    }
    eprintln!("KGSTEP 1 local-identities done +{:?}", _kg.elapsed());

    // ── Fetch each cosigner index's per-index relay pub FIRST (§06.17 — the device
    //    must know every peer's identity before it ships round-1 / arms anyone). ──
    let mut cosigner_pubs: Vec<(u16, String)> = Vec::new();
    for c in &p.cosigners {
        for &idx in &c.indices {
            // #85: verify each per-index relay pub against the PINNED master (when set).
            let pub_hex = fetch_dkg_peer_identity(
                &c.init_url,
                &session,
                idx,
                c.expected_master_pub.as_deref(),
            )
            .await?;
            cosigner_pubs.push((idx, pub_hex));
        }
    }
    eprintln!("KGSTEP 2 cosigner-pub-fetches done +{:?}", _kg.elapsed());

    // ── Full identity map: absolute index → relay pub. ──
    let identity_for = |idx: u16| -> Option<String> {
        if let Some(pos) = local_indices.iter().position(|&k| k == idx) {
            return Some(local_pubs[pos].clone());
        }
        cosigner_pubs
            .iter()
            .find(|(i, _)| *i == idx)
            .map(|(_, h)| h.clone())
    };
    let peers_for = |me: u16| -> Result<Vec<(u16, String)>> {
        (0..n)
            .filter(|&k| k != me)
            .map(|k| {
                identity_for(k).map(|h| (k, h)).ok_or_else(|| {
                    MpcError::Protocol(format!("dkg-over-relay: no identity for party {k}"))
                })
            })
            .collect()
    };

    // ── Arm each cosigner index FIRST + ASYNC (§06.17 ordering): each arm subscribes
    //    + ships its own round-1 before responding, so spawn them all so their relay
    //    slots come live while the device ships its round-1. Every arm asserts its
    //    response pub == the device-fetched per-index pub (drift catch). ──
    let arm_timeout = timeout + Duration::from_secs(60);
    let mut arm_handles = Vec::new();
    for c in &p.cosigners {
        for &idx in &c.indices {
            let peers = peers_for(idx)?;
            let expected_pub = identity_for(idx).ok_or_else(|| {
                MpcError::Protocol(format!("dkg-over-relay: no fetched pub for index {idx}"))
            })?;
            let init_url = c.init_url.clone();
            let signer = c.arm_signer.clone();
            let agent_id = p.provisional_agent_id.clone();
            let session_hex_c = session_hex.clone();
            let t = p.threshold;
            // #104: ship (group_id, aux_epoch) so the Notary reuses its sealed aux
            // for this index — present only when the device declares a group.
            let aux_reuse = match (p.group_id, p.aux_epoch) {
                (Some(gid), Some(epoch)) => Some((hex::encode(gid), epoch)),
                _ => None,
            };
            arm_handles.push(tokio::spawn(async move {
                let armed = arm_dkg_container(
                    &init_url,
                    &*signer,
                    &agent_id,
                    &session_hex_c,
                    idx,
                    t,
                    n,
                    &peers,
                    aux_reuse,
                    arm_timeout,
                )
                .await?;
                if armed != expected_pub {
                    return Err(MpcError::Protocol(format!(
                        "dkg-over-relay: cosigner index {idx} relay identity changed between \
                         peer-identity fetch ({expected_pub}) and arm ({armed}) — index drift"
                    )));
                }
                Ok::<u16, MpcError>(idx)
            }));
        }
    }

    // ── Device's in-process keygen parties.
    //
    //    PRE-SEED the safe primes BEFORE initiate (the proven step-4 ordering), NOT
    //    late-seed. A device backing `w = t−1` parties runs that many CPU-heavy
    //    auxinfo proceeds IN-PROCESS; if a party reaches the keygen→auxinfo
    //    transition before a late-seed lands it inline-generates a 2048-bit safe
    //    prime *inside* `proceed()` — blocking the thread for ~minutes and (with
    //    `w` parties) starving the message loops. Pre-seeding keeps every proceed
    //    short so the runtime stays responsive even on a phone. The arms were
    //    spawned ABOVE, so the cosigner warms up on the relay during this gen.
    //    The device joining the relay slightly later is fine — it is the
    //    coordinator, and the cosigner's early round-1 backfills. ──
    //
    //    LEVER B (#99): when a device prime pool is present, draw ONE pre-generated
    //    set PER local index from it (`pool.take()`) — each held index gets a
    //    DISTINCT set (FIFO `take`, never reused across two of the device's own
    //    parties). A miss (empty pool / decrypt failure / pool-key rotation) falls
    //    back to inline `generate_serialized` for THAT index only, so a partially
    //    warm pool still speeds up the sets it covers and an empty/absent pool is
    //    byte-for-byte today's behavior (the `None` / all-miss path). The set fed
    //    into the DKG is identical whether pooled or inline — only the source moves.
    // #104 aux-REUSE: indices whose aux is being REUSED need NO primes (the aux SM
    // never runs for them). Generate primes only for the remaining (fresh-aux)
    // local indices; reuse-indices `set_loaded_aux_json` below.
    let device_aux_map: std::collections::HashMap<u16, Vec<u8>> = p
        .device_aux
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();
    let n_prime = local_indices
        .iter()
        .filter(|i| !device_aux_map.contains_key(i))
        .count();
    let prime_pool = p.prime_pool.clone();
    let at_rest_root = p.at_rest_root;
    let pool_id = p.pool_id.clone();
    let mut primes: Vec<PregeneratedPrimes<SecurityLevel128>> =
        tokio::task::spawn_blocking(move || {
            // Build the pool view once (cheap: derives the AES key, no I/O) if the
            // host supplied a store; otherwise every index inline-generates.
            let pool = prime_pool
                .map(|storage| PaillierPool::new(storage, &at_rest_root, &pool_id, n_prime));
            (0..n_prime)
                .map(|_| {
                    // WARM: a pooled set is microseconds (one AES-GCM decrypt).
                    // A decrypt/storage error is treated as a miss (→ inline), never
                    // a hard failure — the pool can NEVER regress provisioning.
                    let pooled = pool.as_ref().and_then(|pl| pl.take().ok().flatten());
                    match pooled {
                        Some(pp) => pp,
                        // COLD fallback: route through `generate_serialized` (the RSS
                        // gate) rather than the bare `PregeneratedPrimes::generate`
                        // so a phone never spikes num-bigint memory in parallel.
                        None => generate_serialized(&mut rand::rngs::OsRng),
                    }
                })
                .collect()
        })
        .await
        .map_err(|e| {
            MpcError::Protocol(format!("dkg-over-relay: device prime gen panicked: {e}"))
        })?;

    let dkg_handlers: Vec<DkgHandler> = local_indices
        .iter()
        .map(|&idx| DkgHandler::new(cfg, idx, fresh_storage()))
        .collect();
    // #104: per local index, either REUSE its pre-validated aux (skip the aux SM)
    // or seed it a freshly-generated prime set. `primes` holds exactly the sets
    // for the non-reuse indices, consumed in local-index order.
    let mut prime_iter = primes.drain(..);
    for (h, &idx) in dkg_handlers.iter().zip(local_indices.iter()) {
        match device_aux_map.get(&idx) {
            Some(aux_bytes) => {
                let aux_json = String::from_utf8(aux_bytes.clone()).map_err(|e| {
                    MpcError::Protocol(format!("dkg-over-relay: device aux for index {idx} not UTF-8: {e}"))
                })?;
                h.set_loaded_aux_json(aux_json);
            }
            None => {
                let pp = prime_iter.next().ok_or_else(|| {
                    MpcError::Protocol(format!(
                        "dkg-over-relay: no prime set for non-reuse index {idx} (internal count error)"
                    ))
                })?;
                h.seed_primes_for(session, pp);
            }
        }
    }
    // #8: start the w device-party listeners CONCURRENTLY (each is an independent relay WS
    // subscribe; sequential was ~5.5s). try_join_all preserves order so listeners[pos] ↔
    // local_indices[pos].
    let listener_futs = dkg_handlers.iter().enumerate().map(|(pos, h)| {
        let client = local_clients[pos].clone();
        let hf = h.handler_fn();
        async move {
            MessageBoxListener::start(client, BOX_DKG, hf)
                .await
                .map_err(|e| MpcError::Protocol(format!("dkg-over-relay listener: {e}")))
        }
    });
    let listeners: Vec<MessageBoxListener> = futures::future::try_join_all(listener_futs).await?;
    eprintln!("KGSTEP 3 listeners-started done +{:?}", _kg.elapsed());
    let mut rxs = Vec::new();
    // #101: keygen-boundary receivers, one per local party. Taken right after
    // `initiate` (which registers them). Only awaited when `on_keygen` is set.
    let mut keygen_rxs: Vec<Option<tokio::sync::oneshot::Receiver<JointPublicKey>>> = Vec::new();
    let mut sends: Vec<(usize, Vec<OutgoingRoundMessage>)> = Vec::new();
    for (pos, &idx) in local_indices.iter().enumerate() {
        let (rx, out) = dkg_handlers[pos]
            .initiate(session, peers_for(idx)?)
            .await
            .map_err(|e| MpcError::Protocol(format!("dkg-over-relay initiate: {e}")))?;
        keygen_rxs.push(dkg_handlers[pos].take_keygen_rx(session));
        rxs.push(rx);
        sends.push((pos, out));
    }
    // #8: ship ALL round-1 messages CONCURRENTLY. Each `/sendMessage` is an independent
    // ~1-2s CF-Worker+D1 write; sending the device's w parties' round-1 broadcasts
    // SEQUENTIALLY was the dominant keygen-phase cost (~18s of the 67s time-to-address).
    // Safe: the relay dedups on the stable message_id (bounded idempotent retry inside
    // send_round_message_reliable), and the receiving SM buffers out-of-order arrivals.
    let mut send_futs = Vec::new();
    for (pos, out) in sends {
        let client = &local_clients[pos];
        for o in out {
            send_futs.push(async move {
                client
                    .send_round_message_reliable(
                        &o.recipient_pub_hex,
                        &o.message_box,
                        &o.round_msg,
                        o.params,
                        4,
                    )
                    .await
                    .map_err(|e| MpcError::Protocol(e.to_string()))
            });
        }
    }
    futures::future::try_join_all(send_futs).await?;
    eprintln!("KGSTEP 4 round-1-shipped done +{:?}", _kg.elapsed());

    // ── Confirm every cosigner arm succeeded (auth/owner errors surface here in
    //    seconds, with the real error, instead of as an opaque DKG timeout). ──
    for handle in arm_handles {
        match handle.await {
            Ok(Ok(_idx)) => {}
            Ok(Err(e)) => {
                for l in listeners {
                    let _ = l.shutdown().await;
                }
                return Err(e);
            }
            Err(e) => {
                for l in listeners {
                    let _ = l.shutdown().await;
                }
                return Err(MpcError::Protocol(format!(
                    "dkg-over-relay: arm task panicked: {e}"
                )));
            }
        }
    }

    eprintln!("KGSTEP 5 arms-confirmed done +{:?}", _kg.elapsed());
    // ── #101 KEYGEN CHECKPOINT (Shape B): surface the address the instant keygen
    //    completes — BEFORE aux-info — but only when the caller asked for it. The
    //    background `MessageBoxListener` tasks (started above) keep driving each
    //    handler's `process_round`, so these keygen oneshots resolve mid-ceremony
    //    while the completion oneshots (awaited below) resolve later from the SAME
    //    drive — no separate drive, no deadlock. ──
    let keygen_checkpoint_ran = p.on_keygen.is_some();
    if let Some(on_keygen) = p.on_keygen.take() {
        let mut keygen_jks: Vec<JointPublicKey> = Vec::with_capacity(keygen_rxs.len());
        for (pos, krx) in keygen_rxs.into_iter().enumerate() {
            let krx = match krx {
                Some(r) => r,
                None => {
                    for l in listeners {
                        let _ = l.shutdown().await;
                    }
                    return Err(MpcError::Protocol(format!(
                        "dkg-over-relay: party {} missing keygen receiver",
                        local_indices[pos]
                    )));
                }
            };
            match tokio::time::timeout(timeout, krx).await {
                Ok(Ok(jk)) => keygen_jks.push(jk),
                Ok(Err(e)) => {
                    for l in listeners {
                        let _ = l.shutdown().await;
                    }
                    return Err(MpcError::Protocol(format!(
                        "dkg-over-relay: party {} keygen channel dropped: {e}",
                        local_indices[pos]
                    )));
                }
                Err(_) => {
                    for l in listeners {
                        let _ = l.shutdown().await;
                    }
                    return Err(MpcError::Protocol(format!(
                        "dkg-over-relay: party {} timed out awaiting keygen completion",
                        local_indices[pos]
                    )));
                }
            }
        }
        // GATE: byte-identical keygen joint key across the device's own w parties
        // (mirror of the final completion gate) — a disagreeing keygen can never
        // surface a bogus address.
        let keygen_jk = keygen_jks[0].clone();
        for (pos, jk) in keygen_jks.iter().enumerate() {
            if jk.compressed != keygen_jk.compressed {
                for l in listeners {
                    let _ = l.shutdown().await;
                }
                return Err(MpcError::Protocol(format!(
                    "dkg-over-relay: device party {} keygen pubkey != party {} — keygen disagreement",
                    local_indices[pos], local_indices[0]
                )));
            }
        }
        // #85 FUNDING GATE — MOVED to the keygen checkpoint (was at completion).
        // Confirm each PINNED cosigner is live + controls its master FOR THIS joint
        // key BEFORE the address is surfaced as fundable. Binds only
        // `joint_key.compressed`, which is final at keygen (aux-info never changes
        // it). Fail-closed: any challenge error tears down and aborts the ceremony.
        for c in &p.cosigners {
            if let Some(master_hex) = &c.expected_master_pub {
                let challenge_url = c.init_url.replace("/dkg-relay/init", "/identity-challenge");
                if let Err(e) =
                    challenge_cosigner(&challenge_url, master_hex, &keygen_jk.compressed).await
                {
                    for l in listeners {
                        let _ = l.shutdown().await;
                    }
                    return Err(e);
                }
            }
        }
        // #85-verified: surface the address now. Aux-info CONTINUES below in this
        // SAME call (Shape B) — listeners + cosigner arms are never torn down.
        eprintln!("KGSTEP 6 keygen-rounds+#85 done (=time-to-address) +{:?}", _kg.elapsed());
        on_keygen(keygen_jk, session);
    }

    // ── Await the device's completions. ──
    let mut results: Vec<(u16, DkgResult)> = Vec::new();
    for (pos, &idx) in local_indices.iter().enumerate() {
        match tokio::time::timeout(timeout, &mut rxs[pos]).await {
            Ok(Ok(r)) => results.push((idx, r)),
            Ok(Err(e)) => {
                for l in listeners {
                    let _ = l.shutdown().await;
                }
                return Err(MpcError::Protocol(format!(
                    "dkg-over-relay: party {idx} channel dropped: {e}"
                )));
            }
            Err(_) => {
                for l in listeners {
                    let _ = l.shutdown().await;
                }
                return Err(MpcError::Protocol(format!(
                    "dkg-over-relay: party {idx} timed out awaiting DKG completion"
                )));
            }
        }
    }
    for l in listeners {
        let _ = tokio::time::timeout(Duration::from_secs(10), l.shutdown()).await;
    }

    // ── THE GATE: byte-identical joint key across the device's own parties (the
    //    cross-party agreement is implied — a disagreeing ceremony cannot complete). ──
    let first_idx = results[0].0;
    let joint_key = results[0].1.joint_key.clone();
    for (idx, r) in &results {
        if r.joint_key.compressed != joint_key.compressed {
            return Err(MpcError::Protocol(format!(
                "dkg-over-relay: device party {idx} joint pubkey != party {first_idx} — DKG disagreement"
            )));
        }
    }

    // ── #85 FUNDING GATE: independently confirm each PINNED cosigner is LIVE and
    //    controls its master identity FOR THIS joint key, before returning a wallet
    //    that could be funded. A fresh-nonce signed challenge to the pinned master
    //    catches a cosigner that participated under a MITM'd/wrong identity (its
    //    challenge fails) — so funds never move to a joint key the real Notary
    //    doesn't co-hold. Skipped for un-pinned dev/test cosigners.
    //
    //    #101: when the keygen checkpoint ran (`on_keygen` was `Some`), this gate
    //    ALREADY fired there against the byte-identical keygen joint key — don't
    //    re-challenge. When there was no early surface (`on_keygen` None), run it
    //    here exactly as before — byte-identical to today's behavior. ──
    if !keygen_checkpoint_ran {
        for c in &p.cosigners {
            if let Some(master_hex) = &c.expected_master_pub {
                let challenge_url = c.init_url.replace("/dkg-relay/init", "/identity-challenge");
                challenge_cosigner(&challenge_url, master_hex, &joint_key.compressed).await?;
            }
        }
    }

    let mut local_shares: Vec<(u16, Vec<u8>)> = results
        .into_iter()
        .map(|(idx, r)| (idx, r.share.ciphertext))
        .collect();
    local_shares.sort_by_key(|(idx, _)| *idx);

    Ok(DkgOverRelayOutput {
        joint_key,
        session_id: session,
        local_shares,
    })
}

/// #85 funding/liveness gate: POST `/identity-challenge` with a fresh nonce + the
/// joint pubkey, and verify the returned signature against the PINNED master. Proves
/// the real cosigner is live and controls its pinned identity for THIS wallet. Fails
/// closed on a master mismatch, a bad signature, or a transport error. Shared by DKG
/// provisioning AND reshare/recovery (#85); `challenge_url` is the cosigner's full
/// `/identity-challenge` URL.
pub(crate) async fn challenge_cosigner(
    challenge_url: &str,
    master_pub_hex: &str,
    joint_pubkey_compressed: &[u8],
) -> Result<()> {
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let url = challenge_url.to_string();
    let body = serde_json::json!({
        "joint_pubkey_hex": hex::encode(joint_pubkey_compressed),
        "nonce_hex": hex::encode(nonce),
    });
    let resp = crate::bounded_http_client(crate::RELAY_HTTP_TIMEOUT)?
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| MpcError::Protocol(format!("identity-challenge: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "identity-challenge returned {status}: {txt}"
        )));
    }
    #[derive(serde::Deserialize)]
    struct ChallengeResp {
        master_pub_hex: String,
        challenge_sig_hex: String,
    }
    let parsed: ChallengeResp = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse identity-challenge response: {e}")))?;
    if parsed.master_pub_hex != master_pub_hex {
        return Err(MpcError::Protocol(format!(
            "identity-challenge master {} != pinned {master_pub_hex} (#85)",
            parsed.master_pub_hex
        )));
    }
    let master = PublicKey::from_hex(master_pub_hex)
        .map_err(|e| MpcError::Protocol(format!("pinned master pub hex: {e}")))?;
    let sig: [u8; 64] = hex::decode(&parsed.challenge_sig_hex)
        .map_err(|e| MpcError::Protocol(format!("challenge sig hex: {e}")))?
        .try_into()
        .map_err(|_| MpcError::Protocol("challenge sig must be 64 bytes".into()))?;
    if !bsv_mpc_core::hd::verify_cosigner_challenge(&master, joint_pubkey_compressed, &nonce, &sig)
    {
        return Err(MpcError::Protocol(
            "identity-challenge signature FAILED under the pinned master (#85) — the cosigner \
             does not control its pinned identity; refusing to return a fundable wallet"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod prime_pool_seam_tests {
    //! Lever B (#99) — fast unit proof of the prime-pool CONSUMPTION SEAM, with NO
    //! real safe-prime generation (Blum primes `p ≡ 3 mod 4` are seconds-fast and
    //! satisfy `PregeneratedPrimes`'s bit-size invariant — the same shortcut the
    //! core `paillier_pool` tests use). These assert the device drains the warm pool
    //! FIRST, one DISTINCT set per held index, and only falls back to inline gen on
    //! a miss — the exact contract of the production loop at the inline-gen block.

    use bsv_mpc_core::paillier_pool::{InMemoryPoolStorage, PaillierPool, PrimePoolStorage};
    use cggmp24::security_level::{SecurityLevel, SecurityLevel128};
    use cggmp24::PregeneratedPrimes;
    use rand::RngCore;

    fn gen_blum<R: RngCore>(rng: &mut R, bits: u32) -> cggmp24::backend::Integer {
        use cggmp24::backend::Integer;
        loop {
            let n = Integer::generate_prime(rng, bits);
            if n.mod_u(4) == 3 {
                break n;
            }
        }
    }

    /// Fast stand-in for `PregeneratedPrimes::generate` (real safe primes are
    /// minutes-class). Used both to seed the pool and as the inline-fallback gen in
    /// the test, so the seam logic is exercised without the slow safe-prime path.
    fn fast_primes<R: RngCore>(rng: &mut R) -> PregeneratedPrimes<SecurityLevel128> {
        let bits = SecurityLevel128::RSA_PRIME_BITLEN;
        let primes = [
            gen_blum(rng, bits),
            gen_blum(rng, bits),
            gen_blum(rng, bits),
            gen_blum(rng, bits),
        ];
        PregeneratedPrimes::try_from(primes).expect("Blum primes have correct bit size")
    }

    fn ser(p: &PregeneratedPrimes<SecurityLevel128>) -> Vec<u8> {
        serde_json::to_vec(p).expect("serialize PregeneratedPrimes")
    }

    /// The PRODUCTION drain logic, factored out so the test exercises the exact
    /// take-or-generate decision (mirrors the inline-gen block in
    /// `coordinate_dkg_over_relay`). Returns `(primes, n_inline_fallbacks)`.
    fn drain_like_production(
        pool: Option<&PaillierPool<InMemoryPoolStorage>>,
        n_local: usize,
        fallback_rng: &mut impl RngCore,
    ) -> (Vec<PregeneratedPrimes<SecurityLevel128>>, usize) {
        let mut fallbacks = 0;
        let primes = (0..n_local)
            .map(|_| {
                let pooled = pool.and_then(|pl| pl.take().ok().flatten());
                match pooled {
                    Some(pp) => pp,
                    None => {
                        fallbacks += 1;
                        fast_primes(fallback_rng)
                    }
                }
            })
            .collect();
        (primes, fallbacks)
    }

    /// A warm pool seeded with `w` DISTINCT sets is fully drained — each held index
    /// gets a distinct pooled set (FIFO order) and ZERO inline fallbacks occur.
    #[test]
    fn warm_pool_drained_distinct_before_any_inline_fallback() {
        let mut rng = rand::rngs::OsRng;
        let w = 3; // 4-of-6 device holds w = t−1 = 3 indices.

        // Seed `w` distinct sets, recording their serialized bytes in FIFO order.
        let pool = PaillierPool::new(InMemoryPoolStorage::new(), &[0x11u8; 32], b"seam", w);
        let mut seeded = Vec::new();
        for _ in 0..w {
            let p = fast_primes(&mut rng);
            seeded.push(ser(&p));
            pool.put(p).unwrap();
        }
        assert_eq!(pool.storage().count().unwrap(), w);
        // Sanity: the seeded sets are mutually distinct.
        for i in 0..w {
            for j in (i + 1)..w {
                assert_ne!(seeded[i], seeded[j], "seeded sets must be distinct");
            }
        }

        let (drawn, fallbacks) = drain_like_production(Some(&pool), w, &mut rng);

        assert_eq!(fallbacks, 0, "a fully warm pool must NOT inline-generate");
        assert_eq!(drawn.len(), w);
        // Each held index got the pooled set, in FIFO order — distinct per index.
        for (i, p) in drawn.iter().enumerate() {
            assert_eq!(
                ser(p),
                seeded[i],
                "index {i} must get the i-th pooled set (FIFO)"
            );
        }
        assert_eq!(pool.storage().count().unwrap(), 0, "pool fully drained");
    }

    /// A partially warm pool (fewer sets than indices) drains every pooled set
    /// FIRST, then falls back to inline gen ONLY for the shortfall — proving the
    /// pool is exhausted before any inline generation (strictly Pareto).
    #[test]
    fn partial_pool_drains_first_then_falls_back_for_shortfall() {
        let mut rng = rand::rngs::OsRng;
        let w = 3;
        let seeded_count = 1;

        let pool = PaillierPool::new(InMemoryPoolStorage::new(), &[0x22u8; 32], b"seam", w);
        let mut seeded = Vec::new();
        for _ in 0..seeded_count {
            let p = fast_primes(&mut rng);
            seeded.push(ser(&p));
            pool.put(p).unwrap();
        }

        let (drawn, fallbacks) = drain_like_production(Some(&pool), w, &mut rng);

        assert_eq!(drawn.len(), w);
        assert_eq!(
            fallbacks,
            w - seeded_count,
            "exactly the shortfall must inline-generate"
        );
        // The FIRST index consumed the one pooled set (warm-first ordering).
        assert_eq!(
            ser(&drawn[0]),
            seeded[0],
            "pooled set drained before fallback"
        );
        assert_eq!(pool.storage().count().unwrap(), 0, "pool fully drained");
    }

    /// No pool (the `None` arm) is byte-identical to today: every index inline-gens.
    #[test]
    fn absent_pool_falls_back_for_every_index() {
        let mut rng = rand::rngs::OsRng;
        let w = 3;
        let (drawn, fallbacks) = drain_like_production(None, w, &mut rng);
        assert_eq!(drawn.len(), w);
        assert_eq!(
            fallbacks, w,
            "no pool ⇒ all indices inline-generate (unchanged)"
        );
    }
}
