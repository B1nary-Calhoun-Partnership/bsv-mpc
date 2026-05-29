//! **Shared §18.2 cross-(t,n) reshare-over-relay coordinator**, factored out of
//! `bsv-mpc-proxy::bridge::MpcBridge::reshare_change_threshold_over_relay` (issue
//! #66, path a-extended) so the BRC-100 proxy AND the native `bsv-mpc-client` run
//! the EXACT same address-preserving reshare ceremony.
//!
//! The caller drives one-or-more in-process NEW-set parties while the deployed CF
//! **Container** (armed via `POST /reshare-relay/init`) plays its own NEW-set party
//! (the remote contributor). Exactly ONE in-process party contributes its OLD secret
//! (the proxy's live share for the change-threshold path; the recovered backup
//! share B for the #66 L1 recovery path); the rest are recipient-only.
//!
//! Two callers, one ceremony:
//! - **proxy** (2-of-2 → 2-of-3): plays NEW parties `{1, 2}`; party 1 is the local
//!   contributor (proxy's old share), party 2 recipient-only; container = NEW party 0.
//! - **client recovery** (2-of-2 → 2-of-2): plays NEW party `{1}` (the local
//!   contributor, old secret = the unwrapped backup share B); container = NEW party 0.
//!
//! The joint pubkey is UNCHANGED (the §18 invariant — same address, no funds move);
//! [`coordinate_reshare_over_relay`] rejects any PSS commit whose joint pubkey
//! changed.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::error::{MpcError, Result};
use bsv_mpc_core::reshar_coordinator::{
    combine_reshared_with_aux, ContributorInputs, ResharConfig,
};
use bsv_mpc_core::types::{SessionId, ThresholdConfig};
use bsv_mpc_messagebox::types::{BOX_DKG, BOX_REFRESH};
use bsv_mpc_messagebox::MessageBoxClient;
use bsv_mpc_service::{
    DkgHandler, MessageBoxListener, OutgoingRoundMessage, ResharHandler, SqliteShareStorage,
};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::{KeyShare, PregeneratedPrimes};
use generic_ec::{NonZero, Scalar, SecretScalar};
use rand::RngCore;

// ─── Arm-the-container helpers (moved verbatim from bsv-mpc-proxy::relay_reshare) ─
//
// The proxy re-exports these via `pub use bsv_mpc_relay::reshare::*` so existing
// `crate::relay_reshare::*` references resolve unchanged.

/// Canonical BRC-31 request signer (same shape as [`crate::RelayRequestSigner`]).
pub type RequestSigner<'a> =
    &'a (dyn Fn(&str, &str, &[u8]) -> Result<Vec<(String, String)>> + Send + Sync);

/// An owned, `'static` canonical BRC-31 request signer — the form
/// [`coordinate_reshare_over_relay`] needs because it arms the container in a
/// spawned task (which requires `'static + Send + Sync`). Callers wrap their
/// session closure in an `Arc`.
pub type ArmRequestSigner =
    Arc<dyn Fn(&str, &str, &[u8]) -> Result<Vec<(String, String)>> + Send + Sync>;

/// A new-set peer's relay identity, as sent to the container's `peers` field.
#[derive(serde::Serialize, Clone)]
pub struct ReshareRelayPeer {
    pub index: u16,
    pub pub_hex: String,
}

/// Everything the container needs to play its new-set party in the reshare.
pub struct ContainerArm {
    /// The container's `/reshare-relay/init` URL.
    pub url: String,
    /// The share's `agent_id` (joint pubkey hex K) for owner-authz (§08.1).
    pub agent_id: String,
    /// The throwaway-DKG session_id (hex).
    pub dkg_session_hex: String,
    /// The PSS reshare session_id (hex).
    pub reshare_session_hex: String,
    /// The container's index in the NEW party set.
    pub my_new_index: u16,
    /// The NEW threshold `t'`.
    pub new_threshold: u16,
    /// The NEW party count `n'`.
    pub new_parties: u16,
    /// The NEW set's VSS eval points (party order), 32-byte BE scalar hex each.
    pub new_eval_points_hex: Vec<String>,
    /// The NEW-set indices of the contributors.
    pub contributor_new_indices: Vec<u16>,
    /// The OLD-set indices of the same contributors (canonical ascending).
    pub contributor_old_indices: Vec<u16>,
    /// All OTHER new-set parties' relay identities (the caller's in-process parties).
    pub peers: Vec<ReshareRelayPeer>,
}

#[derive(serde::Deserialize)]
struct ArmResponse {
    peer_pub_hex: String,
}

/// GET the container's `/reshare-relay/identity` (read-only) → its relay identity hex.
pub async fn fetch_peer_identity(init_url: &str) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct IdResponse {
        peer_pub_hex: String,
    }
    let url = init_url.replace("/reshare-relay/init", "/reshare-relay/identity");
    let resp = crate::bounded_http_client(crate::RELAY_HTTP_TIMEOUT)?
        .get(&url)
        .send()
        .await
        .map_err(|e| MpcError::Protocol(format!("fetch reshare peer identity: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "/reshare-relay/identity returned {status}: {txt}"
        )));
    }
    let parsed: IdResponse = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse reshare identity response: {e}")))?;
    Ok(parsed.peer_pub_hex)
}

/// POST `/reshare-relay/init`, BRC-31-signed over the canonical wire. Returns the
/// container's relay identity hex (must match the earlier `fetch_peer_identity`).
///
/// Uses a long-timeout client (the container runs BOTH ceremony phases — including
/// safe-prime generation for its throwaway DKG — before its completion task, but
/// it RESPONDS as soon as it has armed both phases; the timeout is defensive).
pub async fn arm_container(
    arm: &ContainerArm,
    request_signer: RequestSigner<'_>,
    timeout: Duration,
) -> Result<String> {
    let body = serde_json::json!({
        "agent_id": arm.agent_id,
        "dkg_session": arm.dkg_session_hex,
        "reshare_session": arm.reshare_session_hex,
        "my_new_index": arm.my_new_index,
        "new_threshold": arm.new_threshold,
        "new_parties": arm.new_parties,
        "new_eval_points_hex": arm.new_eval_points_hex,
        "contributor_new_indices": arm.contributor_new_indices,
        "contributor_old_indices": arm.contributor_old_indices,
        "peers": arm.peers,
    });
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| MpcError::Serialization(format!("serialize reshare-relay/init: {e}")))?;
    let path = reqwest::Url::parse(&arm.url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| "/reshare-relay/init".to_string());

    let http = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| MpcError::Protocol(format!("build reshare http client: {e}")))?;
    let mut builder = http
        .post(&arm.url)
        .header("content-type", "application/json")
        .body(body_bytes.clone());
    for (name, value) in request_signer("POST", &path, &body_bytes)? {
        builder = builder.header(name, value);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| MpcError::Protocol(format!("arm reshare peer request: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "container /reshare-relay/init returned {status}: {txt}"
        )));
    }
    let parsed: ArmResponse = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse reshare-relay/init response: {e}")))?;
    Ok(parsed.peer_pub_hex)
}

// ─── The shared reshare-over-relay coordinator ───────────────────────────────────

/// The OLD-share topology a caller needs to plan the reshare, parsed from a
/// serialized cggmp24 `KeyShare` JSON (so the client never depends on cggmp24 /
/// generic-ec directly — the parse lives here, in the native-only relay crate).
#[derive(Debug, Clone)]
pub struct OldShareTopology {
    /// This share's OLD-set index (`core.i`).
    pub old_index: u16,
    /// The OLD threshold `t`.
    pub threshold: u16,
    /// The OLD party count `n`.
    pub parties: u16,
    /// The wallet's joint (shared) public key (33-byte compressed) — the §18
    /// invariant K + the wallet `agent_id`. Carried inside the share itself, so a
    /// recovering device derives the address it is restoring from the backup share
    /// alone (no separate joint-pubkey input).
    pub joint_pubkey_compressed: Vec<u8>,
}

/// Parse the OLD `(t, n)` + this share's index + the joint pubkey out of a
/// serialized cggmp24 `KeyShare` JSON (the device-sealed share / recovered backup
/// share B), so the client never depends on cggmp24 / generic-ec directly.
pub fn parse_old_share_topology(share_json: &[u8]) -> Result<OldShareTopology> {
    let ks: KeyShare<Secp256k1, SecurityLevel128> = serde_json::from_slice(share_json)
        .map_err(|e| MpcError::Protocol(format!("reshare: bad old key share: {e}")))?;
    let old_index = ks.core.i;
    let parties = ks.core.public_shares.len() as u16;
    let threshold = ks
        .core
        .key_info
        .vss_setup
        .as_ref()
        .map(|v| v.min_signers)
        .ok_or_else(|| MpcError::Protocol("reshare: old key share has no VSS setup".into()))?;
    let joint_pubkey_compressed = ks.core.key_info.shared_public_key.to_bytes(true).to_vec();
    Ok(OldShareTopology {
        old_index,
        threshold,
        parties,
        joint_pubkey_compressed,
    })
}

/// Inputs for the in-process side of a §18.2 reshare over the relay.
pub struct ReshareOverRelay {
    /// MessageBox relay URL.
    pub relay_url: String,
    /// The container's `/reshare-relay/init` URL.
    pub container_init_url: String,
    /// The share's `agent_id` (joint pubkey hex K) — owner-authz (§08.1) + session salt.
    pub agent_id: String,
    /// The UNCHANGED joint pubkey (33-byte compressed) — the §18 invariant.
    pub joint_pubkey_compressed: Vec<u8>,
    /// The NEW threshold `t'`.
    pub new_threshold: u16,
    /// The NEW party count `n'`.
    pub new_parties: u16,
    /// The NEW-set indices of the `new_threshold` contributors.
    pub contributor_new_indices: Vec<u16>,
    /// The OLD-set indices of the same contributors (canonical ascending).
    pub contributor_old_indices: Vec<u16>,
    /// The container's index in the NEW set (the remote contributor; `0` in the
    /// proven flows).
    pub container_new_index: u16,
    /// The NEW-set indices of the in-process parties this caller drives.
    pub local_new_indices: Vec<u16>,
    /// The local contributing party's NEW index (one of `local_new_indices`). The
    /// other in-process parties are recipient-only.
    pub local_contributor_new_index: u16,
    /// The local contributing party's OLD-set index.
    pub local_contributor_old_index: u16,
    /// The local contributing party's OLD cggmp24 `KeyShare` JSON. Its secret scalar
    /// + the contributor subset's OLD eval points are extracted here.
    pub local_contributor_old_share_json: Vec<u8>,
    /// **#85 MITM gate.** The container's MASTER identity pubkey hex, PINNED
    /// out-of-band (the recovering device targets a *named* cosigner — it knows its
    /// identity, not whatever the unauthenticated `/reshare-relay/identity` returns).
    /// When `Some`, the fetched container identity MUST equal this pin (a MITM
    /// substitution → reject) and the device routes to the PINNED value, then runs a
    /// post-reshare liveness challenge against it (the preserved joint pubkey is the
    /// §18 invariant) before returning the rotated shares. `None` = unpinned (legacy/dev).
    pub expected_master_pub: Option<String>,
}

/// The reshare output: the UNCHANGED joint pubkey + this caller's rotated NEW-set
/// signable KeyShares.
pub struct ReshareOutput {
    /// The UNCHANGED joint pubkey (hex compressed) — the reshare invariant.
    pub joint_pubkey_hex: String,
    /// The new threshold `t'`.
    pub new_threshold: u16,
    /// The new party count `n'`.
    pub new_parties: u16,
    /// This caller's signing-ready NEW-set KeyShares: `(new_index, KeyShare JSON)`.
    pub local_key_shares_json: Vec<(u16, Vec<u8>)>,
}

/// Fresh isolated (Sqlite-backed) storage for a throwaway-DKG party — its share is
/// DISCARDED (only the aux is combined), so a unique temp path avoids collisions.
fn fresh_throwaway_storage() -> Arc<RwLock<SqliteShareStorage>> {
    let mut tag = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut tag);
    let dir = std::env::temp_dir().join(format!("mpc-reshare-throwaway-{}", hex::encode(tag)));
    let path = dir.to_string_lossy().to_string();
    let s = SqliteShareStorage::open(&path).expect("open throwaway storage");
    Arc::new(RwLock::new(s))
}

/// Run the §18.2 cross-(t,n) reshare over the relay for this caller's in-process
/// NEW-set parties, arming the deployed container as NEW party
/// [`container_new_index`](ReshareOverRelay::container_new_index).
///
/// Mirrors the proven `MpcBridge::reshare_change_threshold_over_relay` ceremony,
/// generalized over the new topology + the in-process party set. Phase A is a
/// throwaway joint DKG (fresh aux) over `mpc-dkg`; phase B is the cross-(t,n) PSS
/// over `mpc-refresh`; each commit is combined with its aux into a signable share.
/// The joint pubkey is asserted UNCHANGED on every commit (the §18 invariant).
pub async fn coordinate_reshare_over_relay(
    p: ReshareOverRelay,
    arm_request_signer: ArmRequestSigner,
    timeout: Duration,
) -> Result<ReshareOutput> {
    let proto = |e: bsv_mpc_messagebox::error::MessageBoxError| MpcError::Protocol(e.to_string());

    let new_t = p.new_threshold;
    let n_new = p.new_parties;
    let new_cfg = ThresholdConfig::new(new_t, n_new)?;

    // Canonical NEW-set VSS eval points (1..=n'), matching the proven ceremony.
    let new_eval: Vec<NonZero<Scalar<Secp256k1>>> = (1..=n_new)
        .map(|i| {
            NonZero::from_scalar(Scalar::from(i as u64))
                .ok_or_else(|| MpcError::Protocol("zero new eval point".into()))
        })
        .collect::<Result<_>>()?;
    let new_eval_points_hex: Vec<String> = new_eval
        .iter()
        .map(|s| hex::encode(s.as_ref().to_be_bytes().as_bytes()))
        .collect();

    // ── The UNCHANGED joint pubkey K ──
    let jpk_bytes = p.joint_pubkey_compressed.clone();
    if jpk_bytes.len() != 33 {
        return Err(MpcError::Protocol(
            "reshare: joint pubkey must be 33 bytes".into(),
        ));
    }

    // ── Extract the local contributor's OLD secret + eval points from its OLD share. ──
    let old_keyshare: KeyShare<Secp256k1, SecurityLevel128> =
        serde_json::from_slice(&p.local_contributor_old_share_json)
            .map_err(|e| MpcError::Protocol(format!("reshare: bad local old key share: {e}")))?;
    let parsed_old_index: u16 = old_keyshare.core.i;
    if parsed_old_index != p.local_contributor_old_index {
        return Err(MpcError::Protocol(format!(
            "reshare: local old share index {parsed_old_index} != declared {}",
            p.local_contributor_old_index
        )));
    }
    let old_eval: Vec<NonZero<Scalar<Secp256k1>>> = old_keyshare
        .core
        .key_info
        .vss_setup
        .as_ref()
        .ok_or_else(|| MpcError::Protocol("reshare: local old share has no VSS setup".into()))?
        .I
        .clone();
    let local_old_secret: Scalar<Secp256k1> =
        *<SecretScalar<Secp256k1> as AsRef<Scalar<Secp256k1>>>::as_ref(&old_keyshare.core.x);
    // The contributor subset's OLD eval points (ascending by old index).
    let subset_old_eval: Vec<NonZero<Scalar<Secp256k1>>> =
        p.contributor_old_indices
            .iter()
            .map(|k| {
                old_eval.get(*k as usize).copied().ok_or_else(|| {
                    MpcError::Protocol(format!("reshare: old eval point {k} missing"))
                })
            })
            .collect::<Result<_>>()?;

    // ── Sessions ──
    let mk_session = |tag: &str| {
        let mut seed = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        SessionId::from_str_hash(&format!(
            "reshare-{tag}-{}-{}",
            p.agent_id,
            hex::encode(seed)
        ))
    };
    let dkg_session = mk_session("dkg");
    let reshare_session = mk_session("pss");

    // ── The caller's in-process NEW-set parties: fresh relay identities + clients. ──
    let local_new_indices = p.local_new_indices.clone();
    let mut local_privs: Vec<PrivateKey> = Vec::new();
    let mut local_clients: Vec<MessageBoxClient> = Vec::new();
    let mut local_pubs: Vec<String> = Vec::new();
    for _ in 0..local_new_indices.len() {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b[0] |= 0x01;
        let priv_key = PrivateKey::from_bytes(&b)
            .map_err(|e| MpcError::Protocol(format!("reshare: party identity: {e}")))?;
        let c = MessageBoxClient::new(&p.relay_url, priv_key.clone()).map_err(proto)?;
        let ph = c.identity_hex().await.map_err(proto)?;
        local_privs.push(priv_key);
        local_clients.push(c);
        local_pubs.push(ph);
    }

    // ── Fetch the container's relay identity (the remote contributor) FIRST (§06.17). ──
    let fetched_container_pub = fetch_peer_identity(&p.container_init_url).await?;
    // #85: the reshare cosigner identity IS its master — when pinned, verify the
    // fetched value equals the pin (a MITM substitution → reject) and route to the
    // PINNED value (only the real master controls that relay identity).
    let container_pub_hex = match &p.expected_master_pub {
        Some(pinned) => {
            if &fetched_container_pub != pinned {
                return Err(MpcError::Protocol(format!(
                    "reshare cosigner identity {fetched_container_pub} != pinned master {pinned} (#85 MITM)"
                )));
            }
            pinned.clone()
        }
        None => fetched_container_pub,
    };

    // The full NEW-set identity map: container_new_index = container; the rest = local.
    let identity_for = |idx: u16| -> Option<String> {
        if idx == p.container_new_index {
            return Some(container_pub_hex.clone());
        }
        local_new_indices
            .iter()
            .position(|&k| k == idx)
            .map(|pos| local_pubs[pos].clone())
    };
    let peers_for = |me: u16| -> Result<Vec<(u16, String)>> {
        (0..n_new)
            .filter(|&k| k != me)
            .map(|k| {
                identity_for(k).map(|h| (k, h)).ok_or_else(|| {
                    MpcError::Protocol(format!("reshare: no identity for party {k}"))
                })
            })
            .collect()
    };

    // ── Arm the container FIRST + ASYNC so its phase-A slot is live before we ship
    //    round-1 (§06.17 ordering). It runs BOTH phases SEQUENTIALLY for its own
    //    party and stores its rotated new-(t,n) share on commit. ──
    let arm = ContainerArm {
        url: p.container_init_url.clone(),
        agent_id: p.agent_id.clone(),
        dkg_session_hex: dkg_session.hex(),
        reshare_session_hex: reshare_session.hex(),
        my_new_index: p.container_new_index,
        new_threshold: new_t,
        new_parties: n_new,
        new_eval_points_hex,
        contributor_new_indices: p.contributor_new_indices.clone(),
        contributor_old_indices: p.contributor_old_indices.clone(),
        peers: local_new_indices
            .iter()
            .enumerate()
            .map(|(pos, &idx)| ReshareRelayPeer {
                index: idx,
                pub_hex: local_pubs[pos].clone(),
            })
            .collect(),
    };
    let arm_timeout = timeout + Duration::from_secs(60);
    let arm_signer = arm_request_signer.clone();
    let arm_handle =
        tokio::spawn(async move { arm_container(&arm, &*arm_signer, arm_timeout).await });

    // ════ PHASE A — throwaway joint DKG over the relay (caller's parties) ════
    //
    // §06.17 ORDERING: SUBSCRIBE + initiate + ship keygen round-1 IMMEDIATELY (no
    // late relay join), THEN generate primes off the hot path and `seed_primes_late`
    // into the live coordinators before the keygen→auxinfo transition.
    let dkg_handlers: Vec<DkgHandler> = local_new_indices
        .iter()
        .map(|&idx| DkgHandler::new(new_cfg, idx, fresh_throwaway_storage()))
        .collect();
    let mut dkg_listeners: Vec<MessageBoxListener> = Vec::new();
    for (pos, h) in dkg_handlers.iter().enumerate() {
        let l = MessageBoxListener::start(local_clients[pos].clone(), BOX_DKG, h.handler_fn())
            .await
            .map_err(|e| MpcError::Protocol(format!("reshare dkg listener: {e}")))?;
        dkg_listeners.push(l);
    }
    let mut dkg_rxs = Vec::new();
    let mut dkg_sends: Vec<(usize, Vec<OutgoingRoundMessage>)> = Vec::new();
    for (pos, &idx) in local_new_indices.iter().enumerate() {
        let (rx, out) = dkg_handlers[pos]
            .initiate(dkg_session, peers_for(idx)?)
            .await
            .map_err(|e| MpcError::Protocol(format!("reshare dkg initiate: {e}")))?;
        dkg_rxs.push(rx);
        dkg_sends.push((pos, out));
    }
    for (pos, out) in dkg_sends {
        for o in out {
            local_clients[pos]
                .send_round_message(&o.recipient_pub_hex, &o.message_box, &o.round_msg, o.params)
                .await
                .map_err(proto)?;
        }
    }

    // Round-1 shipped — generate the safe-prime sets in parallel off the hot path
    // and late-seed them into the live coordinators before the auxinfo transition.
    {
        let seed_handlers: Vec<DkgHandler> = dkg_handlers.clone();
        let n_parties = local_new_indices.len();
        tokio::spawn(async move {
            let primes: Vec<PregeneratedPrimes<SecurityLevel128>> =
                match tokio::task::spawn_blocking(move || {
                    (0..n_parties)
                        .map(|_| {
                            std::thread::spawn(|| {
                                PregeneratedPrimes::<SecurityLevel128>::generate(
                                    &mut rand::rngs::OsRng,
                                )
                            })
                        })
                        .collect::<Vec<_>>()
                        .into_iter()
                        .map(|h| h.join().expect("prime thread"))
                        .collect()
                })
                .await
                {
                    Ok(pp) => pp,
                    Err(e) => {
                        tracing::warn!(
                            "reshare: prime gen task panicked: {e}; auxinfo will generate inline"
                        );
                        return;
                    }
                };
            for (h, pp) in seed_handlers.iter().zip(primes) {
                h.seed_primes_late(dkg_session, pp);
            }
        });
    }

    // Confirm the container ARMED before the (long) phase-A wait. The arm responds
    // in seconds — right after it subscribes + ships its own round-1 — so an
    // owner-authz / auth failure (e.g. a wrong recovery identity) surfaces HERE with
    // the real error in seconds, instead of as an opaque "DKG timed out" only after
    // the full ceremony timeout elapses. The caller's parties have ALREADY subscribed
    // + shipped round-1, so the container's messages are delivered (live push or
    // backfill) regardless of this await — the happy path is unchanged.
    match arm_handle.await {
        Ok(Ok(armed_pub)) if armed_pub == container_pub_hex => {}
        Ok(Ok(armed_pub)) => {
            for l in dkg_listeners {
                let _ = l.shutdown().await;
            }
            return Err(MpcError::Protocol(format!(
                "reshare: container relay identity changed between identity ({container_pub_hex}) and arm ({armed_pub})"
            )));
        }
        Ok(Err(e)) => {
            for l in dkg_listeners {
                let _ = l.shutdown().await;
            }
            return Err(e);
        }
        Err(e) => {
            for l in dkg_listeners {
                let _ = l.shutdown().await;
            }
            return Err(MpcError::Protocol(format!(
                "reshare: container arm task panicked: {e}"
            )));
        }
    }

    // Await phase A (caller's parties' aux), then RELEASE the DKG subscriptions
    // before phase B (sequential — one subscription per identity).
    let mut local_aux: Vec<bsv_mpc_core::types::DkgResult> = Vec::new();
    for (pos, &idx) in local_new_indices.iter().enumerate() {
        match tokio::time::timeout(timeout, &mut dkg_rxs[pos]).await {
            Ok(Ok(r)) => local_aux.push(r),
            Ok(Err(e)) => {
                for l in dkg_listeners {
                    let _ = l.shutdown().await;
                }
                return Err(MpcError::Protocol(format!(
                    "reshare: party {idx} DKG channel dropped: {e}"
                )));
            }
            Err(_) => {
                for l in dkg_listeners {
                    let _ = l.shutdown().await;
                }
                return Err(MpcError::Protocol(format!(
                    "reshare: party {idx} timed out awaiting throwaway DKG aux"
                )));
            }
        }
    }
    for l in dkg_listeners {
        let _ = tokio::time::timeout(Duration::from_secs(10), l.shutdown()).await;
    }

    // ════ PHASE B — cross-(t,n) PSS reshare over the relay (caller's parties) ════
    let reshar_handlers: Vec<ResharHandler> = local_new_indices
        .iter()
        .map(|_| ResharHandler::new())
        .collect();
    let mut pss_listeners: Vec<MessageBoxListener> = Vec::new();
    for (pos, h) in reshar_handlers.iter().enumerate() {
        let l = MessageBoxListener::start(local_clients[pos].clone(), BOX_REFRESH, h.handler_fn())
            .await
            .map_err(|e| MpcError::Protocol(format!("reshare pss listener: {e}")))?;
        pss_listeners.push(l);
    }
    let mut pss_rxs = Vec::new();
    let mut pss_sends: Vec<(usize, Vec<OutgoingRoundMessage>)> = Vec::new();
    for (pos, &idx) in local_new_indices.iter().enumerate() {
        // Exactly one in-process party contributes its OLD secret; the rest are
        // recipient-only.
        let contributor = if idx == p.local_contributor_new_index {
            let my_subset_pos = p
                .contributor_old_indices
                .iter()
                .position(|k| *k == p.local_contributor_old_index)
                .ok_or_else(|| {
                    MpcError::Protocol(format!(
                        "reshare: local old index {} not in contributor set",
                        p.local_contributor_old_index
                    ))
                })?;
            Some(ContributorInputs {
                my_subset_pos,
                subset_eval_points: subset_old_eval.clone(),
                my_old_secret: local_old_secret,
            })
        } else {
            None
        };
        let config = ResharConfig {
            session_id: reshare_session,
            my_new_index: idx,
            new_eval_points: new_eval.clone(),
            new_t,
            contributor_new_indices: p.contributor_new_indices.clone(),
            original_joint_pubkey: jpk_bytes.clone(),
            contributor,
        };
        let (rx, out) = reshar_handlers[pos]
            .initiate(config, peers_for(idx)?)
            .await
            .map_err(|e| MpcError::Protocol(format!("reshare pss initiate: {e}")))?;
        pss_rxs.push(rx);
        pss_sends.push((pos, out));
    }
    for (pos, out) in pss_sends {
        for o in out {
            local_clients[pos]
                .send_round_message(&o.recipient_pub_hex, &o.message_box, &o.round_msg, o.params)
                .await
                .map_err(proto)?;
        }
    }

    // ── Await phase B (PSS commits) + combine each with its phase-A aux ──
    let mut local_key_shares_json: Vec<(u16, Vec<u8>)> = Vec::new();
    for (pos, &idx) in local_new_indices.iter().enumerate() {
        let commit = match tokio::time::timeout(timeout, &mut pss_rxs[pos]).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                for l in pss_listeners {
                    let _ = l.shutdown().await;
                }
                return Err(MpcError::Protocol(format!(
                    "reshare: party {idx} PSS channel dropped: {e}"
                )));
            }
            Err(_) => {
                for l in pss_listeners {
                    let _ = l.shutdown().await;
                }
                return Err(MpcError::Protocol(format!(
                    "reshare: party {idx} timed out awaiting PSS commit"
                )));
            }
        };
        // §18 invariant: the joint pubkey MUST be unchanged (same address).
        if commit.joint_pubkey_compressed != jpk_bytes {
            for l in pss_listeners {
                let _ = l.shutdown().await;
            }
            return Err(MpcError::Protocol(format!(
                "reshare: party {idx} joint pubkey CHANGED (reshare invariant violated)"
            )));
        }
        let combined = combine_reshared_with_aux(
            &commit.incomplete_share_json,
            &local_aux[pos].share.ciphertext,
        )?;
        local_key_shares_json.push((idx, combined));
    }
    for l in pss_listeners {
        let _ = tokio::time::timeout(Duration::from_secs(10), l.shutdown()).await;
    }

    // (The container arm was confirmed BEFORE phase A — see the early `arm_handle`
    // await above — so by here it has stored its own rotated new-(t,n) share.)

    // ── #85 liveness gate: confirm the PINNED cosigner is live + controls its master
    //    for THIS (preserved §18) joint key before returning the rotated shares — a
    //    fresh-nonce signed challenge to the pinned master (parity with the DKG
    //    funding gate). Skipped for un-pinned legacy/dev. ──
    if let Some(master_hex) = &p.expected_master_pub {
        let challenge_url = p
            .container_init_url
            .replace("/reshare-relay/init", "/identity-challenge");
        crate::provision_dkg::challenge_cosigner(&challenge_url, master_hex, &jpk_bytes).await?;
    }

    Ok(ReshareOutput {
        joint_pubkey_hex: hex::encode(&jpk_bytes),
        new_threshold: new_t,
        new_parties: n_new,
        local_key_shares_json,
    })
}
