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
struct PeerIdentityResponse {
    relay_pub_hex: String,
    /// #85: the cosigner's MASTER pub (what the device pins) + its attestation over
    /// (master, session, index, relay_pub). `Option` so an un-hardened/legacy
    /// container still parses — but a PINNED device rejects a missing attestation.
    #[serde(default)]
    master_pub_hex: Option<String>,
    #[serde(default)]
    attestation_hex: Option<String>,
}

#[derive(serde::Deserialize)]
struct ArmResponse {
    peer_pub_hex: String,
}

/// Fresh isolated SQLite storage for an in-process device keygen party. The share
/// is read out of the completion channel (`DkgResult`) and sealed by the caller,
/// so this storage is incidental — a unique temp path avoids collisions.
fn fresh_storage() -> Arc<RwLock<SqliteShareStorage>> {
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
    timeout: Duration,
) -> Result<String> {
    let peers_json: Vec<serde_json::Value> = peers
        .iter()
        .map(|(i, h)| serde_json::json!({ "index": i, "pub_hex": h }))
        .collect();
    let body = serde_json::json!({
        "agent_id": agent_id,
        "dkg_session": session_hex,
        "my_index": my_index,
        "threshold": threshold,
        "parties": parties,
        "peers": peers_json,
    });
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
    p: DkgOverRelay,
    timeout: Duration,
) -> Result<DkgOverRelayOutput> {
    let proto = |e: bsv_mpc_messagebox::error::MessageBoxError| MpcError::Protocol(e.to_string());
    let cfg = ThresholdConfig::new(p.threshold, p.parties)?;
    let n = p.parties;

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
    let n_local = local_indices.len();
    let mut primes: Vec<PregeneratedPrimes<SecurityLevel128>> =
        tokio::task::spawn_blocking(move || {
            (0..n_local)
                .map(|_| {
                    std::thread::spawn(|| {
                        PregeneratedPrimes::<SecurityLevel128>::generate(&mut rand::rngs::OsRng)
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().expect("prime thread"))
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
    for (h, pp) in dkg_handlers.iter().zip(primes.drain(..)) {
        h.seed_primes_for(session, pp);
    }
    let mut listeners: Vec<MessageBoxListener> = Vec::new();
    for (pos, h) in dkg_handlers.iter().enumerate() {
        let l = MessageBoxListener::start(local_clients[pos].clone(), BOX_DKG, h.handler_fn())
            .await
            .map_err(|e| MpcError::Protocol(format!("dkg-over-relay listener: {e}")))?;
        listeners.push(l);
    }
    let mut rxs = Vec::new();
    let mut sends: Vec<(usize, Vec<OutgoingRoundMessage>)> = Vec::new();
    for (pos, &idx) in local_indices.iter().enumerate() {
        let (rx, out) = dkg_handlers[pos]
            .initiate(session, peers_for(idx)?)
            .await
            .map_err(|e| MpcError::Protocol(format!("dkg-over-relay initiate: {e}")))?;
        rxs.push(rx);
        sends.push((pos, out));
    }
    for (pos, out) in sends {
        for o in out {
            // Reliable (bounded idempotent retry): a dropped round-1 message
            // stalls the whole ceremony; the stable-id re-send is a relay no-op.
            local_clients[pos]
                .send_round_message_reliable(
                    &o.recipient_pub_hex,
                    &o.message_box,
                    &o.round_msg,
                    o.params,
                    4,
                )
                .await
                .map_err(proto)?;
        }
    }

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
    //    doesn't co-hold. Skipped for un-pinned dev/test cosigners. ──
    for c in &p.cosigners {
        if let Some(master_hex) = &c.expected_master_pub {
            let challenge_url = c.init_url.replace("/dkg-relay/init", "/identity-challenge");
            challenge_cosigner(&challenge_url, master_hex, &joint_key.compressed).await?;
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
