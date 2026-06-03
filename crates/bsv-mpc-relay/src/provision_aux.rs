//! **#104 aux-REUSE — the one-time group AUX-SETUP ceremony (the PRODUCER).**
//!
//! Mirrors [`provision_dkg::coordinate_dkg_over_relay`](crate::provision_dkg::coordinate_dkg_over_relay)
//! but runs the n-of-n CGGMP'24 aux-info ceremony in **CAPTURE mode**: instead of
//! keeping the throwaway keygen share, each party captures its index's `AuxInfo`.
//! The device drives its `w = t−1` in-process parties; each Notary index is armed
//! via `POST /aux-setup/init`, captures + KEK-seals its own aux into durable
//! custody. Aux-info is independent of any wallet key, so this ceremony runs ONCE
//! for a fixed `(device, Notary-set)` group, and every later per-wallet provision
//! REUSES the sealed aux (keygen + `from_parts` only — the per-wallet
//! time-to-sendable lever).
//!
//! ## Security (the #104 must-dos this function enforces)
//! - **#1 attestation** — each per-index relay pub fetched over
//!   `/aux-setup/peer-identity` MUST carry a valid attestation by the PINNED
//!   master (identical gate to DKG; a network MITM cannot forge the master's
//!   signature, so it cannot be the Notary's transport identity).
//! - **#2 aux-bound liveness challenge** — after the ceremony, the device extracts
//!   each Notary index's Paillier/Pedersen moduli FROM ITS OWN captured aux and
//!   challenges the live pinned master to sign over exactly those moduli
//!   (`/aux-setup/challenge`). A setup-time modulus swap (attacker-known
//!   factorization) makes this signature fail — the device REFUSES to seal aux it
//!   could not prove the live Notary owns. Fail-closed.
//! - **#5/#6/#7 binding envelope** — the device builds a MAC'd
//!   [`AuxBindingRecord`] over the frozen group + moduli; every future load
//!   re-verifies it ([`validate_aux_for_load`]), so a tampered sealed blob is
//!   rejected at the load boundary, not at a late sign abort.
//!
//! There is no joint key at aux-setup, so the per-wallet #101 keygen checkpoint and
//! the #85 funding challenge (which bind the joint pubkey) are ABSENT here — the
//! aux-bound liveness challenge is their setup-phase analogue.
//!
//! Heavy MPC — the Notary side runs on the CONTAINER, never the worker isolate.

use std::sync::Arc;
use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv_mpc_core::aux_binding::{
    aux_binding_mac, aux_index_moduli_msf, build_aux_binding_record, derive_binding_mac_key,
    AuxBindingRecord,
};
use bsv_mpc_core::canonical::{canonical_aux_setup_execution_id, AuxGroupDescriptor};
use bsv_mpc_core::error::{MpcError, Result};
use bsv_mpc_core::paillier_pool::{generate_serialized, PaillierPool, PrimePoolStorage};
use bsv_mpc_core::types::{SessionId, ThresholdConfig};
use bsv_mpc_messagebox::types::BOX_DKG;
use bsv_mpc_messagebox::MessageBoxClient;
use bsv_mpc_service::{DkgHandler, MessageBoxListener, OutgoingRoundMessage};
use cggmp24::key_share::AuxInfo;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::PregeneratedPrimes;
use rand::RngCore;

use crate::provision_dkg::{fresh_storage, ArmResponse, PeerIdentityResponse};
use crate::reshare::ArmRequestSigner;

/// One deployed Notary endpoint for the aux-setup ceremony + the indices it drives.
///
/// `init_url` is the Notary's `/aux-setup/init` URL; the `/aux-setup/peer-identity`
/// and `/aux-setup/challenge` URLs are derived from it. `expected_master_pub` is the
/// PINNED master (the #85 MITM gate + the #2 liveness-challenge verifier); `None` is
/// hermetic-test only (NOT for a group whose aux will guard funds).
pub struct AuxCosignerEndpoint {
    /// The Notary's `POST /aux-setup/init` URL.
    pub init_url: String,
    /// The absolute aux-setup indices this Notary drives, ascending.
    pub indices: Vec<u16>,
    /// BRC-31 request signer for this Notary's session (arms are POSTed signed).
    pub arm_signer: ArmRequestSigner,
    /// **#1/#2 PINNED master.** Every per-index relay pub MUST attest to it, and the
    /// post-ceremony liveness challenge is verified against it before sealing.
    pub expected_master_pub: Option<String>,
}

/// Inputs for the device side of the one-time group aux-setup ceremony.
pub struct AuxSetupOverRelay {
    /// MessageBox relay URL.
    pub relay_url: String,
    /// The wallet threshold `t` this group will use (recorded into the binding).
    pub threshold: u16,
    /// The party count `n`.
    pub parties: u16,
    /// The device's in-process aux-setup indices (`w = t−1` of them).
    pub local_indices: Vec<u16>,
    /// The Notary endpoints driving the remaining `n − w` indices.
    pub cosigners: Vec<AuxCosignerEndpoint>,
    /// A provisional ceremony handle for each arm body's `agent_id` (owner-authz
    /// §08.1 salt). The sealed aux is keyed `auxblob-{group_id}#{index}`, so this is
    /// transient, not the storage key.
    pub provisional_agent_id: String,
    /// **OPTIONAL device Paillier prime pool** (Lever B / #99). When `Some`, the
    /// device draws one pre-generated safe-prime set per local index instead of
    /// grinding it inline; a miss falls back to inline gen (strictly Pareto). The
    /// aux SM runs for EVERY local index here (it is the producer), so each needs a
    /// prime set.
    pub prime_pool: Option<Arc<dyn PrimePoolStorage>>,
    /// The device's 32-byte at-rest root: BRC-42-derives the pool encryption key
    /// (when `prime_pool` is `Some`) AND the binding-MAC key sealing each blob.
    pub at_rest_root: [u8; 32],
    /// Domain-separation bytes for the pool encryption key (e.g. the device identity
    /// pubkey). Only consulted when `prime_pool` is `Some`.
    pub pool_id: Vec<u8>,
    /// The 32-byte group-id (= [`bsv_mpc_core::canonical::aux_group_id`] of
    /// [`Self::descriptor`]). Binds every blob + arm to this group.
    pub group_id: [u8; 32],
    /// The pinned-Notary epoch this aux is minted for (must-do #10).
    pub aux_epoch: u64,
    /// The frozen group descriptor (index→master map, `t`, security level) the
    /// binding record pins. `aux_group_id(&descriptor)` MUST equal [`Self::group_id`].
    pub descriptor: AuxGroupDescriptor,
}

/// One device-held index's sealed-ready aux blob: the serialized `AuxInfo`, its
/// MAC'd binding record. The FFI seals each into the Secure Enclave (key-grade).
pub struct AuxSetupBlob {
    /// The absolute share index this aux belongs to (a member of `local_indices`).
    pub index: u16,
    /// The serialized `AuxInfo<SecurityLevel128>` for this index (its secret p,q +
    /// the full public moduli vector).
    pub aux_json: Vec<u8>,
    /// The tamper-evidence record over the group + moduli (must-do #5).
    pub record: AuxBindingRecord,
    /// HMAC of `record` under the at-rest-derived binding-MAC key (must-do #5).
    pub mac: [u8; 32],
}

/// Output: the device-held index aux blobs (the Notaries sealed their own).
pub struct AuxSetupOutput {
    /// One `(index, aux_json, record, mac)` per LOCAL index, ascending.
    pub blobs: Vec<AuxSetupBlob>,
    /// The ceremony session id (audit/log only — the aux is keyed by group_id).
    pub session_id: SessionId,
}

/// Run the one-time group aux-setup ceremony over the relay and return the device's
/// per-index aux blobs (each #2-liveness-proven + #5-binding-sealed). The Notaries
/// capture + KEK-seal their own indices' aux during the ceremony.
pub async fn coordinate_aux_setup_over_relay(
    p: AuxSetupOverRelay,
    timeout: Duration,
) -> Result<AuxSetupOutput> {
    let proto = |e: bsv_mpc_messagebox::error::MessageBoxError| MpcError::Protocol(e.to_string());
    let cfg = ThresholdConfig::new(p.threshold, p.parties)?;
    let n = p.parties;

    // The group-id MUST be the canonical hash of the descriptor the caller pins —
    // a mismatch means the binding record and the arms would disagree on identity.
    let descriptor_gid = bsv_mpc_core::canonical::aux_group_id(&p.descriptor);
    if descriptor_gid != p.group_id {
        return Err(MpcError::Protocol(format!(
            "aux-setup: group_id {} != aux_group_id(descriptor) {} — frozen-group mismatch",
            hex::encode(p.group_id),
            hex::encode(descriptor_gid)
        )));
    }

    // ── Topology: device holds w = t−1; device + Notary indices partition 0..n. ──
    if (p.local_indices.len() as u16) != p.threshold - 1 {
        return Err(MpcError::Protocol(format!(
            "aux-setup: device must hold w = t−1 = {} indices, got {} ({:?})",
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
            "aux-setup: device + Notary indices must be exactly 0..{n} (no gaps/dupes), got {all_indices:?}"
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
            .map_err(|e| MpcError::Protocol(format!("aux-setup: party identity: {e}")))?;
        let c = MessageBoxClient::new(&p.relay_url, priv_key).map_err(proto)?;
        let ph = c.identity_hex().await.map_err(proto)?;
        local_clients.push(c);
        local_pubs.push(ph);
    }

    // ── Fetch each Notary index's per-index relay pub FIRST (#1 attestation). ──
    let mut cosigner_pubs: Vec<(u16, String)> = Vec::new();
    for c in &p.cosigners {
        for &idx in &c.indices {
            let pub_hex = fetch_aux_peer_identity(
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
                    MpcError::Protocol(format!("aux-setup: no identity for party {k}"))
                })
            })
            .collect()
    };

    // ── Arm each Notary index FIRST + ASYNC (§06.17 ordering). ──
    let arm_timeout = timeout + Duration::from_secs(60);
    let mut arm_handles = Vec::new();
    for c in &p.cosigners {
        for &idx in &c.indices {
            let peers = peers_for(idx)?;
            let expected_pub = identity_for(idx).ok_or_else(|| {
                MpcError::Protocol(format!("aux-setup: no fetched pub for index {idx}"))
            })?;
            let init_url = c.init_url.clone();
            let signer = c.arm_signer.clone();
            let agent_id = p.provisional_agent_id.clone();
            let session_hex_c = session_hex.clone();
            let t = p.threshold;
            let group_id_hex = hex::encode(p.group_id);
            let aux_epoch = p.aux_epoch;
            arm_handles.push(tokio::spawn(async move {
                let armed = arm_aux_container(
                    &init_url,
                    &*signer,
                    &agent_id,
                    &session_hex_c,
                    idx,
                    t,
                    n,
                    &peers,
                    &group_id_hex,
                    aux_epoch,
                    arm_timeout,
                )
                .await?;
                if armed != expected_pub {
                    return Err(MpcError::Protocol(format!(
                        "aux-setup: Notary index {idx} relay identity changed between \
                         peer-identity fetch ({expected_pub}) and arm ({armed}) — index drift"
                    )));
                }
                Ok::<u16, MpcError>(idx)
            }));
        }
    }

    // ── Device's in-process aux-setup parties. The aux SM runs for EVERY local
    //    index (this is the producer) — pre-seed one prime set per index (the
    //    proven step-4 ordering keeps every proceed short so the runtime stays
    //    responsive). Lever B draws from the pool when present; an empty/absent
    //    pool inline-generates (byte-identical, just slower). ──
    let n_prime = local_indices.len();
    let prime_pool = p.prime_pool.clone();
    let at_rest_root = p.at_rest_root;
    let pool_id = p.pool_id.clone();
    let primes: Vec<PregeneratedPrimes<SecurityLevel128>> =
        tokio::task::spawn_blocking(move || {
            let pool = prime_pool
                .map(|storage| PaillierPool::new(storage, &at_rest_root, &pool_id, n_prime));
            (0..n_prime)
                .map(|_| {
                    let pooled = pool.as_ref().and_then(|pl| pl.take().ok().flatten());
                    match pooled {
                        Some(pp) => pp,
                        None => generate_serialized(&mut rand::rngs::OsRng),
                    }
                })
                .collect()
        })
        .await
        .map_err(|e| MpcError::Protocol(format!("aux-setup: device prime gen panicked: {e}")))?;

    // CAPTURE mode: each device handler captures its index's aux (no share kept).
    let dkg_handlers: Vec<DkgHandler> = local_indices
        .iter()
        .map(|&idx| DkgHandler::new(cfg, idx, fresh_storage()))
        .collect();
    for (h, pp) in dkg_handlers.iter().zip(primes) {
        h.set_aux_setup_capture(p.group_id);
        h.seed_primes_for(session, pp);
    }

    // Start the device-party listeners concurrently.
    let listener_futs = dkg_handlers.iter().enumerate().map(|(pos, h)| {
        let client = local_clients[pos].clone();
        let hf = h.handler_fn();
        async move {
            MessageBoxListener::start(client, BOX_DKG, hf)
                .await
                .map_err(|e| MpcError::Protocol(format!("aux-setup listener: {e}")))
        }
    });
    let listeners: Vec<MessageBoxListener> = futures::future::try_join_all(listener_futs).await?;

    // Initiate each device party + collect its completion receiver.
    let mut rxs = Vec::new();
    let mut sends: Vec<(usize, Vec<OutgoingRoundMessage>)> = Vec::new();
    for (pos, &idx) in local_indices.iter().enumerate() {
        let (rx, out) = dkg_handlers[pos]
            .initiate(session, peers_for(idx)?)
            .await
            .map_err(|e| MpcError::Protocol(format!("aux-setup initiate: {e}")))?;
        rxs.push(rx);
        sends.push((pos, out));
    }
    // Ship all round-1 messages concurrently (the relay dedups on message_id; the
    // receiving SM buffers out-of-order arrivals).
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

    // ── Confirm every Notary arm succeeded (auth/owner errors surface here fast). ──
    for handle in arm_handles {
        match handle.await {
            Ok(Ok(_idx)) => {}
            Ok(Err(e)) => {
                shutdown_all(listeners).await;
                return Err(e);
            }
            Err(e) => {
                shutdown_all(listeners).await;
                return Err(MpcError::Protocol(format!(
                    "aux-setup: arm task panicked: {e}"
                )));
            }
        }
    }

    // ── Await each device party's completion (throwaway DkgResult — we only want
    //    the captured aux), then drain its captured aux. ──
    for (pos, &idx) in local_indices.iter().enumerate() {
        match tokio::time::timeout(timeout, &mut rxs[pos]).await {
            Ok(Ok(_r)) => {}
            Ok(Err(e)) => {
                shutdown_all(listeners).await;
                return Err(MpcError::Protocol(format!(
                    "aux-setup: party {idx} channel dropped: {e}"
                )));
            }
            Err(_) => {
                shutdown_all(listeners).await;
                return Err(MpcError::Protocol(format!(
                    "aux-setup: party {idx} timed out awaiting completion"
                )));
            }
        }
    }
    // Drain each device index's captured aux JSON.
    let mut device_auxes: Vec<(u16, String)> = Vec::with_capacity(local_indices.len());
    for (pos, &idx) in local_indices.iter().enumerate() {
        let json = dkg_handlers[pos].take_captured_aux().ok_or_else(|| {
            MpcError::Protocol(format!(
                "aux-setup: party {idx} completed but captured no aux (capture flag lost?)"
            ))
        })?;
        device_auxes.push((idx, json));
    }
    shutdown_all(listeners).await;

    // ── The device's view of the full moduli vector (any index's captured aux
    //    carries the same public N[0..n]; the secret p,q differs by index). Used to
    //    drive the #2 liveness challenge + to build the group binding record. ──
    let aux_view: AuxInfo<SecurityLevel128> = serde_json::from_str(&device_auxes[0].1)
        .map_err(|e| MpcError::Protocol(format!("aux-setup: captured aux deserialize: {e}")))?;
    // The full moduli vector MUST match the declared n (catches a short/garbled aux).
    if aux_view.N.len() != n as usize {
        return Err(MpcError::Protocol(format!(
            "aux-setup: captured aux has {} moduli, expected n={n}",
            aux_view.N.len()
        )));
    }

    // ── #2 AUX-BOUND LIVENESS CHALLENGE. For each PINNED Notary index, prove the
    //    live master owns the EXACT moduli the device captured for that index —
    //    a setup-time modulus swap makes the master signature fail. Fail-closed:
    //    refuse to seal aux that any pinned Notary could not prove it owns. ──
    let aux_session = canonical_aux_setup_execution_id(&p.group_id);
    for c in &p.cosigners {
        let master_hex = match &c.expected_master_pub {
            Some(m) => m,
            None => continue, // hermetic/dev: no pin → no challenge (NOT for funded groups)
        };
        let challenge_url = c
            .init_url
            .replace("/aux-setup/init", "/aux-setup/challenge");
        for &idx in &c.indices {
            let (n_i, hat_n_i, s_i, t_i) = aux_index_moduli_msf(&aux_view, idx as usize)
                .ok_or_else(|| {
                    MpcError::Protocol(format!(
                        "aux-setup: captured aux has no moduli at Notary index {idx}"
                    ))
                })?;
            challenge_aux_notary(
                &challenge_url,
                master_hex,
                &p.group_id,
                &aux_session,
                idx,
                &n_i,
                &hat_n_i,
                &s_i,
                &t_i,
            )
            .await?;
        }
    }

    // ── #5/#6/#7 BINDING ENVELOPE. One record per group (the public moduli are
    //    shared); MAC it under the at-rest-derived key. Each device blob carries the
    //    same record + MAC + ITS OWN aux_json. ──
    let record = build_aux_binding_record(&p.descriptor, &aux_view, p.aux_epoch)?;
    let mac_key = derive_binding_mac_key(&p.at_rest_root);
    let mac = aux_binding_mac(&record, &mac_key);

    let mut blobs: Vec<AuxSetupBlob> = device_auxes
        .into_iter()
        .map(|(index, aux_json)| AuxSetupBlob {
            index,
            aux_json: aux_json.into_bytes(),
            record: record.clone(),
            mac,
        })
        .collect();
    blobs.sort_by_key(|b| b.index);

    Ok(AuxSetupOutput {
        blobs,
        session_id: session,
    })
}

async fn shutdown_all(listeners: Vec<MessageBoxListener>) {
    for l in listeners {
        let _ = tokio::time::timeout(Duration::from_secs(10), l.shutdown()).await;
    }
}

/// GET the Notary's `/aux-setup/peer-identity?session&index` → the per-index relay
/// pub, verifying the #85 attestation against the PINNED master (when set). Mirror
/// of [`crate::provision_dkg`]'s DKG peer fetch but on the aux-setup route; the
/// per-index relay identity is derived identically, so the attestation is the same
/// shape — a network MITM cannot forge the master's signature.
async fn fetch_aux_peer_identity(
    init_url: &str,
    session: &SessionId,
    index: u16,
    expected_master_pub: Option<&str>,
) -> Result<String> {
    let session_hex = session.hex();
    let base = init_url.replace("/aux-setup/init", "/aux-setup/peer-identity");
    let url = format!("{base}?session={session_hex}&index={index}");
    let resp = crate::bounded_http_client(crate::RELAY_HTTP_TIMEOUT)?
        .get(&url)
        .send()
        .await
        .map_err(|e| MpcError::Protocol(format!("fetch aux peer identity (index {index}): {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "/aux-setup/peer-identity (index {index}) returned {status}: {txt}"
        )));
    }
    let parsed: PeerIdentityResponse = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse aux peer-identity response: {e}")))?;

    if let Some(pinned_hex) = expected_master_pub {
        let claimed = parsed.master_pub_hex.as_deref().ok_or_else(|| {
            MpcError::Protocol(format!(
                "aux peer-identity (index {index}) returned no master_pub_hex — cannot verify \
                 against the pinned master (#85); refusing"
            ))
        })?;
        if claimed != pinned_hex {
            return Err(MpcError::Protocol(format!(
                "aux peer-identity (index {index}) master {claimed} != pinned {pinned_hex} (#85 MITM)"
            )));
        }
        let att_hex = parsed.attestation_hex.as_deref().ok_or_else(|| {
            MpcError::Protocol(format!(
                "aux peer-identity (index {index}) returned no attestation (#85); refusing"
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
                "aux peer-identity (index {index}) attestation FAILED under the pinned master \
                 (#85 MITM) — refusing to route to an unattested relay identity"
            )));
        }
    }
    Ok(parsed.relay_pub_hex)
}

/// POST `/aux-setup/init`, BRC-31-signed over the canonical wire. Returns the
/// Notary's per-index relay pub (must equal the earlier `fetch_aux_peer_identity`).
#[allow(clippy::too_many_arguments)]
async fn arm_aux_container(
    init_url: &str,
    request_signer: crate::reshare::RequestSigner<'_>,
    agent_id: &str,
    session_hex: &str,
    my_index: u16,
    threshold: u16,
    parties: u16,
    peers: &[(u16, String)],
    group_id_hex: &str,
    aux_epoch: u64,
    timeout: Duration,
) -> Result<String> {
    let peers_json: Vec<serde_json::Value> = peers
        .iter()
        .map(|(i, h)| serde_json::json!({ "index": i, "pub_hex": h }))
        .collect();
    // Exactly the `deny_unknown_fields` AuxSetupInitRequest shape.
    let body = serde_json::json!({
        "agent_id": agent_id,
        "dkg_session": session_hex,
        "my_index": my_index,
        "threshold": threshold,
        "parties": parties,
        "group_id": group_id_hex,
        "aux_epoch": aux_epoch,
        "peers": peers_json,
    });
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| MpcError::Serialization(format!("serialize aux-setup/init: {e}")))?;
    let path = reqwest::Url::parse(init_url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| "/aux-setup/init".to_string());

    let http = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| MpcError::Protocol(format!("build aux http client: {e}")))?;
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
        .map_err(|e| MpcError::Protocol(format!("arm aux peer (index {my_index}): {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "Notary /aux-setup/init (index {my_index}) returned {status}: {txt}"
        )));
    }
    let parsed: ArmResponse = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse aux-setup/init response: {e}")))?;
    Ok(parsed.peer_pub_hex)
}

/// #2 liveness gate: POST `/aux-setup/challenge` with a fresh nonce + the moduli the
/// DEVICE captured for `index`, and verify the returned signature against the PINNED
/// master. Proves the live Notary owns exactly those moduli for this group — a
/// setup-time modulus swap fails here. Fails closed on a master mismatch, a bad
/// signature, an altered modulus, or a transport error.
///
/// The Notary seals its aux ASYNC right after its own completion, so the blob may
/// not exist the instant the device finishes — a `409`/`412` (not-yet-sealed) is
/// retried with a short backoff before giving up.
#[allow(clippy::too_many_arguments)]
async fn challenge_aux_notary(
    challenge_url: &str,
    master_pub_hex: &str,
    group_id: &[u8; 32],
    aux_session: &[u8; 32],
    index: u16,
    n_i_msf: &[u8],
    hat_n_i_msf: &[u8],
    s_i_msf: &[u8],
    t_i_msf: &[u8],
) -> Result<()> {
    let master = PublicKey::from_hex(master_pub_hex)
        .map_err(|e| MpcError::Protocol(format!("pinned master pub hex: {e}")))?;
    let mut last_err = String::new();
    for attempt in 0..6u32 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(1000 * u64::from(attempt))).await;
        }
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let body = serde_json::json!({
            "group_id_hex": hex::encode(group_id),
            "index": index,
            "nonce_hex": hex::encode(nonce),
        });
        let resp = match crate::bounded_http_client(crate::RELAY_HTTP_TIMEOUT)?
            .post(challenge_url)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                last_err = format!("transport: {e}");
                continue;
            }
        };
        let status = resp.status();
        // Not-yet-sealed (the Notary's async seal task is still running) → retry.
        if status == reqwest::StatusCode::CONFLICT
            || status == reqwest::StatusCode::PRECONDITION_FAILED
        {
            last_err = format!("Notary index {index} aux not yet sealed ({status})");
            continue;
        }
        if !status.is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(MpcError::Protocol(format!(
                "/aux-setup/challenge (index {index}) returned {status}: {txt}"
            )));
        }
        let parsed: AuxChallengeResponse = resp
            .json()
            .await
            .map_err(|e| MpcError::Protocol(format!("parse aux-setup/challenge response: {e}")))?;
        if parsed.master_pub_hex != master_pub_hex {
            return Err(MpcError::Protocol(format!(
                "aux-setup/challenge (index {index}) master {} != pinned {master_pub_hex} (#2 MITM)",
                parsed.master_pub_hex
            )));
        }
        let sig: [u8; 64] = hex::decode(&parsed.challenge_sig_hex)
            .map_err(|e| MpcError::Protocol(format!("challenge sig hex: {e}")))?
            .try_into()
            .map_err(|_| {
                MpcError::Protocol(format!("challenge sig (index {index}) must be 64 bytes"))
            })?;
        if !bsv_mpc_core::hd::verify_aux_liveness_challenge(
            &master,
            group_id,
            aux_session,
            index,
            n_i_msf,
            hat_n_i_msf,
            s_i_msf,
            t_i_msf,
            &nonce,
            &sig,
        ) {
            return Err(MpcError::Protocol(format!(
                "aux-setup/challenge (index {index}) liveness signature FAILED under the pinned \
                 master (#2) — the live Notary does not own the captured moduli; refusing to seal"
            )));
        }
        return Ok(());
    }
    Err(MpcError::Protocol(format!(
        "aux-setup/challenge (index {index}) never confirmed after retries: {last_err}"
    )))
}

#[derive(serde::Deserialize)]
struct AuxChallengeResponse {
    master_pub_hex: String,
    challenge_sig_hex: String,
}
