//! **Genuine n-party presignature generation over the relay** — the device-holds
//! GENERATION half of the §1 two-mandatory-sides sign (#69 PR-2 step 7 / #86).
//!
//! Mirrors [`coordinate_dkg_over_relay`](crate::provision_dkg::coordinate_dkg_over_relay):
//! the device drives its `w = t−1` co-located parties in-process while ONE external
//! cosigner completes the `t`-quorum, all over the `mpc_{session}` relay box. But
//! where DKG keeps a fresh share, this keeps a **correlated presignature set** — the
//! `w` raw `(Presignature, PublicData)` boxes the device folds locally at sign-time
//! (`device_holds_combine`), plus the external cosigner's sealed ciphertext (shipped
//! back via `trigger.cosigner_encrypted_share` at sign-time).
//!
//! ## Zero-drift on the deployed cosigner (locked design, #86)
//!
//! Every party runs the **unchanged**, mainnet-proven [`PresignHandler`]:
//!   - the device's PRIMARY party in the **coordinator** role (assembles the proven
//!     [`PresigBundle`]),
//!   - the device's other `w−1` parties + the external cosigner in the **cosigner**
//!     role (ship BRC-2 ciphertexts to the primary).
//!
//! The device then **reconstructs** its `w` raw boxes from that bundle — unsealing
//! its primary party ([`unseal_presig_bytes`]) and BRC-2-decrypting its co-located
//! parties' ciphertexts (it minted those ephemeral relay identities, so it holds the
//! keys), each paired with the shared `commitments` public data via
//! [`deserialize_party_presig_with_public_data`]. The external cosigner's ciphertext
//! it CANNOT decrypt (sealed under the cosigner's identity) — exactly the §06.17.1
//! artifact the sign-time trigger ships back. The deployed cosigner's presign
//! runtime is byte-identical to the 2-party path; only `/presign-relay/init` gained
//! a `peers` list.

use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::error::{MpcError, Result};
use bsv_mpc_core::presig_at_rest::{derive_presig_at_rest_key, unseal_presig_bytes};
use bsv_mpc_core::presig_encryption::{decrypt_presig_share, wallet_from_identity};
use bsv_mpc_core::presigning::deserialize_party_presig_with_public_data;
use bsv_mpc_core::types::{EncryptedShare, PolicyId, PresigBundle, SessionId, ThresholdConfig};
use bsv_mpc_messagebox::types::{presig_return_box, presign_protocol_box};
use bsv_mpc_messagebox::MessageBoxClient;
use bsv_mpc_service::{
    BundleStore, InMemoryBundleStore, MessageBoxListener, PresignHandler, PresignHandlerConfig,
    PresignOutcome,
};
use rand::RngCore;

use crate::reshare::{ArmRequestSigner, RequestSigner};

/// The single external cosigner that completes the device's `t`-quorum.
pub struct PresignCosignerArm {
    /// The cosigner's `/presign-relay/init` URL (identity URL is derived from it).
    pub init_url: String,
    /// The absolute keygen index this cosigner drives in the signing subset.
    pub index: u16,
    /// BRC-31 request signer for this cosigner's session (the arm is POSTed signed).
    pub arm_signer: ArmRequestSigner,
    /// **#85 MITM gate.** The cosigner's MASTER identity pubkey hex, PINNED
    /// out-of-band. The presign cosigner's relay identity IS this master, so when
    /// `Some` we VERIFY the fetched identity equals the pin and ROUTE to the pinned
    /// value (a MITM on the unauthenticated GET is then irrelevant — only the real
    /// master controls that relay identity). `None` = unpinned (dev/test only).
    pub expected_master_pub: Option<String>,
}

/// Inputs for the device side of a genuine n-party presign over the relay.
pub struct PresignOverRelay {
    /// MessageBox relay URL.
    pub relay_url: String,
    /// The wallet threshold config (`t`-of-`n`); `t` gates the topology check.
    pub config: ThresholdConfig,
    /// The device's co-located parties in the signing subset, each with its share
    /// (the 33-byte joint pubkey populated). Length MUST be `w = t−1`.
    pub local_shares: Vec<(u16, EncryptedShare)>,
    /// The single external cosigner completing the `t`-quorum.
    pub cosigner: PresignCosignerArm,
    /// `agent_id` (joint pubkey hex) for owner-authz (§08.1) on the arm.
    pub agent_id: String,
    /// Policy id this presig binds to (§09 binding triple).
    pub policy_id: PolicyId,
    /// At-rest root the device's primary party seals its own presig under (and the
    /// device immediately unseals with) — transient, ceremony-scoped.
    pub at_rest_root: [u8; 32],
}

/// Output: the device's `w` correlated raw presig boxes + the external cosigner's
/// sealed ciphertext, ready for the device-holds combine.
pub struct PresignOverRelayOutput {
    /// The presign session id (= `PresigBundle.presig_id`).
    pub session_id: SessionId,
    /// The signing subset (ascending) the presig was generated over.
    pub participants: Vec<u16>,
    /// The device's primary (coordinator) party index.
    pub primary_index: u16,
    /// `w` correlated raw `(Presignature, PublicData)` boxes, party-indexed
    /// ascending — a `DevicePresigSetPool` set.
    pub device_presigs: Vec<(u16, Box<dyn Any + Send>)>,
    /// The external cosigner's BRC-2 ciphertext (shipped back via
    /// `trigger.cosigner_encrypted_share` at sign-time; the device cannot decrypt it).
    pub cosigner_encrypted_share: Vec<u8>,
    /// The external cosigner's signing-subset index (the sign-time `trigger.do_index`).
    pub cosigner_index: u16,
}

#[derive(serde::Deserialize)]
struct PresignIdentityResponse {
    cosigner_pub_hex: String,
}

#[derive(serde::Deserialize)]
struct PresignArmResponse {
    cosigner_pub_hex: String,
}

/// A device-driven co-located presign party: its ephemeral relay identity + client.
struct LocalParty {
    index: u16,
    priv_key: PrivateKey,
    client: MessageBoxClient,
    pub_hex: String,
    share: EncryptedShare,
}

/// GET the cosigner's `/presign-relay/identity` (read-only) → its relay / BRC-2
/// identity-key hex.
async fn fetch_presign_cosigner_identity(init_url: &str) -> Result<String> {
    let url = init_url.replace("/presign-relay/init", "/presign-relay/identity");
    let resp = crate::bounded_http_client(crate::RELAY_HTTP_TIMEOUT)?
        .get(&url)
        .send()
        .await
        .map_err(|e| MpcError::Protocol(format!("fetch presign cosigner identity: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "/presign-relay/identity returned {status}: {txt}"
        )));
    }
    let parsed: PresignIdentityResponse = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse presign identity response: {e}")))?;
    Ok(parsed.cosigner_pub_hex)
}

/// POST `/presign-relay/init`, BRC-31-signed over the canonical wire, with the full
/// n-party `peers` list. Returns the cosigner's relay pub (must equal the earlier
/// `fetch_presign_cosigner_identity`).
#[allow(clippy::too_many_arguments)]
async fn arm_presign_cosigner(
    init_url: &str,
    request_signer: RequestSigner<'_>,
    agent_id: &str,
    session_hex: &str,
    coordinator_pub_hex: &str,
    coordinator_party: u16,
    my_party_index: u16,
    participants: &[u16],
    policy_id: &PolicyId,
    peers: &[(u16, String)],
    timeout: Duration,
) -> Result<String> {
    let peers_json: Vec<serde_json::Value> = peers
        .iter()
        .map(|(i, h)| serde_json::json!({ "index": i, "pub_hex": h }))
        .collect();
    let body = serde_json::json!({
        "agent_id": agent_id,
        "session_id": session_hex,
        "coordinator_pub_hex": coordinator_pub_hex,
        "coordinator_party": coordinator_party,
        "my_party_index": my_party_index,
        "parties_at_keygen": participants,
        "policy_id_hex": hex::encode(policy_id.0),
        "peers": peers_json,
    });
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| MpcError::Serialization(format!("serialize presign-relay/init: {e}")))?;
    let path = reqwest::Url::parse(init_url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| "/presign-relay/init".to_string());

    let http = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| MpcError::Protocol(format!("build presign http client: {e}")))?;
    let mut builder = http
        .post(init_url)
        .header("content-type", "application/json")
        .body(body_bytes.clone());
    for (name, value) in request_signer("POST", &path, &body_bytes)? {
        builder = builder.header(name, value);
    }
    let resp = builder.send().await.map_err(|e| {
        MpcError::Protocol(format!(
            "arm presign cosigner (index {my_party_index}): {e}"
        ))
    })?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "container /presign-relay/init (index {my_party_index}) returned {status}: {txt}"
        )));
    }
    let parsed: PresignArmResponse = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse presign-relay/init response: {e}")))?;
    Ok(parsed.cosigner_pub_hex)
}

/// Run a genuine n-party presign over the relay for the device's `w = t−1`
/// co-located parties + ONE external cosigner. Returns the `w` correlated raw presig
/// boxes (reconstructed from the assembled bundle) + the external cosigner's sealed
/// ciphertext.
pub async fn coordinate_presign_over_relay_nparty(
    p: PresignOverRelay,
    timeout: Duration,
) -> Result<PresignOverRelayOutput> {
    let proto = |e: bsv_mpc_messagebox::error::MessageBoxError| MpcError::Protocol(e.to_string());
    let t = p.config.threshold;

    // ── Topology validation: device holds w = t−1, cosigner completes the quorum,
    //    all indices distinct (anything else is a different tier — reject, never
    //    silently accept). ──
    if (p.local_shares.len() as u16) != t - 1 {
        return Err(MpcError::Protocol(format!(
            "presign-over-relay: device must hold w = t−1 = {} shares, got {}",
            t - 1,
            p.local_shares.len()
        )));
    }
    let mut local_indices: Vec<u16> = p.local_shares.iter().map(|(i, _)| *i).collect();
    local_indices.sort_unstable();
    local_indices.dedup();
    if local_indices.len() != p.local_shares.len() {
        return Err(MpcError::Protocol(
            "presign-over-relay: duplicate local share indices".into(),
        ));
    }
    if local_indices.contains(&p.cosigner.index) {
        return Err(MpcError::Protocol(format!(
            "presign-over-relay: cosigner index {} collides with a device index {:?}",
            p.cosigner.index, local_indices
        )));
    }
    let primary_index = local_indices[0];
    let mut participants: Vec<u16> = local_indices.clone();
    participants.push(p.cosigner.index);
    participants.sort_unstable();
    // Each local share MUST carry the 33-byte joint pubkey (presign requires it).
    for (idx, share) in &p.local_shares {
        if share.joint_pubkey_compressed.len() != 33 {
            return Err(MpcError::Protocol(format!(
                "presign-over-relay: local share {idx} missing the 33-byte joint pubkey"
            )));
        }
    }

    // ── Ceremony session (shared across all t parties). ──
    let session = {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        SessionId(b)
    };
    let session_hex = session.hex();

    // ── Device mints fresh relay identities for its co-located parties. ──
    let mut local_parties: Vec<LocalParty> = Vec::new();
    for (idx, share) in &p.local_shares {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b[0] |= 0x01;
        let priv_key = PrivateKey::from_bytes(&b)
            .map_err(|e| MpcError::Protocol(format!("presign-over-relay: party identity: {e}")))?;
        let client = MessageBoxClient::new(&p.relay_url, priv_key.clone()).map_err(proto)?;
        let pub_hex = client.identity_hex().await.map_err(proto)?;
        local_parties.push(LocalParty {
            index: *idx,
            priv_key,
            client,
            pub_hex,
            share: share.clone(),
        });
    }
    local_parties.sort_by_key(|lp| lp.index);

    // ── Fetch the external cosigner's relay identity FIRST (§06.17 ordering). ──
    let fetched_cosigner_pub = fetch_presign_cosigner_identity(&p.cosigner.init_url).await?;
    // #85: when pinned, the presign cosigner identity IS the master — verify the
    // fetched value matches the pin (a MITM substitution → reject) and route to the
    // PINNED value, never whatever the unauthenticated GET returned.
    let cosigner_pub_hex = match &p.cosigner.expected_master_pub {
        Some(pinned) => {
            if &fetched_cosigner_pub != pinned {
                return Err(MpcError::Protocol(format!(
                    "presign cosigner identity {fetched_cosigner_pub} != pinned master {pinned} (#85 MITM)"
                )));
            }
            pinned.clone()
        }
        None => fetched_cosigner_pub,
    };

    // ── Identity map over all participants. ──
    let identity_for = |idx: u16| -> Option<String> {
        if idx == p.cosigner.index {
            return Some(cosigner_pub_hex.clone());
        }
        local_parties
            .iter()
            .find(|lp| lp.index == idx)
            .map(|lp| lp.pub_hex.clone())
    };
    let peers_for = |me: u16| -> Result<Vec<(u16, String)>> {
        participants
            .iter()
            .filter(|&&k| k != me)
            .map(|&k| {
                identity_for(k).map(|h| (k, h)).ok_or_else(|| {
                    MpcError::Protocol(format!("presign-over-relay: no identity for party {k}"))
                })
            })
            .collect()
    };

    // ── Arm the external cosigner FIRST + ASYNC (§06.17 ordering): it subscribes +
    //    ships its own round-1 before responding (backfilled to the device). Its
    //    response pub MUST equal the device-fetched pub (drift catch). ──
    let arm_timeout = timeout + Duration::from_secs(60);
    let arm_handle = {
        let cosigner_peers = peers_for(p.cosigner.index)?;
        let expected_pub = cosigner_pub_hex.clone();
        let init_url = p.cosigner.init_url.clone();
        let signer = p.cosigner.arm_signer.clone();
        let agent_id = p.agent_id.clone();
        let session_hex_c = session_hex.clone();
        let participants_c = participants.clone();
        let policy_id = p.policy_id;
        let cosigner_index = p.cosigner.index;
        // The primary's relay pub is the coordinator (the return-ciphertext sink).
        let coordinator_pub = identity_for(primary_index).ok_or_else(|| {
            MpcError::Protocol("presign-over-relay: no identity for primary".into())
        })?;
        tokio::spawn(async move {
            let armed = arm_presign_cosigner(
                &init_url,
                &*signer,
                &agent_id,
                &session_hex_c,
                &coordinator_pub,
                primary_index,
                cosigner_index,
                &participants_c,
                &policy_id,
                &cosigner_peers,
                arm_timeout,
            )
            .await?;
            if armed != expected_pub {
                return Err(MpcError::Protocol(format!(
                    "presign-over-relay: cosigner index {cosigner_index} relay identity changed \
                     between identity fetch ({expected_pub}) and arm ({armed}) — drift"
                )));
            }
            Ok::<(), MpcError>(())
        })
    };

    // ── Build the device's PresignHandlers (primary = coordinator role, others =
    //    cosigner role) + start listeners. The primary collects return ciphertexts,
    //    so it listens on BOTH the protocol box AND the return box. ──
    let protocol_box = presign_protocol_box(&session_hex);
    let return_box = presig_return_box(&session_hex);
    let mut handlers: Vec<(u16, PresignHandler)> = Vec::new();
    let mut listeners: Vec<MessageBoxListener> = Vec::new();
    for lp in &local_parties {
        let store: Arc<dyn BundleStore> = Arc::new(InMemoryBundleStore::new());
        let handler = PresignHandler::new(PresignHandlerConfig {
            my_party_index: lp.index,
            coordinator_party: primary_index,
            parties_at_keygen: participants.clone(),
            policy_id: p.policy_id,
            identity_priv: lp.priv_key.clone(),
            at_rest_root: p.at_rest_root,
            bundle_store: store,
        });
        let listener = if lp.index == primary_index {
            MessageBoxListener::start_many(
                lp.client.clone(),
                vec![protocol_box.clone(), return_box.clone()],
                handler.handler_fn(),
            )
            .await
        } else {
            MessageBoxListener::start(lp.client.clone(), &protocol_box, handler.handler_fn()).await
        }
        .map_err(|e| MpcError::Protocol(format!("presign-over-relay listener: {e}")))?;
        handlers.push((lp.index, handler));
        listeners.push(listener);
    }

    let shutdown_all = |ls: Vec<MessageBoxListener>| async move {
        for l in ls {
            let _ = tokio::time::timeout(Duration::from_secs(10), l.shutdown()).await;
        }
    };

    // ── Initiate every device party (registers its slot + round-1 outbound). ──
    let mut primary_rx = None;
    let mut extra_rxs: Vec<(u16, tokio::sync::oneshot::Receiver<PresignOutcome>)> = Vec::new();
    let mut sends: Vec<(usize, Vec<bsv_mpc_service::OutgoingRoundMessage>)> = Vec::new();
    for (pos, lp) in local_parties.iter().enumerate() {
        let handler = &handlers[pos].1;
        let peers = match peers_for(lp.index) {
            Ok(v) => v,
            Err(e) => {
                shutdown_all(listeners).await;
                return Err(e);
            }
        };
        match handler.initiate(session, lp.share.clone(), peers).await {
            Ok((rx, out)) => {
                if lp.index == primary_index {
                    primary_rx = Some(rx);
                } else {
                    extra_rxs.push((lp.index, rx));
                }
                sends.push((pos, out));
            }
            Err(e) => {
                shutdown_all(listeners).await;
                return Err(MpcError::Protocol(format!(
                    "presign-over-relay initiate: {e}"
                )));
            }
        }
    }

    // ── Ship each device party's round-1 (reliable idempotent retry). ──
    for (pos, out) in sends {
        for o in out {
            if let Err(e) = local_parties[pos]
                .client
                .send_round_message_reliable(
                    &o.recipient_pub_hex,
                    &o.message_box,
                    &o.round_msg,
                    o.params,
                    4,
                )
                .await
            {
                shutdown_all(listeners).await;
                return Err(proto(e));
            }
        }
    }

    // ── Confirm the arm (auth/owner errors surface here in seconds with the real
    //    error, not as an opaque presign timeout). ──
    match arm_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            shutdown_all(listeners).await;
            return Err(e);
        }
        Err(e) => {
            shutdown_all(listeners).await;
            return Err(MpcError::Protocol(format!(
                "presign-over-relay: arm task panicked: {e}"
            )));
        }
    }

    // ── Await the primary's bundle (the gate — completion requires every cosigner
    //    + co-located return ciphertext to have arrived). ──
    let primary_rx = match primary_rx {
        Some(rx) => rx,
        None => {
            shutdown_all(listeners).await;
            return Err(MpcError::Protocol(
                "presign-over-relay: primary party never initiated".into(),
            ));
        }
    };
    let bundle: PresigBundle = match tokio::time::timeout(timeout, primary_rx).await {
        Ok(Ok(PresignOutcome::BundlePersisted(b))) => *b,
        Ok(Ok(PresignOutcome::ReturnShipped)) => {
            shutdown_all(listeners).await;
            return Err(MpcError::Protocol(
                "presign-over-relay: primary unexpectedly produced a cosigner outcome".into(),
            ));
        }
        Ok(Err(e)) => {
            shutdown_all(listeners).await;
            return Err(MpcError::Protocol(format!(
                "presign-over-relay: primary completion channel dropped: {e}"
            )));
        }
        Err(_) => {
            shutdown_all(listeners).await;
            return Err(MpcError::Protocol(
                "presign-over-relay: timed out awaiting PresigBundle assembly".into(),
            ));
        }
    };

    // ── Confirm each co-located extra shipped (defensive; by now the bundle holds
    //    their ciphertexts, so these are already Ready). ──
    for (idx, rx) in extra_rxs {
        match tokio::time::timeout(Duration::from_secs(5), rx).await {
            Ok(Ok(PresignOutcome::ReturnShipped)) => {}
            Ok(Ok(PresignOutcome::BundlePersisted(_))) => {
                shutdown_all(listeners).await;
                return Err(MpcError::Protocol(format!(
                    "presign-over-relay: extra party {idx} unexpectedly assembled a bundle"
                )));
            }
            Ok(Err(e)) => {
                shutdown_all(listeners).await;
                return Err(MpcError::Protocol(format!(
                    "presign-over-relay: extra party {idx} completion dropped: {e}"
                )));
            }
            Err(_) => {
                shutdown_all(listeners).await;
                return Err(MpcError::Protocol(format!(
                    "presign-over-relay: extra party {idx} did not confirm return-ship"
                )));
            }
        }
    }

    shutdown_all(listeners).await;

    // ── Reconstruct the device's w raw presig boxes from the assembled bundle.
    //    Primary: unseal its own sealed presig. Extras: BRC-2-decrypt their
    //    positional ciphertext with the ephemeral identity the device minted. Each
    //    presig is paired with the SHARED commitments (public data). ──
    let presig_id = bundle.presig_id.clone();
    let at_rest_key = derive_presig_at_rest_key(&p.at_rest_root, &presig_id);
    if bundle.parties_at_keygen != participants {
        return Err(MpcError::Protocol(format!(
            "presign-over-relay: bundle parties {:?} != expected subset {:?}",
            bundle.parties_at_keygen, participants
        )));
    }
    let mut device_presigs: Vec<(u16, Box<dyn Any + Send>)> = Vec::new();
    for lp in &local_parties {
        let presig_json: Vec<u8> = if lp.index == primary_index {
            unseal_presig_bytes(&bundle.presig_bytes, &at_rest_key)?
        } else {
            let pos = participants
                .iter()
                .position(|&k| k == lp.index)
                .ok_or_else(|| {
                    MpcError::Protocol(format!(
                        "presign-over-relay: party {} not in participants",
                        lp.index
                    ))
                })?;
            let ct = bundle.cosigner_encrypted_shares.get(pos).ok_or_else(|| {
                MpcError::Protocol(format!(
                    "presign-over-relay: no ciphertext slot for co-located party {}",
                    lp.index
                ))
            })?;
            let wallet = wallet_from_identity(&lp.priv_key);
            decrypt_presig_share(&wallet, &presig_id, ct.as_ref())?
        };
        let raw = deserialize_party_presig_with_public_data(&presig_json, &bundle.commitments)?;
        device_presigs.push((lp.index, raw));
    }
    device_presigs.sort_by_key(|(i, _)| *i);

    // ── Keep the external cosigner's ciphertext (sealed under ITS identity — the
    //    device cannot decrypt it; it ships it back at sign-time). ──
    let cos_pos = participants
        .iter()
        .position(|&k| k == p.cosigner.index)
        .ok_or_else(|| {
            MpcError::Protocol("presign-over-relay: cosigner not in participants".into())
        })?;
    let cosigner_encrypted_share = bundle
        .cosigner_encrypted_shares
        .get(cos_pos)
        .ok_or_else(|| {
            MpcError::Protocol("presign-over-relay: no ciphertext slot for cosigner".into())
        })?
        .to_vec();
    if cosigner_encrypted_share.is_empty() {
        return Err(MpcError::Protocol(
            "presign-over-relay: external cosigner ciphertext is empty (cosigner never shipped)"
                .into(),
        ));
    }

    Ok(PresignOverRelayOutput {
        session_id: session,
        participants,
        primary_index,
        device_presigs,
        cosigner_encrypted_share,
        cosigner_index: p.cosigner.index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_mpc_core::types::ShareIndex;

    fn dummy_share(index: u16, with_jpk: bool) -> EncryptedShare {
        EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![1u8; 16],
            session_id: SessionId([7u8; 32]),
            share_index: ShareIndex(index),
            config: ThresholdConfig::new(4, 6).unwrap(),
            joint_pubkey_compressed: if with_jpk { vec![2u8; 33] } else { Vec::new() },
        }
    }

    fn dummy_arm(index: u16) -> PresignCosignerArm {
        PresignCosignerArm {
            init_url: "http://127.0.0.1:0/presign-relay/init".to_string(),
            index,
            arm_signer: Arc::new(|_: &str, _: &str, _: &[u8]| Ok(Vec::new())),
            expected_master_pub: None,
        }
    }

    fn inputs(local: Vec<(u16, EncryptedShare)>, cosigner_index: u16) -> PresignOverRelay {
        PresignOverRelay {
            relay_url: "http://127.0.0.1:0".to_string(),
            config: ThresholdConfig::new(4, 6).unwrap(),
            local_shares: local,
            cosigner: dummy_arm(cosigner_index),
            agent_id: "02".to_string() + &"ab".repeat(32),
            policy_id: PolicyId([0u8; 32]),
            at_rest_root: [9u8; 32],
        }
    }

    // All four reject BEFORE any relay connection (validation precedes
    // `MessageBoxClient::new` / `identity_hex`), so they are hermetic.
    async fn assert_rejected(p: PresignOverRelay, needle: &str) {
        match coordinate_presign_over_relay_nparty(p, Duration::from_millis(50)).await {
            Ok(_) => panic!("expected rejection containing {needle:?}, got Ok"),
            Err(e) => assert!(e.to_string().contains(needle), "wrong reason: {e}"),
        }
    }

    #[tokio::test]
    async fn rejects_wrong_device_share_count() {
        // t=4 needs w=3 device shares; supply only 2.
        let p = inputs(
            vec![(0, dummy_share(0, true)), (1, dummy_share(1, true))],
            3,
        );
        assert_rejected(p, "device must hold w = t−1 = 3 shares, got 2").await;
    }

    #[tokio::test]
    async fn rejects_duplicate_local_indices() {
        // Three shares but indices {0,0,1} — a duplicate.
        let p = inputs(
            vec![
                (0, dummy_share(0, true)),
                (0, dummy_share(0, true)),
                (1, dummy_share(1, true)),
            ],
            3,
        );
        assert_rejected(p, "duplicate local share indices").await;
    }

    #[tokio::test]
    async fn rejects_cosigner_index_collision() {
        // Device holds {0,1,2}; cosigner claims index 1 — a collision.
        let p = inputs(
            vec![
                (0, dummy_share(0, true)),
                (1, dummy_share(1, true)),
                (2, dummy_share(2, true)),
            ],
            1,
        );
        assert_rejected(p, "cosigner index 1 collides").await;
    }

    #[tokio::test]
    async fn rejects_share_missing_joint_pubkey() {
        // Valid topology, but party 2's share lacks the 33-byte joint pubkey.
        let p = inputs(
            vec![
                (0, dummy_share(0, true)),
                (1, dummy_share(1, true)),
                (2, dummy_share(2, false)),
            ],
            3,
        );
        assert_rejected(p, "local share 2 missing the 33-byte joint pubkey").await;
    }
}
