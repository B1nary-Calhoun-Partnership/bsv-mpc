//! `bsv-mpc-relay` — the presigned-1-round relay-sign **combiner**, shared by
//! the BRC-100 proxy and the native client. Drives a local `SigningCoordinator`
//! (with a presignature) while HTTP-triggering the cosigner DO and folding its
//! relayed partial in to combine. Factored out of `bsv-mpc-proxy::relay_sign` so
//! `bsv-mpc-client` reuses the EXACT mainnet-proven combiner (issue #63).

//! #12 (I-4c) — proxy-side **relay combiner**.
//!
//! ADR-018 splits the online sign: the deployed wasm DO holds `share_A` and
//! issues *its* partial signature from a provisioned `Presignature_A`, sending
//! it over the canonical MessageBox relay; the **proxy** (this side) holds
//! `share_B` + the matching `(Presignature_B, PresignaturePublicData_B)` and is
//! the **combiner** — it issues its own partial and combines the DO's into the
//! final ECDSA signature (the public data never crosses the boundary).
//!
//! This is the production analog of the `bsv-mpc-service` `sign_relay_deployed`
//! harness (#15 Part B): same crypto, but driven from the proxy with its real
//! `share_B` + relay identity, so a `createSignature` / `createAction` can be
//! served by the deployed cosigner over the relay instead of the legacy HTTP
//! request/response path.

use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::error::{MpcError, Result};
use bsv_mpc_core::signing::{SigningCoordinator, SigningRoundResult};
use bsv_mpc_core::types::{
    EncryptedShare, JointPublicKey, SessionId, ShareIndex, SigningResult, ThresholdConfig,
};
use bsv_mpc_messagebox::types::BOX_SIGN;
use bsv_mpc_messagebox::MessageBoxClient;

// ─── Shared deployed-cosigner orchestration (issue #63, path a-extended) ─────
//
// These were factored out of `bsv-mpc-proxy` so the BRC-100 proxy AND the native
// `bsv-mpc-client` reuse the EXACT mainnet-proven ceremony: the BRC-31
// `RelaySession`, the authed DKG-over-HTTP driver, and the §06.17.1 presign-over-
// relay coordinator (the sign-from-bundle combiner already lived here).
pub mod dkg;
pub mod presign;
pub mod session;

pub use dkg::{run_dkg_over_http, run_dkg_over_http_authed};
pub use presign::{coordinate_presign_over_relay, CosignerArm};
pub use session::RelaySession;
// `RequestSigner` (presign trigger signer) is the SAME shape as
// [`RelayRequestSigner`] (sign trigger signer); re-export both names so existing
// proxy `crate::relay_presign::RequestSigner` references resolve unchanged.
pub use presign::RequestSigner;

/// How the proxy reaches the DO to make it issue + relay its partial.
pub struct DoTrigger {
    /// The DO's sign-relay endpoint (the deployed `/poc/sign-relay`, or the
    /// production authed `/sign-relay`).
    pub url: String,
    /// **POC mode only**: serialized cggmp24 `Presignature_A` (party
    /// `do_index`'s presignature), posted in the trigger body so the POC proof
    /// is self-contained. **Production** leaves this empty — the authed
    /// `/sign-relay` consumes the presignature from the DO's provisioned pool
    /// (#14), so `PresignaturePublicData` never crosses the boundary and the
    /// presig is never re-sent on the wire.
    pub presig_a_json: Vec<u8>,
    /// The DO party's signing-time index — the `from` index its partial carries
    /// (the combiner keys partials by this).
    pub do_index: u16,
    /// **Production mode**: the share's `agent_id` (joint pubkey hex) so the DO
    /// can enforce owner-authz (§08.1) on the relay sign trigger. `None` for the
    /// unauthed POC route.
    pub agent_id: Option<String>,
    /// **Production mode**: BRC-31 auth headers (name, value) for the authed
    /// `/sign-relay` route. Empty for the unauthed POC route. Superseded by
    /// `request_signer` on [`combine_sign_over_relay`] when canonical signing of
    /// the exact body is required (the deployed worker verifies the canonical wire).
    pub auth_headers: Vec<(String, String)>,
    /// **§06.17.1 coordinator-holds-ciphertext mode** (issue #30 / #25c): the
    /// cosigner's BRC-2 ciphertext (`PresigBundle.cosigner_encrypted_shares[do_index]`)
    /// that the coordinator persisted at presign-time. When `Some`, the
    /// coordinator ships this opaque blob in the trigger body as
    /// `cosigner_encrypted_share` and the worker decrypts it under its OWN
    /// identity via `decrypt_and_issue_partial` (#25b) — the worker generated +
    /// encrypted this share itself, so the coordinator never held the worker's
    /// plaintext presig. Supersedes the POC `presig_a_json` plaintext shortcut.
    /// `None` falls back to the pool/plaintext paths for legacy callers (the
    /// field is non-breaking: omitted from the body when `None`).
    pub cosigner_encrypted_share: Option<Vec<u8>>,
    /// **BRC-42 HD-derived child-key signing over the relay (MPC-Spec §06.20,
    /// issue #26).** Hex of the 32-byte BRC-42 additive offset. When `Some`, the
    /// combiner applies it to ITS OWN presig + public data (via
    /// `sign_with_presignature_with_offset`) and ships it in the trigger body as
    /// `brc42_offset` so the cosigner applies the SAME offset in
    /// `decrypt_and_issue_partial`. ALL signers apply the same offset; the
    /// resulting signature verifies under `child_pub = joint + offset·G`. `None`
    /// = base-key signing (omitted from the body, non-breaking for legacy callers).
    pub brc42_offset: Option<String>,
}

/// A canonical BRC-31 request signer: given `(method, path, body_bytes)`, returns
/// the `x-bsv-auth-*` headers signed over the EXACT body bytes. Supplied by the
/// proxy bridge (its worker session) so the relay-built `/sign-relay` body can be
/// signed AFTER it is serialized inside [`combine_sign_over_relay`].
pub type RelayRequestSigner<'a> =
    &'a (dyn Fn(&str, &str, &[u8]) -> Result<Vec<(String, String)>> + Send + Sync);

/// The combiner's signing-time index = position of its share index within
/// `participants` (matches `SigningCoordinator`'s internal convention).
fn signing_index(share: &EncryptedShare, participants: &[u16]) -> Result<u16> {
    participants
        .iter()
        .position(|&p| p == share.share_index.0)
        .map(|p| p as u16)
        .ok_or_else(|| {
            MpcError::Signing(format!(
                "share index {} not in participants {participants:?}",
                share.share_index.0
            ))
        })
}

/// Combine the deployed DO's partial into a final BSV-ready signature over the
/// relay.
///
/// Flow (mirrors the proven #15 path):
/// 1. Connect to the relay as `identity_priv`; subscribe to `mpc-sign`.
/// 2. Prime a [`SigningCoordinator`] with `share` (`share_B`) + `my_presig_box`
///    (this party's `(Presignature, PresignaturePublicData)`), issuing our partial.
/// 3. Trigger the DO (HTTP) to issue + relay party-`do_index`'s partial.
/// 4. Receive the DO's partial over the relay; combine → [`SigningResult`].
///
/// `my_presig_box` is the type-erased `(cggmp24::Presignature,
/// PresignaturePublicData)` from `PresigningManager::take_raw()` — the proxy's
/// own presignature, correlated with the DO's `Presignature_A` at generation.
#[allow(clippy::too_many_arguments)]
pub async fn combine_sign_over_relay(
    relay_url: &str,
    identity_priv: PrivateKey,
    share: EncryptedShare,
    participants: Vec<u16>,
    config: ThresholdConfig,
    session_id: SessionId,
    sighash: &[u8; 32],
    my_presig_box: Box<dyn std::any::Any + Send>,
    joint_key: &JointPublicKey,
    // **BRC-42 HD-derived signing (issue #26).** When `Some`, this is the 32-byte
    // additive offset the combiner applies to its OWN presig + public data; the
    // SAME bytes are shipped (hex) to the cosigner via the trigger body so it
    // applies the identical shift in `decrypt_and_issue_partial`. The combined
    // signature then verifies under `child_pub = joint + offset·G`. `None` =
    // base-key signing (unchanged behavior).
    brc42_offset: Option<[u8; 32]>,
    trigger: DoTrigger,
    // When `Some`, signs the EXACT serialized trigger body with canonical BRC-31
    // (the deployed worker `/sign-relay` verifies the canonical wire). When
    // `None`, falls back to `trigger.auth_headers` (unauthed POC / legacy callers).
    request_signer: Option<RelayRequestSigner<'_>>,
    recv_timeout: Duration,
) -> Result<SigningResult> {
    // 2-party is the N-party combine with NO co-located extras (the device holds
    // exactly its own share; one external cosigner completes it).
    combine_sign_over_relay_nparty(
        relay_url,
        identity_priv,
        share,
        Vec::new(),
        participants,
        config,
        session_id,
        sighash,
        my_presig_box,
        joint_key,
        brc42_offset,
        trigger,
        request_signer,
        recv_timeout,
    )
    .await
}

/// **§1 device-holds-(t−1) N-party relay combiner (issue #38).**
///
/// Generalizes [`combine_sign_over_relay`] from 2-party (one device share + one
/// external cosigner) to the "two mandatory sides" subset: the device holds
/// `t−1` co-located shares and one external cosigner completes the threshold.
/// The combiner:
/// 1. primes the presigned path for its PRIMARY party (`share` + `my_presig_box`),
/// 2. issues each co-located party's partial LOCALLY from
///    `extra_local_presigs` (never on the wire) via
///    [`SigningCoordinator::add_local_presig_partial`],
/// 3. triggers the ONE external cosigner (`trigger.do_index`) over the relay
///    exactly as the 2-party path does, and
/// 4. folds the cosigner's relayed partial in → `process_round` combines all `t`
///    partials in commitment order.
///
/// `extra_local_presigs` is `(party_signing_index, presig_box)` for each
/// co-located party OTHER than the primary — the boxes are correlated with the
/// primary's (same presign ceremony, identical shared public data). When empty,
/// this is byte-for-byte the proven 2-party flow. `brc42_offset` (§06.20) is
/// applied to the primary, every extra, and the cosigner — all identical bytes.
///
/// The KSS `/sign-relay` is unchanged: it issues exactly one party's partial
/// from `from_index`, agnostic to how many parties exist.
#[allow(clippy::too_many_arguments)]
pub async fn combine_sign_over_relay_nparty(
    relay_url: &str,
    identity_priv: PrivateKey,
    share: EncryptedShare,
    // Co-located parties OTHER than the primary: (signing-time index, presig box).
    extra_local_presigs: Vec<(u16, Box<dyn std::any::Any + Send>)>,
    participants: Vec<u16>,
    config: ThresholdConfig,
    session_id: SessionId,
    sighash: &[u8; 32],
    my_presig_box: Box<dyn std::any::Any + Send>,
    joint_key: &JointPublicKey,
    brc42_offset: Option<[u8; 32]>,
    trigger: DoTrigger,
    request_signer: Option<RelayRequestSigner<'_>>,
    recv_timeout: Duration,
) -> Result<SigningResult> {
    let proto = |e: bsv_mpc_messagebox::error::MessageBoxError| MpcError::Protocol(e.to_string());

    // 1. Relay client + subscription — BEFORE triggering the DO so we don't
    //    miss the live push (backfill also covers a late subscribe).
    let combiner = MessageBoxClient::new(relay_url, identity_priv).map_err(proto)?;
    let combiner_pub = combiner.identity_hex().await.map_err(proto)?;
    let mut sub = combiner
        .subscribe_round_messages(BOX_SIGN)
        .await
        .map_err(proto)?;

    // 2. Prime our coordinator for the PRIMARY co-located party (issues its
    //    partial; installs the shared public data), then issue EACH OTHER
    //    co-located party's partial locally — the device's `t−1` partials never
    //    cross the wire.
    let my_index = signing_index(&share, &participants)?;
    let mut coord = SigningCoordinator::new(session_id, share, config, participants);
    coord.sign_with_presignature_with_offset(sighash, my_presig_box, brc42_offset)?;
    for (extra_idx, extra_box) in extra_local_presigs {
        coord.add_local_presig_partial(extra_idx, extra_box, brc42_offset)?;
    }

    // 3. Trigger the DO to issue + relay its partial to us.
    //    Production: presig is consumed from the DO pool (no `presignature_hex`
    //    in the body), `agent_id` carries the share key for owner-authz, and
    //    BRC-31 auth headers gate the route. POC: presig in body, no auth.
    let http = reqwest::Client::new();
    let mut trigger_body = serde_json::json!({
        "sighash_hex": hex::encode(sighash),
        "recipient_pub_hex": combiner_pub,
        "from_index": trigger.do_index,
        "to_index": my_index,
        "joint_pubkey_hex": hex::encode(&joint_key.compressed),
        "session_id_hex": session_id.hex(),
    });
    if !trigger.presig_a_json.is_empty() {
        trigger_body["presignature_hex"] = serde_json::json!(hex::encode(&trigger.presig_a_json));
    }
    if let Some(ref agent_id) = trigger.agent_id {
        trigger_body["agent_id"] = serde_json::json!(agent_id);
    }
    // §06.17.1: when the coordinator holds the cosigner's ciphertext, ship it so
    // the worker decrypts its OWN share at sign-time (#25b decrypt_and_issue_partial)
    // instead of consuming a proxy-provisioned plaintext presig from the pool.
    if let Some(ref ct) = trigger.cosigner_encrypted_share {
        trigger_body["cosigner_encrypted_share"] = serde_json::json!(hex::encode(ct));
    }
    // §06.20 / issue #26: ship the BRC-42 offset (hex) so the cosigner applies the
    // SAME additive shift in `decrypt_and_issue_partial`. The combiner already
    // applied it to its own presig + public data above (via `brc42_offset` →
    // `sign_with_presignature_with_offset`); both sides MUST use identical bytes.
    if let Some(ref h) = trigger.brc42_offset {
        trigger_body["brc42_offset"] = serde_json::json!(h);
    }
    // Serialize the body ONCE so the canonical signature covers the EXACT bytes
    // sent (NOT `.json()`, which re-serializes and could diverge from the signed
    // bytes).
    let body_bytes = serde_json::to_vec(&trigger_body)
        .map_err(|e| MpcError::Protocol(format!("serialize sign-relay body: {e}")))?;
    let mut builder = http
        .post(&trigger.url)
        .header("content-type", "application/json")
        .body(body_bytes.clone());
    if let Some(sign) = request_signer {
        // Canonical: sign over (POST, url-path, exact body). The worker
        // reconstructs the same path (e.g. "/sign-relay") from the request it
        // receives, so client + server agree byte-for-byte.
        let path = reqwest::Url::parse(&trigger.url)
            .map(|u| u.path().to_string())
            .unwrap_or_else(|_| "/sign-relay".to_string());
        for (name, value) in sign("POST", &path, &body_bytes)? {
            builder = builder.header(name, value);
        }
    } else {
        for (name, value) in &trigger.auth_headers {
            builder = builder.header(name, value);
        }
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| MpcError::Protocol(format!("trigger DO sign-relay: {e}")))?;
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("DO sign-relay response: {e}")))?;
    if !status.is_success() || body["sent"] != serde_json::json!(true) {
        return Err(MpcError::Protocol(format!(
            "DO sign-relay did not send (status {status}): {body}"
        )));
    }

    // 4. Receive the DO's partial over the relay; combine.
    //
    //    The `mpc-sign` box is SHARED across signs (and across signers), and the
    //    relay backfills recent messages — so a fresh subscription can surface a
    //    STALE partial from a prior sign or another joint key. Combining that
    //    with this sign's presignature fails ("malformed or cheating party").
    //    Filter to THIS sign: accept only a partial from the DO party that
    //    carries this sign's unique `session_id` (the combiner picks a fresh id
    //    per sign, sends it in the trigger, and the DO echoes it in the §05
    //    envelope). Drain everything else until the matching partial or timeout.
    let deadline = tokio::time::Instant::now() + recv_timeout;
    let round_msg = loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| MpcError::Protocol("timed out awaiting DO partial over relay".into()))?;
        let decoded = tokio::time::timeout(remaining, sub.next())
            .await
            .map_err(|_| MpcError::Protocol("timed out awaiting DO partial over relay".into()))?
            .ok_or_else(|| MpcError::Protocol("relay subscription closed before partial".into()))?
            .map_err(proto)?;
        let rm = decoded.round_msg;
        if rm.from == ShareIndex(trigger.do_index) && rm.session_id == session_id {
            break rm;
        }
        tracing::debug!(
            from = rm.from.0,
            stale_session = %rm.session_id.hex(),
            "relay: skipping unrelated/stale partial (not this sign's session)"
        );
    };

    let result = coord.process_round(vec![round_msg])?;
    sub.shutdown().await;
    match result {
        SigningRoundResult::Complete(sig) => Ok(sig),
        SigningRoundResult::NextRound(_) => Err(MpcError::Signing(
            "combiner did not complete after the DO's partial".into(),
        )),
    }
}

/// **§06.17.1 sign-from-bundle over the relay (issue #30, CONTAINER target).**
///
/// The durable sibling of [`combine_sign_over_relay`]: instead of a live
/// in-memory `(Presignature, PresignaturePublicData)` tuple, the coordinator
/// signs from a persisted [`PresigBundle`](bsv_mpc_core::types::PresigBundle):
///
/// 1. Reconstruct the coordinator's OWN partial via
///    [`SigningCoordinator::sign_from_bundle`] — its serialized presig share
///    (`own_presig_json`, unsealed from `bundle.presig_bytes`) + the shared
///    public data (reconstructed from `bundle.commitments`).
/// 2. Trigger the container's authed `/sign-relay`, shipping the cosigner's OWN
///    BRC-2 ciphertext (`bundle.cosigner_encrypted_shares[do_index]`,
///    `cosigner_ct`) — opaque to the coordinator. The container decrypts it under
///    ITS OWN identity (`decrypt_and_issue_partial`, #25b), issues its partial,
///    and relays it back.
/// 3. Receive the container's partial over the relay; combine into the final
///    ECDSA signature.
///
/// The coordinator never held the cosigner's plaintext presig share — the
/// §06.17.1 threshold gain over the POC proxy-knows-both-shares shortcut.
#[allow(clippy::too_many_arguments)]
pub async fn combine_sign_from_bundle_over_relay(
    relay_url: &str,
    identity_priv: PrivateKey,
    share: EncryptedShare,
    participants: Vec<u16>,
    config: ThresholdConfig,
    sign_session_id: SessionId,
    sighash: &[u8; 32],
    own_presig_json: &[u8],
    // CBOR `commitments` from the bundle (#25a) — reconstructed into the shared
    // `PresignaturePublicData` here, so the proxy never names the cggmp24 type.
    commitments: &[u8],
    cosigner_ct: Vec<u8>,
    // The bundle's canonical `presig_id` (= PRESIGN session_id hex) — the key_id
    // the cosigner sealed its share under, DISTINCT from the per-sign
    // `sign_session_id` used for relay correlation.
    presig_id: &str,
    joint_key: &JointPublicKey,
    trigger: DoTrigger,
    request_signer: Option<RelayRequestSigner<'_>>,
    recv_timeout: Duration,
) -> Result<SigningResult> {
    let proto = |e: bsv_mpc_messagebox::error::MessageBoxError| MpcError::Protocol(e.to_string());

    // 1. Relay client + subscription BEFORE triggering the cosigner.
    let combiner = MessageBoxClient::new(relay_url, identity_priv).map_err(proto)?;
    let combiner_pub = combiner.identity_hex().await.map_err(proto)?;
    let mut sub = combiner
        .subscribe_round_messages(BOX_SIGN)
        .await
        .map_err(proto)?;

    // 2. Reconstruct our own partial from the durable bundle artifacts.
    let public_data = bsv_mpc_core::signing::deserialize_presig_public_data(commitments)?;
    let my_index = signing_index(&share, &participants)?;
    let mut coord = SigningCoordinator::new(sign_session_id, share, config, participants);
    // §06.20 HD path: when the trigger carries a BRC-42 offset, the coordinator
    // applies it to its own presig + the shared public data; the cosigner applies
    // the SAME offset below. None = base key.
    let offset_bytes: Option<[u8; 32]> = match &trigger.brc42_offset {
        Some(h) => {
            let v =
                hex::decode(h).map_err(|e| MpcError::Protocol(format!("brc42_offset hex: {e}")))?;
            let arr: [u8; 32] = v
                .try_into()
                .map_err(|_| MpcError::Protocol("brc42_offset must be 32 bytes".into()))?;
            Some(arr)
        }
        None => None,
    };
    coord.sign_from_bundle_with_offset(sighash, own_presig_json, public_data, offset_bytes)?;

    // 3. Trigger the container's /sign-relay shipping the cosigner's own
    //    ciphertext (the §06.17.1 path).
    let http = reqwest::Client::new();
    let mut trigger_body = serde_json::json!({
        "sighash_hex": hex::encode(sighash),
        "recipient_pub_hex": combiner_pub,
        "from_index": trigger.do_index,
        "to_index": my_index,
        "joint_pubkey_hex": hex::encode(&joint_key.compressed),
        "session_id_hex": sign_session_id.hex(),
        "presig_id": presig_id,
        "cosigner_encrypted_share": hex::encode(&cosigner_ct),
    });
    if let Some(ref agent_id) = trigger.agent_id {
        trigger_body["agent_id"] = serde_json::json!(agent_id);
    }
    if let Some(ref offset_hex) = trigger.brc42_offset {
        trigger_body["brc42_offset"] = serde_json::json!(offset_hex);
    }
    let body_bytes = serde_json::to_vec(&trigger_body)
        .map_err(|e| MpcError::Protocol(format!("serialize sign-relay body: {e}")))?;
    let mut builder = http
        .post(&trigger.url)
        .header("content-type", "application/json")
        .body(body_bytes.clone());
    if let Some(sign) = request_signer {
        let path = reqwest::Url::parse(&trigger.url)
            .map(|u| u.path().to_string())
            .unwrap_or_else(|_| "/sign-relay".to_string());
        for (name, value) in sign("POST", &path, &body_bytes)? {
            builder = builder.header(name, value);
        }
    } else {
        for (name, value) in &trigger.auth_headers {
            builder = builder.header(name, value);
        }
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| MpcError::Protocol(format!("trigger container sign-relay: {e}")))?;
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("container sign-relay response: {e}")))?;
    if !status.is_success() || body["sent"] != serde_json::json!(true) {
        return Err(MpcError::Protocol(format!(
            "container sign-relay did not send (status {status}): {body}"
        )));
    }

    // 4. Receive the container's partial over the relay (filter to this sign's
    //    session + the cosigner's from-index), combine.
    let deadline = tokio::time::Instant::now() + recv_timeout;
    let round_msg = loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| {
                MpcError::Protocol("timed out awaiting cosigner partial over relay".into())
            })?;
        let decoded = tokio::time::timeout(remaining, sub.next())
            .await
            .map_err(|_| {
                MpcError::Protocol("timed out awaiting cosigner partial over relay".into())
            })?
            .ok_or_else(|| MpcError::Protocol("relay subscription closed before partial".into()))?
            .map_err(proto)?;
        let rm = decoded.round_msg;
        if rm.from == ShareIndex(trigger.do_index) && rm.session_id == sign_session_id {
            break rm;
        }
        tracing::debug!(
            from = rm.from.0,
            stale_session = %rm.session_id.hex(),
            "relay: skipping unrelated/stale partial (not this sign's session)"
        );
    };

    let result = coord.process_round(vec![round_msg])?;
    sub.shutdown().await;
    match result {
        SigningRoundResult::Complete(sig) => Ok(sig),
        SigningRoundResult::NextRound(_) => Err(MpcError::Signing(
            "combiner did not complete after the cosigner's partial".into(),
        )),
    }
}
