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
    trigger: DoTrigger,
    // When `Some`, signs the EXACT serialized trigger body with canonical BRC-31
    // (the deployed worker `/sign-relay` verifies the canonical wire). When
    // `None`, falls back to `trigger.auth_headers` (unauthed POC / legacy callers).
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

    // 2. Prime our coordinator (issues our own partial; holds public data).
    let my_index = signing_index(&share, &participants)?;
    let mut coord = SigningCoordinator::new(session_id, share, config, participants);
    coord.sign_with_presignature(sighash, my_presig_box)?;

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

/// **§06.17.1 coordinator-holds-ciphertext sign over the relay (issue #30 /
/// #25c Stage 2).**
///
/// The production-binary analog of the Stage-1 hermetic capstone
/// (`sign_from_bundle_hermetic_e2e`), driven against the DEPLOYED worker over
/// the live relay. The coordinator does NOT consume a raw presig box from a
/// pool; it signs from a durable [`PresigBundle`](bsv_mpc_core::types::PresigBundle)
/// it persisted at presign-time (the worker self-presigned + self-encrypted its
/// share; the coordinator only ever held the opaque ciphertext).
///
/// Flow:
/// 1. Connect to the relay as `identity_priv`; subscribe to `mpc-sign`.
/// 2. Unseal the coordinator's OWN presig share from `bundle.presig_bytes`
///    (under `at_rest_root` + `bundle.presig_id`), reconstruct the shared
///    `PresignaturePublicData` from `bundle.commitments`, and `sign_from_bundle`
///    → the coordinator's own partial.
/// 3. Trigger the deployed worker `/sign-relay` with the cosigner's BRC-2
///    ciphertext (`bundle.cosigner_encrypted_shares[do_index]`) so the worker
///    decrypts its OWN share (`decrypt_and_issue_partial`, #25b) and relays its
///    partial — the coordinator never re-sends a plaintext presig.
/// 4. Receive the worker's partial over the relay; combine → [`SigningResult`].
#[allow(clippy::too_many_arguments)]
pub async fn combine_sign_from_bundle_over_relay(
    relay_url: &str,
    identity_priv: PrivateKey,
    share: EncryptedShare,
    participants: Vec<u16>,
    config: ThresholdConfig,
    session_id: SessionId,
    sighash: &[u8; 32],
    bundle: &bsv_mpc_core::types::PresigBundle,
    at_rest_root: &[u8; 32],
    joint_key: &JointPublicKey,
    mut trigger: DoTrigger,
    request_signer: Option<RelayRequestSigner<'_>>,
    recv_timeout: Duration,
) -> Result<SigningResult> {
    use bsv_mpc_core::presig_at_rest::{derive_presig_at_rest_key, unseal_presig_bytes};
    use bsv_mpc_core::signing::deserialize_presig_public_data;

    let proto = |e: bsv_mpc_messagebox::error::MessageBoxError| MpcError::Protocol(e.to_string());

    // The coordinator's positional slot in the bundle = its index within
    // `parties_at_keygen`. Its own ciphertext slot is empty (plaintext sealed in
    // `presig_bytes`); the cosigner's ciphertext lives at `do_index`'s position.
    let do_pos = bundle
        .parties_at_keygen
        .iter()
        .position(|&p| p == trigger.do_index)
        .ok_or_else(|| {
            MpcError::Signing(format!(
                "cosigner party {} not in bundle.parties_at_keygen {:?}",
                trigger.do_index, bundle.parties_at_keygen
            ))
        })?;
    let cosigner_ct = bundle
        .cosigner_encrypted_shares
        .get(do_pos)
        .map(|b| b.clone().into_vec())
        .unwrap_or_default();
    if cosigner_ct.is_empty() {
        return Err(MpcError::Signing(format!(
            "bundle has no cosigner ciphertext at position {do_pos} (party {})",
            trigger.do_index
        )));
    }
    trigger.cosigner_encrypted_share = Some(cosigner_ct);

    // 1. Relay client + subscription BEFORE triggering the DO.
    let combiner = MessageBoxClient::new(relay_url, identity_priv).map_err(proto)?;
    let combiner_pub = combiner.identity_hex().await.map_err(proto)?;
    let mut sub = combiner
        .subscribe_round_messages(BOX_SIGN)
        .await
        .map_err(proto)?;

    // 2. Sign FROM the bundle: unseal own share, reconstruct public data, issue
    //    the coordinator's own partial (no live presig tuple required).
    let at_rest_key = derive_presig_at_rest_key(at_rest_root, &bundle.presig_id);
    let own_presig_json = unseal_presig_bytes(&bundle.presig_bytes, &at_rest_key)
        .map_err(|e| MpcError::Signing(format!("unseal coordinator presig share: {e}")))?;
    let public_data = deserialize_presig_public_data(&bundle.commitments)
        .map_err(|e| MpcError::Signing(format!("reconstruct PresignaturePublicData: {e}")))?;
    let my_index = signing_index(&share, &participants)?;
    let mut coord = SigningCoordinator::new(session_id, share, config, participants);
    coord.sign_from_bundle(sighash, &own_presig_json, public_data)?;

    // 3. Trigger the worker with the cosigner ciphertext (no plaintext presig).
    let http = reqwest::Client::new();
    let mut trigger_body = serde_json::json!({
        "sighash_hex": hex::encode(sighash),
        "recipient_pub_hex": combiner_pub,
        "from_index": trigger.do_index,
        "to_index": my_index,
        "joint_pubkey_hex": hex::encode(&joint_key.compressed),
        "session_id_hex": session_id.hex(),
    });
    if let Some(ref agent_id) = trigger.agent_id {
        trigger_body["agent_id"] = serde_json::json!(agent_id);
    }
    if let Some(ref ct) = trigger.cosigner_encrypted_share {
        trigger_body["cosigner_encrypted_share"] = serde_json::json!(hex::encode(ct));
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

    // 4. Receive the worker's partial over the relay; combine. Filter to THIS
    //    sign's session (the `mpc-sign` box is shared + backfilled).
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
