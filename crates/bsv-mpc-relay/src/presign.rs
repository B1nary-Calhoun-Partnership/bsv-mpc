//! **Coordinator** for §06.17.1 presign-over-the-relay (issue #30 / #25c Stage 2,
//! CONTAINER target). Factored out of the proxy `relay_presign.rs` (issue #63,
//! path a-extended) so the BRC-100 proxy AND the native client run the EXACT same
//! presign-over-relay coordinator.
//!
//! The deployed CF **Container** cosigner runs `PresignHandler` as a presign
//! cosigner over the relay (`POST /presign-relay/init`): it generates + BRC-2
//! self-encrypts its OWN presig share and ships the ciphertext to this
//! coordinator. This module is the matching **coordinator** half:
//!
//! 1. Trigger the container to arm itself as the cosigner (it returns its relay
//!    identity hex).
//! 2. Run the relay-proven [`PresignHandler`] (coordinator role) + a
//!    `MessageBoxListener` on the protocol box + the return box.
//! 3. The 3-round presign completes over the relay; on round-3 the coordinator
//!    keeps its OWN sealed share + collects the cosigner's return ciphertext,
//!    assembles + persists the [`PresigBundle`] to the durable [`FileBundleStore`].
//!
//! The coordinator NEVER holds the cosigner's plaintext presig share — only the
//! opaque BRC-2 ciphertext in the bundle (the §06.17.1 threshold gain). At
//! sign-time, [`crate::combine_sign_from_bundle_over_relay`] ships that ciphertext
//! back to the container's `/sign-relay`, which decrypts it under its OWN identity
//! and co-signs.

use std::sync::Arc;
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::error::{MpcError, Result};
use bsv_mpc_core::types::{EncryptedShare, PolicyId, PresigBundle, SessionId};
use bsv_mpc_messagebox::types::{presig_return_box, presign_protocol_box};
use bsv_mpc_messagebox::MessageBoxClient;
use bsv_mpc_service::{
    FileBundleStore, MessageBoxListener, PresignHandler, PresignHandlerConfig, PresignOutcome,
};

/// A canonical BRC-31 request signer (same shape as [`crate::RelayRequestSigner`])
/// — signs the exact serialized body for the container's authed
/// `/presign-relay/init` route.
pub type RequestSigner<'a> =
    &'a (dyn Fn(&str, &str, &[u8]) -> Result<Vec<(String, String)>> + Send + Sync);

/// How the coordinator reaches the container to arm it as a presign cosigner.
pub struct CosignerArm {
    /// The container's `/presign-relay/init` URL.
    pub url: String,
    /// The share's `agent_id` (joint pubkey hex) for owner-authz (§08.1).
    pub agent_id: String,
}

/// The container's `/presign-relay/init` response.
#[derive(serde::Deserialize)]
struct ArmResponse {
    cosigner_pub_hex: String,
    #[allow(dead_code)]
    protocol_box: String,
}

/// Run the §06.17.1 presign over the relay as the coordinator, persisting the
/// assembled [`PresigBundle`] to `bundle_store`.
///
/// - `share` is the coordinator's DKG key share with its 33-byte joint pubkey
///   populated.
/// - `coordinator_party` / `cosigner_party` are the keygen-subset indices.
/// - `arm` triggers the container cosigner; `request_signer` BRC-31-signs that
///   trigger over the canonical wire.
#[allow(clippy::too_many_arguments)]
pub async fn coordinate_presign_over_relay(
    relay_url: &str,
    identity_priv: PrivateKey,
    share: EncryptedShare,
    coordinator_party: u16,
    cosigner_party: u16,
    parties_at_keygen: Vec<u16>,
    policy_id: PolicyId,
    at_rest_root: [u8; 32],
    session_id: SessionId,
    bundle_store: Arc<FileBundleStore>,
    arm: CosignerArm,
    request_signer: RequestSigner<'_>,
    timeout: Duration,
) -> Result<PresigBundle> {
    let proto = |e: bsv_mpc_messagebox::error::MessageBoxError| MpcError::Protocol(e.to_string());
    let sid_hex = session_id.hex();

    // 1. Coordinator relay client + identity.
    let coord_client = MessageBoxClient::new(relay_url, identity_priv.clone()).map_err(proto)?;
    let coord_pub_hex = coord_client.identity_hex().await.map_err(proto)?;

    // 2. Build the coordinator handler + listen on BOTH the protocol box and the
    //    return box over a single connection (start_many: avoids the
    //    two-subscription split race; the handler routes on the RETURN_SHARE_ROUND
    //    sentinel).
    let handler = PresignHandler::new(PresignHandlerConfig {
        my_party_index: coordinator_party,
        coordinator_party,
        parties_at_keygen: parties_at_keygen.clone(),
        policy_id,
        identity_priv: identity_priv.clone(),
        at_rest_root,
        bundle_store: bundle_store.clone(),
    });
    let protocol_box = presign_protocol_box(&sid_hex);
    let return_box = presig_return_box(&sid_hex);
    let listener = MessageBoxListener::start_many(
        coord_client.clone(),
        vec![protocol_box.clone(), return_box.clone()],
        handler.handler_fn(),
    )
    .await
    .map_err(|e| MpcError::Protocol(format!("coord listener: {e}")))?;

    // 3. Fetch the cosigner's relay identity FIRST (read-only) so the coordinator
    //    can register its ceremony slot + ship its round-1 BEFORE the cosigner
    //    ships — otherwise the cosigner's round-1 races ahead of the coordinator's
    //    slot and is dropped (the §06.17 ordering invariant; the relay delivers
    //    immediately, and an inbound for an unregistered session is discarded,
    //    deadlocking the presign).
    let cosigner_pub_hex = match fetch_cosigner_identity(&arm).await {
        Ok(h) => h,
        Err(e) => {
            listener.shutdown().await;
            return Err(e);
        }
    };

    // 4. Initiate the coordinator's own SM (init_generate) — this REGISTERS the
    //    ceremony slot but does NOT ship round-1 yet. We ship round-1 AFTER the
    //    cosigner has joined (step 6) so it rides the BRC-103 WS live-push, never
    //    the unreliable HTTP backfill — the §06.17 ordering invariant.
    let peers = vec![(cosigner_party, cosigner_pub_hex.clone())];
    let (rx, round1_out) = match handler.initiate(session_id, share, peers).await {
        Ok(v) => v,
        Err(e) => {
            listener.shutdown().await;
            return Err(MpcError::Protocol(format!("coord initiate: {e}")));
        }
    };

    // 5. Arm the cosigner — it subscribes (joining its protocol box), runs
    //    init_generate, and ships its OWN round-1 to the coordinator (whose slot
    //    now exists and which subscribed in step 2). `/presign-relay/init` returns
    //    200 only AFTER the cosigner has subscribed. Verify its relay identity
    //    matches what we fetched.
    let armed_pub_hex = match arm_cosigner(
        &arm,
        &session_id,
        &coord_pub_hex,
        coordinator_party,
        cosigner_party,
        &parties_at_keygen,
        &policy_id,
        request_signer,
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            listener.shutdown().await;
            return Err(e);
        }
    };
    if armed_pub_hex != cosigner_pub_hex {
        listener.shutdown().await;
        return Err(MpcError::Protocol(format!(
            "cosigner relay identity changed between identity ({cosigner_pub_hex}) and arm ({armed_pub_hex})"
        )));
    }

    // 6. NOW ship the coordinator's round-1 — the cosigner has joined its box, so
    //    the relay delivers this by WS live-push (NOT the unreliable HTTP
    //    backfill). The cosigner's SM buffers it in order even if the
    //    coordinator's round-2 races ahead.
    for out in &round1_out {
        if let Err(e) = coord_client
            .send_round_message(
                &out.recipient_pub_hex,
                &out.message_box,
                &out.round_msg,
                out.params.clone(),
            )
            .await
        {
            listener.shutdown().await;
            return Err(MpcError::Protocol(format!("ship coord round-1: {e}")));
        }
    }

    // 7. Await bundle assembly.
    let outcome = match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            listener.shutdown().await;
            return Err(MpcError::Protocol(format!(
                "coordinator completion channel dropped: {e}"
            )));
        }
        Err(_) => {
            listener.shutdown().await;
            return Err(MpcError::Protocol(
                "timed out awaiting PresigBundle assembly over the relay".into(),
            ));
        }
    };
    listener.shutdown().await;

    match outcome {
        PresignOutcome::BundlePersisted(b) => Ok(*b),
        PresignOutcome::ReturnShipped => Err(MpcError::Protocol(
            "coordinator unexpectedly produced a cosigner outcome".into(),
        )),
    }
}

/// GET the container's `/presign-relay/identity` (read-only) → its relay / BRC-2
/// identity-key hex. Derived from the `/presign-relay/init` URL.
async fn fetch_cosigner_identity(arm: &CosignerArm) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct IdResponse {
        cosigner_pub_hex: String,
    }
    let url = arm
        .url
        .replace("/presign-relay/init", "/presign-relay/identity");
    let resp = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|e| MpcError::Protocol(format!("fetch cosigner identity: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "/presign-relay/identity returned {status}: {txt}"
        )));
    }
    let parsed: IdResponse = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse identity response: {e}")))?;
    Ok(parsed.cosigner_pub_hex)
}

/// POST the container's `/presign-relay/init`, BRC-31-signed over the canonical
/// wire, returning the cosigner's relay identity hex.
#[allow(clippy::too_many_arguments)]
async fn arm_cosigner(
    arm: &CosignerArm,
    session_id: &SessionId,
    coordinator_pub_hex: &str,
    coordinator_party: u16,
    cosigner_party: u16,
    parties_at_keygen: &[u16],
    policy_id: &PolicyId,
    request_signer: RequestSigner<'_>,
) -> Result<String> {
    let body = serde_json::json!({
        "agent_id": arm.agent_id,
        "session_id": session_id.hex(),
        "coordinator_pub_hex": coordinator_pub_hex,
        "coordinator_party": coordinator_party,
        "my_party_index": cosigner_party,
        "parties_at_keygen": parties_at_keygen,
        "policy_id_hex": hex::encode(policy_id.0),
    });
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| MpcError::Serialization(format!("serialize presign-relay/init: {e}")))?;
    let path = reqwest::Url::parse(&arm.url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| "/presign-relay/init".to_string());

    let http = reqwest::Client::new();
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
        .map_err(|e| MpcError::Protocol(format!("arm cosigner request: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "container /presign-relay/init returned {status}: {txt}"
        )));
    }
    let parsed: ArmResponse = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse presign-relay/init response: {e}")))?;
    Ok(parsed.cosigner_pub_hex)
}
