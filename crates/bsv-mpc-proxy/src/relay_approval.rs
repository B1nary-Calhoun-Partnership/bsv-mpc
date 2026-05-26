//! §09.5.1 **approval-request / -response over the MessageBox relay** (issue #43,
//! increment 2b).
//!
//! When the policy engine ([`bsv_mpc_core::policy`]) returns
//! `Verdict::RequireApproval`, the coordinator (this proxy) must collect `k`
//! Allow approvals from the quorum's `eligible` set BEFORE it signs. This module
//! carries that exchange over the SAME canonical MessageBox substrate the
//! device-holds relay sign uses ([`crate::relay_sign`]): BRC-31-authed,
//! BRC-78-encrypted §05 envelopes on the [`BOX_APPROVAL`] box.
//!
//! - [`collect_approval_over_relay`] (coordinator) — emit the approval-request to
//!   each eligible approver, then collect their signed responses into an
//!   [`ApprovalCollector`] until k-Allow / k-Deny / deadline.
//! - [`serve_one_approval`] (approver) — the SDK `mpc.approve()` core: receive one
//!   approval-request, sign `BRC-77(request_view_hash ‖ "mpc-approval-v1" ‖
//!   session_id)`, and reply to the coordinator.
//!
//! The approval signature (not the transport) is the security boundary: a valid
//! response binds an eligible signer to the exact `request_view_hash` +
//! `session_id` (see [`bsv_mpc_core::approval`]). The envelope `phase` is set to
//! `"sign"` (transport metadata only — there is no separate approval phase tag;
//! approval semantics live entirely in the payload + the BRC-77 signature).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::approval::{sign_approval, ApprovalCollector, ApprovalDecision, ApprovalStatus};
use bsv_mpc_core::envelope::WrapParams;
use bsv_mpc_core::error::{MpcError, Result};
use bsv_mpc_core::policy::ApprovalQuorum;
use bsv_mpc_core::types::{RoundMessage, SessionId, ShareIndex};
use bsv_mpc_messagebox::types::BOX_APPROVAL;
use bsv_mpc_messagebox::MessageBoxClient;
use serde::{Deserialize, Serialize};

/// Current epoch-ms (proxy is native — a wall-clock read is fine here, unlike the
/// wasm-portable core engine which takes `now_ms` as a parameter).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The approval-request payload the coordinator emits (§09.5.1 step 2), carried
/// in a [`RoundMessage`] on [`BOX_APPROVAL`]. The approver signs over
/// `request_view_hash` + `session_id` (NOT this JSON), so the JSON is advisory
/// context; the binding is the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApprovalRequestPayload {
    /// Discriminator: always `"approval-request"`.
    kind: String,
    /// Hex of the 32-byte `request_view_hash` (§09.5.1 step 1).
    request_view_hash: String,
    /// Hex of the 32-byte session id this approval is bound to.
    session_id: String,
    /// Quorum threshold `k`.
    k: u32,
    /// Human-visible rendered text the wallet displayed (advisory; the binding is
    /// `request_view_hash`).
    rendered_text: String,
    /// Joint pubkey hex (33 bytes) the spend is under (advisory display context).
    joint_pubkey: String,
}

/// The approver's response payload (§09.5.1 step 3-4).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApprovalResponsePayload {
    /// Discriminator: always `"approval-response"`.
    kind: String,
    /// `"allow"` or `"deny"`.
    decision: String,
    /// Hex of the BRC-77 approval signature over the §09.5.1 preimage.
    sig: String,
}

fn proto(e: bsv_mpc_messagebox::error::MessageBoxError) -> MpcError {
    MpcError::Protocol(e.to_string())
}

/// **Coordinator side (§09.5.1 steps 2,4,5).** Emit the approval-request to every
/// approver in `quorum.eligible` over the relay, then collect signed responses
/// until `k` Allow ([`ApprovalStatus::Approved`]), `k` Deny
/// ([`ApprovalStatus::Denied`]), or the deadline ([`ApprovalStatus::Expired`]).
///
/// Each inbound response is verified by [`ApprovalCollector::record_vote`]: the
/// BRC-77 signature must be valid over THIS `(request_view_hash, session_id)` and
/// the signer must be in `eligible` — a relay-injected or non-approver message is
/// dropped, never counted. The proxy proceeds to sign only on `Approved`.
#[allow(clippy::too_many_arguments)]
pub async fn collect_approval_over_relay(
    relay_url: &str,
    coordinator_priv: PrivateKey,
    quorum: ApprovalQuorum,
    request_view_hash: [u8; 32],
    session_id: SessionId,
    joint_pubkey: [u8; 33],
    rendered_text: &str,
    recv_timeout: Duration,
) -> Result<ApprovalStatus> {
    let client = MessageBoxClient::new(relay_url, coordinator_priv).map_err(proto)?;
    // Subscribe BEFORE sending so a fast approver reply isn't missed (backfill
    // also covers a late subscribe).
    let mut sub = client
        .subscribe_round_messages(BOX_APPROVAL)
        .await
        .map_err(proto)?;

    // Emit the approval-request to each eligible approver (N-unicast).
    let req = ApprovalRequestPayload {
        kind: "approval-request".to_string(),
        request_view_hash: hex::encode(request_view_hash),
        session_id: session_id.hex(),
        k: quorum.k,
        rendered_text: rendered_text.to_string(),
        joint_pubkey: hex::encode(joint_pubkey),
    };
    let payload = serde_json::to_vec(&req)
        .map_err(|e| MpcError::Serialization(format!("approval-request: {e}")))?;
    let round_msg = RoundMessage {
        session_id,
        round: 1,
        from: ShareIndex(0),
        to: Some(ShareIndex(0)),
        payload,
    };
    for approver in &quorum.eligible {
        let approver_hex = hex::encode(approver);
        let params = WrapParams {
            to_party: 0,
            joint_pubkey,
            phase: "sign".to_string(),
            execution_id_prefix: [0u8; 8],
            correlation_id: Some(session_id.hex()),
            traceparent: None,
        };
        client
            .send_round_message(&approver_hex, BOX_APPROVAL, &round_msg, params)
            .await
            .map_err(proto)?;
    }

    // Collect until quorum / deadline.
    let start = now_ms();
    let deadline_ms = start.saturating_add(recv_timeout.as_millis() as u64);
    let mut collector = ApprovalCollector::new(
        quorum,
        request_view_hash,
        *session_id.as_bytes(),
        deadline_ms,
    );

    let recv_deadline = tokio::time::Instant::now() + recv_timeout;
    loop {
        if collector.is_approved() {
            return Ok(ApprovalStatus::Approved);
        }
        let remaining = match recv_deadline.checked_duration_since(tokio::time::Instant::now()) {
            Some(d) => d,
            None => {
                sub.shutdown().await;
                return Ok(collector.status(now_ms()));
            }
        };
        let decoded = match tokio::time::timeout(remaining, sub.next()).await {
            Err(_) => {
                sub.shutdown().await;
                return Ok(collector.status(now_ms()));
            }
            Ok(None) => return Err(MpcError::Protocol("approval relay closed".into())),
            Ok(Some(r)) => r.map_err(proto)?,
        };

        // Parse a response; skip anything that isn't one (e.g. our own request
        // echo, or an unrelated message on the shared box).
        let resp: ApprovalResponsePayload = match serde_json::from_slice(&decoded.round_msg.payload)
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        if resp.kind != "approval-response" || decoded.round_msg.session_id != session_id {
            continue;
        }
        let sig = match hex::decode(&resp.sig) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let decision = match resp.decision.as_str() {
            "allow" => ApprovalDecision::Allow,
            "deny" => ApprovalDecision::Deny,
            _ => continue,
        };
        // record_vote verifies the BRC-77 sig over (view_hash, session) AND that
        // the signer is eligible; a bad/ineligible vote is dropped (Err → skip).
        match collector.record_vote(&sig, decision, now_ms()) {
            Ok(ApprovalStatus::Approved) => {
                sub.shutdown().await;
                return Ok(ApprovalStatus::Approved);
            }
            Ok(ApprovalStatus::Denied) => {
                sub.shutdown().await;
                return Ok(ApprovalStatus::Denied);
            }
            _ => continue,
        }
    }
}

/// **Approver side (§09.5.1 step 3) — the SDK `mpc.approve()` core.** Subscribe to
/// [`BOX_APPROVAL`] as the approver identity, wait for ONE approval-request, sign
/// it with `decision`, and reply to the requesting coordinator over the relay.
///
/// Returns the `(request_view_hash_hex, session_id_hex)` it approved, for
/// logging / the requester status surface. Times out with an error if no request
/// arrives within `recv_timeout`.
pub async fn serve_one_approval(
    relay_url: &str,
    approver_priv: PrivateKey,
    decision: ApprovalDecision,
    recv_timeout: Duration,
) -> Result<(String, String)> {
    let client = MessageBoxClient::new(relay_url, approver_priv.clone()).map_err(proto)?;
    let mut sub = client
        .subscribe_round_messages(BOX_APPROVAL)
        .await
        .map_err(proto)?;

    let recv_deadline = tokio::time::Instant::now() + recv_timeout;
    loop {
        let remaining = recv_deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| MpcError::Protocol("approver timed out awaiting request".into()))?;
        let decoded = match tokio::time::timeout(remaining, sub.next()).await {
            Err(_) => {
                return Err(MpcError::Protocol(
                    "approver timed out awaiting request".into(),
                ))
            }
            Ok(None) => return Err(MpcError::Protocol("approval relay closed".into())),
            Ok(Some(r)) => r.map_err(proto)?,
        };
        let req: ApprovalRequestPayload = match serde_json::from_slice(&decoded.round_msg.payload) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if req.kind != "approval-request" {
            continue;
        }
        // Decode the binding inputs.
        let vh_bytes = hex::decode(&req.request_view_hash)
            .map_err(|e| MpcError::Protocol(format!("request_view_hash hex: {e}")))?;
        if vh_bytes.len() != 32 {
            return Err(MpcError::Protocol(
                "request_view_hash must be 32 bytes".into(),
            ));
        }
        let mut request_view_hash = [0u8; 32];
        request_view_hash.copy_from_slice(&vh_bytes);
        let session_id = SessionId::from_hex(&req.session_id)
            .map_err(|e| MpcError::Protocol(format!("session_id hex: {e}")))?;

        // Sign the §09.5.1 preimage and reply to the coordinator.
        let sig = sign_approval(&request_view_hash, session_id.as_bytes(), &approver_priv)?;
        let resp = ApprovalResponsePayload {
            kind: "approval-response".to_string(),
            decision: match decision {
                ApprovalDecision::Allow => "allow".to_string(),
                ApprovalDecision::Deny => "deny".to_string(),
            },
            sig: hex::encode(&sig),
        };
        let payload = serde_json::to_vec(&resp)
            .map_err(|e| MpcError::Serialization(format!("approval-response: {e}")))?;
        let round_msg = RoundMessage {
            session_id,
            round: 1,
            from: ShareIndex(0),
            to: Some(ShareIndex(0)),
            payload,
        };
        let joint_pubkey = {
            let mut jpk = [0u8; 33];
            if let Ok(b) = hex::decode(&req.joint_pubkey) {
                if b.len() == 33 {
                    jpk.copy_from_slice(&b);
                }
            }
            jpk
        };
        let params = WrapParams {
            to_party: 0,
            joint_pubkey,
            phase: "sign".to_string(),
            execution_id_prefix: [0u8; 8],
            correlation_id: Some(session_id.hex()),
            traceparent: None,
        };
        let coordinator_hex = decoded.sender_pub.to_hex();
        client
            .send_round_message(&coordinator_hex, BOX_APPROVAL, &round_msg, params)
            .await
            .map_err(proto)?;
        sub.shutdown().await;
        return Ok((req.request_view_hash, req.session_id));
    }
}
