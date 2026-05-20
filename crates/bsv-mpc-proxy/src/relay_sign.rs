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
    /// production authed route once it lands).
    pub url: String,
    /// Serialized cggmp24 `Presignature_A` (party `do_index`'s presignature),
    /// already provisioned to the DO's pool (#14). Posted here so the proof is
    /// self-contained; production reads it from the DO pool.
    pub presig_a_json: Vec<u8>,
    /// The DO party's signing-time index — the `from` index its partial carries
    /// (the combiner keys partials by this).
    pub do_index: u16,
}

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
    let http = reqwest::Client::new();
    let resp = http
        .post(&trigger.url)
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "presignature_hex": hex::encode(&trigger.presig_a_json),
            "sighash_hex": hex::encode(sighash),
            "recipient_pub_hex": combiner_pub,
            "from_index": trigger.do_index,
            "to_index": my_index,
            "joint_pubkey_hex": hex::encode(&joint_key.compressed),
            "session_id_hex": session_id.hex(),
        }))
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
    let decoded = tokio::time::timeout(recv_timeout, sub.next())
        .await
        .map_err(|_| MpcError::Protocol("timed out awaiting DO partial over relay".into()))?
        .ok_or_else(|| MpcError::Protocol("relay subscription closed before partial".into()))?
        .map_err(proto)?;

    if decoded.round_msg.from != ShareIndex(trigger.do_index) {
        return Err(MpcError::Signing(format!(
            "expected partial from DO party {}, got party {}",
            trigger.do_index, decoded.round_msg.from.0
        )));
    }

    let result = coord.process_round(vec![decoded.round_msg])?;
    sub.shutdown().await;
    match result {
        SigningRoundResult::Complete(sig) => Ok(sig),
        SigningRoundResult::NextRound(_) => Err(MpcError::Signing(
            "combiner did not complete after the DO's partial".into(),
        )),
    }
}
