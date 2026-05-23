//! Native **`/sign-relay`** handler — the §06.17.1 sign-time co-sign over the
//! MessageBox relay, run by the deployed **CF Container** cosigner (issue #30 /
//! #25c Stage 2, CONTAINER target).
//!
//! This is the native (tokio) sibling of the wasm worker's
//! `bsv_mpc_worker::poc::handle_prod_sign_relay`. The deployed CF **Worker**
//! isolate cannot run the heavy presign math, so the full §06.17.1 self-presign
//! property lives on the native container instead (POCS.md fallback: "If CF
//! Worker fails, fall back to CF Container … a deployment change, not an
//! architecture change"). The container already does DKG + presign natively;
//! this module gives it the sign-time half so the SAME native cosigner that
//! generated + self-encrypted its presig share at presign-time can decrypt it +
//! issue its partial at sign-time.
//!
//! ## Flow (mirrors the proven worker `handle_prod_sign_relay`)
//!
//! 1. Owner-authz: only the share's DKG-time `owner_identity` (§08.1) may
//!    trigger the cosigner. Enforced at the route layer
//!    ([`crate::handlers::handle_sign_relay`]) before this runs.
//! 2. Decrypt the coordinator-shipped `cosigner_encrypted_share` under THIS
//!    cosigner's own identity + the canonical `presig_id` (= session_id hex) via
//!    [`decrypt_and_issue_partial`] (#25b). The coordinator only ever held the
//!    opaque BRC-2 blob — it never had the cosigner's plaintext presig share
//!    (the §06.17.1 threshold gain over the POC proxy-knows-both shortcut).
//! 3. Wrap the resulting partial as a canonical §05 `MessageEnvelope`
//!    (BRC-78 encrypt to the combiner, BRC-31 sign with our identity) and ship
//!    it to the combiner on `mpc-sign` over the live relay via the native
//!    [`MessageBoxClient`].
//!
//! The combiner (the proxy, party `to_index`) holds the matching public data +
//! its own partial and combines into the final ECDSA signature; the cosigner
//! ships ONLY the serialized partial.

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::envelope::WrapParams;
use bsv_mpc_core::presig_encryption::{decrypt_and_issue_partial, wallet_from_identity};
use bsv_mpc_core::types::{RoundMessage, SessionId, ShareIndex};
use bsv_mpc_messagebox::types::BOX_SIGN;
use bsv_mpc_messagebox::MessageBoxClient;
use tracing::info;

/// Inputs the cosigner needs to decrypt its own §06.17.1 ciphertext, issue its
/// partial, and ship it to the combiner over the relay.
pub struct SignRelayParams {
    /// This cosigner's BRC-31 / relay + BRC-2 self-encryption identity. MUST be
    /// the same key the share's presig was self-encrypted under at presign-time
    /// (so `decrypt_and_issue_partial` re-derives the same wallet key).
    pub identity_priv: PrivateKey,
    /// The combiner's (coordinator/proxy) BRC-31 identity-key hex — the relay
    /// recipient of the partial.
    pub recipient_pub_hex: String,
    /// 32-byte sighash to sign.
    pub sighash: [u8; 32],
    /// This cosigner's BRC-2 ciphertext (the coordinator-held
    /// `PresigBundle.cosigner_encrypted_shares[from_index]`), opaque to the
    /// coordinator.
    pub cosigner_encrypted_share: Vec<u8>,
    /// Canonical `presig_id` = session_id hex — the key_id the share was sealed
    /// under at presign-time (§06.16 convention).
    pub presig_id: String,
    /// 33-byte compressed joint pubkey (the §05 envelope carries the real joint
    /// pubkey on the signing phase, §05.4.3).
    pub joint_pubkey: [u8; 33],
    /// Per-sign correlation session_id (the combiner picks this, ships it in the
    /// trigger, and filters the relay box on it). The cosigner echoes it.
    pub session_id: SessionId,
    /// This cosigner's signing-time index (the `from` index its partial carries).
    pub from_index: u16,
    /// The combiner's signing-time index.
    pub to_index: u16,
    /// MessageBox relay URL.
    pub relay_url: String,
}

/// Outcome of a relay co-sign — surfaced to the route for the JSON response.
pub struct SignRelayOutcome {
    /// This cosigner's relay identity-key hex.
    pub client_identity: String,
    /// The serialized partial signature shipped (hex), for response/debug parity
    /// with the worker route.
    pub partial_hex: String,
    /// Whether the partial was sent to the combiner over the relay.
    pub sent: bool,
}

/// Decrypt this cosigner's own §06.17.1 ciphertext, issue its partial, and ship
/// it to the combiner over the relay. Native counterpart of the worker's
/// `handle_prod_sign_relay`.
pub async fn cosign_over_relay(params: SignRelayParams) -> anyhow::Result<SignRelayOutcome> {
    if params.cosigner_encrypted_share.is_empty() {
        anyhow::bail!("cosigner_encrypted_share is empty");
    }

    // 1. Decrypt the at-rest BRC-2 blob under THIS cosigner's identity + the
    //    canonical presig_id, then issue this party's partial. None = base key
    //    (no BRC-42 offset; HD-derived signing stays on the legacy HTTP path).
    let wallet = wallet_from_identity(&params.identity_priv);
    let partial_json = decrypt_and_issue_partial(
        &wallet,
        &params.presig_id,
        &params.cosigner_encrypted_share,
        &params.sighash,
        None,
    )
    .map_err(|e| anyhow::anyhow!("§06.17.1 decrypt+issue_partial: {e}"))?;

    // 2. Wrap the partial as a canonical §05 RoundMessage and ship it to the
    //    combiner on the shared `mpc-sign` box. The native MessageBoxClient
    //    handles the BRC-78 encrypt + BRC-31 sign + relay send. `correlation_id`
    //    carries this sign's session_id hex (parity with the worker route);
    //    `from`/`to` carry the signing-time indices the combiner keys partials by.
    let client = MessageBoxClient::new(&params.relay_url, params.identity_priv.clone())
        .map_err(|e| anyhow::anyhow!("relay client: {e}"))?;
    let client_identity = client
        .identity_hex()
        .await
        .map_err(|e| anyhow::anyhow!("relay identity: {e}"))?;

    let round_msg = RoundMessage {
        session_id: params.session_id,
        round: 1,
        from: ShareIndex(params.from_index),
        to: Some(ShareIndex(params.to_index)),
        payload: partial_json.clone(),
    };
    let wrap = WrapParams {
        to_party: params.to_index,
        joint_pubkey: params.joint_pubkey,
        phase: "sign".to_string(),
        execution_id_prefix: [0u8; 8],
        correlation_id: Some(params.session_id.hex()),
        traceparent: None,
    };

    let send_result = client
        .send_round_message(&params.recipient_pub_hex, BOX_SIGN, &round_msg, wrap)
        .await;
    let sent = send_result.is_ok();
    if let Err(e) = send_result {
        // Surface but don't hard-fail: the partial was issued; a transient relay
        // send error is reported to the caller (parity with the worker route,
        // which returns `sent: false`).
        tracing::warn!("sign-relay: send partial to combiner failed: {e}");
    }

    info!(
        from_index = params.from_index,
        to_index = params.to_index,
        sent,
        "sign-relay: cosigner issued + shipped its partial over the relay"
    );

    Ok(SignRelayOutcome {
        client_identity,
        partial_hex: hex::encode(&partial_json),
        sent,
    })
}
