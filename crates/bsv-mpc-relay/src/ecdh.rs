//! **Device coordinator** for the #90 distributed-ECDH partial round.
//!
//! BRC-42 `Self_`/`Other` derivation needs the ECDH shared secret
//! `counterparty_pub * root_priv`, but `root_priv` is split across MPC shares and
//! is NEVER reconstructed. The device computes its own `w = t−1` partials locally
//! (`bsv_mpc_core::ecdh::compute_partial_ecdh_point`) and fetches the remaining
//! partial(s) from a cosigner over this round, then Lagrange-combines `t` of them
//! (`combine_partials_lagrange`) into the full shared secret — exactly the math
//! `bsv-mpc-core/src/ecdh.rs` proves equals a full ECDH (POC 3 / 9).
//!
//! Transport (#90 decision): **response-direct** — a single authed HTTP POST to
//! the cosigner's `/ecdh-relay`, which returns its `(partial, vss_point)` pairs in
//! the response body. ECDH is single-shot (no presig/pool/multi-round), so unlike
//! the sign path there is no MessageBox listener/SM here. Because the partials ride
//! the HTTP response rather than the BRC-31-authed relay box, the cosigner's PINNED
//! master ATTESTS the exact returned set and this coordinator VERIFIES it against
//! the out-of-band pin before returning anything (#85, fail-closed).
//!
//! This module returns the cosigner's VERIFIED partials; the caller (the #91 FFI)
//! supplies its own `w` local partials and runs `combine_partials_lagrange`.

use std::time::Duration;

use bsv::primitives::ec::PublicKey;
use bsv_mpc_core::error::{MpcError, Result};
use bsv_mpc_core::hd::{ecdh_partials_digest, verify_ecdh_partials_attestation};

use crate::RequestSigner;

/// One cosigner-returned partial: `counterparty_pub * share(index)` + the VSS eval
/// point `I[index]` to pair it with for Lagrange interpolation
/// (`bsv_mpc_core::ecdh::combine_partials_lagrange`).
#[derive(Clone, Debug)]
pub struct EcdhPartial {
    pub index: u16,
    pub partial: PublicKey,
    pub vss_point: [u8; 32],
}

/// How the device reaches a cosigner to fetch its ECDH partial(s).
pub struct EcdhCosignerArm {
    /// The cosigner's `/ecdh-relay` URL.
    pub url: String,
    /// The wallet's joint pubkey hex (§08.1 owner-authz + composite-share id).
    pub agent_id: String,
    /// The cosigner's held keygen indices to request partials for (one
    /// `(partial, vss_point)` pair returned per index).
    pub indices: Vec<u16>,
    /// **#85 MITM gate.** The cosigner's MASTER identity pubkey hex, PINNED
    /// out-of-band. When `Some`, the device verifies the response's `master_pub_hex`
    /// equals this AND that the master attestation covers the EXACT returned partial
    /// set, failing closed otherwise — so a network MITM that swaps the partials in
    /// the HTTP response cannot steer derivation. `None` = unpinned (dev/test only).
    pub expected_master_pub: Option<String>,
}

#[derive(serde::Deserialize)]
struct EcdhRelayPartialJson {
    index: u16,
    partial_hex: String,
    vss_point_hex: String,
}

#[derive(serde::Deserialize)]
struct EcdhRelayResponse {
    partials: Vec<EcdhRelayPartialJson>,
    master_pub_hex: String,
    attestation_sig_hex: String,
}

fn decode_pubkey(hex_str: &str, what: &str) -> Result<PublicKey> {
    hex::decode(hex_str)
        .ok()
        .and_then(|b| PublicKey::from_bytes(&b).ok())
        .ok_or_else(|| MpcError::Protocol(format!("ecdh-relay: {what} not a valid pubkey")))
}

fn decode_32(hex_str: &str, what: &str) -> Result<[u8; 32]> {
    let b = hex::decode(hex_str)
        .map_err(|e| MpcError::Protocol(format!("ecdh-relay: bad {what}: {e}")))?;
    b.as_slice()
        .try_into()
        .map_err(|_| MpcError::Protocol(format!("ecdh-relay: {what} must be 32 bytes")))
}

/// Fetch a cosigner's distributed-ECDH partials over a single authed HTTP
/// round-trip (#90, response-direct).
///
/// - `counterparty_pub` is the BRC-42 ECDH peer (the joint pubkey itself for `Self_`).
/// - `nonce` is a FRESH 32-byte device nonce bound into the #85 attestation.
/// - `arm` carries the cosigner URL, the wallet `agent_id`, the indices to request,
///   and the optional `#85` master pin.
/// - `request_signer` BRC-31-signs the canonical request body when `Some`; `None`
///   is for an unauthed (permissive in-process) cosigner only.
///
/// Returns the cosigner's `(partial, vss_point)` pairs. When `arm.expected_master_pub`
/// is pinned, a wrong master, a tampered/substituted partial set, a replayed nonce,
/// or a cross-wallet/counterparty reuse all fail closed before any partial is returned.
pub async fn coordinate_ecdh_over_relay(
    counterparty_pub: &PublicKey,
    nonce: &[u8; 32],
    arm: &EcdhCosignerArm,
    request_signer: Option<RequestSigner<'_>>,
    timeout: Duration,
) -> Result<Vec<EcdhPartial>> {
    if arm.indices.is_empty() {
        return Err(MpcError::Protocol(
            "ecdh-relay: no cosigner indices requested".into(),
        ));
    }

    let body = serde_json::json!({
        "agent_id": arm.agent_id,
        "counterparty_pub_hex": hex::encode(counterparty_pub.to_compressed()),
        "indices": arm.indices,
        "nonce_hex": hex::encode(nonce),
    });
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| MpcError::Serialization(format!("serialize ecdh-relay body: {e}")))?;
    let path = reqwest::Url::parse(&arm.url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| "/ecdh-relay".to_string());

    let http = crate::bounded_http_client(timeout)?;
    let mut builder = http
        .post(&arm.url)
        .header("content-type", "application/json")
        .body(body_bytes.clone());
    if let Some(sign) = request_signer {
        for (name, value) in sign("POST", &path, &body_bytes)? {
            builder = builder.header(name, value);
        }
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| MpcError::Protocol(format!("ecdh-relay request: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "/ecdh-relay returned {status}: {txt}"
        )));
    }
    let parsed: EcdhRelayResponse = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse ecdh-relay response: {e}")))?;

    // Decode the partials and sanity-check the indices are the ones we asked for
    // (a genuine cosigner returns exactly the requested set; the #85 attestation
    // below is the integrity gate, this is an early clear-error guard).
    let mut partials = Vec::with_capacity(parsed.partials.len());
    for p in &parsed.partials {
        if !arm.indices.contains(&p.index) {
            return Err(MpcError::Protocol(format!(
                "ecdh-relay: cosigner returned unrequested index {}",
                p.index
            )));
        }
        partials.push(EcdhPartial {
            index: p.index,
            partial: decode_pubkey(&p.partial_hex, "partial_hex")?,
            vss_point: decode_32(&p.vss_point_hex, "vss_point_hex")?,
        });
    }
    if partials.is_empty() {
        return Err(MpcError::Protocol(
            "ecdh-relay: cosigner returned no partials".into(),
        ));
    }

    // #85: verify the PINNED master attested EXACTLY these partials (fail closed).
    if let Some(pinned) = &arm.expected_master_pub {
        if &parsed.master_pub_hex != pinned {
            return Err(MpcError::Protocol(format!(
                "ecdh-relay cosigner master {} != pinned master {pinned} (#85 MITM)",
                parsed.master_pub_hex
            )));
        }
        let master_pub = decode_pubkey(pinned, "pinned master")?;
        let sig = {
            let b = hex::decode(&parsed.attestation_sig_hex).map_err(|e| {
                MpcError::Protocol(format!("ecdh-relay: bad attestation_sig_hex: {e}"))
            })?;
            let arr: [u8; 64] = b.as_slice().try_into().map_err(|_| {
                MpcError::Protocol("ecdh-relay: attestation sig must be 64 bytes".into())
            })?;
            arr
        };
        let digest_input: Vec<(u16, PublicKey, [u8; 32])> = partials
            .iter()
            .map(|p| (p.index, p.partial.clone(), p.vss_point))
            .collect();
        let digest = ecdh_partials_digest(&digest_input);
        if !verify_ecdh_partials_attestation(
            &master_pub,
            &arm.agent_id,
            counterparty_pub,
            nonce,
            &digest,
            &sig,
        ) {
            return Err(MpcError::Protocol(
                "ecdh-relay: #85 partial-set attestation failed against pinned master (MITM?)"
                    .into(),
            ));
        }
    }

    Ok(partials)
}
