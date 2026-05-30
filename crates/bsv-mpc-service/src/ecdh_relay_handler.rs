//! Native **`/ecdh-relay`** executor — the #90 distributed-ECDH partial round,
//! run by the deployed **CF Container** cosigner.
//!
//! BRC-42 `Self_`/`Other` key derivation needs the ECDH shared secret
//! `counterparty_pub * root_priv`, but `root_priv` is split across MPC shares and
//! must NEVER be reconstructed. Each party instead returns a *partial*
//! `counterparty_pub * its_share_scalar`; the device Lagrange-combines `t` of them
//! into the full shared secret (`bsv_mpc_core::ecdh`, POC 3 / 9, SDK-validated).
//!
//! This is the cosigner half: for each held keygen index the container loads its
//! durable composite share `{agent_id}#{index}`, computes that party's partial +
//! its VSS eval point, and (unlike the sign path, whose partial rides the authed
//! MessageBox from the pinned relay identity) returns them in the HTTP RESPONSE
//! BODY (#90 chose response-direct — ECDH is single-shot, no presig/pool). To keep
//! that response MITM-safe, the container's PINNED master ATTESTS the exact partial
//! set (`bsv_mpc_core::hd::sign_ecdh_partials_attestation`); the device verifies it
//! against the out-of-band-pinned master before combining (#85).
//!
//! This module is the PURE crypto half (no I/O, unit-testable); the route layer
//! [`crate::relay_handlers::handle_ecdh_relay`] does BRC-31 auth, §08.1 per-index
//! owner-authz, and the durable share-load before calling in.

use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv_mpc_core::ecdh::{compute_partial_ecdh_point, parse_share_scalar, parse_share_vss_points};
use bsv_mpc_core::hd::{ecdh_partials_digest, sign_ecdh_partials_attestation};

/// One returned partial: `counterparty_pub * share(index)` + the VSS eval point
/// `I[index]` the device pairs with it for Lagrange interpolation.
pub struct EcdhPartialOut {
    pub index: u16,
    pub partial: PublicKey,
    pub vss_point: [u8; 32],
}

/// The full `/ecdh-relay` result: the per-index partials + the #85 master
/// attestation binding the whole set.
pub struct EcdhRelayOutcome {
    pub partials: Vec<EcdhPartialOut>,
    /// The cosigner's MASTER identity pubkey hex (the device verifies this equals
    /// its out-of-band pin).
    pub master_pub_hex: String,
    /// 64-byte compact attestation over `(master, agent_id, counterparty_pub,
    /// nonce, partials_digest)`, hex.
    pub attestation_sig_hex: String,
}

/// Compute this cosigner's partial ECDH point per held index + the #85 attestation
/// binding the set. PURE — no network, no storage. `shares[k] = (keygen_index,
/// cggmp24 KeyShare JSON)`, where the JSON is `EncryptedShare.ciphertext` (the raw
/// share the device unseals/loads). The eval point for party `index` is `I[index]`
/// from that share's VSS setup.
pub fn issue_ecdh_partials(
    master_priv: &PrivateKey,
    agent_id: &str,
    counterparty_pub: &PublicKey,
    nonce: &[u8; 32],
    shares: &[(u16, Vec<u8>)],
) -> anyhow::Result<EcdhRelayOutcome> {
    if shares.is_empty() {
        anyhow::bail!("no shares to compute ECDH partials for");
    }

    let mut partials = Vec::with_capacity(shares.len());
    for (index, share_json) in shares {
        let scalar = parse_share_scalar(share_json)
            .map_err(|e| anyhow::anyhow!("parse share scalar (index {index}): {e}"))?;
        let vss_points = parse_share_vss_points(share_json)
            .map_err(|e| anyhow::anyhow!("parse VSS points (index {index}): {e}"))?;
        // Party `index`'s eval point is `I[index]` — the point its scalar
        // `f(I[index])` evaluates the secret-sharing polynomial at.
        let eval_point = *vss_points.get(*index as usize).ok_or_else(|| {
            anyhow::anyhow!(
                "keygen index {index} out of range for {} VSS eval points",
                vss_points.len()
            )
        })?;
        let partial = compute_partial_ecdh_point(counterparty_pub, &scalar)
            .map_err(|e| anyhow::anyhow!("partial ECDH (index {index}): {e}"))?;
        partials.push(EcdhPartialOut {
            index: *index,
            partial,
            vss_point: eval_point,
        });
    }

    // #85: bind the EXACT partial set to the pinned master so the HTTP-direct
    // response is MITM-verifiable by the device before it combines.
    let digest_input: Vec<(u16, PublicKey, [u8; 32])> = partials
        .iter()
        .map(|p| (p.index, p.partial.clone(), p.vss_point))
        .collect();
    let digest = ecdh_partials_digest(&digest_input);
    let sig =
        sign_ecdh_partials_attestation(master_priv, agent_id, counterparty_pub, nonce, &digest)
            .map_err(|e| anyhow::anyhow!("ecdh-partials attestation sign: {e}"))?;

    Ok(EcdhRelayOutcome {
        partials,
        master_pub_hex: master_priv.public_key().to_hex(),
        attestation_sig_hex: hex::encode(sig),
    })
}
