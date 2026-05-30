//! BRC-42 key derivation for MPC shares.
//!
//! BSV wallets use BRC-42 key derivation (not BIP-32). BRC-42 derives child keys
//! using ECDH shared secrets and invoice numbers:
//!
//! ```text
//! shared_secret = ECDH(counterparty_pub, root_priv)
//! hmac = HMAC-SHA256(key=compressed(shared_secret), data=invoice_bytes)
//! child_pub = root_pub + G * hmac
//! child_priv = root_priv + hmac   (scalar addition mod n)
//! ```
//!
//! Invoice format: `"{security_level}-{protocol_name}-{key_id}"`
//!
//! ## Counterparty Types (proven in POC 3)
//!
//! | Counterparty | Shared Secret          | MPC Round-Trips |
//! |-------------|------------------------|-----------------|
//! | Anyone      | = root_pubkey          | 0 (local)       |
//! | Self_       | ECDH(root_pub, root_priv) | 1 (partial ECDH) |
//! | Other(key)  | ECDH(other_pub, root_priv) | 1 (partial ECDH) |
//!
//! For "Anyone", the counterparty private key is scalar 1, so:
//!   `ECDH(anyone_pub, root_priv) = G * root_priv = root_pubkey`
//!
//! For "Self_" and "Other", the proxy needs MPC cooperation (partial ECDH
//! with Lagrange interpolation) to compute the shared secret without
//! reconstructing the private key. See POC 3 and POC 8.
//!
//! ## BRC-42 Spec
//!
//! Full specification: ~/bsv/BRCs/key-derivation/0042.md
//! BSV SDK implementation: `bsv::wallet::KeyDeriver`

use crate::error::{MpcError, Result};
use crate::types::{JointPublicKey, SessionId};

use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv::primitives::hash::sha256_hmac;
use bsv::Address;
use cggmp24::supported_curves::Secp256k1;
use generic_ec::Scalar;
use sha2::{Digest, Sha256};

/// Derive a BRC-42 child public key from a shared secret and invoice number.
///
/// This is the core BRC-42 derivation math:
///   `child_pub = root_pub + G * HMAC-SHA256(compressed(shared_secret), invoice)`
///
/// The shared secret depends on the counterparty type:
/// - Anyone: `shared_secret = root_pubkey` (no private key needed)
/// - Self_: `shared_secret = ECDH(root_pub, root_priv)` (needs partial ECDH via MPC)
/// - Other(key): `shared_secret = ECDH(other_pub, root_priv)` (needs partial ECDH via MPC)
///
/// Proven in POC 3 (`derive_child_pubkey_manual`), POC 8, and POC 9.
///
/// # Arguments
///
/// * `root_pub` - The joint MPC public key (33 bytes compressed).
/// * `shared_secret` - The ECDH shared secret as a compressed public key (33 bytes).
/// * `invoice_number` - The BRC-42 invoice string, e.g. `"2-worm memory-block-42"`.
///
/// # Returns
///
/// The derived child public key.
pub fn derive_child_pubkey(
    root_pub: &PublicKey,
    shared_secret: &PublicKey,
    invoice_number: &str,
) -> Result<PublicKey> {
    // HMAC-SHA256(key=compressed(shared_secret), data=invoice_bytes)
    let hmac = sha256_hmac(&shared_secret.to_compressed(), invoice_number.as_bytes());

    // G * hmac — compute the offset point
    let offset_pub = PublicKey::from_scalar_mul_generator(&hmac)
        .map_err(|e| MpcError::Protocol(format!("BRC-42: failed to compute G * hmac: {}", e)))?;

    // child_pub = root_pub + offset_pub (point addition)
    let child_pub = root_pub
        .add(&offset_pub)
        .map_err(|e| MpcError::Protocol(format!("BRC-42: point addition failed: {}", e)))?;

    Ok(child_pub)
}

/// Compute the BRC-42 HMAC scalar (the "tweak") for share offset addition.
///
/// In MPC, each party adds this scalar to their private key share locally:
///   `child_share_i = share_i + hmac`
///
/// This is the additive share offset property proven in POC 8.
///
/// # Arguments
///
/// * `shared_secret` - The ECDH shared secret (33 bytes compressed pubkey).
/// * `invoice_number` - The BRC-42 invoice string.
///
/// # Returns
///
/// The 32-byte HMAC scalar that each MPC party adds to their share.
pub fn compute_brc42_hmac(shared_secret: &PublicKey, invoice_number: &str) -> [u8; 32] {
    sha256_hmac(&shared_secret.to_compressed(), invoice_number.as_bytes())
}

/// Build a BRC-42 invoice number string in canonical form.
///
/// Per BRC-42 §03.9 (and the cross-impl conformance gate at
/// `MPC-Spec/conformance/test-vectors/03-brc42-invoice.json`), the invoice
/// MUST be built from a CANONICALIZED protocol name and a VALIDATED key id —
/// otherwise two implementations given inputs differing only in case or
/// whitespace will derive DIFFERENT keys for what should be the same logical
/// derivation. Pre-2026-05-17 this function was a raw `format!` that skipped
/// validation entirely; every downstream caller was silently emitting
/// non-canonical invoices.
///
/// This function delegates to `bsv::wallet::types::validate_protocol_name` and
/// `bsv::wallet::types::validate_key_id` — the same canonical path that
/// `bsv-rs::wallet::KeyDeriver::compute_invoice_number` and every conformant
/// BSV SDK use. Output is byte-identical to those paths for any input they
/// accept. This is the cross-impl wire-compat floor for BRC-42 derivation
/// across the partnership.
///
/// Format: `"{security_level}-{canonical_protocol_name}-{key_id}"` where
/// `canonical_protocol_name = protocol_name.trim().to_lowercase()` with
/// format validation (5-400 chars, lowercase + digits + spaces only, no
/// consecutive spaces, no trailing " protocol").
///
/// Security levels (from BRC-42):
/// - 0 = No security
/// - 1 = App-level
/// - 2 = Counterparty-level (most common — used by bsv-worm)
///
/// Examples (post-canonicalization):
/// - `compute_invoice(2, "worm memory", "block-42")?` → `"2-worm memory-block-42"`
/// - `compute_invoice(2, "  WORM Memory  ", "block-42")?` → `"2-worm memory-block-42"` (canonicalized)
/// - `compute_invoice(2, "auth message signature", "request-nonce-abc123")?`
///   → `"2-auth message signature-request-nonce-abc123"`
///
/// # Errors
///
/// `MpcError::Protocol` if `security_level > 2`, `protocol_name` fails
/// `validate_protocol_name`, or `key_id` fails `validate_key_id`. The
/// error message includes the underlying bsv-rs validation detail.
///
/// Resolves [`MPC-Spec` issue #1] / [ADR-0002] (canonical BRC-42 invoice).
pub fn compute_invoice(security_level: u8, protocol_name: &str, key_id: &str) -> Result<String> {
    if security_level > 2 {
        return Err(MpcError::Protocol(format!(
            "BRC-42: security_level must be 0, 1, or 2 (got {})",
            security_level
        )));
    }
    bsv::wallet::types::validate_key_id(key_id)
        .map_err(|e| MpcError::Protocol(format!("BRC-42: invalid key_id: {}", e)))?;
    let canonical_name = bsv::wallet::types::validate_protocol_name(protocol_name)
        .map_err(|e| MpcError::Protocol(format!("BRC-42: invalid protocol_name: {}", e)))?;
    Ok(format!("{}-{}-{}", security_level, canonical_name, key_id))
}

/// Derive a child public key for the "Anyone" counterparty (0 MPC round-trips).
///
/// For "Anyone", the counterparty private key is scalar 1 (the "anyone key"),
/// so `ECDH(anyone_pub, root_priv) = G * root_priv = root_pubkey`.
/// The shared secret IS the root public key — no private key or MPC needed.
///
/// This is proven in POC 3, Test 1 (`test_anyone_counterparty_local_derivation`).
///
/// # Arguments
///
/// * `root_pub` - The joint MPC public key.
/// * `protocol_name` - BRC-42 protocol name (e.g., "worm memory").
/// * `key_id` - BRC-42 key ID (e.g., "block-42").
/// * `security_level` - BRC-42 security level (usually 2 for counterparty-level).
pub fn derive_anyone_pubkey(
    root_pub: &PublicKey,
    protocol_name: &str,
    key_id: &str,
    security_level: u8,
) -> Result<PublicKey> {
    // For "anyone": shared_secret = root_pubkey
    let invoice = compute_invoice(security_level, protocol_name, key_id)?;
    derive_child_pubkey(root_pub, root_pub, &invoice)
}

/// Derive a child JointPublicKey for the "Anyone" counterparty.
///
/// Convenience wrapper that returns a full `JointPublicKey` with BSV address.
pub fn derive_anyone_joint_key(
    joint_key: &JointPublicKey,
    protocol_name: &str,
    key_id: &str,
    security_level: u8,
) -> Result<JointPublicKey> {
    let root_pub = PublicKey::from_bytes(&joint_key.compressed)
        .map_err(|e| MpcError::InvalidShare(format!("invalid joint public key: {}", e)))?;

    let child_pub = derive_anyone_pubkey(&root_pub, protocol_name, key_id, security_level)?;
    pubkey_to_joint_key(&child_pub)
}

/// Derive a child JointPublicKey given a pre-computed shared secret.
///
/// Used after MPC partial ECDH has produced the shared secret for
/// Self_ or Other(key) counterparty types.
pub fn derive_joint_key_with_secret(
    joint_key: &JointPublicKey,
    shared_secret: &PublicKey,
    protocol_name: &str,
    key_id: &str,
    security_level: u8,
) -> Result<JointPublicKey> {
    let root_pub = PublicKey::from_bytes(&joint_key.compressed)
        .map_err(|e| MpcError::InvalidShare(format!("invalid joint public key: {}", e)))?;

    let invoice = compute_invoice(security_level, protocol_name, key_id)?;
    let child_pub = derive_child_pubkey(&root_pub, shared_secret, &invoice)?;
    pubkey_to_joint_key(&child_pub)
}

/// Domain-separation tag for the per-index DKG-relay ceremony identity.
///
/// Versioned (`v1`) so a future construction change is a distinct domain and
/// can never collide with keys minted under this one. Container-internal — this
/// string is NOT a cross-impl wire format (the derived *public* key crosses the
/// relay-fetch boundary, but the derivation itself is purely local to the
/// cosigner that holds `server_priv`).
const DKG_RELAY_IDENTITY_DOMAIN_V1: &[u8] = b"bsv-mpc dkg-relay identity v1";

/// Derive a **per-index, ceremony-scoped, one-way** relay identity private key
/// for a single keygen party that a cosigner drives in a genuine n-party DKG
/// over the MessageBox relay (ADR-0052 Model B, §06.22).
///
/// ```text
/// relay_priv_i = reduce_mod_n(
///     HMAC-SHA256(
///         key = server_priv_bytes,
///         msg = b"bsv-mpc dkg-relay identity v1" ‖ session_id(32) ‖ index_be_u16
///     )
/// )
/// ```
///
/// ## Why one-way HMAC and NOT additive (`server_priv + H(pub‖i)`)
///
/// A cosigner that holds 2+ keygen indices (the "two Notaries, one holds two"
/// topology) needs a DISTINCT relay identity per index so each party lands in
/// its own relay room (`{identity}-{box}`) and round messages route cleanly.
///
/// The tempting shortcut — an **additive** offset `relay_priv_i = server_priv +
/// H(pub‖i)` — is **catastrophic** and was rejected (PERSON-A-HANDOFF,
/// ADR-0052): the offset `H(pub‖i)` is public, so leaking ANY single
/// `relay_priv_i` immediately yields `server_priv = relay_priv_i − H(pub‖i)`.
/// And `server_priv` is *also* the BRC-31 transport-auth key and the BRC-2
/// share-sealing key — recovering it from one ephemeral relay key would defeat
/// auth and unseal every custody share at once.
///
/// This HMAC construction is **one-way**: `server_priv` is the HMAC *key*, so
/// no derived `relay_priv_i` (or set of them) reveals it. It is also
/// ceremony-scoped (binds `session_id`) and index-separated (binds `index`),
/// so identities never collide across ceremonies or indices.
///
/// Because the derivation is one-way, the **device cannot** recompute a
/// cosigner's relay public key — it fetches each one read-only from the
/// cosigner over `GET /dkg-relay/peer-identity?session&index` (a fetch the
/// `#85` hardening will authenticate).
///
/// # Arguments
/// * `server_priv` — the cosigner's enforced server identity key
///   (`MPC_SERVER_PRIVATE_KEY`). Used ONLY as the HMAC key; never transmitted.
/// * `session_id` — the canonical 64-char-hex DKG session id, shared across all
///   `n` parties of the ceremony (§04).
/// * `index` — this party's absolute keygen index in `[0, n)`.
///
/// # Errors
/// `MpcError::Protocol` only in the cryptographically-negligible case that the
/// reduced scalar is zero (≈ 2⁻²⁵⁶); the value is always reduced mod the
/// secp256k1 group order so it is otherwise a valid private key.
pub fn derive_relay_index_privkey(
    server_priv: &PrivateKey,
    session_id: &SessionId,
    index: u16,
) -> Result<PrivateKey> {
    let mut msg = Vec::with_capacity(DKG_RELAY_IDENTITY_DOMAIN_V1.len() + 32 + 2);
    msg.extend_from_slice(DKG_RELAY_IDENTITY_DOMAIN_V1);
    msg.extend_from_slice(session_id.as_bytes());
    msg.extend_from_slice(&index.to_be_bytes());

    // server_priv is the HMAC KEY (one-way): no derived key reveals it.
    let mac = sha256_hmac(&server_priv.to_bytes(), &msg);

    // Reduce mod n so the result is ALWAYS a valid scalar in [0, n) — the
    // ~2⁻¹²⁸ of raw HMAC outputs that land in [n, 2²⁵⁶) would otherwise be
    // rejected by PrivateKey::from_bytes, making derivation non-total.
    let reduced = Scalar::<Secp256k1>::from_be_bytes_mod_order(mac);
    let reduced_bytes = reduced.to_be_bytes();

    PrivateKey::from_bytes(reduced_bytes.as_bytes()).map_err(|e| {
        MpcError::Protocol(format!(
            "dkg-relay identity derivation produced an invalid scalar (zero key?): {e}"
        ))
    })
}

// ── #85 MITM gate: pinned-master identity ATTESTATION + liveness CHALLENGE ──────
//
// The device discovers a cosigner's per-(session,index) relay identity over an
// otherwise-unauthenticated GET (the per-index pub is a ONE-WAY HMAC of the master
// key, so the device cannot recompute it). A network MITM could substitute an
// attacker pub → the DKG co-holds the joint key with the attacker. The fix: the
// device PINS the cosigner's master identity out-of-band, the cosigner ATTESTS each
// relay pub with that master key, and the device VERIFIES every attestation against
// the PINNED master before routing a single round message — so it only ever
// federates with the intended Notary. A signed liveness CHALLENGE re-confirms the
// real master is live + controls its key before any sats move (the funding gate).

/// Domain tag for the relay-identity attestation signature (#85).
const RELAY_IDENTITY_ATTESTATION_DOMAIN_V1: &[u8] = b"bsv-mpc relay-identity attestation v1";
/// Domain tag for the cosigner liveness/funding challenge signature (#85).
const COSIGNER_CHALLENGE_DOMAIN_V1: &[u8] = b"bsv-mpc cosigner liveness challenge v1";

/// The canonical 32-byte message a cosigner's MASTER identity signs to ATTEST that
/// `relay_pub` is the genuine per-(session, index) relay identity it derived (#85).
/// Binds `master_pub ‖ session ‖ index ‖ relay_pub` under a domain tag, so an
/// attestation cannot be replayed across cosigners, sessions, or indices.
pub fn relay_identity_attestation_msg(
    master_pub: &PublicKey,
    session_id: &SessionId,
    index: u16,
    relay_pub: &PublicKey,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RELAY_IDENTITY_ATTESTATION_DOMAIN_V1);
    h.update(master_pub.to_compressed());
    h.update(session_id.as_bytes());
    h.update(index.to_be_bytes());
    h.update(relay_pub.to_compressed());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Sign a [`relay_identity_attestation_msg`] with the cosigner's MASTER identity
/// (RFC-6979 → deterministic, low-S). Returns the 64-byte compact `r ‖ s`.
pub fn sign_relay_identity_attestation(
    master_priv: &PrivateKey,
    session_id: &SessionId,
    index: u16,
    relay_pub: &PublicKey,
) -> Result<[u8; 64]> {
    let msg =
        relay_identity_attestation_msg(&master_priv.public_key(), session_id, index, relay_pub);
    let sig = master_priv
        .sign(&msg)
        .map_err(|e| MpcError::Protocol(format!("attestation sign: {e}")))?;
    let mut c = [0u8; 64];
    c[..32].copy_from_slice(sig.r());
    c[32..].copy_from_slice(sig.s());
    Ok(c)
}

/// Verify a relay-identity attestation against the PINNED master pub (#85). Returns
/// `true` ONLY if the pinned master signed exactly `(session, index, relay_pub)` —
/// a MITM-substituted `relay_pub`, a wrong master, or a malformed signature all fail
/// closed (`false`).
pub fn verify_relay_identity_attestation(
    master_pub: &PublicKey,
    session_id: &SessionId,
    index: u16,
    relay_pub: &PublicKey,
    sig_compact: &[u8; 64],
) -> bool {
    let msg = relay_identity_attestation_msg(master_pub, session_id, index, relay_pub);
    match Signature::from_compact(sig_compact) {
        Ok(sig) => master_pub.verify(&msg, &sig),
        Err(_) => false,
    }
}

/// The canonical 32-byte message a cosigner's MASTER identity signs to prove it is
/// LIVE and controls its key for a SPECIFIC wallet, before funding (#85 funding
/// gate). Binds `master_pub ‖ joint_pubkey ‖ nonce` — the device picks a fresh
/// `nonce`, so a captured signature cannot be replayed.
pub fn cosigner_challenge_msg(
    master_pub: &PublicKey,
    joint_pubkey_compressed: &[u8],
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COSIGNER_CHALLENGE_DOMAIN_V1);
    h.update(master_pub.to_compressed());
    h.update(joint_pubkey_compressed);
    h.update(nonce);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Sign a [`cosigner_challenge_msg`] with the MASTER identity. Returns 64-byte compact.
pub fn sign_cosigner_challenge(
    master_priv: &PrivateKey,
    joint_pubkey_compressed: &[u8],
    nonce: &[u8; 32],
) -> Result<[u8; 64]> {
    let msg = cosigner_challenge_msg(&master_priv.public_key(), joint_pubkey_compressed, nonce);
    let sig = master_priv
        .sign(&msg)
        .map_err(|e| MpcError::Protocol(format!("challenge sign: {e}")))?;
    let mut c = [0u8; 64];
    c[..32].copy_from_slice(sig.r());
    c[32..].copy_from_slice(sig.s());
    Ok(c)
}

/// Verify a cosigner liveness/funding challenge against the PINNED master pub (#85).
/// Fails closed on a wrong master, wrong wallet, replayed/altered nonce, or malformed sig.
pub fn verify_cosigner_challenge(
    master_pub: &PublicKey,
    joint_pubkey_compressed: &[u8],
    nonce: &[u8; 32],
    sig_compact: &[u8; 64],
) -> bool {
    let msg = cosigner_challenge_msg(master_pub, joint_pubkey_compressed, nonce);
    match Signature::from_compact(sig_compact) {
        Ok(sig) => master_pub.verify(&msg, &sig),
        Err(_) => false,
    }
}

// ── #90 distributed-ECDH partial-set attestation (#85 pin for the HTTP-direct
//    /ecdh-relay return) ───────────────────────────────────────────────────────
//
// The device fetches its `Self_`/`Other` BRC-42 derivation by asking a cosigner
// for `counterparty_pub * its_share(s)` over a single authed HTTP round-trip
// (#90, response-direct — ECDH has no presig/pool/multi-round semantics). Unlike
// the sign path (whose partial rides the BRC-31-authed MessageBox from the pinned
// relay identity), the ECDH partials come back in the HTTP RESPONSE BODY — so a
// network MITM could let a liveness challenge through yet SWAP the returned
// partials, steering the device to a WRONG derived key (→ funds to an address the
// attacker can derive). The fix mirrors the rest of #85: the cosigner's PINNED
// MASTER signs an attestation that BINDS the exact partial set it returned, and
// the device verifies it against the out-of-band-pinned master before combining a
// single partial. A MITM cannot forge the master's signature, and cannot reuse a
// genuine one for different partials / a different wallet / counterparty / nonce.

/// Domain tag for the ECDH partial-set attestation signature (#90 / #85).
const ECDH_PARTIALS_ATTESTATION_DOMAIN_V1: &[u8] = b"bsv-mpc ecdh-partials attestation v1";
/// Domain tag for the canonical ECDH partial-set digest (#90).
const ECDH_PARTIALS_DIGEST_DOMAIN_V1: &[u8] = b"bsv-mpc ecdh-partials digest v1";

/// Canonical 32-byte digest over a distributed-ECDH partial set. Each entry is
/// `(keygen_index, partial_point, vss_eval_point)`. The digest is order-INdependent
/// (entries are sorted by `index` ascending first), so the device and cosigner
/// agree regardless of wire order, and binds the EXACT bytes of every partial +
/// its paired VSS eval point. Layout per entry (after sort): `index` big-endian
/// u16 ‖ `partial.to_compressed()` (33) ‖ `vss_point` (32), under a domain tag and
/// a big-endian u16 count prefix.
pub fn ecdh_partials_digest(partials: &[(u16, PublicKey, [u8; 32])]) -> [u8; 32] {
    let mut sorted: Vec<&(u16, PublicKey, [u8; 32])> = partials.iter().collect();
    sorted.sort_by_key(|(idx, _, _)| *idx);

    let mut h = Sha256::new();
    h.update(ECDH_PARTIALS_DIGEST_DOMAIN_V1);
    h.update((sorted.len() as u16).to_be_bytes());
    for (idx, partial, vss_point) in sorted {
        h.update(idx.to_be_bytes());
        h.update(partial.to_compressed());
        h.update(vss_point);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// The canonical 32-byte message a cosigner's MASTER identity signs to ATTEST that
/// it returned exactly `partials_digest` for `(agent_id, counterparty_pub, nonce)`
/// (#90 / #85). Binds `master_pub ‖ agent_id ‖ counterparty_pub ‖ nonce ‖
/// partials_digest` under a domain tag, so an attestation cannot be replayed across
/// cosigners, wallets, counterparties, device nonces, or a substituted partial set.
pub fn ecdh_partials_attestation_msg(
    master_pub: &PublicKey,
    agent_id: &str,
    counterparty_pub: &PublicKey,
    nonce: &[u8; 32],
    partials_digest: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ECDH_PARTIALS_ATTESTATION_DOMAIN_V1);
    h.update(master_pub.to_compressed());
    // Length-prefix the variable-length agent_id so it can't be confused with the
    // fixed-width fields that follow (canonical-encoding hygiene).
    h.update((agent_id.len() as u32).to_be_bytes());
    h.update(agent_id.as_bytes());
    h.update(counterparty_pub.to_compressed());
    h.update(nonce);
    h.update(partials_digest);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Sign an [`ecdh_partials_attestation_msg`] with the cosigner's MASTER identity
/// (RFC-6979 → deterministic, low-S). Returns the 64-byte compact `r ‖ s`.
pub fn sign_ecdh_partials_attestation(
    master_priv: &PrivateKey,
    agent_id: &str,
    counterparty_pub: &PublicKey,
    nonce: &[u8; 32],
    partials_digest: &[u8; 32],
) -> Result<[u8; 64]> {
    let msg = ecdh_partials_attestation_msg(
        &master_priv.public_key(),
        agent_id,
        counterparty_pub,
        nonce,
        partials_digest,
    );
    let sig = master_priv
        .sign(&msg)
        .map_err(|e| MpcError::Protocol(format!("ecdh-partials attestation sign: {e}")))?;
    let mut c = [0u8; 64];
    c[..32].copy_from_slice(sig.r());
    c[32..].copy_from_slice(sig.s());
    Ok(c)
}

/// Verify an ECDH partial-set attestation against the PINNED master pub (#90 / #85).
/// Returns `true` ONLY if the pinned master signed exactly
/// `(agent_id, counterparty_pub, nonce, partials_digest)` — a MITM-swapped partial
/// set (different digest), a wrong master, a replayed nonce, a different wallet /
/// counterparty, or a malformed signature all fail closed (`false`).
pub fn verify_ecdh_partials_attestation(
    master_pub: &PublicKey,
    agent_id: &str,
    counterparty_pub: &PublicKey,
    nonce: &[u8; 32],
    partials_digest: &[u8; 32],
    sig_compact: &[u8; 64],
) -> bool {
    let msg = ecdh_partials_attestation_msg(
        master_pub,
        agent_id,
        counterparty_pub,
        nonce,
        partials_digest,
    );
    match Signature::from_compact(sig_compact) {
        Ok(sig) => master_pub.verify(&msg, &sig),
        Err(_) => false,
    }
}

/// Convert a PublicKey to a JointPublicKey with BSV address.
fn pubkey_to_joint_key(pubkey: &PublicKey) -> Result<JointPublicKey> {
    let compressed = pubkey.to_compressed().to_vec();
    let address = Address::new_from_public_key(pubkey, true)
        .map_err(|e| MpcError::InvalidShare(format!("failed to derive BSV address: {}", e)))?
        .to_string();
    Ok(JointPublicKey {
        compressed,
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::primitives::ec::PrivateKey;

    /// Known test key (same as POC 3 for consistency).
    fn test_root_key() -> (PrivateKey, PublicKey) {
        let privkey = PrivateKey::from_bytes(&[
            0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1,
            0xe2, 0xf3, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
            0xd0, 0xe1, 0xf2, 0x03,
        ])
        .expect("valid test private key");
        let pubkey = privkey.public_key();
        (privkey, pubkey)
    }

    fn test_joint_key() -> JointPublicKey {
        let (_, pubkey) = test_root_key();
        pubkey_to_joint_key(&pubkey).unwrap()
    }

    // -------------------------------------------------------------------
    // compute_invoice tests
    // -------------------------------------------------------------------

    #[test]
    fn test_invoice_format() {
        assert_eq!(
            compute_invoice(2, "worm memory", "block-42").unwrap(),
            "2-worm memory-block-42"
        );
    }

    // ── BRC-42 invoice canonicalization regression (M1 spec #1) ────────────
    //
    // Pre-fix `compute_invoice` was `format!("{}-{}-{}", ...)` with zero
    // input validation — uppercase, leading/trailing whitespace, double
    // spaces, and ` protocol` suffixes all passed through verbatim. The
    // canonical BRC-42 path (`bsv::wallet::types::validate_protocol_name`,
    // exercised by `bsv-rs::wallet::KeyDeriver::compute_invoice_number` and
    // every conformant SDK) applies `.trim().to_lowercase()` + format
    // validation BEFORE the format!. The pre-fix bug meant bsv-mpc derived
    // DIFFERENT keys than every other conformant SDK for inputs differing
    // only in case or whitespace — silent cross-impl drift, exactly the
    // class the partnership conformance gate is supposed to catch.
    //
    // These tests are the gate. They FAIL on pre-fix code; they PASS after
    // routing through `bsv::wallet::types::validate_protocol_name` and
    // `validate_key_id`. Both invariants — canonicalization AND rejection —
    // are asserted.

    #[test]
    fn compute_invoice_canonicalizes_uppercase_protocol_name() {
        // Pre-fix: returns "2-WORM MEMORY-block-42"
        // Post-fix: returns "2-worm memory-block-42" (matches bsv-rs canonical)
        assert_eq!(
            compute_invoice(2, "WORM MEMORY", "block-42").unwrap(),
            "2-worm memory-block-42",
            "BRC-42 §03.9: protocol_name MUST be lowercased before invoice format"
        );
    }

    #[test]
    fn compute_invoice_trims_protocol_name_whitespace() {
        assert_eq!(
            compute_invoice(2, "  worm memory  ", "block-42").unwrap(),
            "2-worm memory-block-42",
            "BRC-42 §03.9: protocol_name MUST be trimmed before invoice format"
        );
    }

    #[test]
    fn compute_invoice_canonicalizes_uppercase_and_whitespace_together() {
        assert_eq!(
            compute_invoice(2, "  WORM Memory  ", "block-42").unwrap(),
            "2-worm memory-block-42"
        );
    }

    #[test]
    fn compute_invoice_rejects_protocol_name_with_double_space() {
        // validate_protocol_name rejects this — bsv-rs canonical behavior.
        let err = compute_invoice(2, "worm  memory", "block-42").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("consecutive spaces") || msg.contains("protocol_name"),
            "expected double-space rejection, got: {msg}"
        );
    }

    #[test]
    fn compute_invoice_rejects_protocol_name_too_short() {
        // validate_protocol_name minimum: 5 chars.
        let err = compute_invoice(2, "wm", "block-42").unwrap_err();
        assert!(
            err.to_string().contains("5 characters") || err.to_string().contains("protocol_name"),
            "expected min-length rejection, got: {err}"
        );
    }

    #[test]
    fn compute_invoice_rejects_protocol_name_with_hyphen() {
        // validate_protocol_name: only lowercase + digits + spaces.
        let err = compute_invoice(2, "worm-memory", "block-42").unwrap_err();
        assert!(
            err.to_string().contains("lowercase letters")
                || err.to_string().contains("protocol_name"),
            "expected invalid-char rejection, got: {err}"
        );
    }

    #[test]
    fn compute_invoice_rejects_empty_key_id() {
        // validate_key_id minimum: 1 char.
        let err = compute_invoice(2, "worm memory", "").unwrap_err();
        assert!(
            err.to_string().contains("at least 1 character") || err.to_string().contains("key_id"),
            "expected empty-key_id rejection, got: {err}"
        );
    }

    #[test]
    fn compute_invoice_rejects_security_level_above_2() {
        let err = compute_invoice(3, "worm memory", "block-42").unwrap_err();
        assert!(
            err.to_string().contains("security_level"),
            "expected security-level rejection, got: {err}"
        );
    }

    #[test]
    fn compute_invoice_matches_bsv_rs_canonical_path() {
        // The canonical invoice format is what bsv-rs's KeyDeriver computes
        // internally. Our compute_invoice MUST produce byte-identical output
        // for any input that bsv-rs's path accepts. This locks cross-impl
        // wire-compat for BRC-42 derivation across the partnership.
        use bsv::wallet::types::{validate_key_id, validate_protocol_name};

        let cases = [
            (2u8, "worm memory", "block-42"),
            (2, "auth message signature", "request-nonce-abc123"),
            (2, "3241645161d8", "test-prefix test-suffix"),
            (0, "proto", "key"),
            (1, "proto", "key"),
        ];

        for (level, proto, key) in cases {
            // bsv-rs canonical path (what KeyDeriver::compute_invoice_number does)
            let canonical_proto = validate_protocol_name(proto).unwrap();
            validate_key_id(key).unwrap();
            let canonical_invoice = format!("{}-{}-{}", level, canonical_proto, key);

            let ours = compute_invoice(level, proto, key).unwrap();
            assert_eq!(
                ours, canonical_invoice,
                "bsv-mpc::compute_invoice MUST be byte-identical to the bsv-rs canonical \
                 path for input ({level}, {proto:?}, {key:?})"
            );
        }
    }

    #[test]
    fn test_invoice_auth_protocol() {
        assert_eq!(
            compute_invoice(2, "auth message signature", "request-nonce-abc123").unwrap(),
            "2-auth message signature-request-nonce-abc123"
        );
    }

    #[test]
    fn test_invoice_different_security_levels() {
        let inv0 = compute_invoice(0, "proto", "key").unwrap();
        let inv1 = compute_invoice(1, "proto", "key").unwrap();
        let inv2 = compute_invoice(2, "proto", "key").unwrap();
        assert_ne!(inv0, inv1);
        assert_ne!(inv1, inv2);
        assert_eq!(inv0, "0-proto-key");
    }

    // -------------------------------------------------------------------
    // compute_brc42_hmac tests
    // -------------------------------------------------------------------

    #[test]
    fn test_hmac_deterministic() {
        let (_, pubkey) = test_root_key();
        let h1 = compute_brc42_hmac(&pubkey, "2-test-key1");
        let h2 = compute_brc42_hmac(&pubkey, "2-test-key1");
        assert_eq!(h1, h2, "same inputs must produce same HMAC");
    }

    #[test]
    fn test_hmac_different_invoices() {
        let (_, pubkey) = test_root_key();
        let h1 = compute_brc42_hmac(&pubkey, "2-test-key1");
        let h2 = compute_brc42_hmac(&pubkey, "2-test-key2");
        assert_ne!(h1, h2, "different invoices must produce different HMACs");
    }

    #[test]
    fn test_hmac_different_secrets() {
        let (_, pubkey) = test_root_key();
        let other_priv = PrivateKey::from_bytes(&[0xaa; 32]).expect("valid key");
        let other_pub = other_priv.public_key();
        let h1 = compute_brc42_hmac(&pubkey, "2-test-key1");
        let h2 = compute_brc42_hmac(&other_pub, "2-test-key1");
        assert_ne!(
            h1, h2,
            "different shared secrets must produce different HMACs"
        );
    }

    // -------------------------------------------------------------------
    // derive_child_pubkey tests
    // -------------------------------------------------------------------

    #[test]
    fn test_derive_child_produces_different_key() {
        let (_, pubkey) = test_root_key();
        let child = derive_child_pubkey(&pubkey, &pubkey, "2-test-key1").unwrap();
        assert_ne!(
            pubkey.to_compressed(),
            child.to_compressed(),
            "child must differ from parent"
        );
    }

    #[test]
    fn test_derive_child_deterministic() {
        let (_, pubkey) = test_root_key();
        let c1 = derive_child_pubkey(&pubkey, &pubkey, "2-test-key1").unwrap();
        let c2 = derive_child_pubkey(&pubkey, &pubkey, "2-test-key1").unwrap();
        assert_eq!(
            c1.to_compressed(),
            c2.to_compressed(),
            "same inputs must produce same child"
        );
    }

    #[test]
    fn test_derive_child_different_invoices_differ() {
        let (_, pubkey) = test_root_key();
        let c1 = derive_child_pubkey(&pubkey, &pubkey, "2-test-key1").unwrap();
        let c2 = derive_child_pubkey(&pubkey, &pubkey, "2-test-key2").unwrap();
        assert_ne!(
            c1.to_compressed(),
            c2.to_compressed(),
            "different invoices must produce different children"
        );
    }

    #[test]
    fn test_derive_child_is_valid_pubkey() {
        let (_, pubkey) = test_root_key();
        let child = derive_child_pubkey(&pubkey, &pubkey, "2-test-key1").unwrap();
        // If it's a valid compressed pubkey, prefix must be 0x02 or 0x03
        let compressed = child.to_compressed();
        assert!(
            compressed[0] == 0x02 || compressed[0] == 0x03,
            "derived key must be valid compressed secp256k1 point"
        );
        assert_eq!(compressed.len(), 33);
    }

    // -------------------------------------------------------------------
    // derive_anyone — POC 3 Test 1 pattern
    // -------------------------------------------------------------------

    #[test]
    fn test_anyone_matches_bsv_sdk_key_deriver() {
        // This replicates POC 3 Test 1: "Anyone" counterparty local derivation.
        // The MPC proxy can derive this WITHOUT any private key.
        use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

        let (root_priv, root_pub) = test_root_key();

        // BSV SDK derivation (the "normal wallet" path)
        let deriver = KeyDeriver::new(Some(root_priv));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");
        let key_id = "test-prefix test-suffix";
        let wallet_derived = deriver
            .derive_public_key(&protocol, key_id, &Counterparty::Anyone, true)
            .expect("wallet derivation should work");

        // Our BRC-42 derivation (MPC proxy path — no private key!)
        let mpc_derived = derive_anyone_pubkey(&root_pub, "3241645161d8", key_id, 2).unwrap();

        assert_eq!(
            wallet_derived.to_compressed(),
            mpc_derived.to_compressed(),
            "MPC BRC-42 derivation must match BSV SDK KeyDeriver for Anyone"
        );
    }

    #[test]
    fn test_anyone_joint_key_has_address() {
        let jk = test_joint_key();
        let child = derive_anyone_joint_key(&jk, "worm memory", "block-42", 2).unwrap();
        assert!(!child.address.is_empty());
        assert_ne!(jk.address, child.address);
    }

    // -------------------------------------------------------------------
    // Self_ / Other — shared secret path (POC 3 Tests 2-5)
    // -------------------------------------------------------------------

    #[test]
    fn test_self_counterparty_with_known_secret() {
        // POC 3 Test 2: Self_ counterparty needs ECDH.
        // Here we simulate having already computed the shared secret.
        use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

        let (root_priv, root_pub) = test_root_key();

        // Normal wallet derivation
        let deriver = KeyDeriver::new(Some(root_priv.clone()));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");
        let key_id = "test-prefix test-suffix";
        let wallet_derived = deriver
            .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
            .expect("wallet derivation");

        // Compute the shared secret (in production, this comes from MPC partial ECDH)
        let shared_secret = root_priv
            .derive_shared_secret(&root_pub)
            .expect("ECDH self");

        // Our BRC-42 derivation with the pre-computed shared secret
        let invoice = compute_invoice(2, "3241645161d8", key_id).unwrap();
        let mpc_derived = derive_child_pubkey(&root_pub, &shared_secret, &invoice).unwrap();

        assert_eq!(
            wallet_derived.to_compressed(),
            mpc_derived.to_compressed(),
            "MPC BRC-42 derivation must match BSV SDK for Self_ when given correct shared secret"
        );
    }

    #[test]
    fn test_other_counterparty_with_known_secret() {
        // POC 3 Test 3: Other(server_pub) counterparty.
        use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

        let (root_priv, root_pub) = test_root_key();
        let server_priv = PrivateKey::from_bytes(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0x00, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x13,
            0x57, 0x9b, 0xdf, 0x02,
        ])
        .expect("valid server key");
        let server_pub = server_priv.public_key();

        // Normal wallet derivation
        let deriver = KeyDeriver::new(Some(root_priv.clone()));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");
        let key_id = "test-prefix test-suffix";
        let wallet_derived = deriver
            .derive_public_key(
                &protocol,
                key_id,
                &Counterparty::Other(server_pub.clone()),
                true,
            )
            .expect("wallet derivation");

        // Compute shared secret (in production, this comes from MPC partial ECDH)
        let shared_secret = root_priv
            .derive_shared_secret(&server_pub)
            .expect("ECDH other");

        // Our BRC-42 derivation
        let invoice = compute_invoice(2, "3241645161d8", key_id).unwrap();
        let mpc_derived = derive_child_pubkey(&root_pub, &shared_secret, &invoice).unwrap();

        assert_eq!(
            wallet_derived.to_compressed(),
            mpc_derived.to_compressed(),
            "MPC BRC-42 derivation must match BSV SDK for Other counterparty"
        );
    }

    #[test]
    fn test_worm_memory_protocol_self() {
        // POC 3 Test 4: worm memory protocol [2, "worm memory"] with Self_ counterparty
        use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

        let (root_priv, root_pub) = test_root_key();

        let deriver = KeyDeriver::new(Some(root_priv.clone()));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "worm memory");
        let key_id = "memory-block-42";
        let wallet_derived = deriver
            .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
            .expect("wallet derivation");

        let shared_secret = root_priv.derive_shared_secret(&root_pub).expect("ECDH");
        let invoice = compute_invoice(2, "worm memory", key_id).unwrap();
        let mpc_derived = derive_child_pubkey(&root_pub, &shared_secret, &invoice).unwrap();

        assert_eq!(
            wallet_derived.to_compressed(),
            mpc_derived.to_compressed(),
            "worm memory protocol must match"
        );
    }

    #[test]
    fn test_auth_message_signature_protocol() {
        // POC 3 Test 5: auth message signature with Other counterparty
        use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

        let (root_priv, root_pub) = test_root_key();
        let server_priv = PrivateKey::from_bytes(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0x00, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x13,
            0x57, 0x9b, 0xdf, 0x02,
        ])
        .expect("valid server key");
        let server_pub = server_priv.public_key();

        let deriver = KeyDeriver::new(Some(root_priv.clone()));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "auth message signature");
        let key_id = "request-nonce-abc123";
        let wallet_derived = deriver
            .derive_public_key(
                &protocol,
                key_id,
                &Counterparty::Other(server_pub.clone()),
                true,
            )
            .expect("wallet derivation");

        let shared_secret = root_priv.derive_shared_secret(&server_pub).expect("ECDH");
        let invoice = compute_invoice(2, "auth message signature", key_id).unwrap();
        let mpc_derived = derive_child_pubkey(&root_pub, &shared_secret, &invoice).unwrap();

        assert_eq!(
            wallet_derived.to_compressed(),
            mpc_derived.to_compressed(),
            "auth message signature must match"
        );
    }

    // -------------------------------------------------------------------
    // BRC-42 spec test vector (from POC 3 Test 6)
    // -------------------------------------------------------------------

    #[test]
    fn test_brc42_spec_vector_1() {
        // From BRC-42 specification test vectors.
        let sender_priv = PrivateKey::from_hex(
            "583755110a8c059de5cd81b8a04e1be884c46083ade3f779c1e022f6f89da94c",
        )
        .expect("valid sender key");
        let recipient_pub = PublicKey::from_hex(
            "02c0c1e1a1f7d247827d1bcf399f0ef2deef7695c322fd91a01a91378f101b6ffc",
        )
        .expect("valid recipient pubkey");
        let invoice_number = "IBioA4D/OaE=";
        let expected = PublicKey::from_hex(
            "03c1bf5baadee39721ae8c9882b3cf324f0bf3b9eb3fc1b8af8089ca7a7c2e669f",
        )
        .expect("valid expected pubkey");

        // Compute shared secret (sender_priv * recipient_pub)
        let shared_secret = sender_priv
            .derive_shared_secret(&recipient_pub)
            .expect("ECDH");

        // Our BRC-42 derivation
        let derived = derive_child_pubkey(&recipient_pub, &shared_secret, invoice_number).unwrap();

        assert_eq!(
            derived.to_compressed(),
            expected.to_compressed(),
            "must match BRC-42 spec test vector"
        );
    }

    // -------------------------------------------------------------------
    // derive_joint_key_with_secret tests
    // -------------------------------------------------------------------

    #[test]
    fn test_derive_joint_key_with_secret_has_valid_address() {
        let (root_priv, _) = test_root_key();
        let jk = test_joint_key();
        let root_pub = PublicKey::from_bytes(&jk.compressed).unwrap();
        let shared_secret = root_priv.derive_shared_secret(&root_pub).unwrap();

        // protocol_name was "test" (4 chars) — now rejected by canonical
        // validate_protocol_name which requires ≥ 5 chars. Use a valid
        // protocol_name that exercises the same path.
        let child = derive_joint_key_with_secret(&jk, &shared_secret, "tests", "key1", 2).unwrap();
        assert!(!child.address.is_empty());
        assert_eq!(child.compressed.len(), 33);
        assert_ne!(jk.address, child.address);
    }

    // -------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------

    #[test]
    fn test_invalid_joint_key_rejected() {
        let bad_jk = JointPublicKey {
            compressed: vec![0x04, 0x00], // invalid: wrong length and prefix
            address: "bad".to_string(),
        };
        let result = derive_anyone_joint_key(&bad_jk, "test", "key", 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_invoice_works() {
        // BRC-42 doesn't forbid empty invoices, though they're unusual
        let (_, pubkey) = test_root_key();
        let child = derive_child_pubkey(&pubkey, &pubkey, "").unwrap();
        assert_ne!(pubkey.to_compressed(), child.to_compressed());
    }

    #[test]
    fn test_long_invoice_works() {
        let (_, pubkey) = test_root_key();
        let long_invoice = "a".repeat(10000);
        let child = derive_child_pubkey(&pubkey, &pubkey, &long_invoice).unwrap();
        assert_ne!(pubkey.to_compressed(), child.to_compressed());
    }

    // -------------------------------------------------------------------
    // derive_relay_index_privkey — per-index, one-way, ceremony-scoped
    // DKG-relay identity (ADR-0052 Model B / §06.22). #69 PR-2 step 5a-i.
    //
    // These tests are the gate for the security property that killed the
    // ADDITIVE design (`relay_priv_i = server_priv + H(pub‖i)`, which leaks
    // server_priv — also the BRC-31 auth + BRC-2 sealing key — if any single
    // relay key leaks). The construction here is one-way (server_priv is the
    // HMAC key), index-separated, and ceremony-scoped. Positive + negative
    // (separation) invariants + a frozen wire-vector are all asserted.
    // -------------------------------------------------------------------

    fn relay_server_priv() -> PrivateKey {
        PrivateKey::from_bytes(&[0x11u8; 32]).expect("valid server priv")
    }

    fn relay_session() -> SessionId {
        SessionId::from_bytes([0x22u8; 32])
    }

    #[test]
    fn relay_index_privkey_is_deterministic() {
        let sp = relay_server_priv();
        let sess = relay_session();
        let a = derive_relay_index_privkey(&sp, &sess, 3).unwrap();
        let b = derive_relay_index_privkey(&sp, &sess, 3).unwrap();
        assert_eq!(
            a.to_bytes(),
            b.to_bytes(),
            "same (server_priv, session, index) MUST derive the same relay identity"
        );
    }

    #[test]
    fn relay_index_privkey_distinct_per_index() {
        // Domain-separation negative: a cosigner holding {3,4,5} MUST get three
        // DISTINCT relay identities → three distinct relay rooms. If two indices
        // collided their round messages would cross-deliver and the ceremony
        // would wedge ("no outgoing messages to bundle").
        let sp = relay_server_priv();
        let sess = relay_session();
        let k3 = derive_relay_index_privkey(&sp, &sess, 3).unwrap();
        let k4 = derive_relay_index_privkey(&sp, &sess, 4).unwrap();
        let k5 = derive_relay_index_privkey(&sp, &sess, 5).unwrap();
        assert_ne!(k3.to_bytes(), k4.to_bytes());
        assert_ne!(k4.to_bytes(), k5.to_bytes());
        assert_ne!(k3.to_bytes(), k5.to_bytes());
        // pubs distinct too — the relay routes by the identity *pubkey*.
        assert_ne!(
            k3.public_key().to_compressed(),
            k4.public_key().to_compressed()
        );
    }

    #[test]
    fn relay_index_privkey_index_endianness_is_be_u16() {
        // index is encoded big-endian u16: index 1 and index 256 (0x0100) differ
        // only in byte order — a little-endian bug would still produce distinct
        // keys but with swapped bytes, so distinctness AND the frozen vector
        // together pin BE. This asserts the distinctness half.
        let sp = relay_server_priv();
        let sess = relay_session();
        let k1 = derive_relay_index_privkey(&sp, &sess, 1).unwrap();
        let k256 = derive_relay_index_privkey(&sp, &sess, 256).unwrap();
        assert_ne!(k1.to_bytes(), k256.to_bytes());
    }

    #[test]
    fn relay_index_privkey_distinct_per_session() {
        // Ceremony-scoped: the same index in a different ceremony MUST be a
        // different identity (binds session_id → no cross-ceremony reuse).
        let sp = relay_server_priv();
        let a = derive_relay_index_privkey(&sp, &SessionId::from_bytes([0x22u8; 32]), 3).unwrap();
        let b = derive_relay_index_privkey(&sp, &SessionId::from_bytes([0x23u8; 32]), 3).unwrap();
        assert_ne!(
            a.to_bytes(),
            b.to_bytes(),
            "same index in different ceremonies MUST derive different identities"
        );
    }

    #[test]
    fn relay_index_privkey_is_one_way_distinct_from_server_priv() {
        // THE property that killed the additive design: the derived relay key
        // MUST NOT equal server_priv (the identity map). An additive offset
        // `server_priv + H(pub‖i)` lets a leaked relay key recover server_priv —
        // and server_priv is also the BRC-31 auth + BRC-2 sealing key. One-way
        // HMAC (server_priv = key) cannot be inverted from any derived key.
        let sp = relay_server_priv();
        let sess = relay_session();
        for idx in [0u16, 1, 3, 5, 42] {
            let k = derive_relay_index_privkey(&sp, &sess, idx).unwrap();
            assert_ne!(
                k.to_bytes(),
                sp.to_bytes(),
                "relay identity at index {idx} MUST NOT equal server_priv"
            );
        }
    }

    #[test]
    fn relay_index_privkey_keys_on_server_priv() {
        // Different server identity → different relay identity (server_priv is
        // the HMAC key). Two INDEPENDENT Notaries must never collide on a relay
        // identity for the same (session, index).
        let sp_a = PrivateKey::from_bytes(&[0x11u8; 32]).unwrap();
        let sp_b = PrivateKey::from_bytes(&[0x12u8; 32]).unwrap();
        let sess = relay_session();
        let a = derive_relay_index_privkey(&sp_a, &sess, 3).unwrap();
        let b = derive_relay_index_privkey(&sp_b, &sess, 3).unwrap();
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn relay_index_privkey_is_valid_secp256k1_key() {
        let sp = relay_server_priv();
        let sess = relay_session();
        let k = derive_relay_index_privkey(&sp, &sess, 3).unwrap();
        let pub_c = k.public_key().to_compressed();
        assert_eq!(pub_c.len(), 33);
        assert!(
            pub_c[0] == 0x02 || pub_c[0] == 0x03,
            "derived relay identity must be a valid compressed secp256k1 point"
        );
    }

    #[test]
    fn relay_index_privkey_frozen_vector() {
        // ZERO-DRIFT golden vector. Locks the EXACT construction: domain tag
        // b"bsv-mpc dkg-relay identity v1", then session(32), then index as
        // big-endian u16, HMAC keyed by server_priv bytes, reduced mod n. ANY
        // change to tag / field order / endianness flips this and fails.
        // Inputs: server_priv = [0x11;32], session = [0x22;32], index = 3.
        let sp = relay_server_priv();
        let sess = relay_session();
        let k = derive_relay_index_privkey(&sp, &sess, 3).unwrap();
        assert_eq!(
            hex::encode(k.to_bytes()),
            "f698e3016303f85f5358e07dbe9b23ae798182cf5d1c5bac93163f6afa40d72d",
            "DKG-relay identity derivation drifted from the frozen vector"
        );
    }

    // -------------------------------------------------------------------
    // #85 MITM gate — pinned-master relay-identity ATTESTATION + liveness
    // CHALLENGE. The device PINS the cosigner master out-of-band and verifies
    // every fetched relay pub against it, so a MITM-substituted identity fails
    // closed. Positive round-trip + NEGATIVE (wrong master / tampered field /
    // replay) + frozen zero-drift vectors.
    // -------------------------------------------------------------------

    /// The realistic per-index relay pub the master attests to (derived, deterministic).
    fn attested_relay_pub(index: u16) -> PublicKey {
        derive_relay_index_privkey(&relay_server_priv(), &relay_session(), index)
            .unwrap()
            .public_key()
    }

    #[test]
    fn attestation_roundtrips_and_rejects_mitm() {
        let master = relay_server_priv();
        let master_pub = master.public_key();
        let sess = relay_session();
        let relay_pub = attested_relay_pub(3);

        let sig = sign_relay_identity_attestation(&master, &sess, 3, &relay_pub).unwrap();
        // Positive: the pinned master verifies its own attestation.
        assert!(verify_relay_identity_attestation(
            &master_pub,
            &sess,
            3,
            &relay_pub,
            &sig
        ));

        // NEGATIVE 1 — wrong master (the MITM's key): an attacker who returns a
        // different (or its own) pub is NOT the pinned master → fails closed.
        let attacker = PrivateKey::from_bytes(&[0x99u8; 32]).unwrap().public_key();
        assert!(
            !verify_relay_identity_attestation(&attacker, &sess, 3, &relay_pub, &sig),
            "an attestation MUST NOT verify under a non-pinned master"
        );

        // NEGATIVE 2 — tampered relay_pub (MITM swaps the routed identity): the
        // signature was over the genuine pub, so the swap fails closed.
        let mitm_pub = attested_relay_pub(4);
        assert!(
            !verify_relay_identity_attestation(&master_pub, &sess, 3, &mitm_pub, &sig),
            "a substituted relay_pub MUST fail the attestation"
        );

        // NEGATIVE 3/4 — wrong index / wrong session (replay across slots).
        assert!(!verify_relay_identity_attestation(
            &master_pub,
            &sess,
            4,
            &relay_pub,
            &sig
        ));
        let other_sess = SessionId::from_bytes([0x77u8; 32]);
        assert!(!verify_relay_identity_attestation(
            &master_pub,
            &other_sess,
            3,
            &relay_pub,
            &sig
        ));

        // NEGATIVE 5 — malformed signature bytes fail closed (never panic).
        assert!(!verify_relay_identity_attestation(
            &master_pub,
            &sess,
            3,
            &relay_pub,
            &[0u8; 64]
        ));
    }

    #[test]
    fn challenge_roundtrips_and_rejects_replay() {
        let master = relay_server_priv();
        let master_pub = master.public_key();
        let joint = vec![0x02u8; 33];
        let nonce = [0x5au8; 32];

        let sig = sign_cosigner_challenge(&master, &joint, &nonce).unwrap();
        assert!(verify_cosigner_challenge(&master_pub, &joint, &nonce, &sig));

        // Wrong master (MITM): fails.
        let attacker = PrivateKey::from_bytes(&[0x88u8; 32]).unwrap().public_key();
        assert!(!verify_cosigner_challenge(&attacker, &joint, &nonce, &sig));
        // Replayed/altered nonce: fails (binds the fresh device nonce).
        assert!(!verify_cosigner_challenge(
            &master_pub,
            &joint,
            &[0x5bu8; 32],
            &sig
        ));
        // Wrong wallet (different joint pubkey): fails.
        assert!(!verify_cosigner_challenge(
            &master_pub,
            &[0x03u8; 33],
            &nonce,
            &sig
        ));
        // Malformed sig: fails closed.
        assert!(!verify_cosigner_challenge(
            &master_pub,
            &joint,
            &nonce,
            &[0u8; 64]
        ));
    }

    #[test]
    fn attestation_and_challenge_frozen_vectors() {
        // ZERO-DRIFT vectors. RFC-6979 makes the signatures deterministic, so the
        // exact bytes are frozen. Inputs: master = [0x11;32], session = [0x22;32],
        // index = 3, relay_pub = derived per-index pub; challenge joint = [0x02;33],
        // nonce = [0x5a;32]. ANY change to a domain tag / field order / encoding
        // flips these.
        let master = relay_server_priv();
        let sess = relay_session();
        let relay_pub = attested_relay_pub(3);

        let att_msg = relay_identity_attestation_msg(&master.public_key(), &sess, 3, &relay_pub);
        assert_eq!(
            hex::encode(att_msg),
            "cf87953527fca68195345eb081128b40f166ff7f0842d01d169c1c9861c014e8",
            "attestation message preimage drifted"
        );
        let att_sig = sign_relay_identity_attestation(&master, &sess, 3, &relay_pub).unwrap();
        assert_eq!(
            hex::encode(att_sig),
            "686f7f8d3dcf01f8066ae5a60c08b48705e58e2105e21f9de86eaedafe559a06\
             4632a08176aba25986febce2ac73a85e80d17a3c1a54a0ecb96a83dea5fd8432",
            "attestation signature drifted"
        );
        assert!(verify_relay_identity_attestation(
            &master.public_key(),
            &sess,
            3,
            &relay_pub,
            &att_sig
        ));

        let joint = vec![0x02u8; 33];
        let nonce = [0x5au8; 32];
        let ch_msg = cosigner_challenge_msg(&master.public_key(), &joint, &nonce);
        assert_eq!(
            hex::encode(ch_msg),
            "46cd4923ce91150d41929ed436456b872a36048c82314ee2a0ede00a457bcee4",
            "challenge message preimage drifted"
        );
        let ch_sig = sign_cosigner_challenge(&master, &joint, &nonce).unwrap();
        assert_eq!(
            hex::encode(ch_sig),
            "cece1794fb42fbc731b896ee0380491a9a9461acb0794d5e5e96ada500f6298e\
             64251191b7416e0b5cf59b32103cada690ed77cf03441be74923e8862b18b348",
            "challenge signature drifted"
        );
        assert!(verify_cosigner_challenge(
            &master.public_key(),
            &joint,
            &nonce,
            &ch_sig
        ));
    }

    // -------------------------------------------------------------------
    // #90 ECDH partial-set attestation (#85 pin for the HTTP-direct
    // /ecdh-relay return). The cosigner's pinned master BINDS the exact
    // partial set it returned; the device verifies before combining. Positive
    // round-trip + NEGATIVE (wrong master / swapped partial / replayed nonce /
    // wrong counterparty / wrong wallet / malformed sig) + frozen zero-drift.
    // -------------------------------------------------------------------

    /// A realistic counterparty pubkey (the `Other`/`Self_` ECDH peer).
    fn ecdh_counterparty_pub() -> PublicKey {
        PrivateKey::from_bytes(&[0x33u8; 32]).unwrap().public_key()
    }

    /// A realistic partial set: two `(index, partial_point, vss_point)` entries.
    fn ecdh_partials() -> Vec<(u16, PublicKey, [u8; 32])> {
        vec![
            (3, attested_relay_pub(3), [0x01u8; 32]),
            (4, attested_relay_pub(4), [0x02u8; 32]),
        ]
    }

    #[test]
    fn ecdh_partials_digest_is_order_independent() {
        let a = ecdh_partials();
        let mut b = a.clone();
        b.reverse();
        assert_eq!(
            ecdh_partials_digest(&a),
            ecdh_partials_digest(&b),
            "digest MUST be independent of wire order (sorted by index)"
        );
    }

    #[test]
    fn ecdh_partials_digest_changes_on_any_field() {
        let base = ecdh_partials_digest(&ecdh_partials());
        // swapped partial point
        let mut p = ecdh_partials();
        p[0].1 = attested_relay_pub(5);
        assert_ne!(
            base,
            ecdh_partials_digest(&p),
            "partial swap MUST change digest"
        );
        // changed vss point
        let mut p = ecdh_partials();
        p[1].2 = [0x09u8; 32];
        assert_ne!(
            base,
            ecdh_partials_digest(&p),
            "vss change MUST change digest"
        );
        // changed index
        let mut p = ecdh_partials();
        p[0].0 = 2;
        assert_ne!(
            base,
            ecdh_partials_digest(&p),
            "index change MUST change digest"
        );
    }

    #[test]
    fn ecdh_attestation_roundtrips_and_rejects_mitm() {
        let master = relay_server_priv();
        let master_pub = master.public_key();
        let agent_id = "02c709186cbe1ac811a2f7eb39e17dfeeca4ce7465f009592d300494df981cc32f";
        let cp = ecdh_counterparty_pub();
        let nonce = [0x5au8; 32];
        let digest = ecdh_partials_digest(&ecdh_partials());

        let sig = sign_ecdh_partials_attestation(&master, agent_id, &cp, &nonce, &digest).unwrap();
        // Positive: the pinned master verifies its own attestation.
        assert!(verify_ecdh_partials_attestation(
            &master_pub,
            agent_id,
            &cp,
            &nonce,
            &digest,
            &sig
        ));

        // NEGATIVE 1 — wrong master (the MITM's key) fails closed.
        let attacker = PrivateKey::from_bytes(&[0x99u8; 32]).unwrap().public_key();
        assert!(
            !verify_ecdh_partials_attestation(&attacker, agent_id, &cp, &nonce, &digest, &sig),
            "an attestation MUST NOT verify under a non-pinned master"
        );

        // NEGATIVE 2 — MITM swaps the partial set (different digest) fails closed.
        let mut swapped = ecdh_partials();
        swapped[0].1 = attested_relay_pub(5);
        let swapped_digest = ecdh_partials_digest(&swapped);
        assert!(
            !verify_ecdh_partials_attestation(
                &master_pub,
                agent_id,
                &cp,
                &nonce,
                &swapped_digest,
                &sig
            ),
            "a substituted partial set MUST fail the attestation"
        );

        // NEGATIVE 3 — replayed/altered device nonce fails closed.
        assert!(!verify_ecdh_partials_attestation(
            &master_pub,
            agent_id,
            &cp,
            &[0x5bu8; 32],
            &digest,
            &sig
        ));

        // NEGATIVE 4 — different counterparty (cross-derivation replay) fails closed.
        let other_cp = PrivateKey::from_bytes(&[0x44u8; 32]).unwrap().public_key();
        assert!(!verify_ecdh_partials_attestation(
            &master_pub,
            agent_id,
            &other_cp,
            &nonce,
            &digest,
            &sig
        ));

        // NEGATIVE 5 — different wallet (cross-wallet replay) fails closed.
        assert!(!verify_ecdh_partials_attestation(
            &master_pub,
            "03deadbeef",
            &cp,
            &nonce,
            &digest,
            &sig
        ));

        // NEGATIVE 6 — malformed signature bytes fail closed (never panic).
        assert!(!verify_ecdh_partials_attestation(
            &master_pub,
            agent_id,
            &cp,
            &nonce,
            &digest,
            &[0u8; 64]
        ));
    }

    #[test]
    fn ecdh_attestation_frozen_vectors() {
        // ZERO-DRIFT. RFC-6979 → deterministic signature. Inputs: master =
        // [0x11;32], agent_id = the fixed hex below, counterparty = pub([0x33;32]),
        // nonce = [0x5a;32], partials = ecdh_partials(). ANY change to a domain tag /
        // field order / encoding flips these.
        let master = relay_server_priv();
        let agent_id = "02c709186cbe1ac811a2f7eb39e17dfeeca4ce7465f009592d300494df981cc32f";
        let cp = ecdh_counterparty_pub();
        let nonce = [0x5au8; 32];
        let digest = ecdh_partials_digest(&ecdh_partials());
        assert_eq!(
            hex::encode(digest),
            "ca6f2799624f810d3ef2e3658aacffa9504ede057c24dc49fa066d85d07e5635",
            "ecdh partials digest drifted"
        );
        let msg =
            ecdh_partials_attestation_msg(&master.public_key(), agent_id, &cp, &nonce, &digest);
        assert_eq!(
            hex::encode(msg),
            "84c013d0d1d3394c2258562dcccbbbd3cab35d5109b8a448581c1928844a25a3",
            "ecdh attestation message preimage drifted"
        );
        let sig = sign_ecdh_partials_attestation(&master, agent_id, &cp, &nonce, &digest).unwrap();
        assert_eq!(
            hex::encode(sig),
            "828de750286a57ab7174ec5ecf25cec4c2cf50c560407505278816e1bd15aad0\
             1d8f508381b7003553a257026cbe1a91b7cf242619d69613dea9008ffdee5000",
            "ecdh attestation signature drifted"
        );
        assert!(verify_ecdh_partials_attestation(
            &master.public_key(),
            agent_id,
            &cp,
            &nonce,
            &digest,
            &sig
        ));
    }
}
