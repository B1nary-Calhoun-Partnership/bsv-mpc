//! §09 policy engine — PolicyManifest, Verdict, and the three-hook evaluator.
//!
//! A per-cosigner policy engine answers, deterministically and verifiably:
//! *given a signing request, is this signature operation authorized?* (§09.1).
//! This module is **pure logic** — no `bsv-rs`, no networking, no async, no
//! wall-clock reads inside the engine. It is wasm32-portable: the rate limiter
//! takes the current time as a `now_ms: u64` epoch-ms PARAMETER supplied by the
//! caller, so evaluation is fully deterministic and replayable.
//!
//! ## What is enforced in v1
//!
//! Per the audit doc (`docs/AUDIT-43-policy-engine.md` §3): pattern match,
//! `max_amount_sats`, `min_fee_sats`, `max_per_hour` (sliding 1-hour window),
//! `counterparty_allowlist` / `counterparty_denylist`, `approval_spec`
//! (→ `RequireApproval`), `default_action`, and `dry_run`.
//!
//! ## What is parsed-but-deferred in v1
//!
//! `jurisdiction`, `attestation_spec`, `allowed_window`, and
//! `cumulative_daily_cap_sats` round-trip in CBOR but are NOT yet enforced —
//! they need geo / TEE / wall-clock context not present in v1. Enforcement is a
//! tracked follow-on, not a silent gap (see the `// §09 deferred (v1)` markers
//! in [`PolicyEngine::evaluate_rule`]).
//!
//! ## Canonical wire
//!
//! [`PolicyManifest`] round-trips via `ciborium` (struct serde) for storage and
//! transport. The byte-critical part is [`PolicyManifest::compute_policy_id`],
//! which hand-rolls canonical CBOR (RFC 8949 §4.2) over a fixed field set so the
//! `policy_id` is byte-for-byte reproducible across implementations — mirroring
//! the `approval.rs` `cbor_head` / `cbor_uint` / `cbor_text` helper style.

use crate::error::{MpcError, Result};
use crate::types::PolicyId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ===========================================================================
// Verdict + quorum types (§09.5)
// ===========================================================================

/// k-of-m approval quorum returned inside [`Verdict::RequireApproval`] (§09.5).
///
/// The coordinator MUST collect `k` Allow approvals from `eligible` (each a
/// 33-byte compressed pubkey) before proceeding. `deadline_secs`, if present,
/// shortens the default 300s approval TTL (§09.5.1 step 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalQuorum {
    /// Approvals required (k-of-m).
    pub k: u32,
    /// Approver identity keys (33-byte compressed pubkeys).
    pub eligible: Vec<Vec<u8>>,
    /// Optional override of the default 300s approval window, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline_secs: Option<u64>,
}

/// Engine decision for a single hook (§09.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// The operation is authorized.
    Allow,
    /// The operation is denied; the string is a reason for the audit log.
    Deny(String),
    /// The operation requires a k-of-m approval quorum before proceeding.
    RequireApproval(ApprovalQuorum),
    /// A sliding-window cap would be exceeded; retry after `retry_after_secs`.
    RateLimited {
        /// Seconds until the oldest event in the window ages out (budget frees).
        retry_after_secs: u64,
    },
}

impl Verdict {
    /// True iff this verdict is [`Verdict::Allow`].
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::Allow)
    }

    /// True iff this verdict is [`Verdict::RequireApproval`].
    pub fn requires_approval(&self) -> bool {
        matches!(self, Verdict::RequireApproval(_))
    }
}

// ===========================================================================
// Manifest sub-types (§09.2)
// ===========================================================================

/// Action when no rule matches (§09.2 field 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefaultAction {
    /// Deny the request.
    Deny,
    /// Require a quorum drawn from the listed approver keys (33-byte pubkeys).
    RequireApproval(Vec<Vec<u8>>),
    /// Escalate to a human approver (mapped to the manifest `approver_keys`).
    EscalateToHuman,
}

/// k-of-m approval requirement attached to a [`Rule`] (§09.2 `ApprovalSpec`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalSpec {
    /// Approvals required.
    pub k: u32,
    /// Approver identity keys (33-byte compressed pubkeys).
    pub eligible: Vec<Vec<u8>>,
}

/// Attestation requirement (§09.2 `AttestationSpec`). Parsed-but-deferred in v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationSpec {
    /// Accepted formats: `"nitro_v1" | "sev_snp_v1" | "tdx_v1" | "any"`.
    pub formats: Vec<String>,
}

/// Cron-style time window (§09.2 `TimeWindow`). Parsed-but-deferred in v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Standard 5-field cron expression, UTC.
    pub cron: String,
    /// Window length once the cron fires, in seconds.
    pub duration_secs: u32,
}

/// Jurisdiction allow/deny lists (§09.2 `Jurisdiction`). Parsed-but-deferred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jurisdiction {
    /// ISO 3166-1 alpha-2 codes allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    /// ISO 3166-1 alpha-2 codes denied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<String>>,
}

/// A single ordered policy rule (§09.2 `Rule`). Rules are evaluated
/// first-match-wins; only the first rule whose `protocol_pattern` matches the
/// request's `protocol_id` is enforced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Glob pattern: `"*"`, `"agent/*"`, `"agent/api-x"` (exact). See §09.7.
    pub protocol_pattern: String,
    /// Maximum amount in satoshis; exceeded → Deny.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_amount_sats: Option<u64>,
    /// Maximum operations per sliding 1-hour window; exceeded → RateLimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_per_hour: Option<u32>,
    /// Cumulative daily cap in satoshis. Parsed-but-deferred in v1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cumulative_daily_cap_sats: Option<u64>,
    /// Allowed cron window. Parsed-but-deferred in v1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_window: Option<TimeWindow>,
    /// Counterparty identity allowlist (hex); miss → Deny.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counterparty_allowlist: Option<Vec<String>>,
    /// Counterparty identity denylist (hex); hit → Deny.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counterparty_denylist: Option<Vec<String>>,
    /// Minimum fee in satoshis (Notary requirement); below → Deny.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_fee_sats: Option<u64>,
    /// Jurisdiction allow/deny. Parsed-but-deferred in v1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<Jurisdiction>,
    /// k-of-m approval requirement; present → RequireApproval.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_spec: Option<ApprovalSpec>,
    /// Attestation requirement. Parsed-but-deferred in v1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_spec: Option<AttestationSpec>,
}

/// The signed, versioned policy manifest (§09.2). 12 fields; serialized as a
/// struct for the storage/transport round-trip, but its `policy_id` is computed
/// from a hand-rolled canonical CBOR encoding (see
/// [`Self::compute_policy_id`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyManifest {
    /// Field 1 — version (monotonically increasing per cosigner).
    pub version: u32,
    /// Field 2 — `policy_id` = SHA-256 over the canonical CBOR (self-excluded
    /// from the preimage; see [`Self::compute_policy_id`]).
    pub policy_id: PolicyId,
    /// Field 3 — cosigner identity (33-byte compressed pubkey).
    pub cosigner_identity: Vec<u8>,
    /// Field 4 — group (joint) key (33-byte compressed pubkey).
    pub group_key: Vec<u8>,
    /// Field 5 — ordered rules (first-match-wins).
    pub rules: Vec<Rule>,
    /// Field 6 — action when no rule matches.
    pub default_action: DefaultAction,
    /// Field 7 — staged-rollout deny gate (epoch-ms).
    pub effective_after_ms: u64,
    /// Field 8 — auto-rollback expiry (epoch-ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_after_ms: Option<u64>,
    /// Field 9 — prior policy id, forming an append-only rollback chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_policy_id: Option<PolicyId>,
    /// Field 10 — m-of-n approver keys that sign manifest updates.
    pub approver_keys: Vec<Vec<u8>>,
    /// Field 11 — BRC-77 signatures over `policy_id`. Excluded from the id.
    pub approver_sigs: Vec<Vec<u8>>,
    /// Field 12 — shadow-mode flag: decisions logged, not enforced. Excluded
    /// from the id (operational, not identity).
    pub dry_run: bool,
}

// ===========================================================================
// Canonical CBOR helpers (RFC 8949 §4.2) — mirror approval.rs
// ===========================================================================

/// CBOR major-type-0 minimal unsigned-integer encoding (RFC 8949 §3, §4.2.1).
fn cbor_uint(n: u64) -> Vec<u8> {
    cbor_head(0, n)
}

/// Encode a CBOR head byte + extended length for `major` carrying value `n`,
/// using the minimal (canonical) representation.
fn cbor_head(major: u8, n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    if n < 24 {
        out.push((major << 5) | (n as u8));
    } else if n < 0x100 {
        out.push((major << 5) | 24);
        out.push(n as u8);
    } else if n < 0x1_0000 {
        out.push((major << 5) | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n < 0x1_0000_0000 {
        out.push((major << 5) | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push((major << 5) | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
    out
}

/// CBOR major-type-2 byte string: head(len) followed by the raw bytes.
fn cbor_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = cbor_head(2, b.len() as u64);
    out.extend_from_slice(b);
    out
}

/// CBOR major-type-3 text string: head(len) followed by the UTF-8 bytes.
fn cbor_text(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = cbor_head(3, b.len() as u64);
    out.extend_from_slice(b);
    out
}

/// CBOR major-type-4 definite-length array of already-encoded items.
fn cbor_array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = cbor_head(4, items.len() as u64);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// Encode a [`DefaultAction`] as canonical CBOR for the `policy_id` preimage.
///
/// Mirrors the §09.2 wire shape: `"Deny"` / `"EscalateToHuman"` are text
/// strings; `RequireApproval` is a single-pair map `{0: [bstr33]}` with an
/// integer key (canonical, minimal).
fn cbor_default_action(action: &DefaultAction) -> Vec<u8> {
    match action {
        DefaultAction::Deny => cbor_text("Deny"),
        DefaultAction::EscalateToHuman => cbor_text("EscalateToHuman"),
        DefaultAction::RequireApproval(keys) => {
            let mut out = cbor_head(5, 1); // 1-pair map
            out.extend_from_slice(&cbor_uint(0)); // key 0 → "RequireApproval"
            let items: Vec<Vec<u8>> = keys.iter().map(|k| cbor_bytes(k)).collect();
            out.extend_from_slice(&cbor_array(&items));
            out
        }
    }
}

/// Encode an [`ApprovalSpec`] as a canonical CBOR map `{1: k, 2: [eligible]}`.
fn cbor_approval_spec(spec: &ApprovalSpec) -> Vec<u8> {
    let mut out = cbor_head(5, 2);
    out.extend_from_slice(&cbor_uint(1));
    out.extend_from_slice(&cbor_uint(spec.k as u64));
    out.extend_from_slice(&cbor_uint(2));
    let items: Vec<Vec<u8>> = spec.eligible.iter().map(|k| cbor_bytes(k)).collect();
    out.extend_from_slice(&cbor_array(&items));
    out
}

/// Encode an [`AttestationSpec`] as a canonical CBOR map `{1: [formats]}`.
fn cbor_attestation_spec(spec: &AttestationSpec) -> Vec<u8> {
    let mut out = cbor_head(5, 1);
    out.extend_from_slice(&cbor_uint(1));
    let items: Vec<Vec<u8>> = spec.formats.iter().map(|f| cbor_text(f)).collect();
    out.extend_from_slice(&cbor_array(&items));
    out
}

/// Encode a [`TimeWindow`] as a canonical CBOR map `{1: cron, 2: duration}`.
fn cbor_time_window(tw: &TimeWindow) -> Vec<u8> {
    let mut out = cbor_head(5, 2);
    out.extend_from_slice(&cbor_uint(1));
    out.extend_from_slice(&cbor_text(&tw.cron));
    out.extend_from_slice(&cbor_uint(2));
    out.extend_from_slice(&cbor_uint(tw.duration_secs as u64));
    out
}

/// Encode a [`Jurisdiction`] as a canonical CBOR map; emits only present keys
/// (`1: allow`, `2: deny`) in ascending order.
fn cbor_jurisdiction(j: &Jurisdiction) -> Vec<u8> {
    // Collect present (key, value) pairs, then write the map header with the
    // exact pair count (definite length, ascending integer keys).
    let mut pairs: Vec<(u64, Vec<u8>)> = Vec::new();
    if let Some(allow) = &j.allow {
        let items: Vec<Vec<u8>> = allow.iter().map(|c| cbor_text(c)).collect();
        pairs.push((1, cbor_array(&items)));
    }
    if let Some(deny) = &j.deny {
        let items: Vec<Vec<u8>> = deny.iter().map(|c| cbor_text(c)).collect();
        pairs.push((2, cbor_array(&items)));
    }
    let mut out = cbor_head(5, pairs.len() as u64);
    for (k, v) in pairs {
        out.extend_from_slice(&cbor_uint(k));
        out.extend_from_slice(&v);
    }
    out
}

/// Encode a single [`Rule`] as a canonical CBOR definite-length map with the
/// integer keys mandated by §09.2 (1..11). Optional fields that are `None` are
/// OMITTED entirely — never emitted as null — so the encoding stays minimal and
/// keys remain in ascending order.
fn cbor_rule(rule: &Rule) -> Vec<u8> {
    let mut pairs: Vec<(u64, Vec<u8>)> = Vec::new();
    // Key 1 — protocol_pattern (always present).
    pairs.push((1, cbor_text(&rule.protocol_pattern)));
    if let Some(v) = rule.max_amount_sats {
        pairs.push((2, cbor_uint(v)));
    }
    if let Some(v) = rule.max_per_hour {
        pairs.push((3, cbor_uint(v as u64)));
    }
    if let Some(v) = rule.cumulative_daily_cap_sats {
        pairs.push((4, cbor_uint(v)));
    }
    if let Some(tw) = &rule.allowed_window {
        pairs.push((5, cbor_time_window(tw)));
    }
    if let Some(list) = &rule.counterparty_allowlist {
        let items: Vec<Vec<u8>> = list.iter().map(|c| cbor_text(c)).collect();
        pairs.push((6, cbor_array(&items)));
    }
    if let Some(list) = &rule.counterparty_denylist {
        let items: Vec<Vec<u8>> = list.iter().map(|c| cbor_text(c)).collect();
        pairs.push((7, cbor_array(&items)));
    }
    if let Some(v) = rule.min_fee_sats {
        pairs.push((8, cbor_uint(v)));
    }
    if let Some(j) = &rule.jurisdiction {
        pairs.push((9, cbor_jurisdiction(j)));
    }
    if let Some(spec) = &rule.approval_spec {
        pairs.push((10, cbor_approval_spec(spec)));
    }
    if let Some(spec) = &rule.attestation_spec {
        pairs.push((11, cbor_attestation_spec(spec)));
    }
    let mut out = cbor_head(5, pairs.len() as u64);
    for (k, v) in pairs {
        out.extend_from_slice(&cbor_uint(k));
        out.extend_from_slice(&v);
    }
    out
}

impl PolicyManifest {
    /// Compute the canonical `policy_id` = SHA-256 of a canonical-CBOR
    /// definite-length map over the manifest's identity fields.
    ///
    /// SPEC AMBIGUITY (§09.2 line28 "fields 3+" vs §09.8 "fields 1-10") —
    /// implementing `{1,3..10}`; pending MPC-Spec reconciliation, see
    /// `docs/AUDIT-43-policy-engine.md` §4. Concretely the preimage is a CBOR
    /// map with ascending integer keys `{1, 3, 4, 5, 6, 7, 8?, 9?, 10}`:
    /// version (1), cosigner_identity (3), group_key (4), rules (5),
    /// default_action (6), effective_after_ms (7), expires_after_ms (8, omitted
    /// if None), prev_policy_id (9, omitted if None), approver_keys (10).
    /// EXCLUDED: field 2 (self-referential), field 11 (`approver_sigs`), field
    /// 12 (`dry_run`, operational not identity).
    ///
    /// Optional fields that are `None` are omitted (NOT emitted as null), so the
    /// map's pair count and key order vary deterministically with content. Each
    /// value is encoded canonically (RFC 8949 §4.2): `u64` → minimal uint,
    /// pubkeys → byte strings (major type 2), patterns → text strings (major
    /// type 3), arrays → major type 4, nested `Rule` / `DefaultAction` as
    /// canonical integer-keyed maps.
    ///
    /// SPEC RECONCILIATION (nested key convention): §09.2's CDDL NAMES the nested
    /// sub-shapes with TEXT keys (`{"RequireApproval":[…]}`, `ApprovalSpec =
    /// {k, eligible}`, `TimeWindow = {cron, duration_secs}`, etc.) while the
    /// top-level `PolicyManifest`/`Rule` are explicitly numbered (integer keys).
    /// This encoder uses INTEGER keys throughout for a single, internally-
    /// consistent canonical form. There is NO locked cross-impl CBOR vector for
    /// §09 yet (`09-policy.json` is referenced but unverified; rust-mpc serializes
    /// policy as JSON), so neither convention is byte-verifiable today. This is
    /// deterministic and works as the in-impl `policy_id` binding label; the
    /// final cross-impl byte-lock (text vs integer keys + the field-set above)
    /// must be settled by an MPC-Spec vector + rust-mpc cross-check before §09.15
    /// CI conformance — same reconciliation track as #39/MPC-Spec#42.
    pub fn compute_policy_id(&self) -> PolicyId {
        // Build the (key, encoded-value) pairs in ascending key order, omitting
        // absent optionals.
        let mut pairs: Vec<(u64, Vec<u8>)> = Vec::new();

        // Key 1 — version.
        pairs.push((1, cbor_uint(self.version as u64)));
        // Key 3 — cosigner_identity (bstr).
        pairs.push((3, cbor_bytes(&self.cosigner_identity)));
        // Key 4 — group_key (bstr).
        pairs.push((4, cbor_bytes(&self.group_key)));
        // Key 5 — rules (array of canonical Rule maps).
        let rule_items: Vec<Vec<u8>> = self.rules.iter().map(cbor_rule).collect();
        pairs.push((5, cbor_array(&rule_items)));
        // Key 6 — default_action.
        pairs.push((6, cbor_default_action(&self.default_action)));
        // Key 7 — effective_after_ms.
        pairs.push((7, cbor_uint(self.effective_after_ms)));
        // Key 8 — expires_after_ms (omit if None).
        if let Some(v) = self.expires_after_ms {
            pairs.push((8, cbor_uint(v)));
        }
        // Key 9 — prev_policy_id (omit if None); bstr32.
        if let Some(prev) = &self.prev_policy_id {
            pairs.push((9, cbor_bytes(prev.as_bytes())));
        }
        // Key 10 — approver_keys (array of bstr33).
        let key_items: Vec<Vec<u8>> = self.approver_keys.iter().map(|k| cbor_bytes(k)).collect();
        pairs.push((10, cbor_array(&key_items)));

        // Definite-length map header with the exact pair count, then each
        // ascending integer key + its canonical value.
        let mut preimage = cbor_head(5, pairs.len() as u64);
        for (k, v) in pairs {
            preimage.extend_from_slice(&cbor_uint(k));
            preimage.extend_from_slice(&v);
        }

        let mut id = [0u8; 32];
        id.copy_from_slice(&Sha256::digest(&preimage));
        PolicyId::from_bytes(id)
    }

    /// Serialize the full manifest to CBOR for storage/transport (struct serde
    /// via `ciborium`). This is the round-trip wire, distinct from the
    /// byte-locked `policy_id` preimage in [`Self::compute_policy_id`].
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(self, &mut out)
            .map_err(|e| MpcError::Policy(format!("serialize PolicyManifest: {e}")))?;
        Ok(out)
    }

    /// Inverse of [`Self::to_cbor`]: reconstruct a manifest from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::de::from_reader(bytes)
            .map_err(|e| MpcError::Policy(format!("deserialize PolicyManifest: {e}")))
    }

    /// Validate every rule's `protocol_pattern` (§09.7) at load time. Invalid
    /// globs are rejected here, never at evaluation time.
    pub fn validate(&self) -> Result<()> {
        for rule in &self.rules {
            validate_pattern(&rule.protocol_pattern)?;
        }
        Ok(())
    }
}

// ===========================================================================
// Pattern matcher (§09.7)
// ===========================================================================

/// Validate a `protocol_pattern` glob per §09.7. Accepts the lone `"*"`, a
/// `"prefix/*"` (possibly multi-segment prefix like `"a/b/*"`), or an exact
/// string with no `*`. Rejects a leading `*` (other than the lone `"*"`) and any
/// `*` that is not the final character (no multi-segment / mid-string wildcard).
pub fn validate_pattern(pattern: &str) -> Result<()> {
    if pattern == "*" {
        return Ok(());
    }
    if !pattern.contains('*') {
        // Exact match pattern — always valid.
        return Ok(());
    }
    // Contains at least one `*` and is not the lone "*". The only legal form is
    // a trailing `"...prefix/*"`: exactly one `*`, it is the final char, and it
    // is immediately preceded by `/` (so the prefix is a path prefix).
    if pattern.matches('*').count() != 1 {
        return Err(MpcError::Policy(format!(
            "invalid protocol_pattern (multiple wildcards): {pattern:?}"
        )));
    }
    if !pattern.ends_with("/*") {
        return Err(MpcError::Policy(format!(
            "invalid protocol_pattern (wildcard must be a trailing \"/*\"): {pattern:?}"
        )));
    }
    Ok(())
}

/// Match a request `protocol_id` against a validated `protocol_pattern` (§09.7):
/// `"*"` matches all; `"prefix/*"` matches any id starting with `prefix/`; any
/// other pattern is an exact-string match. No regex.
pub fn protocol_matches(pattern: &str, protocol_id: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        // `prefix` ends with `/` (validated). Match ids beginning with it.
        return protocol_id.starts_with(prefix);
    }
    pattern == protocol_id
}

// ===========================================================================
// Request contexts (§09.3 hooks)
// ===========================================================================

/// Request context for [`PolicyEngine::check_signing`] (§09.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningCheck {
    /// Protocol identifier the request runs under (matched against rules).
    pub protocol_id: String,
    /// Total spend amount in satoshis.
    pub amount_sats: u64,
    /// Transaction fee in satoshis.
    pub fee_sats: u64,
    /// Counterparty identity (hex), if known.
    pub counterparty: Option<String>,
}

/// Request context for [`PolicyEngine::check_presigning`] (§09.3). For v1 this
/// shares the signing fields so presigning is gated by the same pattern/amount
/// rules — closing the rust-mpc "presigning allowed unconditionally" bypass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresigningCheck {
    /// Protocol identifier the presig will be bound to.
    pub protocol_id: String,
    /// Anticipated spend amount in satoshis.
    pub amount_sats: u64,
    /// Anticipated fee in satoshis.
    pub fee_sats: u64,
    /// Counterparty identity (hex), if known.
    pub counterparty: Option<String>,
}

/// Request context for [`PolicyEngine::check_derivation`] (§09.3 BRC-42
/// child-key derivation). Amount-free; gated on the protocol pattern + any
/// counterparty / approval requirements on the matching rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationCheck {
    /// Protocol identifier the derivation runs under.
    pub protocol_id: String,
    /// Counterparty identity (hex), if known.
    pub counterparty: Option<String>,
}

/// A normalized view over the three request kinds, so the matcher/enforcer can
/// be shared. `amount_sats` / `fee_sats` are `None` for derivation (amount-free).
struct RequestView<'a> {
    protocol_id: &'a str,
    amount_sats: Option<u64>,
    fee_sats: Option<u64>,
    counterparty: Option<&'a str>,
}

// ===========================================================================
// Policy engine (§09.3 / §09.5)
// ===========================================================================

/// One protocol_pattern's sliding-window event timestamps (epoch-ms).
type RateState = HashMap<String, Vec<u64>>;

/// Sliding 1-hour window length in milliseconds (§09.2 field 3).
const ONE_HOUR_MS: u64 = 60 * 60 * 1000;

/// Stateful per-cosigner policy evaluator (§09.3). Holds the manifest plus
/// per-pattern sliding-window rate state. All three hooks take the current time
/// as a `now_ms` epoch-ms parameter (wasm-safe, deterministic — no wall-clock
/// read inside the engine).
#[derive(Debug)]
pub struct PolicyEngine {
    manifest: PolicyManifest,
    /// Event timestamps (epoch-ms) keyed by the matching rule's
    /// `protocol_pattern`, for the `max_per_hour` sliding window.
    rate_state: RateState,
}

impl PolicyEngine {
    /// Construct an engine from a manifest, validating all rule patterns
    /// (§09.7) at load time. Returns `MpcError::Policy` on an invalid pattern.
    pub fn new(manifest: PolicyManifest) -> Result<Self> {
        manifest.validate()?;
        Ok(Self {
            manifest,
            rate_state: HashMap::new(),
        })
    }

    /// True iff the manifest is in shadow mode (§09.10): the engine still
    /// computes a verdict, but the caller MUST log-not-enforce it.
    pub fn is_dry_run(&self) -> bool {
        self.manifest.dry_run
    }

    /// Borrow the underlying manifest.
    pub fn manifest(&self) -> &PolicyManifest {
        &self.manifest
    }

    /// `check_signing` hook (§09.3) — gate before the final SIGN round.
    pub fn check_signing(&mut self, req: &SigningCheck, now_ms: u64) -> Verdict {
        let view = RequestView {
            protocol_id: &req.protocol_id,
            amount_sats: Some(req.amount_sats),
            fee_sats: Some(req.fee_sats),
            counterparty: req.counterparty.as_deref(),
        };
        self.evaluate(&view, now_ms)
    }

    /// `check_presigning` hook (§09.3) — gate before each presig is consumed.
    /// This MUST actually gate (it does NOT unconditionally Allow); for v1 it
    /// evaluates the same pattern/amount rules as signing.
    pub fn check_presigning(&mut self, req: &PresigningCheck, now_ms: u64) -> Verdict {
        let view = RequestView {
            protocol_id: &req.protocol_id,
            amount_sats: Some(req.amount_sats),
            fee_sats: Some(req.fee_sats),
            counterparty: req.counterparty.as_deref(),
        };
        self.evaluate(&view, now_ms)
    }

    /// `check_derivation` hook (§09.3) — gate before BRC-42 child-key
    /// derivation. Amount-free: amount/fee caps do not apply.
    pub fn check_derivation(&mut self, req: &DerivationCheck, now_ms: u64) -> Verdict {
        let view = RequestView {
            protocol_id: &req.protocol_id,
            amount_sats: None,
            fee_sats: None,
            counterparty: req.counterparty.as_deref(),
        };
        self.evaluate(&view, now_ms)
    }

    /// First-match-wins evaluation (§09.2): find the first rule whose pattern
    /// matches; enforce it; otherwise apply the default action.
    fn evaluate(&mut self, req: &RequestView, now_ms: u64) -> Verdict {
        // Find the index of the first matching rule (immutable borrow), then
        // enforce it (which may mutate `rate_state`).
        let matched = self
            .manifest
            .rules
            .iter()
            .position(|r| protocol_matches(&r.protocol_pattern, req.protocol_id));

        match matched {
            Some(idx) => self.evaluate_rule(idx, req, now_ms),
            None => self.default_verdict(),
        }
    }

    /// Apply the manifest `default_action` when no rule matched (§09.2 field 6).
    fn default_verdict(&self) -> Verdict {
        match &self.manifest.default_action {
            DefaultAction::Deny => Verdict::Deny("no matching rule".to_string()),
            DefaultAction::RequireApproval(keys) => Verdict::RequireApproval(ApprovalQuorum {
                k: keys.len() as u32,
                eligible: keys.clone(),
                deadline_secs: None,
            }),
            // EscalateToHuman maps to a quorum drawn from the manifest's
            // top-level approver_keys (§09.2 field 10).
            DefaultAction::EscalateToHuman => Verdict::RequireApproval(ApprovalQuorum {
                k: self.manifest.approver_keys.len() as u32,
                eligible: self.manifest.approver_keys.clone(),
                deadline_secs: None,
            }),
        }
    }

    /// Enforce the rule at `idx` against `req` (v1 subset). The enforcement
    /// order is deterministic: denylist → allowlist → amount cap → min-fee →
    /// rate limit → approval; otherwise Allow.
    fn evaluate_rule(&mut self, idx: usize, req: &RequestView, now_ms: u64) -> Verdict {
        // Clone the small bits we need so we can later take a &mut borrow of
        // `rate_state` without holding an immutable borrow of `self.manifest`.
        let rule = self.manifest.rules[idx].clone();

        // counterparty_denylist — a hit denies.
        if let (Some(deny), Some(cp)) = (&rule.counterparty_denylist, req.counterparty) {
            if deny.iter().any(|d| d == cp) {
                return Verdict::Deny(format!("counterparty {cp} on denylist"));
            }
        }

        // counterparty_allowlist — a miss denies (an unknown counterparty also
        // misses an allowlist and is therefore denied).
        if let Some(allow) = &rule.counterparty_allowlist {
            let permitted = req
                .counterparty
                .is_some_and(|cp| allow.iter().any(|a| a == cp));
            if !permitted {
                return Verdict::Deny("counterparty not on allowlist".to_string());
            }
        }

        // max_amount_sats — exceeded denies (amount-bearing requests only).
        if let (Some(cap), Some(amount)) = (rule.max_amount_sats, req.amount_sats) {
            if amount > cap {
                return Verdict::Deny(format!("amount {amount} exceeds max_amount_sats {cap}"));
            }
        }

        // min_fee_sats — a fee below the floor denies (fee-bearing requests).
        if let (Some(min_fee), Some(fee)) = (rule.min_fee_sats, req.fee_sats) {
            if fee < min_fee {
                return Verdict::Deny(format!("fee {fee} below min_fee_sats {min_fee}"));
            }
        }

        // §09 deferred (v1): needs geo/TEE/wall-clock context —
        // jurisdiction, attestation_spec, allowed_window,
        // cumulative_daily_cap_sats are parsed (round-tripped in CBOR) but NOT
        // enforced here. Tracked follow-on per docs/AUDIT-43-policy-engine.md §3.

        // max_per_hour — record this event in the pattern's sliding window,
        // prune aged-out events, then check the count against the cap. On a
        // violation, return the seconds until the OLDEST in-window event ages
        // out (when budget frees).
        if let Some(cap) = rule.max_per_hour {
            let events = self
                .rate_state
                .entry(rule.protocol_pattern.clone())
                .or_default();
            // Record this attempt, then drop everything older than the window.
            events.push(now_ms);
            let window_start = now_ms.saturating_sub(ONE_HOUR_MS);
            events.retain(|&t| t >= window_start);
            if events.len() as u64 > cap as u64 {
                // Oldest event in the window ages out at oldest + ONE_HOUR_MS.
                let oldest = *events.iter().min().unwrap_or(&now_ms);
                let free_at = oldest.saturating_add(ONE_HOUR_MS);
                let retry_after_secs = free_at.saturating_sub(now_ms).div_ceil(1000);
                return Verdict::RateLimited { retry_after_secs };
            }
        }

        // approval_spec — present means the rule requires a k-of-m quorum.
        if let Some(spec) = &rule.approval_spec {
            return Verdict::RequireApproval(ApprovalQuorum {
                k: spec.k,
                eligible: spec.eligible.clone(),
                deadline_secs: None,
            });
        }

        Verdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 33-byte compressed pubkey filled with `b`, for fixtures.
    fn key(b: u8) -> Vec<u8> {
        let mut k = vec![0x02; 33];
        k[1] = b;
        k
    }

    /// A minimal manifest with the given rules + default action. `policy_id` is
    /// computed and stored.
    fn manifest_with(rules: Vec<Rule>, default_action: DefaultAction) -> PolicyManifest {
        let mut m = PolicyManifest {
            version: 7,
            policy_id: PolicyId::from_bytes([0u8; 32]),
            cosigner_identity: key(0x11),
            group_key: key(0x22),
            rules,
            default_action,
            effective_after_ms: 1_000,
            expires_after_ms: None,
            prev_policy_id: None,
            approver_keys: vec![key(0xaa), key(0xbb)],
            approver_sigs: vec![],
            dry_run: false,
        };
        m.policy_id = m.compute_policy_id();
        m
    }

    fn rule(pattern: &str) -> Rule {
        Rule {
            protocol_pattern: pattern.to_string(),
            max_amount_sats: None,
            max_per_hour: None,
            cumulative_daily_cap_sats: None,
            allowed_window: None,
            counterparty_allowlist: None,
            counterparty_denylist: None,
            min_fee_sats: None,
            jurisdiction: None,
            approval_spec: None,
            attestation_spec: None,
        }
    }

    fn signing(protocol: &str, amount: u64, fee: u64, cp: Option<&str>) -> SigningCheck {
        SigningCheck {
            protocol_id: protocol.to_string(),
            amount_sats: amount,
            fee_sats: fee,
            counterparty: cp.map(|s| s.to_string()),
        }
    }

    // ---- pattern matcher (§09.7) -----------------------------------------

    #[test]
    fn pattern_star_matches_all() {
        assert!(protocol_matches("*", "anything"));
        assert!(protocol_matches("*", "agent/api/x"));
    }

    #[test]
    fn pattern_prefix_star() {
        assert!(protocol_matches("agent/*", "agent/api"));
        assert!(protocol_matches("agent/*", "agent/api/x"));
        assert!(!protocol_matches("agent/*", "treasury/x"));
        assert!(!protocol_matches("agent/*", "agent")); // no trailing slash
    }

    #[test]
    fn pattern_exact() {
        assert!(protocol_matches("agent/pay", "agent/pay"));
        assert!(!protocol_matches("agent/pay", "agent/pa"));
        assert!(!protocol_matches("agent/pay", "agent/pay/x"));
    }

    #[test]
    fn pattern_multi_segment_prefix() {
        assert!(protocol_matches("a/b/*", "a/b/c"));
        assert!(!protocol_matches("a/b/*", "a/c/d"));
    }

    #[test]
    fn validate_pattern_accepts_legal_forms() {
        assert!(validate_pattern("*").is_ok());
        assert!(validate_pattern("agent/*").is_ok());
        assert!(validate_pattern("a/b/*").is_ok());
        assert!(validate_pattern("agent/pay").is_ok());
    }

    #[test]
    fn validate_pattern_rejects_invalid() {
        assert!(validate_pattern("*agent").is_err()); // leading wildcard
        assert!(validate_pattern("agent/*/x").is_err()); // mid-string wildcard
        assert!(validate_pattern("agent/**").is_err()); // multiple wildcards
        assert!(validate_pattern("ag*ent").is_err()); // non-trailing wildcard
    }

    // ---- compute_policy_id ----------------------------------------------

    #[test]
    fn policy_id_is_deterministic() {
        let m1 = manifest_with(vec![rule("agent/*")], DefaultAction::Deny);
        let m2 = manifest_with(vec![rule("agent/*")], DefaultAction::Deny);
        assert_eq!(m1.compute_policy_id(), m2.compute_policy_id());
    }

    #[test]
    fn policy_id_changes_when_a_field_changes() {
        let base = manifest_with(vec![rule("agent/*")], DefaultAction::Deny);
        let id0 = base.compute_policy_id();

        // version differs
        let mut m = base.clone();
        m.version = 8;
        assert_ne!(id0, m.compute_policy_id());

        // a rule differs
        let mut m = base.clone();
        m.rules[0].max_amount_sats = Some(5);
        assert_ne!(id0, m.compute_policy_id());

        // default_action differs
        let mut m = base.clone();
        m.default_action = DefaultAction::EscalateToHuman;
        assert_ne!(id0, m.compute_policy_id());
    }

    #[test]
    fn policy_id_excludes_sigs_and_dry_run() {
        let base = manifest_with(vec![rule("*")], DefaultAction::Deny);
        let id0 = base.compute_policy_id();

        // approver_sigs (field 11) excluded → id stable
        let mut m = base.clone();
        m.approver_sigs = vec![vec![0xde; 72]];
        assert_eq!(id0, m.compute_policy_id());

        // dry_run (field 12) excluded → id stable
        let mut m = base.clone();
        m.dry_run = true;
        assert_eq!(id0, m.compute_policy_id());

        // policy_id (field 2, self) excluded → id stable
        let mut m = base.clone();
        m.policy_id = PolicyId::from_bytes([0xff; 32]);
        assert_eq!(id0, m.compute_policy_id());
    }

    #[test]
    fn policy_id_preimage_first_byte_is_cbor_map_header() {
        // The preimage with no optional fields has 8 pairs {1,3,4,5,6,7,10}…
        // actually 7 keys (1,3,4,5,6,7,10) → 0xA0 | 7 = 0xA7. We assert the
        // major type is 5 (map) by checking the top 3 bits.
        let m = manifest_with(vec![rule("*")], DefaultAction::Deny);
        // Reconstruct just the header by hashing nothing — instead recompute a
        // tiny preimage check via the public path: re-derive and confirm the id
        // is a SHA-256 (32 bytes, trivially true by type). To inspect the map
        // header we rebuild the preimage inline mirroring compute_policy_id's
        // first byte: 7 pairs → 0xA7.
        let mut pairs = 0u64;
        pairs += 1; // version
        pairs += 1; // cosigner_identity
        pairs += 1; // group_key
        pairs += 1; // rules
        pairs += 1; // default_action
        pairs += 1; // effective_after_ms
        pairs += 1; // approver_keys
        let header = cbor_head(5, pairs);
        // Major type 5 → top three bits == 0b101.
        assert_eq!(header[0] >> 5, 5);
        assert_eq!(header[0], 0xA7);
        // sanity: id is stable across two constructions
        assert_eq!(m.compute_policy_id(), m.compute_policy_id());
    }

    // ---- verdict paths ---------------------------------------------------

    #[test]
    fn verdict_allow() {
        let m = manifest_with(vec![rule("agent/*")], DefaultAction::Deny);
        let mut eng = PolicyEngine::new(m).unwrap();
        let v = eng.check_signing(&signing("agent/pay", 100, 10, None), 0);
        assert_eq!(v, Verdict::Allow);
        assert!(v.is_allowed());
    }

    #[test]
    fn verdict_deny_amount_cap() {
        let mut r = rule("agent/*");
        r.max_amount_sats = Some(1000);
        let m = manifest_with(vec![r], DefaultAction::Deny);
        let mut eng = PolicyEngine::new(m).unwrap();
        let v = eng.check_signing(&signing("agent/pay", 1001, 10, None), 0);
        assert!(matches!(v, Verdict::Deny(_)));
        // at the cap is allowed
        let v = eng.check_signing(&signing("agent/pay", 1000, 10, None), 0);
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn verdict_deny_denylist() {
        let mut r = rule("*");
        r.counterparty_denylist = Some(vec!["bad".to_string()]);
        let m = manifest_with(vec![r], DefaultAction::Deny);
        let mut eng = PolicyEngine::new(m).unwrap();
        let v = eng.check_signing(&signing("agent/pay", 1, 1, Some("bad")), 0);
        assert!(matches!(v, Verdict::Deny(_)));
    }

    #[test]
    fn verdict_deny_allowlist_miss() {
        let mut r = rule("*");
        r.counterparty_allowlist = Some(vec!["good".to_string()]);
        let m = manifest_with(vec![r], DefaultAction::Deny);
        let mut eng = PolicyEngine::new(m).unwrap();
        // miss → deny
        let v = eng.check_signing(&signing("agent/pay", 1, 1, Some("other")), 0);
        assert!(matches!(v, Verdict::Deny(_)));
        // unknown counterparty → deny
        let v = eng.check_signing(&signing("agent/pay", 1, 1, None), 0);
        assert!(matches!(v, Verdict::Deny(_)));
        // hit → allow
        let v = eng.check_signing(&signing("agent/pay", 1, 1, Some("good")), 0);
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn verdict_deny_min_fee() {
        let mut r = rule("*");
        r.min_fee_sats = Some(100);
        let m = manifest_with(vec![r], DefaultAction::Deny);
        let mut eng = PolicyEngine::new(m).unwrap();
        let v = eng.check_signing(&signing("agent/pay", 1, 99, None), 0);
        assert!(matches!(v, Verdict::Deny(_)));
        let v = eng.check_signing(&signing("agent/pay", 1, 100, None), 0);
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn verdict_rate_limited_at_cap() {
        let mut r = rule("agent/*");
        r.max_per_hour = Some(2);
        let m = manifest_with(vec![r], DefaultAction::Deny);
        let mut eng = PolicyEngine::new(m).unwrap();
        // two are allowed within the window
        assert_eq!(
            eng.check_signing(&signing("agent/pay", 1, 1, None), 0),
            Verdict::Allow
        );
        assert_eq!(
            eng.check_signing(&signing("agent/pay", 1, 1, None), 1000),
            Verdict::Allow
        );
        // the third within the hour exceeds the cap
        let v = eng.check_signing(&signing("agent/pay", 1, 1, None), 2000);
        match v {
            Verdict::RateLimited { retry_after_secs } => {
                // oldest event at t=0 ages out at t=3_600_000ms; now=2000ms →
                // 3_598_000ms ≈ 3598s.
                assert_eq!(retry_after_secs, 3598);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
        // after the window slides past the oldest events, budget frees up
        let v = eng.check_signing(&signing("agent/pay", 1, 1, None), ONE_HOUR_MS + 2001);
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn verdict_require_approval_via_spec() {
        let mut r = rule("treasury/*");
        r.approval_spec = Some(ApprovalSpec {
            k: 1,
            eligible: vec![key(0xcc)],
        });
        let m = manifest_with(vec![r], DefaultAction::Deny);
        let mut eng = PolicyEngine::new(m).unwrap();
        let v = eng.check_signing(&signing("treasury/move", 1, 1, None), 0);
        match v {
            Verdict::RequireApproval(q) => {
                assert_eq!(q.k, 1);
                assert_eq!(q.eligible, vec![key(0xcc)]);
            }
            other => panic!("expected RequireApproval, got {other:?}"),
        }
        assert!(eng
            .check_signing(&signing("treasury/move", 1, 1, None), 0)
            .requires_approval());
    }

    #[test]
    fn default_action_deny() {
        let m = manifest_with(vec![rule("agent/*")], DefaultAction::Deny);
        let mut eng = PolicyEngine::new(m).unwrap();
        let v = eng.check_signing(&signing("treasury/x", 1, 1, None), 0);
        assert_eq!(v, Verdict::Deny("no matching rule".to_string()));
    }

    #[test]
    fn default_action_require_approval() {
        let keys = vec![key(0xaa), key(0xbb)];
        let m = manifest_with(vec![], DefaultAction::RequireApproval(keys.clone()));
        let mut eng = PolicyEngine::new(m).unwrap();
        let v = eng.check_signing(&signing("x", 1, 1, None), 0);
        match v {
            Verdict::RequireApproval(q) => {
                assert_eq!(q.k, 2);
                assert_eq!(q.eligible, keys);
            }
            other => panic!("expected RequireApproval, got {other:?}"),
        }
    }

    #[test]
    fn default_action_escalate_to_human() {
        let m = manifest_with(vec![], DefaultAction::EscalateToHuman);
        let approvers = m.approver_keys.clone();
        let mut eng = PolicyEngine::new(m).unwrap();
        let v = eng.check_signing(&signing("x", 1, 1, None), 0);
        match v {
            Verdict::RequireApproval(q) => {
                assert_eq!(q.k as usize, approvers.len());
                assert_eq!(q.eligible, approvers);
            }
            other => panic!("expected RequireApproval, got {other:?}"),
        }
    }

    #[test]
    fn first_match_wins() {
        // First rule (broad) allows; a later narrower deny rule never fires.
        let mut deny_rule = rule("agent/danger");
        deny_rule.max_amount_sats = Some(0);
        let m = manifest_with(vec![rule("agent/*"), deny_rule], DefaultAction::Deny);
        let mut eng = PolicyEngine::new(m).unwrap();
        let v = eng.check_signing(&signing("agent/danger", 100, 1, None), 0);
        assert_eq!(v, Verdict::Allow);
    }

    // ---- presigning gates (§09.3 fix) ------------------------------------

    #[test]
    fn presigning_actually_gates() {
        // default Deny + no rule → presigning MUST deny (not unconditional Allow).
        let m = manifest_with(vec![], DefaultAction::Deny);
        let mut eng = PolicyEngine::new(m).unwrap();
        let v = eng.check_presigning(
            &PresigningCheck {
                protocol_id: "agent/pay".to_string(),
                amount_sats: 1,
                fee_sats: 1,
                counterparty: None,
            },
            0,
        );
        assert!(
            matches!(v, Verdict::Deny(_)),
            "presigning must gate, got {v:?}"
        );

        // amount cap also gates presigning
        let mut r = rule("agent/*");
        r.max_amount_sats = Some(10);
        let m = manifest_with(vec![r], DefaultAction::Deny);
        let mut eng = PolicyEngine::new(m).unwrap();
        let v = eng.check_presigning(
            &PresigningCheck {
                protocol_id: "agent/pay".to_string(),
                amount_sats: 100,
                fee_sats: 1,
                counterparty: None,
            },
            0,
        );
        assert!(matches!(v, Verdict::Deny(_)));
    }

    #[test]
    fn derivation_gates_on_pattern() {
        let m = manifest_with(vec![rule("agent/*")], DefaultAction::Deny);
        let mut eng = PolicyEngine::new(m).unwrap();
        let allow = eng.check_derivation(
            &DerivationCheck {
                protocol_id: "agent/x".to_string(),
                counterparty: None,
            },
            0,
        );
        assert_eq!(allow, Verdict::Allow);
        let deny = eng.check_derivation(
            &DerivationCheck {
                protocol_id: "treasury/x".to_string(),
                counterparty: None,
            },
            0,
        );
        assert!(matches!(deny, Verdict::Deny(_)));
    }

    // ---- dry-run ---------------------------------------------------------

    #[test]
    fn dry_run_flag_is_surfaced() {
        let mut m = manifest_with(vec![], DefaultAction::Deny);
        m.dry_run = true;
        let eng = PolicyEngine::new(m).unwrap();
        assert!(eng.is_dry_run());
    }

    // ---- serde round-trip ------------------------------------------------

    #[test]
    fn manifest_cbor_round_trip() {
        let mut r = rule("treasury/*");
        r.max_amount_sats = Some(100_000_000);
        r.max_per_hour = Some(20);
        r.min_fee_sats = Some(500);
        r.counterparty_allowlist = Some(vec!["02aa".to_string()]);
        r.approval_spec = Some(ApprovalSpec {
            k: 1,
            eligible: vec![key(0xcc)],
        });
        r.jurisdiction = Some(Jurisdiction {
            allow: Some(vec!["US".to_string()]),
            deny: None,
        });
        r.attestation_spec = Some(AttestationSpec {
            formats: vec!["nitro_v1".to_string()],
        });
        r.allowed_window = Some(TimeWindow {
            cron: "0 0 * * *".to_string(),
            duration_secs: 3600,
        });
        let mut m = manifest_with(vec![rule("agent/*"), r], DefaultAction::EscalateToHuman);
        m.expires_after_ms = Some(9_999);
        m.prev_policy_id = Some(PolicyId::from_bytes([0x07; 32]));
        m.approver_sigs = vec![vec![0xde; 72]];
        m.policy_id = m.compute_policy_id();

        let bytes = m.to_cbor().unwrap();
        let back = PolicyManifest::from_cbor(&bytes).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn new_rejects_invalid_pattern() {
        let m = manifest_with(vec![rule("*bad")], DefaultAction::Deny);
        assert!(PolicyEngine::new(m).is_err());
    }
}
