//! §09.5.1 / ADR-0044 approval canonicalization — `request_view_hash`.
//!
//! The `request_view_hash` binds a wallet's human-rendered approval prompt to
//! the exact transaction-shaping inputs the cosigner will sign over. It is the
//! SHA-256 of a canonical CBOR **definite-length map** with INTEGER keys 1..8,
//! per ADR-0032 (preimage layout) and ADR-0044 (intent-kind dispatch for the
//! `rendered_text` field):
//!
//! | key | field          | CBOR type                                   |
//! |-----|----------------|---------------------------------------------|
//! | 1   | amount         | unsigned int (satoshis or token amount)     |
//! | 2   | recipient      | text string, OR array of text (kind `multi`)|
//! | 3   | sighash        | hex **text** string (32 bytes → 64 chars)   |
//! | 4   | execution_id   | hex **text** string (32 bytes → 64 chars)   |
//! | 5   | policy_id      | hex **text** string (32 bytes → 64 chars)   |
//! | 6   | manifest_ack   | hex **text** string (64 bytes → 128 chars)  |
//! | 7   | human_locale   | text string (BCP-47 tag, e.g. "en-US")      |
//! | 8   | rendered_text  | text string (canonical per ADR-0044)        |
//!
//! IMPORTANT: keys 3-6 are stored as hex **text** strings (CBOR major type 3),
//! NOT raw byte strings. The encoder below reproduces them as text verbatim.
//!
//! The canonical CBOR rules (RFC 8949 §4.2: definite lengths, minimal integer
//! encoding, integer map keys in ascending order 1..8) are hand-rolled here for
//! this fixed map shape so the bytes are byte-for-byte reproducible against the
//! locked MPC-Spec vectors in `tests/fixtures/09-rendered-text.json`. The map
//! header is `0xA8` (major type 5, 8 pairs); each key `i` encodes to the single
//! byte `0x0i` (minimal uint, value < 24), which is already the canonical
//! bytewise-lexicographic key order.
//!
//! NFC requirement: every text string (recipient, locale, rendered_text) MUST
//! be NFC-normalized UTF-8 before being passed in. The canonical vectors are
//! already NFC, so this module passes the bytes through unchanged — it does NOT
//! perform normalization itself (no normalization dependency is pulled in).
//! Callers feeding non-canonical input are responsible for NFC-normalizing.
//!
//! NOTE (ADR-0044): the `rendered_text` strings are hand-authored per intent
//! kind (and contain literal "..." placeholders in the locked vectors); they
//! are NOT derivable byte-exactly from a generic renderer. `rendered_text` is
//! therefore an **input** to this primitive. The deterministic, lockable part
//! is the CBOR-of-8-fields → SHA-256, which this module owns.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Recipient binding for key 2 of the `request_view_hash` preimage.
///
/// Single-recipient intent kinds (`payment`, `token_transfer`, `script_spend`,
/// `brc100_internalize`) encode a single text string. The `multi` kind encodes
/// a CBOR array of text strings (one per recipient output).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    /// A single recipient address / output descriptor (CBOR text string).
    Single(String),
    /// Multiple recipient addresses (CBOR array of text strings).
    Multi(Vec<String>),
}

/// Result of [`request_view_hash`]: the 32-byte digest plus the exact canonical
/// CBOR preimage bytes that were hashed (returned so callers and conformance
/// harnesses can byte-compare the preimage against the locked vector).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestViewHash {
    /// SHA-256 of [`Self::preimage`].
    pub hash: [u8; 32],
    /// The canonical CBOR definite-length map `{1..8}` that was hashed.
    pub preimage: Vec<u8>,
}

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

/// CBOR major-type-3 text string: head(len) ‖ utf-8 bytes. The caller is
/// responsible for NFC normalization (see module docs).
fn cbor_text(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = cbor_head(3, b.len() as u64);
    out.extend_from_slice(b);
    out
}

/// Encode key 2 (recipient): a text string for `Single`, or a major-type-4
/// definite-length array of text strings for `Multi`.
fn cbor_recipient(recipient: &Recipient) -> Vec<u8> {
    match recipient {
        Recipient::Single(s) => cbor_text(s),
        Recipient::Multi(items) => {
            let mut out = cbor_head(4, items.len() as u64);
            for item in items {
                out.extend_from_slice(&cbor_text(item));
            }
            out
        }
    }
}

/// Build the canonical CBOR preimage and compute the `request_view_hash` per
/// §09.5.1 / ADR-0044 / ADR-0032.
///
/// The preimage is a CBOR definite-length map with integer keys 1..8 in
/// ascending order. `sighash_hex`, `execution_id_hex`, `policy_id_hex`, and
/// `manifest_ack_hex` are encoded as hex **text** strings (NOT raw bytes), per
/// the locked vector layout. All text inputs MUST already be NFC-normalized
/// UTF-8 (see module docs).
///
/// Returns the digest and the exact preimage bytes that were hashed.
#[allow(clippy::too_many_arguments)]
pub fn request_view_hash(
    amount: u64,
    recipient: &Recipient,
    sighash_hex: &str,
    execution_id_hex: &str,
    policy_id_hex: &str,
    manifest_ack_hex: &str,
    human_locale: &str,
    rendered_text: &str,
) -> RequestViewHash {
    // Definite-length map header: major type 5, 8 pairs → 0xA8.
    let mut preimage = cbor_head(5, 8);

    // Keys 1..8 in ascending order (single-byte encodings 0x01..0x08 are
    // already the canonical bytewise-lex key order for a CBOR map).
    preimage.extend_from_slice(&cbor_uint(1));
    preimage.extend_from_slice(&cbor_uint(amount));

    preimage.extend_from_slice(&cbor_uint(2));
    preimage.extend_from_slice(&cbor_recipient(recipient));

    preimage.extend_from_slice(&cbor_uint(3));
    preimage.extend_from_slice(&cbor_text(sighash_hex));

    preimage.extend_from_slice(&cbor_uint(4));
    preimage.extend_from_slice(&cbor_text(execution_id_hex));

    preimage.extend_from_slice(&cbor_uint(5));
    preimage.extend_from_slice(&cbor_text(policy_id_hex));

    preimage.extend_from_slice(&cbor_uint(6));
    preimage.extend_from_slice(&cbor_text(manifest_ack_hex));

    preimage.extend_from_slice(&cbor_uint(7));
    preimage.extend_from_slice(&cbor_text(human_locale));

    preimage.extend_from_slice(&cbor_uint(8));
    preimage.extend_from_slice(&cbor_text(rendered_text));

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&Sha256::digest(&preimage));

    RequestViewHash { hash, preimage }
}

// ===========================================================================
// ADR-0044 canonical wallet renderer (issue #75)
// ===========================================================================
//
// `canonical_render(intent)` is the PURE-SUBSTITUTION function that produces
// the `rendered_text` field consumed at key 8 of the [`request_view_hash`]
// preimage above. Both bsv-mpc and rust-mpc MUST agree byte-for-byte on the
// output for the same `Intent`, otherwise WYSIWYS is broken (the wallet would
// display one string while the cosigner bound to another). ADR-0044 §2.1/§2.2/
// §2.3 (amended 2026-05-28) locks the shape:
//
// - `Intent` is a tagged sum-type with discriminant key `kind`; the five
//   accepted values are exactly `payment`, `token_transfer`, `script_spend`,
//   `brc100_internalize`, `multi` (case-sensitive, snake_case, no aliases).
// - Each variant is a closed flat object: missing OR extra fields MUST reject.
// - The renderer is PURE SUBSTITUTION over pre-resolved string fields (no
//   address derivation, no cert-chain lookup, no network, no currency
//   conversion, no key arithmetic). The ONLY in-renderer algorithmic
//   transformations are the counterparty truncation (`cert_name + " + 0x" +
//   pubkey_hex[..8] + "..."`) and the token-contract-hash truncation
//   (`"0x" + hex_no_0x_prefix[..8] + "..."`).
//
// The locked test vectors at `tests/fixtures/09-rendered-text.json` are the
// schema — `tests/conformance_09_canonical_render.rs` byte-locks them.

/// One output of a payment intent (a `{script, value_sats}` pair). Schema is
/// closed (`deny_unknown_fields`); any extra field is a HARD reject per
/// ADR-0044 §2.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentOutput {
    /// Locking-script hex (opaque to the renderer; carried for the
    /// `request_view_hash` binding upstream).
    pub script: String,
    /// Output value in satoshis.
    pub value_sats: u64,
}

/// Counterparty identity for a payment intent: a compressed-secp256k1 pubkey
/// hex (66 chars) and an OPTIONAL BRC-100 cert name. Schema is closed
/// (`deny_unknown_fields`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counterparty {
    /// Full 66-character compressed-secp256k1 pubkey hex. The first 8 chars
    /// are rendered (after `"0x"`) per ADR-0044 §2.2.
    pub pubkey: String,
    /// Optional BRC-100 cert chain root name. `None` → renders as
    /// `"anonymous"`.
    pub cert_name: Option<String>,
}

/// One output of a multi-output intent — itself a tagged sum (`payment` or
/// `fee`). The `payment` variant carries `{amount_satoshis, recipient}` (the
/// pre-resolved recipient address is opaque text); the `fee` variant carries
/// `{amount_satoshis}`. Schema is CLOSED — extra fields hard-reject per
/// ADR-0044 §2.1 (`deny_unknown_fields` on the outer enum applies to each
/// variant's body during internally-tagged deserialization).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MultiOutput {
    /// A payment output — pre-resolved recipient + sats.
    Payment {
        /// Output value in satoshis.
        amount_satoshis: u64,
        /// Pre-resolved recipient address string (no derivation in-renderer).
        recipient: String,
    },
    /// A fee output — sats only (no recipient surface).
    Fee {
        /// Fee value in satoshis.
        amount_satoshis: u64,
    },
}

/// The canonical wallet-renderer intent (ADR-0044 §2.1, amended 2026-05-28).
///
/// Tagged sum on `kind` (snake_case discriminant); each variant is a closed
/// flat object. `canonical_render` dispatches on the variant and produces the
/// byte-locked `rendered_text` string the wallet displays AND the cosigner
/// binds to via `request_view_hash` (key 8).
///
/// All string fields are carried PRE-RESOLVED by the caller (BRC-100 cert
/// name, human address, fiat estimate, locale, …) — the renderer is forbidden
/// from doing address derivation / cert-chain lookup / network / currency
/// conversion / key arithmetic. The only algorithmic transformations are the
/// counterparty truncation (Payment) and the token-contract-hash truncation
/// (TokenTransfer); see `canonical_render` doc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Intent {
    /// P2PKH / P2MS payment intent. Renders as:
    /// `"Send {amount_satoshis} sats (~{fiat_estimate} {fiat_currency}) to
    /// {human_address} with fee {fee_sats} sats. Counterparty: {counterparty}."`
    Payment {
        /// Total satoshis being sent (matches `sum(recipient_outputs.value_sats)`).
        amount_satoshis: u64,
        /// Per-output `{script, value_sats}` list — carried for upstream
        /// `request_view_hash` binding; the renderer itself does not iterate.
        recipient_outputs: Vec<PaymentOutput>,
        /// Pre-resolved recipient human address (BRC-100 cert name OR
        /// Base58Check P2PKH address). Substituted at `<human_address>`.
        human_address: String,
        /// Network fee in satoshis.
        fee_sats: u64,
        /// Counterparty identity (`pubkey` + optional `cert_name`).
        /// Rendered as `"<cert_name|anonymous> + 0x<pubkey[..8]>..."`.
        counterparty_identity: Counterparty,
        /// Pre-formatted fiat estimate (opaque text; locale formatting is the
        /// caller's job — the renderer does NOT call ICU). e.g. `"$50.00"`.
        fiat_estimate: String,
        /// ISO 4217 currency code. e.g. `"USD"`.
        fiat_currency: String,
        /// BCP-47 language tag the caller chose for the human strings.
        human_locale: String,
    },
    /// BRC-22/27/76 token transfer intent. Renders as:
    /// `"Transfer {token_amount} {token_symbol} tokens to {recipient}
    /// (value ~{fiat_estimate} {fiat_currency}). Token contract: 0x{hash[..8]}..."`
    TokenTransfer {
        /// Token amount being transferred (token-native units).
        token_amount: u64,
        /// Token symbol (e.g. `"USDT-on-BSV"`).
        token_symbol: String,
        /// Pre-resolved recipient address string.
        recipient: String,
        /// Pre-formatted fiat estimate (e.g. `"$100.00"`).
        fiat_estimate: String,
        /// ISO 4217 currency code.
        fiat_currency: String,
        /// Token contract identifier hex. May or may not carry a `"0x"`
        /// prefix; the renderer strips it then takes the first 8 chars.
        token_contract_hash: String,
        /// BCP-47 language tag.
        human_locale: String,
    },
    /// sCrypt covenant spend intent. Renders as:
    /// `"Execute sCrypt covenant spend at contract {covenant_address}.
    /// Output value: {amount_satoshis} sats. Covenant function:
    /// {function_name}. Function args summary: {function_args_hash}."`
    ScriptSpend {
        /// Pre-resolved covenant address string.
        covenant_address: String,
        /// Output value in satoshis.
        amount_satoshis: u64,
        /// Covenant function name being executed.
        function_name: String,
        /// Opaque hash summary of the function args (e.g.
        /// `"sha256:abababab…"`).
        function_args_hash: String,
        /// BCP-47 language tag.
        human_locale: String,
    },
    /// BRC-100 `internalizeAction` intent. Renders as:
    /// `"Internalize action: {action_description}. From: {source}. To:
    /// {destination}. Notes: {protocol_notes}."`
    Brc100Internalize {
        /// Action description (e.g. `"payment-received"`).
        action_description: String,
        /// Pre-resolved source identifier.
        source: String,
        /// Pre-resolved destination identifier.
        destination: String,
        /// Free-text protocol notes.
        protocol_notes: String,
        /// BCP-47 language tag.
        human_locale: String,
    },
    /// Compound multi-output intent (mixed payment + fee outputs). Renders as:
    /// `"Compound transaction with {N} outputs: {output_1_summary};
    /// {output_2_summary}; …; {output_N_summary}."`
    ///
    /// Per-output summaries: Payment → `"Send {amount_satoshis} sats to
    /// {recipient}"`; Fee → `"Fee output {amount_satoshis} sats"`.
    Multi {
        /// Output list (each tagged on `kind`: `payment` or `fee`).
        outputs: Vec<MultiOutput>,
        /// BCP-47 language tag.
        human_locale: String,
    },
}

/// Render an [`Intent`] to its canonical `rendered_text` (ADR-0044 §2 + §2.2).
///
/// PURE-SUBSTITUTION over the pre-resolved string fields on the intent. The
/// only in-renderer algorithmic transformations are:
///
/// 1. **Payment counterparty truncation** — `"<cert_name|anonymous> + 0x<pubkey_hex[..8]>..."`.
///    `cert_name == None` → `"anonymous"`. `pubkey_hex` is the full 66-char
///    compressed-secp256k1 hex; first 8 chars are appended.
/// 2. **TokenTransfer contract-hash truncation** — strip any leading `"0x"`
///    from `token_contract_hash`, take the first 8 chars, render as
///    `"0x<hex8>..."`.
///
/// No address derivation, no cert-chain lookup, no network call, no currency
/// conversion, no key arithmetic. Locale-aware decimal/currency formatting is
/// the CALLER's job — `fiat_estimate` is treated as opaque text.
///
/// Returns `Err(MpcError::Protocol)` if a required slice transformation would
/// panic (e.g. `pubkey` shorter than 8 chars OR `token_contract_hash` shorter
/// than 8 chars after stripping `"0x"`). The serde layer guarantees the field
/// shape, so the only ways to reach those errors are malformed (post-deser)
/// data — not a normal path, but we surface them as `Protocol(...)` instead
/// of panicking.
pub fn canonical_render(intent: &Intent) -> crate::error::Result<String> {
    match intent {
        Intent::Payment {
            amount_satoshis,
            recipient_outputs: _,
            human_address,
            fee_sats,
            counterparty_identity,
            fiat_estimate,
            fiat_currency,
            human_locale: _,
        } => {
            if counterparty_identity.pubkey.len() < 8 {
                return Err(crate::error::MpcError::Protocol(format!(
                    "payment.counterparty_identity.pubkey too short: \
                     expected ≥ 8 hex chars, got {}",
                    counterparty_identity.pubkey.len()
                )));
            }
            let cert = counterparty_identity
                .cert_name
                .as_deref()
                .unwrap_or("anonymous");
            let pub8 = &counterparty_identity.pubkey[..8];
            let counterparty = format!("{cert} + 0x{pub8}...");
            // No trailing period after `{counterparty}` — the counterparty
            // string already ends with the truncation marker `...`, and the
            // locked fixture renders it without an additional period.
            Ok(format!(
                "Send {amount_satoshis} sats (~{fiat_estimate} {fiat_currency}) \
                 to {human_address} with fee {fee_sats} sats. \
                 Counterparty: {counterparty}"
            ))
        }
        Intent::TokenTransfer {
            token_amount,
            token_symbol,
            recipient,
            fiat_estimate,
            fiat_currency,
            token_contract_hash,
            human_locale: _,
        } => {
            let stripped = token_contract_hash.trim_start_matches("0x");
            if stripped.len() < 8 {
                return Err(crate::error::MpcError::Protocol(format!(
                    "token_transfer.token_contract_hash too short: \
                     expected ≥ 8 hex chars (after stripping any 0x prefix), \
                     got {}",
                    stripped.len()
                )));
            }
            let hash8 = &stripped[..8];
            Ok(format!(
                "Transfer {token_amount} {token_symbol} tokens to {recipient} \
                 (value ~{fiat_estimate} {fiat_currency}). \
                 Token contract: 0x{hash8}..."
            ))
        }
        Intent::ScriptSpend {
            covenant_address,
            amount_satoshis,
            function_name,
            function_args_hash,
            human_locale: _,
        } => Ok(format!(
            "Execute sCrypt covenant spend at contract {covenant_address}. \
             Output value: {amount_satoshis} sats. \
             Covenant function: {function_name}. \
             Function args summary: {function_args_hash}."
        )),
        Intent::Brc100Internalize {
            action_description,
            source,
            destination,
            protocol_notes,
            human_locale: _,
        } => Ok(format!(
            "Internalize action: {action_description}. \
             From: {source}. To: {destination}. \
             Notes: {protocol_notes}."
        )),
        Intent::Multi {
            outputs,
            human_locale: _,
        } => {
            let summaries: Vec<String> = outputs
                .iter()
                .map(|o| match o {
                    MultiOutput::Payment {
                        amount_satoshis,
                        recipient,
                    } => format!("Send {amount_satoshis} sats to {recipient}"),
                    MultiOutput::Fee { amount_satoshis } => {
                        format!("Fee output {amount_satoshis} sats")
                    }
                })
                .collect();
            let n = outputs.len();
            Ok(format!(
                "Compound transaction with {n} outputs: {}.",
                summaries.join("; ")
            ))
        }
    }
}

// ===========================================================================
// Approval signature + quorum collection (§09.5.1 steps 3-5, issue #43)
// ===========================================================================

use crate::error::{MpcError, Result};
use crate::policy::ApprovalQuorum;
use bsv::primitives::ec::{PrivateKey, PublicKey};

/// Domain-separation tag for the approval-signature preimage (§09.5.1 step 3).
/// **15 bytes** (`b"mpc-approval-v1"`), so the preimage is `32 + 15 + 32 = 79`
/// bytes — built from this literal, never a hardcoded length.
pub const APPROVAL_DOMAIN_TAG: &[u8] = b"mpc-approval-v1";

/// Build the approval-signature preimage (§09.5.1 step 3):
/// `request_view_hash ‖ "mpc-approval-v1" ‖ session_id` — binary concatenation,
/// no separators. The approver signs THIS (via BRC-77), binding their approval
/// to the exact rendered transaction view (`request_view_hash`, see
/// [`request_view_hash`]) AND this ceremony's `session_id` — closing the
/// approve-`policy_id`-alone replay/injection gap.
pub fn approval_preimage(request_view_hash: &[u8; 32], session_id: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + APPROVAL_DOMAIN_TAG.len() + 32);
    m.extend_from_slice(request_view_hash);
    m.extend_from_slice(APPROVAL_DOMAIN_TAG);
    m.extend_from_slice(session_id);
    m
}

/// Sign an approval over the §09.5.1 preimage using **BRC-77** (anyone-verifier
/// mode), with the approver's BRC-31 identity key. A valid signature is an
/// **Allow** vote — signing the view hash == approving the rendered view. Uses
/// `bsv-rs`' BRC-77 `messages::sign` (the same SDK the rest of bsv-mpc uses; NOT
/// rust-mpc's `bsv-sdk`).
pub fn sign_approval(
    request_view_hash: &[u8; 32],
    session_id: &[u8; 32],
    approver: &PrivateKey,
) -> Result<Vec<u8>> {
    let preimage = approval_preimage(request_view_hash, session_id);
    bsv::messages::sign(&preimage, approver, None)
        .map_err(|e| MpcError::Protocol(format!("BRC-77 approval sign: {e}")))
}

/// Verify a BRC-77 approval signature over the §09.5.1 preimage and, on success,
/// return the **signer's** compressed identity pubkey (parsed from the BRC-77
/// wire format `[version:4][sender:33][recipient:1|33][keyID:32][sig:DER]`). A
/// valid signature cryptographically binds that signer to this exact
/// `(request_view_hash, session_id)`. Returns `None` if the signature is invalid
/// or malformed. The caller checks the returned signer against the quorum's
/// `eligible` set ([`ApprovalCollector::record_vote`]).
pub fn verify_approval(
    request_view_hash: &[u8; 32],
    session_id: &[u8; 32],
    sig: &[u8],
) -> Option<Vec<u8>> {
    let preimage = approval_preimage(request_view_hash, session_id);
    // Anyone-verifier mode (signed with verifier=None ⇒ verify with recipient=None).
    match bsv::messages::verify(&preimage, sig, None) {
        Ok(true) => {
            // BRC-77 wire: sender pubkey is the 33 bytes after the 4-byte version.
            if sig.len() < 4 + 33 {
                return None;
            }
            let sender = &sig[4..4 + 33];
            // Sanity: it must parse as a valid compressed point.
            PublicKey::from_bytes(sender).ok()?;
            Some(sender.to_vec())
        }
        _ => None,
    }
}

/// An approver's decision (§09.5.1 step 4). An `Allow` is carried by a valid
/// approval signature; a `Deny` is carried in the BRC-31-authenticated response
/// envelope (the §09.5.1 signed preimage has no decision field — the envelope's
/// outer auth binds the deny to its sender).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// Approve the rendered view.
    Allow,
    /// Reject the rendered view.
    Deny,
}

/// The real-time approval status surfaced to the requester (§09.5.1 step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    /// Still collecting. `collected` Allow votes of `total` (= `k`) required.
    Pending {
        /// Allow votes collected so far.
        collected: u32,
        /// Required Allow votes (`quorum.k`).
        total: u32,
        /// Milliseconds remaining until the deadline.
        deadline_ms_remaining: u64,
        /// Eligible approvers (compressed pubkeys) who have voted (allow or deny).
        eligible_responded: Vec<Vec<u8>>,
    },
    /// `k` Allow votes collected — proceed to sign.
    Approved,
    /// `k` Deny votes collected — abort.
    Denied,
    /// Deadline elapsed before reaching `k` — abort (deny by silence).
    Expired,
}

/// Collects approver votes for a `RequireApproval` verdict until `k`-Allow
/// (Approved), `k`-Deny (Denied), or the deadline (Expired) — §09.5.1 step 4-5.
///
/// Pure state machine: time is supplied as `now_ms` (epoch-ms) by the caller (no
/// wall-clock read inside — deterministic + wasm-safe, same discipline as the
/// policy engine). Votes are deduplicated per signer (the first vote from an
/// eligible approver counts; later votes from the same signer are ignored).
#[derive(Debug, Clone)]
pub struct ApprovalCollector {
    quorum: ApprovalQuorum,
    request_view_hash: [u8; 32],
    session_id: [u8; 32],
    /// Absolute deadline (epoch-ms).
    deadline_ms: u64,
    /// Eligible signers (compressed pubkeys) who voted Allow (deduped).
    allows: Vec<Vec<u8>>,
    /// Eligible signers who voted Deny (deduped).
    denies: Vec<Vec<u8>>,
}

impl ApprovalCollector {
    /// Create a collector for a `RequireApproval` quorum. `deadline_ms` is the
    /// ABSOLUTE epoch-ms deadline (caller computes it from `now + ttl`).
    pub fn new(
        quorum: ApprovalQuorum,
        request_view_hash: [u8; 32],
        session_id: [u8; 32],
        deadline_ms: u64,
    ) -> Self {
        Self {
            quorum,
            request_view_hash,
            session_id,
            deadline_ms,
            allows: Vec::new(),
            denies: Vec::new(),
        }
    }

    /// The exact preimage approvers must sign for this collection.
    pub fn preimage(&self) -> Vec<u8> {
        approval_preimage(&self.request_view_hash, &self.session_id)
    }

    /// Record a vote whose `sig` is a BRC-77 approval signature over this
    /// collection's preimage. Verifies the signature, confirms the signer is in
    /// the quorum's `eligible` set, deduplicates, and tallies per `decision`.
    /// Returns the post-vote [`ApprovalStatus`] (`now_ms` for the deadline view).
    ///
    /// Errors if the signature is invalid/malformed or the signer is not
    /// eligible — a relay-injected or non-approver message is rejected, never
    /// silently counted.
    pub fn record_vote(
        &mut self,
        sig: &[u8],
        decision: ApprovalDecision,
        now_ms: u64,
    ) -> Result<ApprovalStatus> {
        let signer = verify_approval(&self.request_view_hash, &self.session_id, sig)
            .ok_or_else(|| MpcError::Protocol("invalid BRC-77 approval signature".into()))?;
        if !self.quorum.eligible.contains(&signer) {
            return Err(MpcError::Protocol(
                "approval signer is not in the quorum's eligible set".into(),
            ));
        }
        // Dedup: a signer's first vote (allow or deny) is final.
        let already = self.allows.contains(&signer) || self.denies.contains(&signer);
        if !already {
            match decision {
                ApprovalDecision::Allow => self.allows.push(signer),
                ApprovalDecision::Deny => self.denies.push(signer),
            }
        }
        Ok(self.status(now_ms))
    }

    /// Current status (§09.5.1 step 5). `k`-Allow → Approved; `k`-Deny → Denied;
    /// else past-deadline → Expired, otherwise Pending.
    pub fn status(&self, now_ms: u64) -> ApprovalStatus {
        let k = self.quorum.k;
        if self.allows.len() as u32 >= k {
            return ApprovalStatus::Approved;
        }
        if self.denies.len() as u32 >= k {
            return ApprovalStatus::Denied;
        }
        if now_ms >= self.deadline_ms {
            return ApprovalStatus::Expired;
        }
        let mut eligible_responded: Vec<Vec<u8>> = self.allows.clone();
        eligible_responded.extend(self.denies.iter().cloned());
        ApprovalStatus::Pending {
            collected: self.allows.len() as u32,
            total: k,
            deadline_ms_remaining: self.deadline_ms.saturating_sub(now_ms),
            eligible_responded,
        }
    }

    /// Whether the quorum is satisfied (`k` Allow votes) — proceed-to-sign gate.
    pub fn is_approved(&self) -> bool {
        self.allows.len() as u32 >= self.quorum.k
    }
}

/// **WebAuthn binding verification (§08.11, issue #43).** A WebAuthn-bound
/// approver MUST bind the passkey assertion to the rendered transaction view:
/// the `clientDataJSON.challenge` MUST equal the `request_view_hash`, AND the
/// assertion MUST have been made with `userVerification=required` (the UV flag in
/// `authenticatorData`). This closes the gap where a passkey gesture is harvested
/// for a DIFFERENT transaction than the one rendered.
///
/// This verifies the BINDING (challenge == view hash + UV flag set); the WebAuthn
/// assertion *signature* itself is verified by the platform passkey stack at the
/// client (full ceremony wiring lands with the #41 native shells). Given the raw
/// `clientDataJSON` bytes and the 37+-byte `authenticator_data`:
/// 1. parse `clientDataJSON`, require `type == "webauthn.get"`,
/// 2. base64url-decode (no padding) its `challenge` and require it to equal
///    `request_view_hash` (32 bytes),
/// 3. require the UV bit (0x04) set in `authenticator_data[32]` (flags).
pub fn verify_webauthn_approval(
    client_data_json: &[u8],
    authenticator_data: &[u8],
    request_view_hash: &[u8; 32],
) -> Result<()> {
    use base64::Engine;

    let cd: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|e| MpcError::Protocol(format!("clientDataJSON parse: {e}")))?;
    if cd.get("type").and_then(|t| t.as_str()) != Some("webauthn.get") {
        return Err(MpcError::Protocol(
            "WebAuthn clientDataJSON.type must be \"webauthn.get\"".into(),
        ));
    }
    let challenge_b64 = cd
        .get("challenge")
        .and_then(|c| c.as_str())
        .ok_or_else(|| MpcError::Protocol("WebAuthn clientDataJSON.challenge missing".into()))?;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(challenge_b64)
        .map_err(|e| MpcError::Protocol(format!("WebAuthn challenge base64url: {e}")))?;
    if challenge != request_view_hash {
        return Err(MpcError::Protocol(
            "WebAuthn challenge does not equal request_view_hash (§08.11 binding)".into(),
        ));
    }
    // authenticatorData: [0..32]=rpIdHash, [32]=flags. UV is bit 2 (0x04).
    let flags = authenticator_data
        .get(32)
        .ok_or_else(|| MpcError::Protocol("authenticatorData too short (no flags byte)".into()))?;
    if flags & 0x04 == 0 {
        return Err(MpcError::Protocol(
            "WebAuthn userVerification not performed (UV flag clear; §08.11 requires it)".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A reduced, self-contained vector to exercise the encoder shape without
    // depending on the full conformance fixture (that lives in
    // tests/conformance_09_rendered_text.rs).
    fn sample() -> RequestViewHash {
        request_view_hash(
            100,
            &Recipient::Single("1Bexample".into()),
            &"de".repeat(32),
            &"f2".repeat(32),
            &"00".repeat(32),
            &"00".repeat(64),
            "en-US",
            "Send 100 sats to 1Bexample.",
        )
    }

    #[test]
    fn map_header_and_first_key_are_canonical() {
        let r = sample();
        // 0xA8 = major type 5 (map), 8 pairs.
        assert_eq!(r.preimage[0], 0xA8);
        // First key is the single byte 0x01 (minimal uint 1).
        assert_eq!(r.preimage[1], 0x01);
    }

    #[test]
    fn changing_rendered_text_changes_the_hash() {
        let a = sample();
        let b = request_view_hash(
            100,
            &Recipient::Single("1Bexample".into()),
            &"de".repeat(32),
            &"f2".repeat(32),
            &"00".repeat(32),
            &"00".repeat(64),
            "en-US",
            "Send 100 sats to 1Bexample!", // one char differs
        );
        assert_ne!(a.hash, b.hash);
        assert_ne!(a.preimage, b.preimage);
    }

    #[test]
    fn single_vs_multi_recipient_differ() {
        let single = request_view_hash(
            75_000_000,
            &Recipient::Single("1A...".into()),
            &"de".repeat(32),
            &"f2".repeat(32),
            &"00".repeat(32),
            &"00".repeat(64),
            "en-US",
            "rendered",
        );
        let multi = request_view_hash(
            75_000_000,
            &Recipient::Multi(vec!["1A...".into(), "1B...".into()]),
            &"de".repeat(32),
            &"f2".repeat(32),
            &"00".repeat(32),
            &"00".repeat(64),
            "en-US",
            "rendered",
        );
        assert_ne!(single.hash, multi.hash);
        // Locate key 2 (byte 0x02) and inspect its value head. For `Single`
        // it's a text-string head (major type 3 → 0x60..0x7F); for `Multi` it's
        // an array head (major type 4 → 0x80..0x9F). amount 75000000 encodes as
        // 0x1a ‖ 4 bytes, so the key-2 byte sits at a fixed offset; we find it
        // structurally rather than hard-coding the index.
        let single_k2 = single.preimage.iter().position(|&b| b == 0x02).unwrap();
        let multi_k2 = multi.preimage.iter().position(|&b| b == 0x02).unwrap();
        // "1A..." is 5 bytes → text head 0x65.
        assert_eq!(single.preimage[single_k2 + 1], 0x65);
        // 2-element array → 0x82.
        assert_eq!(multi.preimage[multi_k2 + 1], 0x82);
    }

    #[test]
    fn hash_is_sha256_of_preimage() {
        let r = sample();
        let mut expect = [0u8; 32];
        expect.copy_from_slice(&Sha256::digest(&r.preimage));
        assert_eq!(r.hash, expect);
    }

    #[test]
    fn amount_uses_minimal_integer_encoding() {
        // amount 0 → single byte 0x00 as key-1's value (preimage[2]).
        let zero = request_view_hash(
            0,
            &Recipient::Single("x".into()),
            &"de".repeat(32),
            &"f2".repeat(32),
            &"00".repeat(32),
            &"00".repeat(64),
            "en-US",
            "r",
        );
        assert_eq!(zero.preimage[2], 0x00);
    }

    // ── Approval signature + quorum collector (§09.5.1) ──────────────────────

    use bsv::primitives::ec::PrivateKey;

    fn quorum(k: u32, eligible: &[&PrivateKey]) -> ApprovalQuorum {
        ApprovalQuorum {
            k,
            eligible: eligible
                .iter()
                .map(|p| p.public_key().to_compressed().to_vec())
                .collect(),
            deadline_secs: None,
        }
    }

    #[test]
    fn approval_preimage_is_79_bytes_view_tag_session() {
        let vh = [0x11u8; 32];
        let sid = [0x22u8; 32];
        let m = approval_preimage(&vh, &sid);
        // 32 (view hash) + 15 ("mpc-approval-v1") + 32 (session_id) = 79.
        assert_eq!(APPROVAL_DOMAIN_TAG.len(), 15);
        assert_eq!(m.len(), 79);
        assert_eq!(&m[0..32], &vh);
        assert_eq!(&m[32..47], b"mpc-approval-v1");
        assert_eq!(&m[47..79], &sid);
    }

    #[test]
    fn sign_then_verify_returns_signer() {
        let approver = PrivateKey::random();
        let vh = [0x42u8; 32];
        let sid = [0x07u8; 32];
        let sig = sign_approval(&vh, &sid, &approver).expect("sign");
        let signer = verify_approval(&vh, &sid, &sig).expect("verify returns signer");
        assert_eq!(signer, approver.public_key().to_compressed().to_vec());
    }

    #[test]
    fn verify_rejects_wrong_view_hash_or_session() {
        let approver = PrivateKey::random();
        let sig = sign_approval(&[0x42u8; 32], &[0x07u8; 32], &approver).expect("sign");
        // Different view hash → no signer.
        assert!(verify_approval(&[0x43u8; 32], &[0x07u8; 32], &sig).is_none());
        // Different session id → no signer.
        assert!(verify_approval(&[0x42u8; 32], &[0x08u8; 32], &sig).is_none());
    }

    #[test]
    fn collector_k_allow_approves() {
        let (a, b) = (PrivateKey::random(), PrivateKey::random());
        let vh = [0x42u8; 32];
        let sid = [0x07u8; 32];
        let mut c = ApprovalCollector::new(quorum(2, &[&a, &b]), vh, sid, 10_000);
        let sig_a = sign_approval(&vh, &sid, &a).unwrap();
        let sig_b = sign_approval(&vh, &sid, &b).unwrap();
        // One allow → still pending.
        let st = c.record_vote(&sig_a, ApprovalDecision::Allow, 0).unwrap();
        assert!(matches!(
            st,
            ApprovalStatus::Pending {
                collected: 1,
                total: 2,
                ..
            }
        ));
        assert!(!c.is_approved());
        // Second allow → approved.
        let st = c.record_vote(&sig_b, ApprovalDecision::Allow, 1).unwrap();
        assert_eq!(st, ApprovalStatus::Approved);
        assert!(c.is_approved());
    }

    #[test]
    fn collector_dedups_same_signer() {
        let a = PrivateKey::random();
        let vh = [0x42u8; 32];
        let sid = [0x07u8; 32];
        let mut c = ApprovalCollector::new(quorum(2, &[&a]), vh, sid, 10_000);
        let sig_a = sign_approval(&vh, &sid, &a).unwrap();
        c.record_vote(&sig_a, ApprovalDecision::Allow, 0).unwrap();
        // Same signer again — must NOT count twice toward k=2.
        let st = c.record_vote(&sig_a, ApprovalDecision::Allow, 1).unwrap();
        assert!(matches!(st, ApprovalStatus::Pending { collected: 1, .. }));
    }

    #[test]
    fn collector_rejects_non_eligible_signer() {
        let (eligible, outsider) = (PrivateKey::random(), PrivateKey::random());
        let vh = [0x42u8; 32];
        let sid = [0x07u8; 32];
        let mut c = ApprovalCollector::new(quorum(1, &[&eligible]), vh, sid, 10_000);
        let sig_out = sign_approval(&vh, &sid, &outsider).unwrap();
        let err = c
            .record_vote(&sig_out, ApprovalDecision::Allow, 0)
            .unwrap_err();
        assert!(format!("{err}").contains("not in the quorum"));
    }

    #[test]
    fn collector_k_deny_denies_and_deadline_expires() {
        let (a, b) = (PrivateKey::random(), PrivateKey::random());
        let vh = [0x42u8; 32];
        let sid = [0x07u8; 32];
        // k-deny → Denied.
        let mut c = ApprovalCollector::new(quorum(2, &[&a, &b]), vh, sid, 10_000);
        c.record_vote(
            &sign_approval(&vh, &sid, &a).unwrap(),
            ApprovalDecision::Deny,
            0,
        )
        .unwrap();
        let st = c
            .record_vote(
                &sign_approval(&vh, &sid, &b).unwrap(),
                ApprovalDecision::Deny,
                1,
            )
            .unwrap();
        assert_eq!(st, ApprovalStatus::Denied);
        // deadline → Expired (fresh collector, one allow, past the deadline).
        let mut c2 = ApprovalCollector::new(quorum(2, &[&a, &b]), vh, sid, 5_000);
        c2.record_vote(
            &sign_approval(&vh, &sid, &a).unwrap(),
            ApprovalDecision::Allow,
            0,
        )
        .unwrap();
        assert_eq!(c2.status(6_000), ApprovalStatus::Expired);
    }

    // ── WebAuthn binding (§08.11) ────────────────────────────────────────────

    use base64::Engine;

    /// Build a `clientDataJSON` for `webauthn.get` with `challenge` = base64url of
    /// `view_hash`, and `authenticator_data` with the UV flag set/clear.
    fn webauthn_inputs(view_hash: &[u8; 32], uv: bool) -> (Vec<u8>, Vec<u8>) {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(view_hash);
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://wallet.example"}}"#
        );
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = if uv { 0x05 } else { 0x01 }; // UP always; UV (0x04) iff uv
        (cdj.into_bytes(), auth_data)
    }

    #[test]
    fn webauthn_binding_accepts_matching_challenge_with_uv() {
        let vh = [0x42u8; 32];
        let (cdj, ad) = webauthn_inputs(&vh, true);
        assert!(verify_webauthn_approval(&cdj, &ad, &vh).is_ok());
    }

    #[test]
    fn webauthn_binding_rejects_wrong_challenge() {
        let vh = [0x42u8; 32];
        let (cdj, ad) = webauthn_inputs(&[0x99u8; 32], true); // challenge ≠ vh
        let err = verify_webauthn_approval(&cdj, &ad, &vh).unwrap_err();
        assert!(format!("{err}").contains("request_view_hash"));
    }

    #[test]
    fn webauthn_binding_rejects_missing_user_verification() {
        let vh = [0x42u8; 32];
        let (cdj, ad) = webauthn_inputs(&vh, false); // UV flag clear
        let err = verify_webauthn_approval(&cdj, &ad, &vh).unwrap_err();
        assert!(format!("{err}").contains("userVerification"));
    }

    #[test]
    fn webauthn_binding_rejects_wrong_type() {
        let vh = [0x42u8; 32];
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vh);
        let cdj = format!(r#"{{"type":"webauthn.create","challenge":"{challenge}"}}"#).into_bytes();
        let ad = {
            let mut a = vec![0u8; 37];
            a[32] = 0x05;
            a
        };
        assert!(verify_webauthn_approval(&cdj, &ad, &vh).is_err());
    }

    // ── ADR-0044 canonical wallet renderer (#75) ─────────────────────────────
    //
    // Per-kind positive cases here mirror the locked fixture vectors inline so
    // these unit tests stay self-contained; the byte-locked sweep over the full
    // fixture lives in `tests/conformance_09_canonical_render.rs`. Negative
    // cases assert the RIGHT rejection reason (not just any error) per the
    // partnership "validate, don't skip" rule.

    #[test]
    fn canonical_render_payment_matches_fixture() {
        let intent = Intent::Payment {
            amount_satoshis: 100_000_000,
            recipient_outputs: vec![PaymentOutput {
                script: "76a914abcdef...88ac".into(),
                value_sats: 100_000_000,
            }],
            human_address: "1A1zP1...EQK...".into(),
            fee_sats: 333,
            counterparty_identity: Counterparty {
                pubkey: "02abcd123456789012345678901234567890123456789012345678901234567890"
                    .into(),
                cert_name: None,
            },
            fiat_estimate: "$50.00".into(),
            fiat_currency: "USD".into(),
            human_locale: "en-US".into(),
        };
        let got = canonical_render(&intent).expect("render");
        assert_eq!(
            got,
            "Send 100000000 sats (~$50.00 USD) to 1A1zP1...EQK... with fee 333 sats. Counterparty: anonymous + 0x02abcd12..."
        );
    }

    #[test]
    fn canonical_render_payment_uses_cert_name_when_present() {
        // When `cert_name` is Some, it MUST be substituted in place of "anonymous".
        let intent = Intent::Payment {
            amount_satoshis: 100_000_000,
            recipient_outputs: vec![PaymentOutput {
                script: "76a914abcdef...88ac".into(),
                value_sats: 100_000_000,
            }],
            human_address: "1A1zP1...EQK...".into(),
            fee_sats: 333,
            counterparty_identity: Counterparty {
                pubkey: "02abcd123456789012345678901234567890123456789012345678901234567890"
                    .into(),
                cert_name: Some("alice@example".into()),
            },
            fiat_estimate: "$50.00".into(),
            fiat_currency: "USD".into(),
            human_locale: "en-US".into(),
        };
        let got = canonical_render(&intent).expect("render");
        assert_eq!(
            got,
            "Send 100000000 sats (~$50.00 USD) to 1A1zP1...EQK... with fee 333 sats. Counterparty: alice@example + 0x02abcd12..."
        );
    }

    #[test]
    fn canonical_render_token_transfer_matches_fixture() {
        let intent = Intent::TokenTransfer {
            token_amount: 100,
            token_symbol: "USDT-on-BSV".into(),
            recipient: "1B2y3z4a5b6c...K".into(),
            fiat_estimate: "$100.00".into(),
            fiat_currency: "USD".into(),
            token_contract_hash:
                "0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0".into(),
            human_locale: "en-US".into(),
        };
        let got = canonical_render(&intent).expect("render");
        assert_eq!(
            got,
            "Transfer 100 USDT-on-BSV tokens to 1B2y3z4a5b6c...K (value ~$100.00 USD). Token contract: 0x12345678..."
        );
    }

    #[test]
    fn canonical_render_token_transfer_strips_only_one_0x_prefix() {
        // A token_contract_hash carrying NO "0x" prefix must still render
        // identically — `trim_start_matches("0x")` strips only the prefix, the
        // first 8 hex chars are taken verbatim from the remainder.
        let intent = Intent::TokenTransfer {
            token_amount: 1,
            token_symbol: "TOK".into(),
            recipient: "1X".into(),
            fiat_estimate: "$1".into(),
            fiat_currency: "USD".into(),
            // no "0x" prefix
            token_contract_hash: "deadbeefcafebabe1234".into(),
            human_locale: "en-US".into(),
        };
        let got = canonical_render(&intent).expect("render");
        assert!(
            got.contains("Token contract: 0xdeadbeef..."),
            "without 0x prefix, first 8 chars are taken from the start: {got}"
        );
    }

    #[test]
    fn canonical_render_script_spend_matches_fixture() {
        let intent = Intent::ScriptSpend {
            covenant_address: "1C3z4a5b6c7d...K".into(),
            amount_satoshis: 10_000,
            function_name: "settle".into(),
            function_args_hash: "sha256:abababababababababababababababababababababababababababababababab".into(),
            human_locale: "en-US".into(),
        };
        let got = canonical_render(&intent).expect("render");
        assert_eq!(
            got,
            "Execute sCrypt covenant spend at contract 1C3z4a5b6c7d...K. Output value: 10000 sats. Covenant function: settle. Function args summary: sha256:abababababababababababababababababababababababababababababababab."
        );
    }

    #[test]
    fn canonical_render_brc100_internalize_matches_fixture() {
        let intent = Intent::Brc100Internalize {
            action_description: "payment-received".into(),
            source: "payee@example.com".into(),
            destination: "1D4y5z6a7b8c...K".into(),
            protocol_notes: "invoice 12345 paid".into(),
            human_locale: "en-US".into(),
        };
        let got = canonical_render(&intent).expect("render");
        assert_eq!(
            got,
            "Internalize action: payment-received. From: payee@example.com. To: 1D4y5z6a7b8c...K. Notes: invoice 12345 paid."
        );
    }

    #[test]
    fn canonical_render_multi_matches_fixture() {
        let intent = Intent::Multi {
            outputs: vec![
                MultiOutput::Payment {
                    amount_satoshis: 50_000_000,
                    recipient: "1A...".into(),
                },
                MultiOutput::Payment {
                    amount_satoshis: 25_000_000,
                    recipient: "1B...".into(),
                },
                MultiOutput::Fee {
                    amount_satoshis: 333,
                },
            ],
            human_locale: "en-US".into(),
        };
        let got = canonical_render(&intent).expect("render");
        assert_eq!(
            got,
            "Compound transaction with 3 outputs: Send 50000000 sats to 1A...; Send 25000000 sats to 1B...; Fee output 333 sats."
        );
    }

    // ── Negative cases — assert the RIGHT rejection reason ───────────────────

    /// A `kind` value that isn't one of the five MUST hard-reject — there is
    /// no fallback / default kind / partial-render mode (ADR-0044 §2.1).
    #[test]
    fn intent_deser_rejects_unknown_kind() {
        let bad = r#"{"kind":"airdrop","amount_satoshis":1,"recipient":"1X","human_locale":"en-US"}"#;
        let err = serde_json::from_str::<Intent>(bad).expect_err("unknown kind must reject");
        let msg = format!("{err}");
        // serde's tagged-enum error wording is "unknown variant `airdrop`".
        assert!(
            msg.contains("unknown variant") && msg.contains("airdrop"),
            "expected unknown-variant rejection, got: {msg}"
        );
    }

    /// A payment intent missing the required `human_address` field MUST
    /// hard-reject (ADR-0044 §2.3 amendment — `human_address` is required).
    #[test]
    fn intent_deser_rejects_missing_required_field() {
        let bad = r#"{
            "kind": "payment",
            "amount_satoshis": 100,
            "recipient_outputs": [{"script": "76a9...", "value_sats": 100}],
            "fee_sats": 1,
            "counterparty_identity": {"pubkey": "02abcd1234567890123456789012345678901234567890123456789012345678", "cert_name": null},
            "fiat_estimate": "$1",
            "fiat_currency": "USD",
            "human_locale": "en-US"
        }"#;
        let err = serde_json::from_str::<Intent>(bad).expect_err("missing field must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("missing field") && msg.contains("human_address"),
            "expected missing-field rejection naming `human_address`, got: {msg}"
        );
    }

    /// A payment intent carrying an extra field MUST hard-reject — silent
    /// ignore-extra is forbidden because cross-impl drift hides behind it
    /// (ADR-0044 §2.1).
    #[test]
    fn intent_deser_rejects_extra_field() {
        let bad = r#"{
            "kind": "payment",
            "amount_satoshis": 100,
            "recipient_outputs": [{"script": "76a9...", "value_sats": 100}],
            "human_address": "1X",
            "fee_sats": 1,
            "counterparty_identity": {"pubkey": "02abcd1234567890123456789012345678901234567890123456789012345678", "cert_name": null},
            "fiat_estimate": "$1",
            "fiat_currency": "USD",
            "human_locale": "en-US",
            "extra_field": "drift"
        }"#;
        let err = serde_json::from_str::<Intent>(bad).expect_err("extra field must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown field") && msg.contains("extra_field"),
            "expected unknown-field rejection naming `extra_field`, got: {msg}"
        );
    }

    /// A payment intent whose `amount_satoshis` is a string (not a u64) MUST
    /// hard-reject with a type-mismatch error from serde — there is no
    /// silent coercion.
    #[test]
    fn intent_deser_rejects_wrong_field_type() {
        let bad = r#"{
            "kind": "payment",
            "amount_satoshis": "100",
            "recipient_outputs": [{"script": "76a9...", "value_sats": 100}],
            "human_address": "1X",
            "fee_sats": 1,
            "counterparty_identity": {"pubkey": "02abcd1234567890123456789012345678901234567890123456789012345678", "cert_name": null},
            "fiat_estimate": "$1",
            "fiat_currency": "USD",
            "human_locale": "en-US"
        }"#;
        let err = serde_json::from_str::<Intent>(bad).expect_err("wrong type must reject");
        let msg = format!("{err}");
        // serde's wording: "invalid type: string \"100\", expected u64".
        assert!(
            msg.contains("invalid type") && msg.contains("u64"),
            "expected type-mismatch rejection naming u64, got: {msg}"
        );
    }

    /// A multi-output intent with a fee output carrying an unknown field MUST
    /// reject — the per-variant `deny_unknown_fields` applies inside the
    /// nested `MultiOutput` enum as well, not just on the top-level `Intent`.
    #[test]
    fn intent_deser_multi_rejects_extra_field_in_nested_output() {
        let bad = r#"{
            "kind": "multi",
            "outputs": [
                {"kind": "fee", "amount_satoshis": 333, "extra": "drift"}
            ],
            "human_locale": "en-US"
        }"#;
        let err = serde_json::from_str::<Intent>(bad)
            .expect_err("nested extra field must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown field") && msg.contains("extra"),
            "expected nested unknown-field rejection naming `extra`, got: {msg}"
        );
    }

    /// Sanity: a successfully-deserialized payment intent round-trips back to
    /// JSON without losing fields. This guards against accidental
    /// `#[serde(skip)]` regressions.
    #[test]
    fn intent_serde_round_trip_preserves_payment_fields() {
        let original = Intent::Payment {
            amount_satoshis: 12_345,
            recipient_outputs: vec![PaymentOutput {
                script: "76a9...".into(),
                value_sats: 12_345,
            }],
            human_address: "1A...".into(),
            fee_sats: 7,
            counterparty_identity: Counterparty {
                pubkey: "02".to_string() + &"ab".repeat(32),
                cert_name: Some("carol".into()),
            },
            fiat_estimate: "$0.01".into(),
            fiat_currency: "USD".into(),
            human_locale: "en-US".into(),
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let back: Intent = serde_json::from_str(&json).expect("deserialize round-trip");
        assert_eq!(original, back);
    }
}
