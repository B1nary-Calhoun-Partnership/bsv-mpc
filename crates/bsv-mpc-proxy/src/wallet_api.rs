//! BRC-100 endpoint handler implementations.
//!
//! Each function in this module corresponds to a single BRC-100 wallet
//! endpoint. The function signatures match what axum expects: they take
//! shared state and a JSON body, and return a JSON response.
//!
//! ## Handler categories
//!
//! ### MPC-routed (require KSS communication)
//!
//! - [`get_public_key`] — Returns the joint MPC public key (or a derived child key).
//! - [`create_signature`] — Initiates a 2PC ECDSA signing ceremony with the KSS.
//! - [`create_action`] — The big one: UTXO selection + tx construction + fee injection + MPC signing + broadcast.
//! - [`internalize_action`] — Accept an incoming payment by internalizing its outputs into the UTXO set.
//!
//! ### Local-only (no MPC rounds)
//!
//! - [`encrypt`] / [`decrypt`] — Symmetric encryption using a locally-derived key (BRC-42).
//! - [`create_hmac`] / [`verify_hmac`] — HMAC-SHA256 with locally-derived key.
//! - [`list_outputs`] / [`list_actions`] — Query the local UTXO tracker and action history.
//! - [`relinquish_output`] — Mark an output as spent/released.
//! - [`verify_signature`] — Pure ECDSA verification (no secret key needed).
//! - [`get_network`] / [`get_version`] / [`is_authenticated`] — Static metadata.
//! - Certificate and discovery endpoints — local storage or overlay forwarding.
//!
//! ## Error handling
//!
//! All handlers return `Json<Value>` to match the bsv-wallet-cli response
//! format. Errors are returned as JSON objects with an `"error"` field,
//! which is what bsv-worm's `wallet.rs` checks for.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::server::AppState;

// ─── Core signing (MPC) ─────────────────────────────────────────────────────

/// `POST /getPublicKey`
///
/// Returns the joint MPC public key, or a BRC-42 derived child key if
/// `protocolID` and `keyID` are specified in the request.
///
/// ## Request fields
///
/// - `identityKey` (bool) — If true, return the root identity key (no derivation).
/// - `protocolID` (array) — BRC-42 protocol identifier, e.g. `[2, "worm memory"]`.
/// - `keyID` (string) — Key identifier within the protocol.
/// - `counterparty` (string) — Counterparty public key or `"self"`.
/// - `forSelf` (bool) — Derive for self-encryption.
///
/// ## Response
///
/// ```json
/// { "publicKey": "02abc...def" }
/// ```
///
/// ## MPC involvement
///
/// For `identityKey: true`, returns the cached joint public key (no KSS call).
/// For derived keys, computes BIP-32 child derivation from the joint key using
/// BRC-42 invoice number construction. The child public key can be derived from
/// the joint public key alone — no MPC rounds needed for public key derivation.
pub async fn get_public_key(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. If body.identityKey is true, return state.bridge.joint_public_key() as hex\n\
         2. Otherwise, extract protocolID, keyID, counterparty from body\n\
         3. Construct BRC-42 invoice number from protocolID + keyID\n\
         4. Derive child public key from joint key using SLIP-10/BIP-32\n\
         5. Return {{ \"publicKey\": \"<hex>\" }}"
    )
}

/// `POST /createSignature`
///
/// Signs a message hash using the 2-party CGGMP'24 threshold ECDSA protocol.
/// This is the core MPC operation — it requires communication with the KSS.
///
/// ## Request fields
///
/// - `data` (string, hex) — The data to sign (typically a sighash).
/// - `protocolID` (array) — BRC-42 protocol for key derivation.
/// - `keyID` (string) — Key identifier for derivation.
/// - `counterparty` (string) — Counterparty for key derivation.
///
/// ## Response
///
/// ```json
/// { "signature": "3044..." }
/// ```
///
/// ## MPC flow
///
/// 1. Check presignature pool — if available, use single-round online signing.
/// 2. Otherwise, run the full 4-round interactive protocol with the KSS.
/// 3. Return the DER-encoded ECDSA signature.
///
/// Presignature signing takes ~50-100ms. Full protocol takes ~300-500ms.
pub async fn create_signature(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse data, protocolID, keyID, counterparty from body\n\
         2. Compute message hash (SHA-256 of data if not already 32 bytes)\n\
         3. Derive child share using BRC-42 derivation path\n\
         4. Try to take a presignature from the pool\n\
         5. Call state.bridge.sign(hash, presignature) for 2PC with KSS\n\
         6. Return {{ \"signature\": \"<DER hex>\" }}"
    )
}

/// `POST /verifySignature`
///
/// Verify an ECDSA signature against a public key and message. This is a
/// purely local operation — no MPC rounds or KSS communication needed.
///
/// ## Request fields
///
/// - `data` (string, hex) — The signed data.
/// - `signature` (string, hex) — DER-encoded ECDSA signature.
/// - `protocolID` (array) — BRC-42 protocol for key derivation.
/// - `keyID` (string) — Key identifier.
/// - `counterparty` (string) — Counterparty public key.
/// - `forSelf` (bool) — Whether the signature was for self.
///
/// ## Response
///
/// ```json
/// { "valid": true }
/// ```
pub async fn verify_signature(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse signature, data, and key derivation params from body\n\
         2. Derive the expected public key using BRC-42 derivation\n\
         3. Verify the ECDSA signature using the BSV SDK\n\
         4. Return {{ \"valid\": true/false }}"
    )
}

/// `POST /createAction`
///
/// The primary transaction-building endpoint. This is what bsv-worm calls for
/// every on-chain operation: creating proofs, state tokens, payments, etc.
///
/// ## Request fields
///
/// - `description` (string) — Human-readable action description.
/// - `inputs` (array) — Input specifications with UTXO references and unlock templates.
/// - `outputs` (array) — Output specifications with locking scripts, satoshi amounts, baskets, and tags.
/// - `labels` (array) — Action labels for categorization.
/// - `options` (object) — Optional: `signAndProcess`, `acceptDelayedBroadcast`, `trustSelf`, etc.
///
/// ## Response
///
/// ```json
/// {
///   "txid": "abc123...",
///   "tx": { "rawTx": "0100...", "txid": "abc123..." },
///   "outputMap": [...],
///   "mapiResponses": [...]
/// }
/// ```
///
/// ## Processing pipeline
///
/// 1. **UTXO selection**: Select inputs from the local UTXO set matching the request.
/// 2. **Transaction construction**: Build the unsigned transaction with requested outputs.
/// 3. **Fee injection**: If enabled, add MPC signing fee output via `FeeInjector`.
/// 4. **Fee calculation**: Compute miner fee based on transaction size.
/// 5. **Change output**: Add change output if needed.
/// 6. **MPC signing**: For each input, derive the child key and run 2PC signing with KSS.
///    Uses presignatures when available for single-round signing.
/// 7. **Broadcast**: Submit the signed transaction to the BSV network.
/// 8. **UTXO update**: Mark spent inputs, add new outputs to the local tracker.
///
/// This is the most complex handler — it orchestrates UTXO management, fee
/// injection, multiple MPC signing rounds (one per input), and broadcasting.
pub async fn create_action(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse description, inputs, outputs, labels, options from body\n\
         2. Select UTXOs from local tracker for inputs\n\
         3. Build unsigned transaction with requested outputs\n\
         4. If fee_injector.is_enabled(), add MPC fee output\n\
         5. Calculate miner fee, add change output if needed\n\
         6. For each input:\n\
            a. Derive child share using BRC-42 derivation from input's protocolID/keyID\n\
            b. Compute sighash for this input\n\
            c. Try to take a presignature from the pool\n\
            d. Call bridge.sign(sighash, presignature) for 2PC with KSS\n\
            e. Apply signature to transaction input\n\
         7. Serialize signed transaction\n\
         8. Broadcast to BSV network\n\
         9. Update local UTXO set (mark spent inputs, track new outputs)\n\
         10. Return txid, rawTx, outputMap"
    )
}

/// `POST /internalizeAction`
///
/// Accept an incoming payment or BEEF envelope by internalizing its outputs
/// into the local UTXO set. Used by bsv-worm for:
/// - Funding transactions (receiving BSV)
/// - x402 refund internalization
/// - AtomicBEEF payment receipt processing
///
/// ## Request fields
///
/// - `tx` (object) — Transaction data with `rawTx` or BEEF envelope.
/// - `outputs` (array) — Which outputs to internalize, with baskets and tags.
/// - `description` (string) — Human-readable description.
/// - `labels` (array) — Action labels.
///
/// ## Response
///
/// ```json
/// { "accepted": true, "txid": "abc123..." }
/// ```
///
/// ## Processing
///
/// 1. Parse and validate the transaction/BEEF envelope.
/// 2. Verify that claimed outputs are actually payable to our key(s).
/// 3. Add verified outputs to the local UTXO tracker with specified baskets/tags.
/// 4. No MPC signing needed — this is a receive operation.
pub async fn internalize_action(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse tx (rawTx or BEEF), outputs, description, labels from body\n\
         2. Deserialize and validate the transaction\n\
         3. For each output to internalize:\n\
            a. Verify the locking script pays to a key we control\n\
            b. Derive the expected public key using BRC-42 derivation\n\
            c. Check script matches P2PKH of derived key\n\
         4. Add verified outputs to local UTXO tracker with baskets/tags\n\
         5. Return {{ \"accepted\": true, \"txid\": \"...\" }}"
    )
}

// ─── Encryption (local) ─────────────────────────────────────────────────────

/// `POST /encrypt`
///
/// Encrypt data using a locally-derived symmetric key. No MPC rounds needed —
/// the encryption key is derived via BRC-42 from this party's share alone
/// (the symmetric key derivation path is deterministic from the share).
///
/// ## Request fields
///
/// - `plaintext` (string, base64) — Data to encrypt.
/// - `protocolID` (array) — BRC-42 protocol for key derivation.
/// - `keyID` (string) — Key identifier.
/// - `counterparty` (string) — Counterparty public key or `"self"`.
///
/// ## Response
///
/// ```json
/// { "ciphertext": "<base64>" }
/// ```
pub async fn encrypt(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse plaintext, protocolID, keyID, counterparty from body\n\
         2. Derive symmetric key using BRC-42 from local share\n\
         3. Generate random 12-byte nonce\n\
         4. Encrypt with AES-256-GCM\n\
         5. Return {{ \"ciphertext\": \"<base64(nonce || ciphertext || tag)>\" }}"
    )
}

/// `POST /decrypt`
///
/// Decrypt data using a locally-derived symmetric key. Inverse of `encrypt`.
///
/// ## Request fields
///
/// - `ciphertext` (string, base64) — Data to decrypt (nonce || ciphertext || tag).
/// - `protocolID` (array) — BRC-42 protocol for key derivation.
/// - `keyID` (string) — Key identifier.
/// - `counterparty` (string) — Counterparty public key or `"self"`.
///
/// ## Response
///
/// ```json
/// { "plaintext": "<base64>" }
/// ```
pub async fn decrypt(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse ciphertext, protocolID, keyID, counterparty from body\n\
         2. Derive symmetric key using BRC-42 from local share\n\
         3. Split ciphertext into nonce (12 bytes) + ciphertext + tag (16 bytes)\n\
         4. Decrypt with AES-256-GCM\n\
         5. Return {{ \"plaintext\": \"<base64>\" }}"
    )
}

/// `POST /createHmac`
///
/// Compute HMAC-SHA256 using a locally-derived key.
///
/// ## Request fields
///
/// - `data` (string, base64) — Data to HMAC.
/// - `protocolID` (array) — BRC-42 protocol for key derivation.
/// - `keyID` (string) — Key identifier.
/// - `counterparty` (string) — Counterparty public key or `"self"`.
///
/// ## Response
///
/// ```json
/// { "hmac": "<hex>" }
/// ```
pub async fn create_hmac(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse data, protocolID, keyID, counterparty from body\n\
         2. Derive HMAC key using BRC-42 from local share\n\
         3. Compute HMAC-SHA256(key, data)\n\
         4. Return {{ \"hmac\": \"<hex>\" }}"
    )
}

/// `POST /verifyHmac`
///
/// Verify an HMAC-SHA256 against a locally-derived key.
///
/// ## Request fields
///
/// - `data` (string, base64) — Original data.
/// - `hmac` (string, hex) — HMAC to verify.
/// - `protocolID` (array) — BRC-42 protocol for key derivation.
/// - `keyID` (string) — Key identifier.
/// - `counterparty` (string) — Counterparty public key or `"self"`.
///
/// ## Response
///
/// ```json
/// { "valid": true }
/// ```
pub async fn verify_hmac(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse data, hmac, protocolID, keyID, counterparty from body\n\
         2. Derive HMAC key using BRC-42 from local share\n\
         3. Compute HMAC-SHA256(key, data)\n\
         4. Constant-time compare with provided hmac\n\
         5. Return {{ \"valid\": true/false }}"
    )
}

// ─── UTXO management ────────────────────────────────────────────────────────

/// `POST /listOutputs`
///
/// Query the local UTXO set. Supports filtering by basket (BRC-46), tags,
/// and spending status.
///
/// ## Request fields
///
/// - `basket` (string) — BRC-46 basket name to filter by.
/// - `tags` (array) — Tags to filter by.
/// - `tagQueryMode` (string) — `"all"` or `"any"` for tag filtering.
/// - `include` (string) — `"locking scripts"`, `"entire transactions"`.
/// - `includeCustomInstructions` (bool) — Include custom instructions field.
/// - `includeBasket` (bool) — Include basket name in output.
/// - `includeTags` (bool) — Include tags in output.
/// - `includeLabels` (bool) — Include labels.
/// - `limit` (number) — Max results.
/// - `offset` (number) — Pagination offset.
///
/// ## Response
///
/// ```json
/// {
///   "totalOutputs": 42,
///   "BEEF": "...",
///   "outputs": [{ "outpoint": "txid.vout", "satoshis": 1000, ... }]
/// }
/// ```
pub async fn list_outputs(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse basket, tags, tagQueryMode, include, limit, offset from body\n\
         2. Query local UTXO tracker with filters\n\
         3. If include == 'locking scripts', include scriptPubKey for each output\n\
         4. If include == 'entire transactions', include full BEEF envelope\n\
         5. Return {{ \"totalOutputs\": N, \"outputs\": [...] }}"
    )
}

/// `POST /listActions`
///
/// Query the action (transaction) history. Returns a list of past actions
/// with their descriptions, labels, inputs, outputs, and status.
///
/// ## Request fields
///
/// - `labels` (array) — Filter by action labels.
/// - `labelQueryMode` (string) — `"all"` or `"any"`.
/// - `includeLabels` (bool) — Include labels in response.
/// - `includeInputs` (bool) — Include input details.
/// - `includeOutputs` (bool) — Include output details.
/// - `limit` (number) — Max results.
/// - `offset` (number) — Pagination offset.
///
/// ## Response
///
/// ```json
/// {
///   "totalActions": 100,
///   "actions": [{ "txid": "...", "description": "...", ... }]
/// }
/// ```
pub async fn list_actions(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse labels, labelQueryMode, include flags, limit, offset from body\n\
         2. Query local action history with filters\n\
         3. Optionally include inputs/outputs/labels per action\n\
         4. Return {{ \"totalActions\": N, \"actions\": [...] }}"
    )
}

/// `POST /relinquishOutput`
///
/// Mark an output as relinquished (no longer tracked). The output's UTXO
/// is removed from the local tracker. Used for cleaning up state tokens,
/// releasing basket outputs, etc.
///
/// ## Request fields
///
/// - `basket` (string) — Basket containing the output.
/// - `output` (string) — Outpoint reference (`txid.vout`).
///
/// ## Response
///
/// ```json
/// { "relinquished": true }
/// ```
pub async fn relinquish_output(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse basket and output (outpoint) from body\n\
         2. Find the output in the local UTXO tracker\n\
         3. Mark it as relinquished / remove from tracker\n\
         4. Return {{ \"relinquished\": true }}"
    )
}

// ─── Identity & auth ────────────────────────────────────────────────────────

/// `POST /getNetwork`
///
/// Returns the BSV network this proxy operates on.
///
/// ## Response
///
/// ```json
/// { "network": "mainnet" }
/// ```
pub async fn get_network(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    // Static response — MPC proxy always operates on mainnet.
    Json(json!({ "network": "mainnet" }))
}

/// `POST /getVersion`
///
/// Returns the proxy version, presenting itself as a BRC-100 wallet.
///
/// ## Response
///
/// ```json
/// { "version": "bsv-mpc-proxy 0.1.0" }
/// ```
pub async fn get_version(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    Json(json!({
        "version": format!("bsv-mpc-proxy {}", env!("CARGO_PKG_VERSION"))
    }))
}

/// `POST /isAuthenticated`
///
/// Returns whether the proxy is initialized and ready to sign.
///
/// ## Response
///
/// ```json
/// { "authenticated": true }
/// ```
///
/// The proxy is "authenticated" once the share file has been loaded and
/// decrypted successfully (which happens at startup).
pub async fn is_authenticated(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    // If we got this far, the share is loaded and the bridge is initialized.
    Json(json!({ "authenticated": true }))
}

// ─── Certificates ───────────────────────────────────────────────────────────

/// `POST /listCertificates`
///
/// List certificates stored in the local certificate store. Supports filtering
/// by certifier and certificate type.
///
/// ## Request fields
///
/// - `certifiers` (array) — Filter by certifier public keys.
/// - `types` (array) — Filter by certificate type IDs.
/// - `limit` (number) — Max results.
/// - `offset` (number) — Pagination offset.
///
/// ## Response
///
/// ```json
/// {
///   "totalCertificates": 3,
///   "certificates": [{ "type": "...", "certifier": "...", "fields": {...} }]
/// }
/// ```
pub async fn list_certificates(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse certifiers, types, limit, offset from body\n\
         2. Query local certificate store with filters\n\
         3. Return {{ \"totalCertificates\": N, \"certificates\": [...] }}"
    )
}

/// `POST /proveCertificate`
///
/// Create a selective disclosure proof of a certificate. Reveals only the
/// requested fields to a specific verifier.
///
/// ## Request fields
///
/// - `certificate` (object) — The certificate to prove.
/// - `fieldsToReveal` (array) — Which fields to include in the proof.
/// - `verifier` (string) — Public key of the verifier.
///
/// ## Response
///
/// ```json
/// { "keyringForVerifier": {...} }
/// ```
pub async fn prove_certificate(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse certificate, fieldsToReveal, verifier from body\n\
         2. For each field to reveal, derive the field-specific encryption key\n\
         3. Create keyring entries that let the verifier decrypt those fields\n\
         4. Return {{ \"keyringForVerifier\": {{...}} }}"
    )
}

/// `POST /acquireCertificate`
///
/// Acquire a new certificate, either by direct issuance or from a certifier.
///
/// ## Request fields
///
/// - `type` (string) — Certificate type ID.
/// - `certifier` (string) — Public key of the certifier.
/// - `fields` (object) — Certificate field values.
/// - `acquisitionProtocol` (string) — `"direct"` or `"issuance"`.
///
/// ## Response
///
/// ```json
/// { "certificate": { "type": "...", "certifier": "...", ... } }
/// ```
pub async fn acquire_certificate(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse type, certifier, fields, acquisitionProtocol from body\n\
         2. If direct: store certificate locally with encrypted fields\n\
         3. If issuance: contact certifier to obtain signed certificate\n\
         4. Encrypt field values using BRC-42 derived keys\n\
         5. Store in local certificate store\n\
         6. Return the acquired certificate"
    )
}

/// `POST /relinquishCertificate`
///
/// Remove a certificate from the local store.
///
/// ## Request fields
///
/// - `type` (string) — Certificate type ID.
/// - `certifier` (string) — Certifier public key.
/// - `serialNumber` (string) — Certificate serial number.
///
/// ## Response
///
/// Empty body on success (matches bsv-wallet-cli behavior).
pub async fn relinquish_certificate(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse type, certifier, serialNumber from body\n\
         2. Find the certificate in local store\n\
         3. Remove it\n\
         4. Return empty object (bsv-wallet-cli returns empty body)"
    )
}

// ─── Discovery ──────────────────────────────────────────────────────────────

/// `POST /discoverByIdentityKey`
///
/// Discover a peer by their identity public key via the overlay network.
///
/// ## Request fields
///
/// - `identityKey` (string) — The public key to look up.
///
/// ## Response
///
/// ```json
/// {
///   "totalCertificates": 1,
///   "certificates": [{ "certifier": "...", "fields": {...} }]
/// }
/// ```
pub async fn discover_by_identity_key(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse identityKey from body\n\
         2. Forward discovery request to overlay network\n\
         3. Return matching certificates"
    )
}

/// `POST /discoverByAttributes`
///
/// Discover peers by certificate attributes via the overlay network.
///
/// ## Request fields
///
/// - `attributes` (object) — Key-value pairs to search for.
///
/// ## Response
///
/// ```json
/// {
///   "totalCertificates": 5,
///   "certificates": [...]
/// }
/// ```
pub async fn discover_by_attributes(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse attributes from body\n\
         2. Forward discovery request to overlay network\n\
         3. Return matching certificates"
    )
}

// ─── Key linkage ────────────────────────────────────────────────────────────

/// `POST /revealCounterpartyKeyLinkage`
///
/// Reveal the BRC-42 key linkage for a specific counterparty, allowing a
/// third-party auditor to derive all keys used with that counterparty.
///
/// ## Request fields
///
/// - `counterparty` (string) — The counterparty public key.
/// - `verifier` (string) — The auditor's public key.
/// - `protocolID` (array) — The BRC-42 protocol.
/// - `keyID` (string) — The key identifier.
///
/// ## Response
///
/// ```json
/// { "revelationKeyring": {...}, "prover": "..." }
/// ```
pub async fn reveal_counterparty_key_linkage(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse counterparty, verifier, protocolID, keyID from body\n\
         2. Derive the counterparty linkage key from local share\n\
         3. Encrypt the linkage key for the verifier\n\
         4. Return revelation keyring"
    )
}

/// `POST /revealSpecificKeyLinkage`
///
/// Reveal the BRC-42 key linkage for a specific protocol/keyID/counterparty
/// combination. More targeted than counterparty linkage — reveals only one
/// derived key relationship.
///
/// ## Request fields
///
/// - `counterparty` (string) — The counterparty public key.
/// - `verifier` (string) — The auditor's public key.
/// - `protocolID` (array) — The BRC-42 protocol.
/// - `keyID` (string) — The key identifier.
///
/// ## Response
///
/// ```json
/// { "revelationKeyring": {...}, "prover": "..." }
/// ```
pub async fn reveal_specific_key_linkage(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    todo!(
        "1. Parse counterparty, verifier, protocolID, keyID from body\n\
         2. Derive the specific key linkage from local share\n\
         3. Encrypt for the verifier\n\
         4. Return revelation keyring"
    )
}

// ─── Health ─────────────────────────────────────────────────────────────────

/// `GET /health`
///
/// Liveness check for load balancers, monitoring systems, and bsv-worm's
/// startup health check.
///
/// ## Response
///
/// ```json
/// {
///   "status": "ok",
///   "version": "bsv-mpc-proxy 0.1.0",
///   "presignatures_available": 15,
///   "kss_url": "https://kss.lobsterfarm.com"
/// }
/// ```
pub async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    let presig_count = state.presign_manager.read().await.len();

    Json(json!({
        "status": "ok",
        "version": format!("bsv-mpc-proxy {}", env!("CARGO_PKG_VERSION")),
        "presignatures_available": presig_count,
        "kss_url": state.config.kss_url,
        "fee_per_signing_sats": state.config.fee_per_signing,
    }))
}
