# bsv-mpc Threat Model

> Systematic analysis of threats to the MPC threshold signing network.
> Covers Alpha (2-of-2), Beta (2-of-3 + browser DKG), and GA (3-of-5 + overlay).
> All claims reference validated POC code or BRC specifications.

---

## 1. Assets

What we are protecting, ranked by criticality.

| Asset | Description | Compromise Impact |
|-------|-------------|-------------------|
| **Private key shares** | Each party's scalar share of the joint secp256k1 signing key. Stored encrypted (AES-256-GCM) with BRC-42-derived keys. | Share theft enables signing if attacker also obtains a second share (2-of-2) or reaches threshold. |
| **Joint private key** | The reconstructed secret `F(0)`. Never exists in memory or on disk -- computed implicitly during threshold signing. | Total fund loss. This is the asset the entire system exists to protect. |
| **Presignatures** | Pre-computed nonce commitments stored in FIFO pools (proxy and KSS). Each is single-use. | Reuse of a presignature with two different messages leaks the private key (nonce reuse attack). |
| **Protocol session state** | Intermediate values during DKG, signing, and presigning rounds. Stored between HTTP requests on the KSS. | State manipulation could cause protocol abort or, in adversarial settings, bias key generation. |
| **User funds (UTXOs)** | BSV outputs controlled by the joint MPC public key. | Direct financial loss. |
| **Agent identity key** | BRC-31 identity key used for mutual authentication between proxy and KSS. | Impersonation -- attacker can request signatures from the KSS as the compromised agent. |
| **Share encryption key** | Derived via `HMAC-SHA256(root_key, "bsv-mpc-share" || session_id)`. Used for AES-256-GCM share encryption. | Decryption of stored shares, reducing the attack to share theft. |
| **Fee pool UTXOs** | Accumulated MPC signing fees awaiting settlement among node operators. | Theft of operator revenue (not user funds). |

---

## 2. Trust Boundaries

```
+------------------------------------------------------------------+
|  Agent Container (user-controlled or platform-hosted)            |
|  +-----------------------------+  +---------------------------+  |
|  | bsv-worm (agent loop)       |  | MPC Signing Proxy         |  |
|  | Calls localhost:3322        |  | share_B, presig pool,     |  |
|  | Unchanged BRC-100 client    |  | fee injector, UTXO tracker|  |
|  +-----------------------------+  +-----|---------------------+  |
+--------------------------------------------|-----------------------+
                                             | HTTPS (BRC-31 auth)
                                             | Trust boundary 1
+--------------------------------------------|-----------------------+
|  Key Share Service (separate infrastructure)                      |
|  +------------------------------+                                 |
|  | bsv-mpc-worker (CF Worker)   |                                 |
|  | OR bsv-mpc-service (standalone)|                               |
|  | share_A, protocol state,     |                                 |
|  | presignatures                |                                 |
|  +------------------------------+                                 |
+-------------------------------------------------------------------+
                    |                              |
                    | Trust boundary 2             | Trust boundary 3
                    v                              v
+-------------------+---+          +---------------+---------------+
| BSV Overlay Network   |          | BSV Blockchain (Mainnet)      |
| SHIP/SLAP trackers    |          | Miners, ARC broadcasters      |
| CHIP token discovery  |          | Merkle proofs, BEEF           |
| tm_mpc_signing topic  |          |                               |
+-------------------+---+          +-------------------------------+
```

**Trust boundary 1 (Proxy <-> KSS):** The most security-critical boundary. All MPC protocol messages cross here. Protected by HTTPS + BRC-31 mutual authentication. As of bsv-mpc #8 (Phase D), BRC-31 is implemented end-to-end on the canonical @bsv wire across all three crates: proxy uses `bsv_rs::auth::Peer`, the standalone service uses `bsv-middleware-rs`, and the CF Worker uses `bsv-middleware-cloudflare`. Owner-authorization, per-request replay-nonce consumption (§07.1), and header-vs-session identity binding (§07) are all enforced.

**Trust boundary 2 (KSS <-> Overlay):** Node discovery and participation proof publication. Lower sensitivity -- overlay data is public by design.

**Trust boundary 3 (Proxy <-> Blockchain):** Transaction broadcasting, UTXO queries, merkle proof fetching. Standard BSV network trust model.

**Intra-container boundary (worm <-> proxy):** localhost:3322. Currently no authentication -- the proxy trusts any caller on localhost. This is acceptable when both run in the same container.

---

## 3. Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| **Malicious platform operator** | Full access to agent container (share_B, proxy memory, network traffic). Cannot access KSS infrastructure. | Steal agent funds by combining share_B with a compromised or colluding KSS. |
| **Compromised KSS operator** | Access to share_A (encrypted), protocol state, presignatures. Cannot access agent container. | Steal agent funds by combining share_A with a compromised proxy. Deny service by refusing to participate. |
| **Network attacker (MITM)** | Intercept and modify traffic between proxy and KSS. Cannot break TLS without CA compromise. | Inject malicious protocol messages, replay old sessions, deny service. |
| **Malicious MPC node (GA)** | One of n parties in a multi-party configuration. Follows the protocol selectively. | Extract information from protocol transcripts, cause protocol aborts, grief other participants. |
| **Rogue agent** | Controls the agent container. Attempts to drain its own funds faster than expected or attack other agents sharing the same KSS. | Cross-agent share access, resource exhaustion on KSS. |
| **External attacker** | No pre-existing access. Targets publicly exposed KSS endpoints, overlay network, or BSV transactions. | Exploit unauthenticated endpoints, overlay poisoning, transaction manipulation. |

---

## 4. Attack Surface by Phase

### 4.1 Alpha (Current): 2-of-2, Single KSS

The simplest configuration. One proxy holds share_B, one KSS holds share_A. Both must cooperate for any signature.

#### ATTACK A1: Single KSS Compromise

| Field | Detail |
|-------|--------|
| **Description** | Attacker gains access to the KSS infrastructure and extracts share_A (encrypted). If they also obtain the share encryption key (derived from the agent's root key), they can decrypt share_A. Combined with share_B from a separate compromise, the full private key is reconstructable. |
| **Preconditions** | KSS infrastructure breach + encryption key theft (or weak key derivation). |
| **Impact** | **Critical.** Total fund loss for affected agents. In 2-of-2, compromising both shares is sufficient. |
| **Mitigation (current)** | Shares encrypted at rest with AES-256-GCM. KSS runs on separate infrastructure (separate accounts for defense-in-depth). Encryption key derived via BRC-42 HMAC-SHA256 from agent's root key -- attacker needs the root key too. |
| **Mitigation (Beta)** | Move to 2-of-3. Even with KSS compromise, attacker needs a second share. |
| **Residual risk** | In Alpha, this is the primary existential risk. The 2-of-2 setup means any two-share compromise is game over. |

#### ATTACK A2: Share Theft from Agent Container

| Field | Detail |
|-------|--------|
| **Description** | Attacker compromises the agent container and reads `share.enc` from disk or extracts the decrypted share from proxy memory. |
| **Preconditions** | Container compromise (host access, container escape, or insider). |
| **Impact** | **High.** Attacker has share_B. Must still obtain share_A for signing, but one share is now exposed. |
| **Mitigation (current)** | Share file encrypted with AES-256-GCM. Decrypted share exists only in proxy process memory while running. `MPC_ENCRYPTION_KEY` env var provides the decryption key. |
| **Mitigation (planned)** | Hardware-backed key storage (e.g., TEE/SGX) for share decryption keys. Memory zeroization on drop for share material. |
| **Residual risk** | A sufficiently privileged attacker (root on the host) can read process memory. This is inherent to any software-only solution. |

#### ATTACK A3: Replay Attacks on Signing Sessions

| Field | Detail |
|-------|--------|
| **Description** | Attacker captures protocol messages from a previous signing session and replays them to the KSS to obtain a signature on a different message. |
| **Preconditions** | Network traffic capture (TLS termination or compromised logging). |
| **Impact** | **Low.** CGGMP'24 binds each signing session to a unique `ExecutionId` derived from `SHA-256("bsv-mpc-signing-" || session_id)`. Replayed messages fail validation because the execution context differs. |
| **Mitigation (current)** | Unique `ExecutionId` per session. Each signing ceremony uses fresh randomness (`OsRng`). TLS protects the transport. |
| **Residual risk** | Minimal. The protocol is designed to prevent replay by construction. |

#### ATTACK A4: Man-in-the-Middle on Proxy-KSS Channel

| Field | Detail |
|-------|--------|
| **Description** | Attacker intercepts HTTPS traffic between proxy and KSS, modifying protocol messages to cause signing of attacker-chosen messages. |
| **Preconditions** | TLS interception (compromised CA, DNS hijacking, or proxy misconfiguration). |
| **Impact** | **Critical.** If the attacker can modify the sighash sent to the KSS, they can redirect funds to their own address. |
| **Mitigation (current)** | HTTPS with TLS 1.3 (reqwest with rustls-tls) **plus** BRC-31 mutual authentication on all KSS mutation endpoints (bsv-mpc #8, Phase D). The KSS verifies the canonical @bsv BRC-31 signature over the request payload before processing; a modified sighash invalidates the General-message signature, so the request is rejected (401) independently of TLS. BRC-31 thus provides message-level integrity that survives a TLS terminator or CA compromise. |
| **Mitigation (deployed)** | Canonical BRC-31 wire is live: proxy uses `bsv_rs::auth::Peer`, service uses `bsv-middleware-rs`, worker uses `bsv-middleware-cloudflare` (deployed worker `f232a13a`, container standard-4). Proven on mainnet with a real-sats MPC-signed transaction: WhatsOnChain TXID `96c2ebc592c77bab2fc3fba47993bc6638ec248c7f90caf68ba7fddb3cdabcfd`. |
| **Residual risk** | Low. Message-level integrity is now enforced. Residual risk reduces to identity-key compromise (an attacker who steals an authorized identity key can pass BRC-31) and the not-yet-implemented BRC-52 cosigner-certificate verification (§08.12) + policy-manifest enforcement (§09), which are a follow-on authorization layer above the auth layer. |

#### ATTACK A5: Presignature Reuse (Nonce Reuse)

| Field | Detail |
|-------|--------|
| **Description** | A presignature is used to sign two different messages. Because ECDSA nonces must be unique per signature, reusing a presignature with different data allows algebraic extraction of the private key: given `(r, s1)` for message `m1` and `(r, s2)` for message `m2` with the same `k`, the private key `d = (s1*m2 - s2*m1) / (r*(s2-s1))`. |
| **Preconditions** | Bug in presignature pool management (FIFO violation), race condition in concurrent signing, or KSS storage corruption. |
| **Impact** | **Critical.** Complete private key extraction from two signatures sharing the same nonce. |
| **Mitigation (current)** | FIFO consumption with atomic removal. `consume_presignature()` uses `pop_front()` which removes the presignature from the pool before returning it. On the KSS, presignatures are consumed atomically within a mutex lock (in-memory) or database transaction (DO SQLite). Each presignature has a unique `id` for audit. |
| **Mitigation (planned)** | Post-consumption deletion verification. Audit logging of all presignature lifecycle events. Presignature count monitoring with alerts on unexpected consumption patterns. |
| **Residual risk** | Low given the atomic consumption design, but the consequence is so severe that this requires ongoing vigilance. Any storage backend change must preserve atomicity. |

#### ATTACK A6: Fee Output Manipulation

| Field | Detail |
|-------|--------|
| **Description** | Attacker modifies the fee injection logic to redirect fee outputs to their own address, or inflates the fee to drain agent funds. |
| **Preconditions** | Compromise of proxy code or configuration (`MPC_FEE_ADDRESSES`, `MPC_FEE_SATS`). |
| **Impact** | **Medium.** Fee theft (operator revenue loss) or agent fund drain via inflated fees. Default fee is 1,000 sats (~$0.005) per signing -- small individually but significant in aggregate. |
| **Mitigation (current)** | Fee addresses and amount configured via env vars at proxy startup. `inject_fee_into_outputs()` validates that change >= fee before injection; graceful failure otherwise. Fee output is visible on-chain for audit. |
| **Mitigation (planned)** | Level 2 multisig fee outputs require MPC node quorum to spend. Level 3 sCrypt covenant enforces proportional distribution in Script. |
| **Residual risk** | In Alpha, the proxy operator controls fee injection. This is acceptable when the proxy and agent share trust (same operator). |

#### ATTACK A7: Unauthenticated KSS Endpoints

| Field | Detail |
|-------|--------|
| **Description** | An attacker who discovers the KSS URL attempts to initiate protocol sessions (`/dkg/init`, `/dkg/round`, `/sign/init`, `/sign/round`, `/presign/init`, `/presign/round`) without holding an authorized identity. |
| **Preconditions** | KSS URL discovery (not secret, but not publicly advertised in Alpha). |
| **Impact** | **High** (if unauthenticated). Attacker could initiate DKG (creating unwanted shares), trigger signing with crafted messages, or exhaust presignatures via repeated presigning sessions. |
| **Mitigation (current)** | **Resolved (bsv-mpc #8, Phase D).** All KSS mutation endpoints now require canonical @bsv BRC-31 mutual authentication. The upstream verification (handshake + per-request General-message signature) is implemented via `bsv-middleware-rs` (service) and `bsv-middleware-cloudflare` (worker); a request without a valid signature is rejected (401), and a present-but-invalid signature is rejected 401 (not 500). Owner-authorization (`verify_agent_authorization()`) still checks that the authenticated identity matches the requested `agent_id`, preventing cross-agent access. §07 identity-binding additionally requires the request's claimed identity header to equal the session identity the signature was bound to. §07.1 per-request replay-nonce consumption rejects a reused `(session_nonce, request_nonce)` pair (401), checked after signature verification so a forged nonce cannot poison the consumed set. |
| **Mitigation (planned)** | Rate limiting on all KSS endpoints (defense-in-depth against authenticated-but-abusive callers). |
| **Residual risk** | Low. The auth gap is closed and proven on mainnet (TXID `96c2ebc592c77bab2fc3fba47993bc6638ec248c7f90caf68ba7fddb3cdabcfd`). Remaining: rate limiting is not yet in place, and authorization above the auth layer (BRC-52 cosigner-cert verification §08.12 + policy manifest §09) is a follow-on layer. |

#### ATTACK A8: BEEF Construction Manipulation

| Field | Detail |
|-------|--------|
| **Description** | When constructing BEEF (Background Evaluation Extended Format) for ARC broadcasting, the proxy fetches parent transactions and merkle proofs from WhatsOnChain. A compromised WoC API could return fake proofs, causing the proxy to construct invalid BEEF that ARC miners reject (denial of service) or, worse, trick the proxy into believing an unconfirmed parent is confirmed. |
| **Preconditions** | WoC API compromise or DNS hijacking of WoC endpoints. |
| **Impact** | **Medium.** Transaction broadcast failure (DoS) or incorrect UTXO state tracking. Cannot directly steal funds -- the signed transaction itself is still valid regardless of BEEF wrapping. |
| **Mitigation (current)** | BEEF validation via BSV SDK `Beef` struct before broadcasting. Multi-tier broadcast strategy (ARC GorillaPool, TAAL, WoC fallback) provides redundancy. |
| **Residual risk** | Low. BEEF manipulation is a DoS vector, not a fund theft vector. |

### 4.2 Beta: Browser DKG, WAB Onboarding, Deferred Binding

Beta introduces browser-based DKG via Web Authentication Broker (WAB) and a 2-of-3 threshold configuration with a recovery service.

#### ATTACK B1: Deferred Binding Window Attack

| Field | Detail |
|-------|--------|
| **Description** | During WAB onboarding, DKG runs before the user's `rootPrimaryKey` is available (WAB login takes up to 120 seconds). A deferred binding window exists where the DKG has completed but the shares are not yet bound to a specific user. An attacker who can intercept the binding step could associate their identity with the agent's shares. |
| **Preconditions** | Access to the binding API during the 120-second window. Knowledge of the pending DKG session. |
| **Impact** | **High.** Attacker gains control of share_B (bound to their identity instead of the legitimate user). Combined with KSS compromise, this enables fund theft. |
| **Mitigation (planned)** | Binding window constrained to <1 second within the 120-second WAB flow. Binding authenticated via WAB session token (not just agent identity). Share encrypted with WAB-derived key that only the legitimate user can produce. |
| **Residual risk** | Depends on WAB session security. The binding window is a novel attack surface introduced by the deferred onboarding flow. |

#### ATTACK B2: Browser-Based DKG Compromise

| Field | Detail |
|-------|--------|
| **Description** | DKG runs partially in the user's browser (for share_B generation). Browser extensions, XSS, or compromised dependencies could extract the share during generation. |
| **Preconditions** | Malicious browser extension or XSS vulnerability in the WAB page. |
| **Impact** | **High.** share_B extraction during the brief window when it exists in browser memory. |
| **Mitigation (planned)** | DKG share material handled in a Web Worker (isolated from DOM). Share encrypted immediately after generation and before any DOM interaction. Content Security Policy (CSP) headers to prevent XSS. |
| **Residual risk** | Browser environments are inherently less secure than server processes. This is a fundamental trade-off of browser-based onboarding. |

#### ATTACK B3: Recovery Service Compromise (2-of-3)

| Field | Detail |
|-------|--------|
| **Description** | In 2-of-3, the recovery service holds the third share. If the recovery service is compromised alongside either the proxy or KSS, the attacker has 2 shares -- sufficient to sign. |
| **Preconditions** | Compromise of the recovery service AND one of {proxy, KSS}. |
| **Impact** | **Critical.** Fund theft via 2-of-3 threshold breach. |
| **Mitigation (planned)** | Recovery service on independent infrastructure (different provider, different jurisdiction). Recovery share requires additional authentication (e.g., user passphrase or hardware token) before participating in signing. Rate limiting on recovery service signing -- it should only be used for actual recovery, not routine operations. |
| **Residual risk** | 2-of-3 significantly raises the bar compared to 2-of-2. An attacker must compromise two independent systems instead of one. |

### 4.3 GA: Multi-Party (3-of-5), Overlay Discovery, Fee Settlement

#### ATTACK G1: Rogue Key Attack During DKG

| Field | Detail |
|-------|--------|
| **Description** | During DKG, a malicious party crafts their contribution to bias the joint public key toward a value for which they know the private key (or a value that gives them disproportionate control). |
| **Preconditions** | Malicious party participating in DKG. |
| **Impact** | **Critical.** If successful, the malicious party can sign unilaterally. |
| **Mitigation (current)** | CGGMP'24 DKG includes Schnorr zero-knowledge proofs of knowledge for each party's key share contribution. A party cannot bias the joint key without being detected by the ZK proof verification step. The `cggmp24` crate (Kudelski-audited) implements these proofs. |
| **Residual risk** | Negligible, assuming correct implementation of the ZK proofs. The cggmp24 crate has been audited, and POC 1 validated correct DKG behavior. |

#### ATTACK G2: Overlay Poisoning (False Node Registration)

| Field | Detail |
|-------|--------|
| **Description** | Attacker registers fake MPC nodes on the `tm_mpc_signing` overlay topic via fraudulent CHIP tokens. Agents discover these fake nodes and initiate DKG with them. The fake node controls one share from the start. |
| **Preconditions** | Ability to create and broadcast a valid CHIP token (low cost -- a single BSV transaction). |
| **Impact** | **High.** If the fake node participates in DKG, it legitimately holds a share. In 2-of-3, this is not immediately dangerous (attacker needs a second compromise). In 2-of-2, the fake node IS the second party. |
| **Mitigation (planned)** | Reputation scoring based on on-chain participation proof history. New nodes start with zero reputation and must build it over time. Agents should prefer established nodes. CHIP tokens are signed by the node's identity key and validated by the overlay topic manager. Health checking before DKG initiation (implemented in `discovery.rs`). |
| **Residual risk** | Sybil resistance in a permissionless network is fundamentally limited. Reputation scoring mitigates but does not eliminate this risk. For high-value wallets, agents should use pre-vetted node lists rather than pure overlay discovery. |

#### ATTACK G3: Malicious Node in Multi-Party Signing

| Field | Detail |
|-------|--------|
| **Description** | One of the t+1 signing participants behaves maliciously during the signing protocol -- sending invalid messages, aborting selectively, or attempting to extract information from protocol transcripts. |
| **Preconditions** | Malicious node selected as a signing participant. |
| **Impact** | **Medium.** CGGMP'24 provides identifiable abort -- the protocol identifies the malicious party. The worst case is a signing failure (DoS), not a key compromise. The malicious party learns nothing about other parties' shares from the protocol transcript (UC-security). |
| **Mitigation (current)** | CGGMP'24's identifiable abort property (proven in the UC framework). If a party sends an invalid message, the protocol identifies it and aborts without leaking information. The identified party can be excluded from future signing sessions. |
| **Residual risk** | DoS via repeated aborts. The identified party can be blacklisted, but replacing a party requires key refresh (resharing). |

#### ATTACK G4: Fee Settlement Theft

| Field | Detail |
|-------|--------|
| **Description** | In Level 2 (multisig) fee settlement, the MPC nodes co-sign a settlement transaction that distributes accumulated fees. A quorum of malicious nodes could sign a settlement that gives them more than their proportional share. |
| **Preconditions** | Collusion of t+1 node operators. |
| **Impact** | **Medium.** Theft of other operators' fee revenue. Does not affect user funds. |
| **Mitigation (current)** | Settlement amounts calculated from on-chain participation proofs (`calculate_settlement()` in `proofs.rs`). Honest nodes will refuse to co-sign a settlement that contradicts the proof record. POC 11 validated 2-of-3 settlement on mainnet. |
| **Mitigation (planned)** | Level 3 sCrypt covenant enforces proportional distribution in Script -- no trust required. |
| **Residual risk** | In Level 2, honest majority assumption (same assumption required for signing security). Level 3 eliminates this residual risk. |

---

## 5. Cryptographic Assumptions

The security of bsv-mpc rests on the following assumptions. If any of these are broken, the system's security guarantees are invalidated.

### 5.1 CGGMP'24 Protocol Security

| Property | Assumption | Basis |
|----------|-----------|-------|
| **UC-security** | The CGGMP'24 protocol is secure in the Universal Composability framework under the DDH, strong RSA, and Paillier assumptions. | Canetti, Gennaro, Goldfeder, Makriyannis, Peled (2024). Kudelski audit of `cggmp24` crate. |
| **Identifiable abort** | If any party deviates from the protocol, the honest parties can identify the deviating party. | CGGMP'24 Theorem 4.1. Prevents undetected misbehavior. |
| **Threshold security** | Any subset of t or fewer parties learns nothing about the secret key beyond what is publicly known. | Information-theoretic for Shamir secret sharing; computational for the signing protocol. |
| **TSSHOCK mitigations** | The cggmp24 crate v0.7.0+ includes mitigations for the TSSHOCK class of attacks on threshold ECDSA. | Addressed in the crate's security changelog. |

### 5.2 Cryptographic Primitives

| Primitive | Usage | Security Level |
|-----------|-------|---------------|
| **secp256k1 ECDLP** | Joint public key security. An attacker cannot derive the private key from the public key. | ~128-bit security. Standard assumption for Bitcoin/BSV. |
| **Paillier encryption** | Used internally by CGGMP'24 for the multiplication-to-addition (MtA) sub-protocol. | Relies on hardness of factoring Paillier moduli (2048-bit RSA moduli via `SecurityLevel128`). |
| **AES-256-GCM** | Share encryption at rest. 12-byte random nonce, 16-byte authentication tag. | 256-bit key security. Nonce collision probability negligible at ~2^48 encryptions per key. |
| **HMAC-SHA256** | BRC-42 key derivation, share encryption key derivation. | 256-bit PRF security under the SHA-256 compression function. |
| **SHA-256** | Session IDs, execution IDs, participation proof hashes, BIP-143 sighash. | 128-bit collision resistance. Standard for BSV. |

### 5.3 Randomness

All cryptographic operations requiring randomness use `OsRng` (which maps to `getrandom/js` in WASM environments). The security of DKG, signing, presigning, and share encryption depends on the quality of the underlying OS entropy source.

**Risk:** Weak or predictable RNG on the KSS (e.g., a poorly seeded WASM environment) could produce predictable nonces, enabling private key extraction.

**Mitigation:** `getrandom/js` uses `crypto.getRandomValues()` in V8 isolates, which is cryptographically strong. POC 2 and POC 10 validated WASM entropy quality.

---

## 6. Operational Security

### 6.1 Infrastructure Isolation

| Principle | Implementation |
|-----------|---------------|
| **Separate accounts** | Agent container and KSS run on different infrastructure accounts. Compromising one account's credentials does not grant access to the other. |
| **Network segmentation** | KSS endpoints are not publicly advertised (in Alpha). Access requires knowledge of the KSS URL. In Beta/GA, overlay discovery provides controlled exposure with BRC-31 auth. |
| **Minimal surface** | KSS exposes only 8 HTTP endpoints. No admin interface, no SSH, no shell access. |

### 6.2 Share Storage Encryption

Shares are never stored in plaintext. The encryption chain:

1. **Key derivation:** `HMAC-SHA256(root_key, "bsv-mpc-share" || session_id)` produces a 32-byte AES key.
2. **Encryption:** AES-256-GCM with random 12-byte nonce. Ciphertext includes 16-byte authentication tag.
3. **Storage:** `EncryptedShare` struct contains nonce + ciphertext + metadata (session_id, share_index, threshold config). No key material in the struct.
4. **Decryption:** Same root_key + session_id re-derives the encryption key deterministically.

The root_key itself must be protected. In the proxy, it comes from `MPC_ENCRYPTION_KEY` env var. In the KSS worker, the share is encrypted by the agent's root key -- the KSS never possesses the root key.

#### 6.2.1 Share-Encryption-Key Compromise — Blast Radius (#5)

What an attacker gains by compromising an at-rest encryption key, and why it is bounded:

- **Two-factor precondition.** Decrypting a stored secret requires BOTH the derived key (or the `root_key` it derives from) AND the at-rest ciphertext. These live on **separate infrastructure** (§6.1): the ciphertext sits in the KSS/worker DO-SQLite; the `root_key` (`MPC_ENCRYPTION_KEY` / the worker's `SERVER_PRIVATE_KEY`) is a deployment secret on a different account. Compromising the storage backend alone yields only opaque ciphertext.
- **Bounded impact — still 1-of-2.** Even with `root_key` + ciphertext, the attacker recovers `share_A` (the KSS half) **only**. Moving funds still requires the threshold quorum (the device's `share_B`), the per-spend biometric, and the §09 policy/approval gate. One exposed at-rest key ≠ fund loss.
- **No cascade — per-domain, per-session key scope.** Every at-rest key is `HMAC-SHA256(root_key, DOMAIN ‖ id)` under a **distinct domain tag** that cannot collide: `"bsv-mpc-share"` (DKG shares, per `session_id`), `"bsv-mpc-presig-at-rest"` (presig bytes, per `presig_id`), `"bsv-mpc-primes-at-rest"` (seeded primes, per `session_id`, #5). A leaked derived key decrypts exactly its one blob; it does not unlock other shares, presigs, or primes.
- **Rotation effectively zeroizes prior generations.** Key refresh (§6.3 / §06.18) reshares onto fresh material; because at-rest data is ciphertext under a key the storage backend never holds, rotating the key renders the prior generation's stored bytes undecryptable — a conformant best-effort erase even on a backend without secure-delete.
- **Residual risk (disclosed).** Keys and unsealed secrets are software-resident, so an attacker with **live process-memory access** on the holding host can capture them within the in-use window. This is the disclosed in-memory exposure (the client's biometric-unseal window is per-op; `Zeroizing` wipes on drop — `docs/41-AUDIT-FINDINGS.md` F2 / Finding 4). Hardware key custody (HSM/enclave) is the GA mitigation; secp256k1 is not enclave-resident on current mobile (F2), so the wrap-key pattern + minimal exposure window is the Alpha/Beta posture.

### 6.3 Key Refresh Cadence

Key refresh (threshold resharing, POC 13) rotates all shares while preserving the joint public key and BSV address. Recommended cadence:

| Scenario | Refresh Trigger |
|----------|----------------|
| Routine rotation | Every 30 days (proactive defense against undetected share leakage) |
| Node replacement | Immediately when a node is decommissioned or suspected compromised |
| Threshold change | When upgrading from 2-of-2 to 2-of-3 (resharing supports arbitrary (t,n) to (t',n') transitions) |
| Incident response | Immediately upon suspected share compromise |

Properties of key refresh (validated in POC 13):
- Same joint public key (same BSV address, no fund transfer needed).
- 0 on-chain cost (vs ~188 sats for re-DKG with fund transfer).
- Old shares are cryptographically invalidated (different polynomial, same constant term).
- All new subsets can sign; old subsets cannot.

### 6.4 DKG Key Persistence

**CRITICAL:** DKG keys must be persisted before funding the MPC address. Ephemeral keys (lost on process restart) mean permanent fund loss. POC 4 lost 3,000 sats ($0.0015) from ephemeral keys in failed runs. Production enforcement:

- KSS stores encrypted shares in Durable Object SQLite (survives restarts).
- Proxy stores encrypted share to disk (`share.enc`) before returning the joint public key to the agent.
- `createAction` refuses to operate without a persisted share.

### 6.5 Protocol State Cleanup

Intermediate protocol state (DKG rounds, signing sessions) must be cleaned up after completion or timeout:

- **Completed sessions:** `delete_protocol_state()` called on success.
- **Failed sessions:** Timeout-based cleanup (planned). Stale state accumulation is a resource exhaustion vector.
- **Presignature accounting:** Total generated and consumed counters tracked for audit (`PresignManager.total_generated()`, `.total_consumed()`).

---

## 7. Risk Summary

### Alpha Risks (Ordered by Severity)

| Risk | Severity | Likelihood | Status |
|------|----------|-----------|--------|
| Single KSS compromise (A1) | Critical | Low | **Accepted** -- mitigated by Beta 2-of-3 |
| Presignature reuse (A5) | Critical | Very Low | **Mitigated** -- atomic FIFO consumption |
| MITM on proxy-KSS (A4) | Critical | Low | **Mitigated** -- TLS + canonical BRC-31 message integrity (mainnet-proven) |
| Unauthenticated KSS endpoints (A7) | High | Medium | **Resolved** -- canonical BRC-31 + owner-authz + replay (§07.1) + identity-binding (§07) |
| Container share theft (A2) | High | Low | **Mitigated** -- encrypted at rest |
| Fee manipulation (A6) | Medium | Low | **Accepted** -- operator controls proxy |
| BEEF manipulation (A8) | Medium | Very Low | **Mitigated** -- multi-tier broadcast |
| Replay attacks (A3) | Low | Very Low | **Mitigated** -- unique ExecutionId |

### Beta Risks (New)

| Risk | Severity | Likelihood | Status |
|------|----------|-----------|--------|
| Deferred binding window (B1) | High | Low | **Planned mitigation** |
| Browser DKG compromise (B2) | High | Medium | **Planned mitigation** |
| Recovery service compromise (B3) | Critical | Very Low | **Mitigated by 2-of-3** |

### GA Risks (New)

| Risk | Severity | Likelihood | Status |
|------|----------|-----------|--------|
| Overlay poisoning (G2) | High | Medium | **Planned mitigation** (reputation) |
| Fee settlement theft (G4) | Medium | Low | **Mitigated by Level 2 multisig** |
| Malicious node abort (G3) | Medium | Medium | **Mitigated** -- identifiable abort |
| Rogue key attack (G1) | Critical | Negligible | **Mitigated** -- ZK proofs in CGGMP'24 |

---

## 8. Recommendations

### Immediate (Alpha Hardening)

1. **BRC-31 authentication — DONE (bsv-mpc #8, Phase D).** Canonical @bsv BRC-31 is implemented on all KSS mutation endpoints across all three crates (proxy `bsv_rs::auth::Peer`, service `bsv-middleware-rs`, worker `bsv-middleware-cloudflare`), with owner-authorization, §07.1 replay-nonce consumption, and §07 identity-binding enforced. Deployed (worker `f232a13a`, container standard-4) and mainnet-proven (TXID `96c2ebc592c77bab2fc3fba47993bc6638ec248c7f90caf68ba7fddb3cdabcfd`). Follow-on: BRC-52 cosigner-cert verification (§08.12) + policy-manifest enforcement (§09).
2. **Add rate limiting** to KSS endpoints to prevent presignature exhaustion and protocol state flooding.
3. **Implement session timeouts** for protocol state cleanup. Stale DKG/signing sessions should be garbage collected.

### Beta

4. **Move to 2-of-3** to eliminate single-KSS-compromise as a critical risk.
5. **Implement deferred binding** with WAB session-token authentication and sub-second binding window.
6. **Add share zeroization** (memory wiping) when share material is dropped.

### GA

7. **Deploy reputation scoring** for overlay node discovery, informed by on-chain participation proof history.
8. **Implement Level 3 fee covenant** (Runar/sCrypt) for trustless fee distribution.
9. **Regular key refresh** on a 30-day cadence for all production agents.
