# BRC-XXX: Threshold ECDSA Signing Protocol for BSV

| Field      | Value                                                   |
|------------|---------------------------------------------------------|
| Title      | Threshold ECDSA Signing Protocol for BSV                |
| Author     | John Calhoun                                            |
| Status     | Draft                                                   |
| Created    | 2026-03-21                                              |
| Type       | Standards Track                                         |
| Layer      | Wallet / Signing                                        |
| Requires   | BRC-31, BRC-33, BRC-42, BRC-100                        |

## Abstract

This BRC defines a threshold ECDSA signing protocol for BSV wallets and autonomous agents using the CGGMP'24 cryptographic protocol. It enables t-of-n threshold signing where no single party holds the complete private key. The specification covers distributed key generation (DKG), presigning, and threshold signing protocol rounds; BRC-31 mutual authentication between all parties; encrypted share storage via BRC-42 key derivation; and a BRC-100-compatible signing proxy interface that allows any existing wallet client to use MPC signing with zero modifications.

The complete private key never exists at any point in the protocol -- not during generation, not during signing, not at rest. Two or more independent parties must cooperate to produce any valid signature.

## Motivation

### The Key Custody Problem for AI Agents

AI agents operating autonomously on the BSV network require signing capability to construct and broadcast transactions. In the current model, the agent's private key is held by a single wallet process (e.g., bsv-wallet-cli on localhost:3322). This creates a single point of compromise: anyone who gains access to the wallet process -- whether through host compromise, insider threat, or platform vulnerability -- can sign arbitrary transactions and drain the agent's funds.

For hosted AI agents, the problem is acute. The platform operator necessarily has access to the infrastructure running the wallet. Users must trust that the platform will not abuse this access. The statement "not even the platform can sign your transactions" is impossible to make credibly with single-key custody.

### Threshold Signing as the Solution

Threshold ECDSA splits the signing key into n shares distributed among independent parties. Any t+1 parties can cooperate to produce a valid signature, but no subset of t or fewer parties can forge one. This provides:

1. **No single point of compromise.** Compromising one share reveals nothing about the private key.
2. **Fault tolerance.** In a 2-of-3 configuration, any one party can go offline without losing signing capability.
3. **Verifiable platform neutrality.** The platform holds at most one share and provably cannot sign unilaterally.
4. **Standard output.** Threshold ECDSA produces standard (r, s) signatures indistinguishable from single-key signatures. No consensus changes required.

### Why CGGMP'24

The CGGMP'24 protocol (Canetti, Gennaro, Goldfeder, Makriyannis, Peled 2024) is the state of the art for threshold ECDSA:

- **Identifiable abort.** If signing fails, the protocol identifies which party misbehaved. This is critical for MPC networks with economic incentives -- malicious nodes can be penalized.
- **Efficient rounds.** 4-round signing without preprocessing, 1-round with preprocessing (presignatures).
- **Proven security.** UC-secure under standard assumptions (DDH, strong RSA, Paillier).
- **Production implementations.** The `cggmp24` Rust crate (v0.7.0+) implements the full protocol with TSSHOCK mitigations.

### No Existing BRC Coverage

No existing BRC specification covers MPC or threshold signing for BSV. BRC-42 defines key derivation, BRC-29 defines payment key derivation, and BRC-100 defines the wallet API -- but all assume a single party holds the complete private key. This BRC fills that gap.

## Specification

### 1. Protocol Parameters

| Parameter  | Symbol | Description                                      |
|------------|--------|--------------------------------------------------|
| Parties    | n      | Total number of key share holders                |
| Threshold  | t      | Minimum parties required to sign is t+1          |
| Curve      | --     | secp256k1 (required for BSV compatibility)       |
| Protocol   | --     | CGGMP'24 with identifiable abort                 |

**Supported configurations:**

| Configuration | n | t | Use Case                                          |
|---------------|---|---|---------------------------------------------------|
| 2-of-2        | 2 | 1 | Minimum viable: agent + platform                  |
| 2-of-3        | 3 | 1 | Recommended: agent + platform + cold backup       |
| 3-of-5        | 5 | 2 | High security: distributed across 5 operators     |
| t-of-n        | n | t | Arbitrary, where 1 < t < n                        |

The threshold parameter t represents the maximum number of parties that can be corrupted without compromising the key. Signing requires t+1 cooperating parties.

### 2. Party Identification

Each party in the MPC protocol is identified by:

1. **Party index.** An integer from 0 to n-1 assigned during session creation.
2. **BRC-31 identity key.** A 33-byte compressed secp256k1 public key used for authentication and encryption.
3. **Transport address.** Either a BRC-33 MessageBox identifier or a direct WebSocket URL.

All parties MUST mutually authenticate via BRC-31 Authrite before exchanging any protocol messages.

### 3. Session Management

An MPC session groups related protocol executions (DKG, presigning, signing) under a single identifier.

**Session creation:**

```json
{
  "session_id": "sha256-hex-of-creation-params",
  "created_at": 1711036800,
  "threshold": 1,
  "parties": [
    {
      "index": 0,
      "identity_key": "02abc...compressed-pubkey-hex",
      "transport": "messagebox:identity-key-hex"
    },
    {
      "index": 1,
      "identity_key": "03def...compressed-pubkey-hex",
      "transport": "wss://mpc-node.example.com/session"
    }
  ],
  "curve": "secp256k1",
  "protocol": "cggmp24"
}
```

The `session_id` is computed as:

```
session_id = SHA-256(
  sorted(party_identity_keys) ||
  threshold ||
  creation_timestamp ||
  random_nonce
)
```

Sorting identity keys ensures all parties compute the same session ID regardless of party ordering.

### 4. Protocol Message Format

All protocol messages (DKG, presigning, signing) use a uniform envelope:

```json
{
  "session_id": "hex-encoded-sha256",
  "protocol": "dkg" | "presign" | "sign",
  "round": 0,
  "from": 0,
  "to": null,
  "payload": "base64-encoded-protocol-specific-data",
  "signature": "hex-encoded-ecdsa-signature"
}
```

| Field       | Type         | Description                                            |
|-------------|--------------|--------------------------------------------------------|
| session_id  | string       | Hex-encoded SHA-256 session identifier                 |
| protocol    | string       | One of "dkg", "presign", "sign"                        |
| round       | uint8        | Protocol round number (0-indexed)                      |
| from        | uint8        | Sender's party index                                   |
| to          | uint8 / null | Recipient's party index, or null for broadcast         |
| payload     | string       | Base64-encoded protocol-specific binary data           |
| signature   | string       | BRC-77 ECDSA signature over the message fields         |

Messages where `to` is null are broadcast messages (sent to all parties). Messages where `to` is a specific index are point-to-point (encrypted to the recipient's identity key via BRC-78).

The `signature` field is computed over the concatenation of `session_id || protocol || round || from || to || payload` using the sender's BRC-31 identity key per BRC-77.

### 5. Distributed Key Generation (DKG)

DKG produces key shares for all parties and computes the joint public key. The full private key never exists.

**Protocol rounds:**

| Round | Type      | Description                                                |
|-------|-----------|------------------------------------------------------------|
| 0     | Broadcast | Each party commits to a Feldman VSS polynomial             |
| 1     | P2P       | Each party sends encrypted shares to every other party     |
| 2     | Broadcast | Each party publishes decommitments; all verify consistency |
| 3     | Broadcast | Paillier key proofs and ring-Pedersen parameter proofs     |

**Round 0 -- Commitment:**

Each party i:
1. Samples a random polynomial f_i(x) of degree t over the secp256k1 scalar field.
2. Computes Feldman VSS commitments: C_{i,k} = f_i,k * G for k = 0..t.
3. Computes a hash commitment: H_i = SHA-256(C_{i,0} || ... || C_{i,t} || decommitment_randomness).
4. Broadcasts { round: 0, payload: H_i }.

**Round 1 -- Share Distribution:**

Each party i, for each party j (j != i):
1. Computes the share s_{i->j} = f_i(j+1).
2. Encrypts s_{i->j} to party j's identity key via BRC-78.
3. Sends { round: 1, to: j, payload: encrypted(s_{i->j}) }.

**Round 2 -- Decommitment and Verification:**

Each party i:
1. Broadcasts { round: 2, payload: (C_{i,0}, ..., C_{i,t}, decommitment_randomness) }.
2. All parties verify commitments match Round 0 hashes.
3. All parties verify received shares against Feldman commitments:
   s_{j->i} * G == sum_{k=0}^{t} (i+1)^k * C_{j,k}.

**Round 3 -- Auxiliary Proofs:**

Each party i:
1. Generates a Paillier keypair (N_i, phi_i) of sufficient bit length (>= 2048 bits).
2. Generates ring-Pedersen parameters.
3. Broadcasts zero-knowledge proofs of:
   - Correct Paillier key generation (Pi-prm).
   - Ring-Pedersen parameter validity (Pi-mod).
4. All parties verify all proofs.

**Output:**

Each party i holds:
- Their secret share: x_i = sum_{j} s_{j->i} (mod q).
- The joint public key: X = sum_{j} C_{j,0}.
- All Feldman commitments (for share verification).
- Paillier keypairs and ring-Pedersen parameters (for signing).

The joint public key X is the agent's BSV public key. The corresponding BSV address is derived from X using standard P2PKH address generation.

### 6. Presigning Protocol

Presigning produces a presignature that enables 1-round online signing. Presignatures can be generated during idle time.

**Protocol rounds:**

| Round | Type      | Description                                     |
|-------|-----------|-------------------------------------------------|
| 0     | Broadcast | Paillier-encrypted k_i, gamma_i values          |
| 1     | P2P       | MtA (multiplicative-to-additive) conversion     |
| 2     | Broadcast | Delta values and proofs                          |

**Output:**

Each party i holds a presignature share (R_i, k_i, chi_i) where:
- R = product of per-party nonce commitments (the signature's r-value).
- k_i is party i's share of the nonce inverse.
- chi_i is party i's share of the product k * x (nonce inverse times secret key).

Presignatures are **single-use**. Each presignature MUST be used for exactly one signing operation and then discarded.

Presignatures are **session-bound**. A presignature generated in session S cannot be used in a different session.

### 7. Signing Protocol

#### 7.1 Online Signing (with presignature, 1 round)

When a presignature is available:

1. The signing coordinator distributes the message hash h = SHA-256d(transaction) to all t+1 signing parties.
2. Each party i computes: sigma_i = k_i * h + chi_i * r (mod q), where r is the x-coordinate of R from the presignature.
3. Each party broadcasts { protocol: "sign", round: 0, payload: sigma_i }.
4. Any party can reconstruct the full signature: s = sum(sigma_i) (mod q).
5. Verify: (r, s) is a valid ECDSA signature for message hash h under joint public key X.

#### 7.2 Full Signing (without presignature, 4 rounds)

When no presignature is available, the protocol runs a combined presign+sign:

| Round | Description                                              |
|-------|----------------------------------------------------------|
| 0     | Nonce commitment + Paillier encryption                   |
| 1     | MtA shares + range proofs                                |
| 2     | Delta reveal + consistency proofs                        |
| 3     | Partial signatures + final aggregation                   |

This is functionally equivalent to running the presigning protocol followed immediately by online signing.

#### 7.3 Input and Output

**Input:**
- The SHA-256d hash of the serialized BSV transaction to sign.
- The input index being signed (for SIGHASH computation).
- The SIGHASH type (default: SIGHASH_ALL | SIGHASH_FORKID = 0x41).

**Output:**
- A standard DER-encoded ECDSA signature (r, s) with SIGHASH byte appended.
- This signature is indistinguishable from a single-key signature. No changes to BSV Script evaluation are required.

### 8. Identifiable Abort

If any party deviates from the protocol (sends invalid messages, fails proofs, or goes offline), CGGMP'24 provides identifiable abort:

1. Honest parties can identify which party index caused the failure.
2. The identified party's identity key is included in the abort message.
3. This information can be used to:
   - Exclude the malicious party from future sessions.
   - Submit an on-chain penalty proof (see BRC-XXX: MPC Participation Proofs).
   - Trigger re-keying with remaining honest parties.

Abort messages MUST include:
```json
{
  "session_id": "hex",
  "protocol": "sign",
  "abort": true,
  "faulty_party": 2,
  "reason": "invalid_range_proof",
  "evidence": "base64-encoded-proof-transcript"
}
```

### 9. BRC-100 Signing Proxy Interface

The MPC signing system is exposed to wallet clients through a BRC-100-compatible HTTP proxy. This proxy translates standard wallet API calls into threshold signing protocol executions.

**Proxy endpoints:**

| BRC-100 Endpoint     | MPC Behavior                                                  |
|----------------------|---------------------------------------------------------------|
| `getPublicKey`       | Returns the joint MPC public key X                            |
| `createSignature`    | Initiates threshold signing protocol; returns (r, s)          |
| `createAction`       | UTXO selection + tx construction + threshold signing          |
| `listOutputs`        | Queries the UTXO set for addresses derived from X             |
| `internalizeAction`  | Standard (no MPC involvement -- receiving, not signing)       |

**Proxy behavior for `createSignature`:**

1. Receive signing request from BRC-100 client.
2. Authenticate the client via BRC-31.
3. Select t+1 available parties from the session.
4. If a presignature is available, execute 1-round online signing.
5. Otherwise, execute 4-round full signing.
6. Return the standard ECDSA signature to the client.
7. Log the signing operation for participation proofs.

**Proxy behavior for `createAction`:**

1. Receive action request from BRC-100 client.
2. Construct the transaction (UTXO selection, output creation).
3. **Inject the MPC fee output** (see BRC-XXX: MPC Fee Distribution).
4. Compute the SIGHASH for each input.
5. Execute threshold signing for each input.
6. Assemble the fully signed transaction.
7. Return the signed transaction to the client.

The client (e.g., bsv-worm) calls the signing proxy exactly as it would call bsv-wallet-cli. No code changes are required on the client side. The proxy URL is configured via `WORM_WALLET_URL` or equivalent.

### 10. Share Storage and Encryption

Key shares MUST be encrypted at rest using BRC-42 derived keys:

| Parameter    | Value                     |
|--------------|---------------------------|
| Protocol ID  | `[2, "mpc share"]`        |
| Key ID       | `{session_id}`            |
| Counterparty | `"self"`                  |

Encryption algorithm: AES-256-GCM.

The encrypted share blob format:

```
[4 bytes]  magic: 0x4D504353 ("MPCS")
[32 bytes] session_id
[1 byte]   party_index
[12 bytes] AES-GCM nonce
[variable]  AES-GCM ciphertext (encrypted share data)
[16 bytes] AES-GCM authentication tag
```

Shares MUST be stored in one of:
- The wallet's encrypted basket (`mpc-shares` basket via BRC-46).
- An encrypted file on the party's local filesystem.
- A hardware security module (HSM) with PKCS#11 interface.

Shares MUST NOT be:
- Stored in plaintext.
- Transmitted outside of authenticated protocol messages.
- Logged at any verbosity level.

### 11. Transport

#### 11.1 BRC-33 MessageBox (Default)

Protocol messages are exchanged via BRC-33 MessageBox:

- Message type: `mpc-protocol-{session_id}`
- Messages are signed per BRC-77 and optionally encrypted per BRC-78 (point-to-point messages MUST be encrypted).
- MessageBox provides NAT traversal and asynchronous delivery.
- Suitable for DKG and presigning (latency-tolerant).

#### 11.2 Direct WebSocket (Optional Optimization)

For low-latency signing (especially 1-round online signing):

- Parties establish direct WebSocket connections during session setup.
- BRC-31 Authrite handshake on the WebSocket upgrade request.
- Messages use the same JSON envelope format.
- Fallback to MessageBox if WebSocket connection fails.

#### 11.3 Transport Selection

| Protocol Phase | Recommended Transport | Latency Target |
|----------------|-----------------------|----------------|
| DKG            | BRC-33 MessageBox     | < 30 seconds   |
| Presigning     | BRC-33 MessageBox     | < 10 seconds   |
| Online Signing | WebSocket             | < 2 seconds    |
| Full Signing   | WebSocket             | < 5 seconds    |

### 12. Security Requirements

1. **TSSHOCK mitigations.** Implementations MUST use cggmp24 v0.7.0-alpha.2 or later, which includes mitigations for the TSSHOCK vulnerability class (range proof parameter validation).

2. **Infrastructure independence.** In production deployments, parties SHOULD run on independent infrastructure (different cloud providers, different jurisdictions). A 2-of-3 setup with all three parties on the same AWS account provides no meaningful security improvement over single-key custody.

3. **BRC-31 mutual authentication.** All protocol message exchanges MUST be preceded by BRC-31 Authrite mutual authentication. Unauthenticated messages MUST be rejected.

4. **Message signing.** Every protocol message MUST include a BRC-77 signature from the sender's identity key. Messages with invalid signatures MUST be rejected and trigger an abort.

5. **Timeout enforcement.** Each protocol round MUST have a configurable timeout (default: 30 seconds for signing, 120 seconds for DKG). Timeout triggers identifiable abort blaming the non-responsive party.

6. **Share refresh.** Sessions SHOULD support proactive share refresh (re-randomizing shares without changing the joint public key) on a configurable schedule (e.g., weekly). This limits the window of vulnerability if a share is compromised.

7. **Backup and recovery.** Parties SHOULD maintain encrypted backups of their shares. In a t-of-n scheme where t < n-1, loss of one share does not require re-keying. If exactly t shares remain, immediate re-keying with a new party is REQUIRED.

## Implementation

### Reference Implementation

The reference implementation uses the `cggmp24` Rust crate (v0.7.0-alpha.2+) from the `dfns/cggmp21` repository (renamed to cggmp24 for the 2024 protocol revision):

```toml
[dependencies]
cggmp24 = { version = "0.7", features = ["hd-wallet"] }
round-based = "0.4"
```

The `hd-wallet` feature enables BIP-32 compatible child key derivation from MPC shares, which is necessary for BRC-42 key derivation compatibility.

### Integration with bsv-worm

The signing proxy runs as a separate process alongside bsv-wallet-cli:

```
bsv-worm → MPC Signing Proxy (localhost:3323) → bsv-wallet-cli (localhost:3322)
                    ↓
            MPC Node 1 (remote)
            MPC Node 2 (remote)
```

The proxy intercepts `createSignature` and `createAction` calls, forwards all other BRC-100 calls to bsv-wallet-cli unchanged.

Configuration:
```toml
[wallet]
url = "http://localhost:3323"  # Point to MPC proxy instead of wallet directly

[mpc]
session_id = "hex..."
party_index = 0
nodes = ["wss://node1.example.com", "wss://node2.example.com"]
```

### Test Vectors

A conforming implementation MUST pass the following test:

**2-of-2 DKG + Sign:**
1. Two parties execute DKG, producing shares (x_0, x_1) and joint public key X.
2. Verify: x_0 + x_1 == x (the secret key corresponding to X) -- note: this check is only possible in tests where all shares are on one machine.
3. Sign message hash h = SHA-256d("test message").
4. Verify: signature (r, s) is valid under X for hash h.
5. Verify: signature is standard DER-encoded ECDSA, parseable by any BSV library.

### Interoperability

The threshold signatures produced by this protocol are standard ECDSA signatures. They are:
- Valid in BSV Script OP_CHECKSIG evaluation.
- Indistinguishable from single-key signatures on the blockchain.
- Compatible with all existing BSV infrastructure (block explorers, SPV wallets, overlay networks).

No changes to BSV consensus rules, script evaluation, or transaction format are required.

## References

- CGGMP'24: Canetti, Gennaro, Goldfeder, Makriyannis, Peled. "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts." 2024.
- TSSHOCK: Aumayr et al. "TSSHOCK: Attacks on Threshold Signing Protocols." 2024.
- BRC-31: Authrite Mutual Authentication.
- BRC-33: MessageBox Relay.
- BRC-42: Key Derivation via HMAC.
- BRC-77: Message Signing.
- BRC-78: Message Encryption.
- BRC-100: Wallet API.
- `cggmp24` crate: https://github.com/dfns/cggmp21
