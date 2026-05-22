# §07.11 BRC-31 auth conformance vector — DRAFT

`07-brc31-auth.vector.draft.json` is a **draft** of the conformance vector that
MPC-Spec §07.11 references but does not yet contain
(`conformance/test-vectors/07-brc31-auth.json` does not exist as of MPC-Spec
`main`).

## Why this lives in bsv-mpc/brc-drafts, not MPC-Spec

This vector defines **cross-impl wire**: rust-mpc (Binary's stack) consumes the
same BRC-31 wire and MUST reproduce these bytes byte-for-byte to pass the §14
conformance gate. By the same rule that governs §05/§06 (e.g. the §06 presig
bundle coordinated with Ishaan), a cross-impl wire vector is **not** committed to
the canonical spec until it has been byte-locked by at least two independent
implementations. Promoting it unilaterally would make one stack "the reference",
which the conformance protocol forbids — the spec is the reference, not either
team.

So this is a **proposal/draft only**. It is committed to bsv-mpc so the work is
captured and reviewable, and it is the basis for a future MPC-Spec PR once
byte-locked.

## What IS locked in the draft

Produced by an independent re-derivation of the canonical `bsv-rs` auth wire
encoding (mirroring `bsv-rs/src/auth/transports/http.rs` `write_varint`
L443-464, `HttpRequest::to_payload` L219-268, `HttpResponse::to_payload`
L288-317), from pinned test inputs:

- The General-message **request payload** bytes + length + SHA-256 (vector B).
- The General-message **response payload** bytes + length + SHA-256 (vector B).
- The handshake **signing_data** (`yourNonce || initialNonce`) and **key_id**
  for the InitialResponse (vector A).
- Pinned nonces (base64 + hex) and request_id.

These are reproducible: re-running the same encoder over the same pinned inputs
yields the same hex.

## What is NOT yet locked (needs cross-impl coordination)

- **All `signature_der_hex` fields** and **both identity pubkeys**. These require
  a canonical `bsv-rs` run: `PublicKey::from_private_key` for the pinned identity
  privs, then `Peer::sign_message` / `create_signature` under protocol
  `"auth message signature"`, `SecurityLevel::Counterparty`, the listed `key_id`,
  counterparty `Other(peer identity)`. They are intentionally left as
  `<COMPUTED_BY_CROSS_IMPL>` placeholders — no fabricated signature bytes are
  presented as byte-locked.

## Cases covered (per §07.11)

| Vector | Case | §07.11 requirement |
|---|---|---|
| A | valid | InitialRequest -> InitialResponse handshake verifies |
| B | valid | General-message request payload + signature verifies |
| C | reject (401) | replay — reused per-request nonce (§07.1) |
| D | reject (401) | wrong identity (§07 identity-binding) |
| E | reject (401) | malformed: missing nonce headers / truncated payload / present-but-invalid signature (401 not 500) |

## To promote to MPC-Spec

1. Run a canonical `bsv-rs` signing pass to fill the signature + pubkey
   placeholders; add a Python primary + Rust cross-validator path (mirroring
   `conformance/test-vectors/scripts/`).
2. Have rust-mpc reproduce every locked byte (handshake signing_data, payloads,
   and the now-filled signatures).
3. On byte-agreement, open an MPC-Spec PR moving the finalized JSON to
   `conformance/test-vectors/07-brc31-auth.json` and wire it into §14.

## Provenance

- Canonical wire: `~/bsv/bsv-rs/src/auth/{peer.rs,types.rs,transports/http.rs}`
- Spec section: `~/bsv/mpc/MPC-Spec/07-brc31-auth.md` §07.10 / §07.11
- bsv-mpc #8 (Phase D): canonical BRC-31 migration; mainnet TXID
  `96c2ebc592c77bab2fc3fba47993bc6638ec248c7f90caf68ba7fddb3cdabcfd`
