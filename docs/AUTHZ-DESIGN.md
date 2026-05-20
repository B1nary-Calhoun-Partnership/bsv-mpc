# Authz design — handler-level authorization + durable auth sessions (#5)

> **Status: PROPOSED — awaiting sign-off before implementation.**
> Pre-funded-mainnet (#5) security blocker for I-5 (#16). Design-first per the
> god-tier discipline: a wrong authz model on the signing boundary is worse than
> none. Last updated 2026-05-20.

## 1. Threat model

The deployed KSS (the wasm DO) holds **`share_A`** — one half of a 2-of-2 joint
key. The danger: an attacker makes the KSS contribute its half toward signing a
message of the attacker's choosing, draining the joint address.

- `agent_id` is the **joint public key** (compressed hex). It is **public** —
  it appears on-chain in every spend. So `agent_id` is an *identifier*, never a
  *credential*. Knowing it must grant nothing.
- Neither party holds the **joint private key** (that is the entire point of
  MPC), so a requester **cannot** authenticate "as the joint key / agent_id".
  Any model of the form "requester == agent_id" is therefore unsatisfiable as
  written (and is why the current `IdentityMismatch` check is dormant).

**Required property:** the KSS issues a partial signature (HTTP `sign`/`ecdh`,
or the relay `/sign-relay`) **only** for a requester that proves it is the
legitimate counterparty that ran DKG for that share — i.e., the holder of
`share_B`.

## 2. Current gaps (verified in code, 2026-05-20)

1. **Handlers don't check authz.** `api.rs` handlers (`handle_sign_init`,
   `handle_ecdh`, `handle_presign_init`, …) take `body.agent_id`, load the share,
   and proceed — `// TODO: Verify BRC-31 auth and agent authorization`. Any
   BRC-31-authenticated party can sign with **any** share whose `agent_id` (a
   public value) it knows.
2. **Auth identity is discarded.** `auth::verify_or_allow` already returns the
   verified `AuthenticatedIdentity { identity_key }`, but the `lib.rs` entrypoint
   throws it away (`if let Err(resp) = …`), so handlers never see who called.
3. **Auth sessions are per-isolate + in-memory.** `AUTH_SESSIONS` is a process-
   global `static LazyLock<Mutex<HashMap>>`. CF runs many entrypoint isolates;
   the handshake (stores a session) and the follow-up request (reads it) can
   land on **different** isolates → `SessionNotFound`. This is why the
   deterministic deployed proofs use the **unauthed** `/poc/*` routes. Until
   this is durable, no handler-authz can be *proven* on the deployed worker.
4. **Proxy identity is ephemeral.** `bridge.rs::BridgeAuth::new()` generates a
   **random** auth key per process. If the owner identity is the DKG-time
   requester key, a proxy restart would lose its ownership credential.

## 3. The model

### 3a. Share owner = the DKG-time BRC-31 identity

A share gains an **`owner_identity`**: the BRC-31 identity-key (compressed pubkey
hex) of the party that authenticated when DKG was run for that share. This is the
**only** credential a requester can actually present (it is the proxy's auth key,
which the proxy controls), and it is independent of the public joint key.

- **DKG init** (`/dkg/init`, authed): record `owner_identity = authenticated
  requester identity`. Persist it next to the share (`mpc_shares` gains an
  `owner_identity` column).
- **Sign / ECDH / presign init** (authed): require `authenticated requester
  identity == share.owner_identity`, else **403 `IdentityMismatch`**. `agent_id`
  stays the lookup key; `owner_identity` is the gate.
- **Relay `/sign-relay`** (production form, authed): same check — only the
  share's owner can trigger the DO to issue + relay its partial. (The current
  `/poc/sign-relay` is an unauthed POC and stays for the deterministic proofs;
  production gets an authed sibling.)
- **Provisioning `/ceremony/ingest-presig`** (#14): already stores under the
  DO's own identity; tighten to also bind the presig to the owner so a presig
  can only be consumed for the owner that provisioned it.

### 3b. Durable auth sessions (DO SQLite, not a process static)

Move the auth-session store from the per-isolate `AUTH_SESSIONS` static into the
**per-identity `CosignerSessionDo`'s SQLite** (`mpc_auth_sessions` table). The
entrypoint already forwards every authed route to the singleton DO; doing the
session lookup **inside** the DO (one pinned instance) makes BRC-31 reliable
across isolate churn and is the prerequisite that lets handler-authz be *proven*
on the deployed worker. The handshake write and the request read then hit the
same durable store.

- `mpc_auth_sessions(server_nonce PK, peer_identity_key, peer_nonce, created_at)`.
- TTL enforced on read (existing `session_ttl_ms`), evicted lazily.
- The entrypoint may keep a fast in-isolate cache, but the DO SQLite row is
  authoritative.

### 3c. Stable proxy identity

The proxy's BRC-31 auth key (`BridgeAuth`) must be **persisted** (e.g., derived
deterministically from the share file / a configured `MPC_PROXY_AUTH_KEY`, or
saved alongside the share) so the proxy keeps the same `owner_identity` across
restarts. Random-per-process (today) would orphan the share after a restart.

## 4. Per-route authz matrix (target)

| Route | Auth | Authz check |
|---|---|---|
| `/dkg/init` | BRC-31 | none (records `owner_identity` = requester) |
| `/dkg/round`, `/sign/*`, `/presign/*`, `/ecdh` | BRC-31 | requester == share `owner_identity` |
| `/ceremony/seed-primes`, `/ceremony/ingest-presig` | BRC-31 | requester == owner (or DO-self for provisioning) |
| production `/sign-relay` | BRC-31 | requester == share `owner_identity` |
| `/health` | none | n/a |
| `/poc/*` | none | unchanged (deterministic deployed proofs) |

## 5. Implementation plan (incremental, each gated)

1. **Thread the identity.** `lib.rs` entrypoint passes the verified
   `AuthenticatedIdentity` to the DO (header is already present + verified;
   handlers read `x-bsv-auth-identity-key`, trustworthy post-verify). *Gate:*
   unit test — handler sees the caller identity.
2. **Owner-identity storage + check.** Add `owner_identity` to `mpc_shares` +
   `DkgResult` flow; enforce `requester == owner` in sign/ecdh/presign. *Gate:*
   unit tests — owner accepted, non-owner → 403; a mismatched-owner sign is
   rejected before any share is touched.
3. **Durable auth sessions** (`mpc_auth_sessions` in DO SQLite). *Gate:*
   **deployed** — handshake then authed request succeed across a forced isolate
   eviction (the analog of the I-3b fund-safety eviction proof, for auth).
4. **Authed production `/sign-relay`** + stable proxy identity (3c). *Gate:*
   the #12 relay-combine e2e run through the **authed** route (owner accepted,
   stranger rejected).

Steps 1–2 are pure-Rust + unit-provable now; step 3 is the deployed
auth-session-isolate fix; step 4 folds authz into the proven relay path. I-5
(#16) gates on 1–4 being green.

## 6. Open questions

- **OQ-A1:** owner = a single identity, or a set (multiple authorized proxies /
  key rotation)? Single for v1; document rotation as future work.
- **OQ-A2:** proxy stable-key source — derive from the share file deterministically
  (zero new config) vs. an explicit `MPC_PROXY_AUTH_KEY` secret? Leaning derive.
- **OQ-A3:** rate-limiting / DoS (separate #5 item) — out of scope for this doc.
