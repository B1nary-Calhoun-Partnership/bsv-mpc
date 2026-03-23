# Architectural Decision Log

> Records of key architectural decisions for bsv-mpc.
> Format: decision, rationale, date, status.

---

## ADR-001: cggmp24 over cb-mpc

**Decision:** Use cggmp24 (Kudelski Security) as the threshold ECDSA library.

**Rationale:** Pure Rust, compiles to WASM (`wasm32-unknown-unknown`), MIT licensed, Kudelski-audited. The alternative cb-mpc (Coinbase) is C++, doesn't compile to WASM, and uses older GG18/GG20 protocols instead of CGGMP'24.

**Date:** 2026-02 | **Status:** Accepted

---

## ADR-002: cggmp24 local fork with `set_additive_shift()`

**Decision:** Maintain a local fork of cggmp24 at `../cggmp21-fork` that exposes `set_additive_shift()`.

**Rationale:** BRC-42 derived key signing requires an additive offset to the secret share during signing. Upstream cggmp24 doesn't expose this. The fork adds this capability (~50 LOC change). Whether to contribute upstream is an open question.

**Date:** 2026-02 | **Status:** Accepted

---

## ADR-003: `num-bigint` over `rug`

**Decision:** cggmp24 MUST use the `num-bigint` feature, never `rug`.

**Rationale:** Two critical reasons: (1) `rug` depends on GMP which is LGPL — copyleft contamination blocked by `deny.toml`. (2) `rug` is a C library that does not compile to `wasm32-unknown-unknown`, breaking the CF Worker deployment path.

**Date:** 2026-02 | **Status:** Accepted

---

## ADR-004: Drop-in proxy pattern

**Decision:** The MPC signing proxy presents an identical BRC-100 wallet API at localhost:3322. Clients (bsv-worm) require zero code changes.

**Rationale:** Minimizes integration complexity. Any BRC-100 client gets MPC threshold signing transparently. The proxy handles UTXO tracking, fee injection, and MPC ceremony orchestration internally.

**Date:** 2026-02 | **Status:** Accepted

---

## ADR-005: Presigning over on-demand signing

**Decision:** Stockpile presignatures during idle time (7ms effective latency) rather than running 4-round on-demand signing (180ms).

**Rationale:** POC 5 validated that presigned operations take 359µs vs 180ms for interactive 4-round signing. Background presig generation amortizes the cost, making transaction signing near-instant.

**Date:** 2026-02 | **Status:** Accepted

---

## ADR-006: Local symmetric crypto from MPC share

**Decision:** `encrypt`, `decrypt`, `createHmac`, `verifyHmac` derive keys locally from the proxy's MPC share — no KSS communication needed.

**Rationale:** Only signing requires 2-party computation. Symmetric operations (AES-256-GCM, HMAC-SHA256) can use the local share to derive deterministic keys via BRC-42. This eliminates round-trips for ~50% of wallet API calls.

**Date:** 2026-02 | **Status:** Accepted

---

## ADR-007: Fee injection via multisig (Level 2)

**Decision:** MPC nodes self-settle fees using bare multisig outputs. Level 3 (sCrypt/Runar covenant for trustless enforcement) deferred to Phase 2.

**Rationale:** POC 7 and POC 11 validated fee injection and multi-party settlement on mainnet. Bare multisig is simpler and sufficient for alpha. Covenant enforcement adds trustlessness but requires sCrypt or Runar tooling maturity.

**Date:** 2026-02 | **Status:** Accepted

---

## ADR-008: Overlay topic `tm_mpc_signing`

**Decision:** Use `tm_mpc_signing` as the BRC-22 overlay topic for MPC node discovery.

**Rationale:** Leverages existing SHIP/SLAP infrastructure (BRC-22/23/24/25). POC 14 validated that 4/4 mainnet SLAP trackers are alive and responsive. CHIP tokens (BRC-23 PushDrop) encode node capability and fee information.

**Date:** 2026-03 | **Status:** Accepted

---

## ADR-009: Runar for covenants (Phase 2)

**Decision:** Use Runar (Rust-native BSV Script compiler) instead of sCrypt TypeScript for Level 3 fee covenants.

**Rationale:** Keeps the entire project in Rust. sCrypt requires TypeScript toolchain which contradicts our 100% Rust policy. Runar is maintained at `https://github.com/icellan/runar`.

**Date:** 2026-03 | **Status:** Accepted (deferred to Phase 2)

---

## ADR-010: BRC standards, not BIPs

**Decision:** All implementations use BSV BRC standards. No BIP-32, no BIP-39, no BIP-44.

**Rationale:** BSV has its own standards ecosystem. Key derivation is BRC-42 (ECDH + HMAC-SHA256 with invoice strings), auth is BRC-31 (Authrite), wallet API is BRC-100. Using BIPs would produce incompatible implementations.

**Date:** 2026-02 | **Status:** Accepted

---

## ADR-011: Three deployment modes for KSS

**Decision:** Key Share Service supports three deployment modes:
1. **Standalone binary** (`bsv-mpc-service`) — for development and self-hosted deployments
2. **Production service** — for managed production infrastructure
3. **Library** (`bsv-mpc-proxy` as crate) — for embedding directly in host applications

**Rationale:** Each mode serves a different user. Standalone binary is simplest for testing. Production service handles scale. Library mode (enabled by Session B refactor) allows hosted deployments to embed the proxy without running a separate process.

**Date:** 2026-03-22 | **Status:** Accepted

---

## ADR-012: Agent naming convention (kebab-case)

**Decision:** Agents use descriptive kebab-case names (e.g., `research-agent`, `code-reviewer`).

**Rationale:** Matches Rust/CLI conventions, grep-friendly, no spaces or special characters. Consistent with how BSV overlay topics and other identifiers are named in the ecosystem.

**Date:** 2026-03-22 | **Status:** Accepted

---

## ADR-013: Open-source bsv-mpc at launch

**Decision:** Open-source bsv-mpc (core, proxy, service, overlay crates) alongside bsv-worm at launch. The worker crate (`bsv-mpc-worker`) remains private.

**Rationale:** MPC threshold signing is a key differentiator. Open-sourcing the protocol builds trust for key custody — users need to verify that their keys are handled correctly. The worker crate stays private as it contains deployment-specific competitive advantages.

**Date:** 2026-03-22 | **Status:** Accepted

---

## ADR-014: Separate infrastructure accounts for defense-in-depth

**Decision:** The agent container and KSS run on separate infrastructure accounts.

**Rationale:** Compromising one account should not give access to both MPC shares. This is a Beta security hardening task — Alpha uses a single account for simplicity.

**Date:** 2026-02 | **Status:** Accepted (Beta milestone)

---

## ADR-015: DKG before wallet binding

**Decision:** DKG runs before WAB (Wallet Authentication Binding) login. User binding happens in <1s within a 120s window after DKG completes.

**Rationale:** DKG is computationally expensive. Running it eagerly means the key is ready when the user authenticates. Share_B is delivered via WAB. JIT batch funding follows.

**Date:** 2026-03 | **Status:** Accepted

---

## ADR-016: Hosted mode — UTXOs in rust-wallet-infra

**Decision:** In hosted mode, UTXOs live in rust-wallet-infra via StorageClient. The MPC proxy does NOT reimplement wallet storage.

**Rationale:** rust-wallet-infra already has production-grade UTXO management (StorageSqlx). Duplicating this in the MPC proxy would be wasteful and error-prone. The JIT proxy pattern is orthogonal — it handles signing, not storage.

**Date:** 2026-03 | **Status:** Accepted

---

## ADR-017: cggmp21-fork as git submodule

**Decision:** Include cggmp21-fork as a git submodule at `./cggmp21-fork/` instead of relying on `../cggmp21-fork/` sibling path.

**Rationale:** Relative parent paths (`../`) break in git worktrees (resolve to wrong directory) and CI (fork not present). Submodule ensures the fork is always available at a predictable path regardless of checkout location. `git clone --recurse-submodules` handles initial setup.

**Date:** 2026-03-22 | **Status:** Accepted
