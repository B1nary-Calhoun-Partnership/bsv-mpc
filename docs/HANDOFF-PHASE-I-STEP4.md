# Handoff — Phase I Step 4 (ADR-018 hybrid), pickup at presig provisioning

> Read this + `DECISIONS.md` ADR-018 + GitHub issue **bsv-mpc#4** (+ hardening
> **#5**) first. The signing **crypto core** is done + proven (native AND
> deployed-wasm). What remains is **integration**: provisioning → relay wiring
> → proxy migration → real-sats merge gate.

## Architecture (ADR-018, locked + user-confirmed)
Split the CF cosigner by compute weight, all on Cloudflare:
- **Durable Object (wasm)** — durable `share_A` (DO SQLite, eviction-proven),
  per-agent isolation, relay routing, and the **light 1-round presigned
  online-sign** (issue partial — pure field math, proven to fit + run on the
  deployed isolate).
- **Native Rust (CF Container = the existing `bsv-mpc-service`)** — the heavy
  CGGMP'24 work: DKG + presignature generation. **DKG does NOT fit wasm**
  (probe `/poc/dkg-bench`: prime-gen ~16s, full DKG died ~35s at the CF CPU
  ceiling). The proxy (native, holds `share_B`) is the **combiner**.

## What's DONE + PROVEN this session (all on `main`)
- **I-3b2** (`efc6bc5`) — relay handshake from the deployed DO (Socket.IO +
  BRC-103 + envelope round-trip). `server_identity=02d7c923…`.
- **bsv-rs 0.3.11** (`Calhooon/bsv-rs`, tag `v0.3.11`, **on crates.io**) — fixes
  the wasm `Peer::to_peer` hang (`futures-timer/wasm-bindgen`). bsv-mpc bumped.
- **I-4a** (`5b80f68`, `2d2faad`) — DO-SQLite storage (`DoSqlStorage`, tables
  `mpc_shares`/`mpc_protocol_state`/`mpc_presignatures`/`mpc_primes`); KSS
  handlers routed through the per-cosigner DO over an `MpcStore` trait; fixed
  the agent_id keying bug. **Fund-safety gate satisfied** (real `EncryptedShare`
  survives +179s forced eviction byte-identical; `/health` reads DO SQLite).
- **I-4b.1** (`ec19487`) — `/ceremony/seed-primes` (authed) + `mpc_primes`
  storage. (For off-path native DKG; not the worker hot path.)
- **DKG-on-wasm probe** (`4b30c84`) — decisive: DKG doesn't fit CF. `Date.now()`
  is frozen during sync wasm compute (use external wall-clock).
- **ADR-018** (`01069a3`) — the hybrid, locked.
- **Keystone** (`0e27123`) — `SigningCoordinator::sign_with_presignature`:
  1-round presig sign (issue → broadcast → combine). Native-proven + BSV verify.
- **DO light op** (`a8e8805`) — `bsv_mpc_core::signing::issue_partial_signature_json`
  (serialized `Presignature` → serialized `PartialSignature`). Topology insight:
  only the **combiner** needs `PresignaturePublicData` (NOT `Serialize`), and
  that's the native proxy — so **no cggmp24 fork change needed**. Native-proven
  (`hybrid_do_issues_proxy_combines`): DO issues from JSON presig, proxy
  combines, BSV verifies.
- **Deployed wasm light-sign** (`a60155b`) — `POST /poc/issue-partial` runs the
  op in the real CF isolate; returns a partial **byte-identical** to native
  (deterministic op). Fast, no CPU issue. Validates ADR-018's core bet.

## Key APIs (all in `bsv-mpc-core`)
- `SigningCoordinator::sign_with_presignature(&[u8;32], Box<dyn Any+Send>)` —
  the **proxy/combiner** path. The box is `presigning::PresignOutput`
  (`(Presignature, PresignaturePublicData)`) from `PresigningManager::take_raw()`.
- `signing::issue_partial_signature_json(presig_json, sighash) -> partial_json` —
  the **DO** path (issue only; needs only the serializable `Presignature`).
- `DkgCoordinator::set_pregenerated_primes_from_json(&str)` — seed primes.
- `dkg::generate_test_primes` / fixture printer `signing::tests::print_issue_partial_fixture`
  (`#[doc(hidden)]` / `#[ignore]`) — test/bench helpers.
- Base-key only for the presig path: BRC-42 `hmac_offset` keeps the 4-round
  `sign()` path (the offset is baked into a presig at generation time).

## Remaining roadmap (integration — build on the proven crypto)
1. **Presig provisioning.** The native container runs 2-party presig generation
   with the proxy (party A's heavy half — `bsv-mpc-service` already drives presig
   over the relay), then ships `Presignature_A` (JSON) into the DO's
   `mpc_presignatures` pool. Add a DO ingest route (authed, mirror
   `/ceremony/seed-primes`) using `DoSqlStorage::store_presignature`; the DO
   `consume`s one per signature. (`PresignaturePublicData` stays native — never
   shipped.)
2. **Worker relay sign loop (I-4b.2 revised).** DO: wake-on-HTTP → dial relay
   (I-3b2 proven) → pop a presig from the pool → `issue_partial_signature_json`
   → send the partial over the relay (wire format: `wire::wrap_envelope_to_body`
   + `unwrap_envelope_to_round_message`, box `mpc-sign`, room `{id}-mpc-sign`).
3. **Proxy `bridge.rs` migration (I-4c, OQ-I1).** Swap HTTP for native
   `MessageBoxClient` + the `bsv-mpc-service` handler pattern; the proxy issues
   its partial + **combines** (it holds the public data). Author the missing
   presign/ECDH relay handlers. Reuse share-load/BRC-42 logic (research in #4).
4. **I-5 merge gate.** Real-sats mainnet TXID: proxy (share_B) + the **deployed**
   worker (share_A) co-sign over the relay; broadcast; shape-match G-5d
   (`442bd391…`). Wallet `localhost:3321` (Origin `http://admin.com`),
   `E2E_MAINNET=1`.

## Native test harness (for I-4b.2/I-5 proofs)
- Party-1 over relay: copy `crates/bsv-mpc-service/tests/dkg_via_messagebox_e2e.rs`
  + `sign_mainnet_via_messagebox_e2e.rs`. `MessageBoxClient` + `DkgHandler`/
  `SigningHandler`; `cggmp24`/`round_based` are dev-deps of the root + service.
- BRC-31-authed HTTP to the deployed worker (for authed routes): replicate
  `bsv-mpc-proxy/bridge.rs`'s `BridgeAuth` handshake + per-request signing.
  ⚠️ The worker's auth sessions are in-memory in the entrypoint isolate (hardening
  #5) — handshake + request may hit different isolates. POC routes (`/poc/*`) are
  unauthed; the deterministic deployed proofs use those.

## Locked discipline (carry forward)
- 110% no asterisks: RUNTIME proof for deployed work (byte-identical / live TXID),
  not just build-clean. Native crypto changes proven by unit+vector+BSV-verify.
- Each sub-gate lands on `main` before the next; `cargo fmt --all -- --check` +
  `cargo clippy --workspace --all-targets -- -D warnings` + wasm32 build before push.
- `cd ~/bsv/mpc/bsv-mpc/` (NEVER `bsv-mpc-old-unscrubbed/`). `gh auth switch -u Calgooon` to push.
- Deploy: `eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)"`,
  then `cd crates/bsv-mpc-worker && wrangler deploy`. **worker-build self-heals
  to 0.8.3** via the gitignored `wrangler.toml` build command (it intermittently
  downgrades to 0.7.5 — see memory). secrets.md gitignored; redact `[a-f0-9]{16,}`.
- god-tier + full-stack: consult `~/bsv/` before fixes; swarm/orchestrate research, verify it.

---
**Deployed worker:** `https://bsv-mpc-kss.dev-a3e.workers.dev` (version `b41bd7ea`).
**Last commit:** `a60155b`. **Next:** presig provisioning (#1 above).
