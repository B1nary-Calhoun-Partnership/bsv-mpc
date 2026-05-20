# HANDOFF — Phase I Step 4 (ADR-018 hybrid CF cosigner)

> **Single source of truth for continuation.** Read this, then `DECISIONS.md`
> ADR-018, GitHub **bsv-mpc#4** (Phase I tracker), **#5** (hardening), **#2**
> (umbrella), and `docs/CF-CONTAINER-PROBE.md`. Last updated 2026-05-20.
>
> **State in one line:** the cosigner's entire **signing crypto core is done +
> proven** (native AND deployed-wasm byte-identical) and **both halves of the
> ADR-018 architecture are validated on real Cloudflare**. What remains is
> **integration** (provisioning → relay wiring → proxy migration → real-sats),
> not crypto.

---

## 1. Architecture (ADR-018 — locked + user-confirmed 2026-05-20)

Split the CF cosigner **by compute weight**, all on Cloudflare:

| Layer | Runs on | Responsibility | Status |
|---|---|---|---|
| **Durable Object** (wasm, `bsv-mpc-worker`) | CF Worker | Durable `share_A` (DO SQLite), per-agent isolation, relay routing, **light 1-round presigned online-sign** (issue partial) | storage ✅, light-sign ✅ proven |
| **Native** (`bsv-mpc-service`) | **CF Container** | Heavy CGGMP'24: **DKG + presignature generation** | platform ✅ proven (P1); full image = P2 |
| **Proxy** (`bsv-mpc-proxy`, native, holds `share_B`) | agent host | Initiates ceremonies; **combines** partials (holds `PresignaturePublicData`) | migration pending (I-4c) |

**Why:** `/poc/dkg-bench` (`4b30c84`) empirically proved DKG/auxinfo does **not**
fit the CF Worker CPU ceiling (~16s prime-gen, full DKG died ~35s). Light
online-sign-with-presig is pure field math → fits wasm (proven byte-identical on
the deployed isolate). So heavy=native, light=wasm. `PresignaturePublicData` is
NOT `Serialize`, but only the **combiner** (native proxy) needs it → **no
cggmp24 fork change required**; the DO ships/needs only `Presignature` (which IS
`Serialize`).

**Gotcha:** `Date.now()` is frozen during synchronous wasm compute in CF Workers
(Spectre mitigation) — benchmark with external wall-clock, not in-worker timers.

---

## 2. What's DONE + PROVEN (all on `main`, runtime-verified)

| Commit | What | Proof |
|---|---|---|
| `efc6bc5` | I-3b2 relay handshake from deployed DO | `/poc/handshake` → `server_identity=02d7c923…`, envelope round-trip |
| `Calhooon/bsv-rs@613fc61` (tag `v0.3.11`, **crates.io**) | wasm `Peer::to_peer` timer fix (`futures-timer/wasm-bindgen`) | published + consumed |
| `3232122` | bump bsv-mpc → bsv-rs 0.3.11, drop worker workaround | re-proven |
| `5b80f68` | I-4a.1 `DoSqlStorage` (mpc_shares/protocol_state/presignatures/primes) | **real `EncryptedShare` survives +179s forced eviction byte-identical** (fund-safety gate) |
| `2d2faad` | I-4a.2 KSS handlers routed through per-cosigner DO (`MpcStore` trait); agent_id keying fixed | `/health` reads DO SQLite; auth-then-forward (401) |
| `ec19487` | I-4b.1 `/ceremony/seed-primes` (authed) + `mpc_primes` | route wired + enforced |
| `4b30c84` | DKG-on-wasm probe | **decisive: DKG doesn't fit CF** |
| `01069a3` | ADR-018 | architecture locked |
| `0e27123` | **keystone** `SigningCoordinator::sign_with_presignature` (1-round) | `coordinator_presigned_1round_sign` + BSV verify |
| `a8e8805` | `signing::issue_partial_signature_json` (DO light op) | `hybrid_do_issues_proxy_combines` (DO issues from JSON presig, proxy combines, BSV verify) |
| `a60155b` | `/poc/issue-partial` deployed | **deployed-wasm partial byte-identical to native** |
| `f94eadd`/`5ee6547` | CF Container probe P1 | **native Rust on CF Container reachable** (~1.75s cold/~130ms warm) |
| `d6ccf57` | **#14 presig provisioning** — `/ceremony/ingest-presig` (authed, stores under the DO's own identity) + `/poc/presig-pool` | **deployed proof:** pool store→consume **byte-identical** (`round_trip_matches=true`, count 1→0), partial from the *consumed* presig byte-identical to native fixture (`…d2c14a`) |
| `c0c9fbf` | **#15 Part A** DO relay sign loop — `/poc/sign-relay` (consume→issue→wrap §05→relay→self round-trip) | **deployed proof:** `sent=true`, `received_back=true`, `partial_roundtrip_matches=true`, partial byte-identical to fixture; full wrap→relay→strict-decode→unwrap on deployed wasm; `/poc/handshake` re-checked green |
| `5f26db9` | **#15 Part B (I-4b.2 gate)** native combiner harness `sign_relay_deployed_e2e.rs` | **deployed DO co-signs over the LIVE relay → BSV-valid 2-of-2 sig** (combiner received party-0 partial from DO `03cc87ed…`, combined → 70-byte DER under joint pubkey, **no sats**). Local pure-crypto control also PASS |
| `4937955` | **#17 CF Container P2** — full native `bsv-mpc-service` on CF Containers (root `Dockerfile` + `poc/cf-container-p2/`) | **deployed proof:** `bsv-mpc-service-container.dev-a3e.workers.dev/health` → real KSS JSON (`version 0.1.0`, `data_dir=/data`); ADR-018 native half confirmed end-to-end. Build needs libssl (native-tls); CF=amd64 |
| `b29e699` | **#12 proxy relay combiner** — `relay_sign::combine_sign_over_relay` + `MpcBridge::sign_over_relay` (proxy = combiner over MessageBox) | **deployed proof:** proxy combiner + deployed DO co-sign over the live relay → **BSV-valid 70-byte DER** under joint pubkey `0305e6df…` (`relay_combine_deployed_e2e.rs`, `RELAY_COMBINE_E2E=1`, no sats). 145 proxy unit tests green |
| `a518a3a` | **#5 authz steps 1-2** — caller-identity threading + owner-identity (`mpc_shares.owner_identity`); sign/ecdh/presign reject 403 unless caller==DKG-time owner (§08.1) | **39 worker unit tests** (owner ok / stranger 403 / unauth-with-owner 403 / no-owner allowed; owner round-trip + preserve-on-refresh); design `docs/AUTHZ-DESIGN.md` spec-checked §07/§08 |

**Deployed worker:** `https://bsv-mpc-kss.dev-a3e.workers.dev`.
**Deployed native service (CF Container):** `https://bsv-mpc-service-container.dev-a3e.workers.dev`.
**Container probe (P1):** `https://bsv-mpc-container-probe.dev-a3e.workers.dev`.

---

## 3. Key APIs (all in `bsv-mpc-core`)
- `SigningCoordinator::sign_with_presignature(&[u8;32], Box<dyn Any+Send>)` — the
  **proxy/combiner** path. Box = `presigning::PresignOutput`
  (`(Presignature, PresignaturePublicData)`) from `PresigningManager::take_raw()`.
- `signing::issue_partial_signature_json(presig_json, sighash) -> partial_json` —
  the **DO** path (issue only; needs only the serializable `Presignature`).
- `DkgCoordinator::set_pregenerated_primes_from_json(&str)` — seed primes (native).
- Test/bench helpers (`#[doc(hidden)]`/`#[ignore]`): `dkg::generate_test_primes`,
  `signing::tests::print_issue_partial_fixture`.
- **Base-key only for the presig path**: BRC-42 `hmac_offset` (HD-derived keys)
  keeps the 4-round `sign()` path — the offset is baked into a presig at
  generation time and `issue/combine` take no offset.

---

## 4. Remaining roadmap (integration → merge gate)

1. ~~**Presig provisioning** (task #14)~~ **✅ DONE (`d6ccf57`).** Authed
   `/ceremony/ingest-presig` stores `Presignature_A` (JSON) into the DO
   `mpc_presignatures` pool under the DO's **own** identity (handler authz);
   `/poc/presig-pool` proves provision→consume→light-sign byte-identical on the
   deployed worker. `PresignaturePublicData` stays native (never shipped).
   **REMAINING here:** the native container half — `bsv-mpc-service` must
   actually POST to `/ceremony/ingest-presig` after each presig gen (couples to
   the proxy `bridge.rs` migration, #12). The DO `consume` is wired into the
   sign loop in step 2.
2. ~~**Worker relay sign loop** (task #15, I-4b.2)~~ **✅ DONE (`c0c9fbf` +
   `5f26db9`).** `/poc/sign-relay`: DO consumes a presig → issues its partial →
   wraps it as a canonical §05 `MessageEnvelope` → dials the relay → sends to the
   recipient on box `mpc-sign` (room `{recipient}-mpc-sign`). The **deployed DO
   co-signs over the live relay → BSV-valid 2-of-2 signature** (native combiner
   harness `sign_relay_deployed_e2e.rs`, `SIGN_RELAY_E2E=1`, no sats).
   **REMAINING:** the production path is the `/poc/sign-relay` route; folding it
   into an authed, wake-on-HTTP production endpoint couples to the proxy
   `bridge.rs` migration (#12) and I-5.
3. ~~**CF Container P2** (task #17)~~ **✅ DONE (`4937955`).** Full native
   `bsv-mpc-service` deployed + `/health`-proven on CF Containers
   (`bsv-mpc-service-container.dev-a3e.workers.dev`). Root `Dockerfile` +
   `poc/cf-container-p2/`. ADR-018 native half confirmed. See
   `docs/CF-CONTAINER-PROBE.md` (P2/P3). **REMAINING:** this is a bare
   `/health`-reachable service; wiring it as the actual presig-gen driver
   (running 2-party presig gen with the proxy + POSTing to the DO's
   `/ceremony/ingest-presig`) couples to #12 + provisioning automation.
4. ~~**Proxy `bridge.rs` migration** (task #12, I-4c)~~ **✅ CORE DONE (`b29e699`).**
   `relay_sign::combine_sign_over_relay` (+ `MpcBridge::sign_over_relay`) makes the
   proxy the relay **combiner**, deployed-proven (proxy + DO → BSV-valid sig over
   the relay). **REMAINING (the OQ-I1 retirement, not yet done):** route
   `createSignature`/`createAction` through the relay path + retire the HTTP
   `bridge.rs::sign`. That final wiring needs the presig-provisioning automation
   (native Container generates a correlated pair → DO pool via `/ceremony/ingest-presig`
   AND the proxy's presign pool). Tracked with provisioning automation.
5. **🔒 #5 security must-fixes BEFORE I-5** — design `docs/AUTHZ-DESIGN.md`
   (spec-checked §07/§08). **Steps 1-2 DONE (`a518a3a`)**: caller-identity
   threading + owner-identity authz (sign/ecdh/presign reject 403 unless
   caller==DKG-time owner), 39 worker unit tests. **REMAINING:**
   - **Step 3** — durable auth sessions in DO SQLite (`mpc_auth_sessions`),
     replacing the per-isolate `AUTH_SESSIONS` static → fixes auth-session-isolate.
     A 4-file auth-path refactor (`lib.rs` entrypoint + `auth.rs` +
     `poc.rs` + `do_storage.rs`): move BRC-31 handshake + verify INTO the pinned
     DO, backed by DO SQLite. **Gate (deployed, no asterisks):** handshake then
     authed request succeed across a forced isolate eviction (analog of the I-3b
     fund-safety eviction proof). Keep `/poc/handshake` + the 17 auth unit tests
     green.
   - **Step 4** — authed production `/sign-relay` (requester==owner) + stable
     proxy identity (derive `BridgeAuth` key from the share file — OQ-A2 decided).
     **Gate:** the #12 `relay_combine_deployed_e2e` run through the AUTHED route
     (owner accepted, stranger rejected).
   - §08.12 BRC-52 cert verifier + §09 policy = richer follow-on (own issue).
6. **I-5 merge gate** (task #16). Real-sats mainnet TXID: proxy (share_B) + the
   **deployed** worker (share_A) co-sign over the relay; broadcast; shape-match
   G-5d (`442bd391…`). Wallet `localhost:3321` (Origin `http://admin.com`),
   `E2E_MAINNET=1`. Cite the TXID in the commit.

---

## 5. GitHub state (hygiene current as of 2026-05-20)
- **Milestone:** `v1.0 — CF-native cosigner (Calhoun-side)` — issues #2, #4, #5
  assigned; #3 (Phase H) closed.
- **#2** umbrella — updated with the ADR-018 status block; Phase H ticked.
- **#4** Phase I tracker — labels `phase:I,step:implement,wire-compat,security`;
  body has a "CURRENT STATUS" block (this handoff in miniature); fund-safety gate
  ticked; Step 4 reframed per ADR-018.
- **#5** hardening backlog — labels `security,cleanup`; 1-round presig + seed-
  primes-auth items checked off; auth-session-isolate finding in comments.
- Tasks #12, #14, #15, #16, #17 track the remaining roadmap items above.

---

## 6. Native harness for the I-4b.2 / I-5 proofs
- Party-1 over relay: copy `crates/bsv-mpc-service/tests/dkg_via_messagebox_e2e.rs`
  + `sign_mainnet_via_messagebox_e2e.rs`. `MessageBoxClient` + `DkgHandler`/
  `SigningHandler`; `cggmp24`/`round_based` are dev-deps of root + service.
- BRC-31-authed HTTP to the deployed worker: replicate `bridge.rs`'s `BridgeAuth`
  handshake + per-request signing. ⚠️ Worker auth sessions are in-memory in the
  entrypoint isolate (#5) — handshake + request may hit different isolates;
  `/poc/*` routes are unauthed (the deterministic deployed proofs use those).

---

## 7. Discipline + deploy harness (carry forward)
- **110% no asterisks**: RUNTIME proof for deployed work (byte-identical / live
  TXID), not just build-clean. Native crypto changes proven by unit+vector+BSV-verify.
- Each sub-gate lands on `main` before the next; `cargo fmt --all -- --check` +
  `cargo clippy --workspace --all-targets -- -D warnings` + `cargo build --target
  wasm32-unknown-unknown -p bsv-mpc-worker` before push.
- `cd ~/bsv/mpc/bsv-mpc/` (NEVER `bsv-mpc-old-unscrubbed/`). `gh auth switch -u Calgooon` to push.
- **Worker deploy:** `eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)"`
  then `cd crates/bsv-mpc-worker && wrangler deploy`. **worker-build self-heals to
  0.8.3** via the gitignored `wrangler.toml` build command (it intermittently
  downgrades to 0.7.5 — see memory `reference_worker_build_downgrade`).
- **Container deploy:** uses `CLOUDFLARE_CONTAINERS_TOKEN` in secrets.md (has
  Workers+Containers+UserDetails perms) as `CLOUDFLARE_API_TOKEN`. Needs Workers
  Paid + Containers open-beta (account is entitled). `cd poc/poc-cf-container &&
  wrangler deploy`.
- **secrets.md is gitignored — NEVER commit; redact `[a-f0-9]{16,}` and
  `cfut_[A-Za-z0-9]+` from all output.** Verified: no token in any tracked file.
- god-tier + full-stack: consult `~/bsv/` reference stack before fixes; swarm/
  orchestrate research, then VERIFY agent output.

---
**Last commit:** `a518a3a` (#5 authz steps 1-2 — owner-identity handler authz,
39 worker unit tests). **Next pickup:** **#5 step 3** — durable auth sessions in
DO SQLite (the auth-path refactor above; deployed forced-eviction proof). Then
**#5 step 4** (authed `/sign-relay` + stable proxy key). Then **I-5 (#16)**
real-sats TXID:
swap the e2e's test key shares for a funded DKG joint key (fund the joint
address via wallet `localhost:3321`, Origin `http://admin.com`, `E2E_MAINNET=1`),
proxy + deployed DO co-sign over the relay, broadcast, cite the TXID.
Separately, the createAction-over-relay wiring + HTTP-path retirement need
presig-provisioning automation (native Container → DO + proxy pools). The hybrid
sign path, relay transport, proxy combiner, and both deployment homes are all
proven end-to-end; crypto + transport are locked.
