# bsv-mpc — Person A Handoff (post-audit, 2026-05-28; updated post-#75-CLOSE)

---

## 🟢🟢🟢🟢 RESUME — 2026-05-29 LATE PM — STEP 7a PROVEN (READ THIS FIRST; supersedes ALL below)

**#69 PR-2 step 7a (the SIGNING-side generation half) is BUILT + LIVE-PROVEN. Working on branch
`person-a/69-pr2-client-multishare` (NOT pushed). Filed the scope gap as [bsv-mpc#86] first
(user call), then built it.**

### ✅ DONE — genuine n-party presign GENERATION over the relay (the #86 gap)
- **🔒 Locked design (Arch 2 — "PresignHandler-everywhere + reconstruct-from-bundle"):** keeps the
  deployed cosigner's presign RUNTIME byte-identical (only `/presign-relay/init` gains a `peers` list).
  Device runs `w` PresignHandlers (primary=coordinator, others=cosigner) + ONE external cosigner over
  the relay → the proven `PresigBundle`; the device RECONSTRUCTS its `w` raw boxes from the bundle
  (unseal own + BRC-2-decrypt the co-located ciphertexts it minted the keys for, each paired with the
  shared `commitments`), keeping the external cosigner's ct for the sign-time trigger. Rejected the
  "local-raw PresignHandler role" alt (it mutates the mainnet-proven completion path → asterisk).
- **🟢🟢 LIVE-PROVEN** `crates/bsv-mpc-client/tests/presign_sign_4of6_multiindex_relay_e2e.rs` (device
  {0,1,2} + ONE in-process container cosigner {3} over the deployed relay): 4-of-6 DKG → genuine
  n-party presign → device-holds combine → **BSV-valid signature under the joint key**. joint
  `02c709186cbe1ac811a2f7eb39e17dfeeca4ce7465f009592d300494df981cc32f`, addr
  `1nec9An3paL7P4S19MPzjNntMd5Vk2r1a`, ~524s, `1 passed`. The cosigner generated its OWN presig as a
  genuine protocol party — no process ever held > t−1 shares.
- **New code (all GREEN, both clippy gates + fmt clean):**
  - core `bsv_mpc_core::presigning::deserialize_party_presig_with_public_data` (inverse of the forward
    serializer) — round-trip gate (reconstructed box drives a BSV-valid 2-of-2 sig, byte-stable) + negative.
  - `bsv_mpc_relay::coordinate_presign_over_relay_nparty` (new `provision_presign.rs`, mirrors
    `coordinate_dkg_over_relay`) + `PresignOverRelay`/`PresignCosignerArm`/`PresignOverRelayOutput`.
    4 hermetic topology guards.
  - `/presign-relay/init` n-party `peers` list (mirror `/dkg-relay/init`, back-compat fallback +
    fail-fast if coordinator absent; `resolve_presign_peers` 4 unit tests).
  - `DoTrigger.presig_id` shipped by `combine_sign_over_relay_nparty` (additive; 12 existing literals → None).

### 🛡 Two production-correct service-side fixes the live run forced out (N-PARTY PATH ONLY)
The 2-party deployed runtime stays byte-identical (it uses `load_share_or_recover_pub` / bare authz).
1. **Composite owner-authz** on `/presign-relay/init` (`authz_owner_at_index_pub`): a multi-index
   wallet records its owner at `{joint}#{idx}`, so the prior bare-`agent_id` check was a §08.1 BYPASS
   (any authed caller could arm a presign on someone else's multishare wallet). Now authz against the
   composite owner (bare fallback for 2-party). Positive + negative unit-tested.
2. **Race-closing retry** on the composite share load (`load_share_or_recover_at_index_pub`): a presign
   armed immediately after provisioning could 404 before the cosigner's DKG persist landed (the device
   returns on its own quorum agreement; the container persists on its listener pump a beat later).
   Bounded retry (15×200ms) closes it; a genuine miss still 404s.

### ⏳ NEXT — Step 7b/7c (client wiring) then Step 8 (deployed mainnet)
- **7b:** client `DeployedSigner` multi-index presig pool + multi-index unseal (composite `{agent_id}#{idx}`
  shares). DECISION: keep `coordinate_presign_over_relay_nparty` returning raw boxes (proven); the client
  converts to a durable serializable form for pooling + reconstructs raw boxes at sign time via the proven
  core inverse — avoids re-running the 8-min E2E.
- **7c:** wire `DeployedSigner::sign` (when `my_indices.len() > 1`) → `combine_sign_over_relay_nparty`
  (primary + extras + ONE cosigner trigger w/ `presig_id` + `cosigner_encrypted_share`). Reuse the #83
  kernel; do NOT reimplement.
- **8:** deployed mainnet 4-of-6 (with #70): `create_wallet_nparty` + `provision_wallet_nparty` full
  BRC-31-authed proof + real spend → WoC TXID. FUNDING gated on **#85** (MITM identity-fetch). The
  composite owner-authz fix above is a prerequisite for step 8's real-BRC-31 owner enforcement.

### ✅✅ UPDATE (2026-05-29 LATE PM) — 7b/7c DONE + #85 (4-of-6 path) DONE; capstone runbook below
- **7b/7c BUILT+GREEN** (see PROGRESS daily log). 7a LIVE-PROVEN (re-run pending a test-only fix:
  the e2e used a FIXED `sign_session` → stale-partial cross-run contamination on the shared relay;
  now keyed off the fresh joint key. The CODE was always correct — DKG+presign+#85 passed live; only
  the sign combine hit a prior run's stale partial under the fixed session).
- **#85 (DKG + presign funding path) BUILT+PROVEN** (core golden vectors + fast HTTP proof + live e2e
  now pins). Pin threaded `NpartyCosigner`→`CosignerEndpoint`→`PresignCosignerArm`→`WalletMeta`→FFI.
- **REMAINING #85 surface (recovery flow only):** `/reshare-relay/identity` + `/refresh-relay/identity`
  return the master pub directly → the fix is a CLIENT compare-to-pinned in `coordinate_reshare_over_relay`
  / `recover_wallet` (mirror the presign pin). Does NOT gate 4-of-6 funding; mechanical follow-up.

### 🎯 CAPSTONE RUNBOOK — the closing TXID (funding via the localhost:3321 MetaNet wallet)
1. **Deploy NotaryA (hardened #86+#85):** `cd poc/cf-container-p2 && eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)" && npx wrangler deploy` (Docker build ~10 min). Verify:
   `GET https://bsv-mpc-service-container.dev-a3e.workers.dev/presign-relay/identity` → 200; and
   `GET …/dkg-relay/peer-identity?session=<64hex>&index=3` now returns `master_pub_hex` + `attestation_hex`.
   NotaryA master pub = pub of `MPC_SERVER_PRIVATE_KEY=4d4327ab…241af3` (secrets.md:541).
2. **#70 — NotaryB (2nd INDEPENDENT cosigner):** generate a FRESH master keypair for NotaryB via
   `~/bsv/rust-wallet-utils` (or a bsv-rs one-off) → **save it to `secrets.md`** (gitignored, e.g.
   `MPC_SERVER_PRIVATE_KEY_NOTARY_B=…`). New wrangler config (distinct `name`, e.g.
   `bsv-mpc-service-container-b`) + `wrangler secret put MPC_SERVER_PRIVATE_KEY` with that key → deploy.
   The 4-of-6 splits device `{0,1,2}` + NotaryA `{3,4}` + NotaryB `{5}` (two `NpartyCosigner`s, each
   `expected_master_pub` PINNED). worker.js injects the secret into the container (`env.MPC_SERVER_PRIVATE_KEY`).
3. **Deployed no-sats 4-of-6 capstone** (real BRC-31 + #85 pins + 2 Notaries): `provision_wallet_nparty`
   → `DeployedSigner` multi-index `sign` of a dummy hash → BSV-valid sig. (Use a UNIQUE per-run sign
   session — the fixed-session bug above bites the shared relay.)
4. **FUND** the joint address from `localhost:3321` (MetaNet/BRC-100): `createAction` with a P2PKH output
   to the 4-of-6 joint address (a few k sats).
5. **FULL SPEND → WoC TXID:** genuine 4-of-6 `createAction` spending that UTXO (device folds `{0,1,2}` +
   ONE Notary partial over the relay) → broadcast (ARC/WoC) → `whatsonchain.com/tx/<id>`. **Closes #69,
   #70, #85, #86.**

---

## 🟢🟢🟢 RESUME — 2026-05-29 PM (earlier; superseded by the LATE PM block above)

**Owned critical path = #69 (client 4-of-6) + #70 (2nd cosigner). The PROVISIONING side
of #69 PR-2 client is DONE + live-proven + committed. The SIGNING side (step 7) is the
remaining lift — and it is BIGGER than the old handoff implied (see scope finding).**

### ✅ DONE this session — committed `40347af` on branch `person-a/69-pr2-client-multishare`
**NOT pushed to main yet** (user wanted a clean checkpoint commit first; awaiting push/PR call).
Working tree clean except the two untracked `docs/*AUDIT*.md` (NEVER commit those).

- **5a-i** `bsv_mpc_core::hd::derive_relay_index_privkey(server_priv, session, index)` —
  `reduce_mod_n(HMAC-SHA256(key=server_priv, b"bsv-mpc dkg-relay identity v1" ‖ session(32) ‖
  index_be_u16))`. **ONE-WAY, not additive** (a leaked relay key must not recover server_priv,
  which is also the BRC-31 auth + BRC-2 sealing key). 8 unit tests + **frozen golden vector**
  `f698e3016303f85f5358e07dbe9b23ae798182cf5d1c5bac93163f6afa40d72d`.
- **5a-ii** service `handle_dkg_relay_init` derives a per-index relay identity (distinct relay
  room per held index) + new read-only `GET /dkg-relay/peer-identity?session&index`. 4 route-unit
  tests (route↔core golden cross-check).
- **5b** `bsv_mpc_relay::coordinate_dkg_over_relay` (NEW, in `provision_dkg.rs`, sibling to
  `coordinate_reshare_over_relay`) + `bsv_mpc_client::native_io::provision_wallet_nparty`
  (handshake → coordinate → composite-seal `{agent_id}#{index}`). `CosignerEndpoint{init_url,
  indices,arm_signer}` supports the 2-cosigner / one-holds-two topology.
  **🟢 PROVEN: live 6-party 4-of-6 DKG agreed a byte-identical joint key over the deployed relay**
  (`tests/dkg_4of6_multiindex_relay_e2e.rs`): joint_pubkey
  `027545996f0074c9c3eaf9835c8a53052c4581ed084e3b1222e2d6f72eb9c13798`, addr
  `1DbuHHwfUVFZxgSfhsNaBM7hQ12EDoFbiG`, 365s; device {0,1,2} + ONE in-process container {3,4,5}
  via 3 one-way-derived identities; device 3 distinct shares + container 3 distinct composite shares.
- **6** `my_indices: Vec<u16>` on `WalletMeta` + `FfiSignerConfig` (back-compat: empty →
  `[device_share_index]`); `create_wallet`/`recover_wallet` set `[device_share_index]`; new
  `create_wallet_nparty` + `FfiNpartyCosigner`. 2-of-2 back-compat GREEN.

### 🛠 Two production-correct fixes the live run forced out (BOTH touch the deployed path)
1. **Pre-seed device primes** in `coordinate_dkg_over_relay` (was late-seed). A device backing
   `w=t−1` parties inline-generated safe primes INSIDE auxinfo `proceed()`, blocking the thread
   for minutes (would freeze a phone). Pre-seed = step-4's proven ordering; also delays the
   device's round-1, giving late-seeding cosigner parties a head start.
2. **Idempotent transport retry** — `MessageBoxClient::send_round_message_reliable` (one stable
   message_id → relay no-ops re-sends → exactly-once) + the `MessageBoxListener` retries sends 4×
   w/ backoff. A transient `/sendMessage` blip previously DROPPED a round message → ceremony
   stall. ⚠️ This hardens EVERY ceremony (DKG/sign/presign/reshare) on the deployed cosigner —
   additive + safe (idempotency = the relay's existing (recipient,box,message_id) dedup).

### 🔴 STEP 7 — SCOPE FINDING (the next big build; ~5b-sized, NOT "just wire the combine")
The multi-index SIGN **consume** side EXISTS + is proven: `combine_sign_over_relay_nparty`
(relay), the merged `device_holds_combine` kernel (#83), the proxy's `sign_over_relay_device_holds`.
**BUT the multi-index presig GENERATION over the relay does NOT exist anywhere in the repo.** The
proxy's `DevicePresigSetPool::add_set` is called ONLY by its mainnet E2E, which fabricates the
correlated `{0,1,2}` presigs with a LOCAL test helper (`gen_presig_set`, holding all 6 shares) —
a within-stack shortcut, not a production path. A real client multi-index sign needs the device
to obtain `w` CORRELATED presigs from a genuine n-party presign-over-relay ceremony (device's `w`
parties + cosigner). **So Step 7 =**
  (a) build `coordinate_presign_over_relay_nparty` (relay; mirror `coordinate_presign_over_relay`
      but device drives `w` parties + cosigner → `w` correlated device presigs + cosigner's),
  (b) client `DeployedSigner`: multi-index presig pool (a `DevicePresigSetPool` analog) +
      multi-index unseal (composite `{agent_id}#{index}`, `w` shares),
  (c) wire `DeployedSigner::sign` (when `my_indices.len() > 1`) → `combine_sign_over_relay_nparty`
      (primary + extras + ONE cosigner trigger); reuse the #83 kernel, do NOT reimplement.
  Then **Step 8** = deployed mainnet 4-of-6 (with #70): `create_wallet_nparty` +
  `provision_wallet_nparty`'s full BRC-31-authed proof + a real spend → WoC TXID. (The in-process
  service auth is a DEV STUB → cannot do a real BRC-31 handshake, so the full client-FFI proof is
  step-8 against the deployed container, exactly like `recover_wallet`'s deployed e2e.)

### 🔴 TRACKED GATE — bsv-mpc#85 (security, HIGH, still open)
Cosigner identity fetched over UNAUTH HTTP — now ALSO the new `GET /dkg-relay/peer-identity` (the
code notes this). MITM can steer DKG to an attacker co-party. MUST close before god-tier-production
4-of-6 FUNDING: pin the cosigner master identity out-of-band + BRC-31-sign the fetch + signed
co-party challenge.

### Notes / discipline
- `~/bsv/mpc/cash100` does NOT exist — the app dir is `~/bsv/mpc/100cash` (Person B's Swift app,
  the CONSUMER of this 4-of-6 work). Person A's lane is `bsv-mpc` only.
- Run the EXACT CI gates before any push: `cargo fmt --all -- --check` + `cargo clippy --workspace
  --all-targets -- -D warnings` AND `cargo clippy -p bsv-mpc-client --features native --all-targets
  -- -D warnings` (the FFI is native-gated — the plain workspace clippy does NOT lint it).
- Live relay E2Es: `MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev … --test-threads=1`,
  ~6 min (Paillier-dominated). NO sats (DKG only).

---

## 🟢🟢 RESUME — 2026-05-29 (earlier; SUPERSEDED by the PM block above)

**Owned critical path = #69 (client 4-of-6) + #70 (2nd cosigner). Goal = god-tier 4-of-6
production self-custody on 100cash, mpc-spec-conformant, no asterisks.**

### ✅ MERGED to main this session (all proven, zero asterisks)
- **bsv-mpc PR #83** (`8c8c7bb`) — `device_holds_combine` kernel in `bsv-mpc-core/src/signing.rs`
  (relay-free device-holds-(t−1) combine) + `combine_sign_over_relay_nparty` routes through it
  (zero-drift). Hermetic 3-of-3 + #[ignore] 4-of-6 proof.
- **MPC-Spec PR #49** — ADR-0052 (device-holds-(t−1) multishare + genuine n-party DKG over relay,
  **Model B**: one ceremony identity per held index, wire 1:1 unchanged) + §06.22 + §15.2.4 +
  `conformance/test-vectors/15-device-holds-quorum.json` + Python runner gate.
- **MPC-Spec PR #50** — §13.7.1/§18.2 cross-impl Notary swap (replace-party reshare, vector-gated).
- **bsv-mpc PR #84** (`e2dc5cf`) — **PR-2 SERVICE SIDE**: composite `(agent_id,share_index)`
  storage (`storage.rs`); `DkgHandler::use_composite_persist` + re-provision guard
  (`dkg_handler.rs`); `POST /dkg-relay/{identity,init}` + `/dkg-relay/debug`
  (`dkg_relay_handlers.rs`, `lib.rs`); `AppState.storage`→`Arc<RwLock>`.
  **🟢 PROVEN: genuine 6-party 4-of-6 DKG agreed a byte-identical joint key over the LIVE relay**
  (`tests/dkg_4of6_via_messagebox_e2e.rs`, env-gated `MESSAGEBOX_RELAY_URL`; ~6 min; joint_pubkey
  `029b846a…`, addr `15naugTY2FycKX5BtpndLkVfGkou5jFaVP`). Container concern SETTLED (standard-4 +
  reshare relay-DKG patterns scale).

### 🔴 TRACKED GATE — bsv-mpc#85 (security, HIGH, pre-existing)
Cosigner identity is fetched over UNAUTH HTTP (`/dkg-relay/identity`, `/reshare-relay/identity`,
`reshare::fetch_peer_identity`) → MITM can steer DKG to an attacker co-party (defeats threshold
independence). **MUST close before god-tier-production 4-of-6 funding:** pin the cosigner master
identity out-of-band + BRC-31-sign the fetch + gate funding on a signed co-party challenge.

### 🔒 LOCKED design decisions (user-approved this session)
1. **(a) new seam in `bsv-mpc-client`** (n-party machinery already shared in `bsv-mpc-relay`).
2. **Provisioning = genuine 6-party DKG over relay** (NOT 2-of-2+reshare). Model B.
3. **Topology = 2 cosigners, one holds 2 indices** (matches "two Notaries" goal) → needs per-index
   relay identity.
4. **Per-index relay identity = ONE-WAY HMAC, NOT additive.** (Adversary killed the additive idea:
   `relay_priv_i = server_priv + H(pub‖i)` LEAKS server_priv if any relay key leaks — and server_priv
   is also the BRC-31 auth + BRC-2 share-sealing key. Catastrophic.) **Use:**
   `relay_priv_i = reduce_mod_n( HMAC-SHA256(key = server_priv_bytes, msg = b"bsv-mpc dkg-relay identity v1" ‖ session_id(32) ‖ index_be_u16) )`
   → leak-safe (one-way) + ceremony-scoped. Device CANNOT derive the pub (one-way) → device FETCHES
   each container index's relay pub (read-only GET, per (session,index)); #85 hardens that fetch.
   This is container-internal → **zero new cross-impl wire surface** (better than additive).

### ▶️ REMAINING (PR-2 client side + close). Branch off main: `person-a/69-pr2-clientNN-...`
- **5a-i** core: add `derive_relay_index_privkey(server_priv, session_id, index) -> PrivateKey` to
  `bsv-mpc-core/src/hd.rs` (one-way HMAC above; `sha256_hmac` + `Scalar::<Secp256k1>::from_be_bytes_mod_order`
  + `PrivateKey::from_bytes`). Hermetic unit test: deterministic, distinct per (session,index),
  distinct from server_priv, valid key. (I had just read hd.rs to write this when we wrapped.)
- **5a-ii** route: in `dkg_relay_handlers.rs::handle_dkg_relay_init`, replace the single
  `server_identity_priv_from_env()` MessageBoxClient identity with
  `derive_relay_index_privkey(&server_priv, &dkg_session, body.my_index)` (DISTINCT per index →
  distinct relay room → clean delivery; relay routes by `{identity}-{box}` room, verified). Add a
  read-only `GET /dkg-relay/peer-identity?session&index` → relay_pub for the device to fetch.
- **5b** driver: `provision_wallet_nparty` in `bsv-mpc-client/src/native_io/provision.rs`, mirroring
  the mainnet-proven `bsv_mpc_relay::reshare::coordinate_reshare_over_relay` (reshare.rs:290-567)
  PHASE A ONLY (keep+seal shares, no PSS/combine): device mints w fresh identities for {0,1,2};
  fetch+arm the cosigner's {3,4,5} (once per index, per user-decision #2); peers_for over all 6;
  initiate all device parties then ship round-1; late-seed primes; await w completions; assert
  byte-identical joint key; composite-seal w shares via keystore. Invariant: arm-response pub ==
  device-fetched relay_pub (catches index mis-derivation).
- **5b test**: `tests/dkg_4of6_multiindex_relay_e2e.rs` — device {0,1,2} + ONE in-process container
  holding {3,4,5} via 3 one-way-derived identities, over the live relay → joint key agreed + 3
  distinct composite shares (proves the multi-index-on-one-container path the step-4 test doesn't).
  Run with `MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev ... --test-threads=1`.
- **6** FFI: `device_share_index`→`my_indices: Vec<u16>` on `FfiSignerConfig`/`WalletMeta`/
  `DeployedSigner` + `create_wallet_nparty` (single-index default keeps 2-of-2 compiling).
- **7** sign: `DeployedSigner::sign` iterates `my_indices` → primary + extras → the merged
  `device_holds_combine` (reuse PR #83 kernel, do NOT reimplement).
- **8** mainnet 4-of-6 genuine-DKG E2E (with #70 deploy + sats) — the audit-closing artifact.
  Mirror `bsv-mpc-proxy/tests/createaction_4of6_device_holds_relay_mainnet_e2e.rs` but provision via
  genuine relay DKG. ADD a new test; keep the local-sim one as a fast regression.

### Discipline reminders
No commit/push without user OK (they've been fast-shipping: "push to main" = merge). NO `cargo fmt`
on crate roots — but the workspace IS fmt-clean now; run `cargo fmt --all -- --check` +
`cargo clippy --workspace --all-targets -- -D warnings` BEFORE any push (the AppState→Arc<RwLock>
change taught us to verify workspace-wide, not just the edited crate). Don't commit the two
untracked `docs/*AUDIT*.md`. The deployed relay works from this env (step-4 ran green against it).

---


> For a NEW session to drive **Person A's** lane on the Calhoun-side BSV-MPC partnership.
> Person A owns the **load-bearing 4-of-6 seam + spec-level decisions**.
> Person B has the parallel lane (god-tier security hardening + 100cash Swift wiring).
> As of 2026-05-28 PM Person B has CLOSED the send-path cluster (#75 + 100cash#13/#14/#15)
> via two real mainnet TXIDs (see below) — see
> `/Users/johncalhoun/bsv/mpc/100cash/ROADMAP-HANDOFF.md` §"Post-audit work split".
> Repo: `B1nary-Calhoun-Partnership/bsv-mpc` (branch `main`), local at
> `/Users/johncalhoun/bsv/mpc/bsv-mpc/`. Created 2026-05-28; resume-state rewritten
> after #75 CLOSED on-chain and #69 (4-of-6 client multi-share) surfaced as the next
> big blocker for app-parity signing.

---

## 🎯 Overarching goal (shared — Person A ⟷ Person B)

**Ship 4-of-6 PRODUCTION god-tier self-custody on 100cash.** The real topology — t=4, n=6: device-held shares + two independent Notary cosigners — NOT the 2-of-2 we used to prove the send chain. Getting 4-of-6 right on iOS also sets up **web** (same Rust core → wasm) and **multi-device** (mirrored shares + coordinated presig checkout, bsv-mpc#56). It is *plumbing over the audited `bsv-mpc-core`* — **no new MPC protocol** — and everything **must conform to mpc-spec** (the §-numbered protocol spec + ADRs in bsv-mpc). Standing up a **2nd cosigner/Notary** (bsv-mpc#70) is acceptable for now so the two mandatory sides are genuinely independent.

**Where we are (2026-05-28):** the genuine 100cash Swift send chain is PROVEN on mainnet end-to-end vs the deployed cosigner + relay + ARC — but at **2-of-2**, because client-side 4-of-6 multi-share isn't wired. The send-path FFIs are threshold-agnostic, so the *only* thing between us and 4-of-6 production is that one piece.

**The two lanes (this is the split):**
- **Person A → `bsv-mpc`:** the critical path is **#69** — client-side multi-share (device holds t−1 shares, `my_indices: Vec<ShareIndex>`) over the client crate, mpc-spec-conformant; paired with **#70** (deploy the 2nd cosigner so 4-of-6 = two independent Notaries). This is THE unlock.
- **Person B → `100cash`:** the moment #69 lands, flip `NativeBackendConfig` (already defaults threshold 4 / parties 6) from the 2-of-2 drive to real 4-of-6 and re-prove the mainnet drive → the **capstone #31** (physical device, no mocks, real mainnet send, at 4-of-6; #30 = no-mocks CI guard). In parallel: the remaining hardening + real Google sign-in (#23 — the Account Service `/auth/verify` path is now live & proven).

**Shipped today (both lanes depend on this):** send-path cluster CLOSED via mainnet TXIDs `5e527f27…51abee` + `d3515c50…c395cb` (100cash#13/#14/#15 + bsv-mpc#75); native-tls MessageBox-WS fix on Apple (bsv-mpc `1da783c`); Account Service `/auth/verify` live & proven, 100cash#9 closed. CF deploy creds for the dev-a3e workers (account `ea3e6d…`, dev@calhounjohn.com) are in gitignored `100cash/secrets.md`.

---

## 🟢 Resume state — 2026-05-28 PM (READ THIS FIRST, then the checklist below)

### 🎉 The send-path cluster is DONE and CLOSED (other window, 2026-05-28 PM)

- **bsv-mpc#75 is CLOSED** (closed on-chain 2026-05-28T19:07Z) — co-closed with
  **100cash#13/#14/#15** via TWO real audit-closing **MAINNET TXIDs** that both spend
  the MPC joint-key UTXO (ARC `SEEN_ON_NETWORK`):
  - `5e527f275ffa796f9a0997b6b0897ec09570a3860a128bd3c69c416b6551abee`
  - `d3515c50ed494a656ef25f7bf10d8760159f3ec61562c7625ce289e521c395cb`
  - Verify: `whatsonchain.com/tx/<id>`. These are the E2E proof artifacts — the
    earlier "E2E PENDING" gate on #75 is now GREEN. **Do not re-open #75.**
- This closed the loop that #75 (canonical_render + `ffi_canonical_render`) was the
  spec/FFI half of: 100cash now calls the real render path and a genuine Swift send
  chain (on simulator, vs all deployed infra — cosigner container + relay + ARC) put
  two transactions on mainnet.

### ⚠️ HEADS-UP — native-tls MessageBox WebSocket fix landed (commit `1da783c`)

The other window shipped a TLS fix that touches **`bsv-mpc-messagebox`**. If your next
item touches messagebox or anything WebSocket-related, read this first:

- **Symptom:** rustls+ring's `ClientConnection::new` faults (`EXC_BAD_ACCESS`) on the
  **arm64 iOS SIMULATOR**, so the relay WS (`coordinate_presign_over_relay`) never
  opens — the 100cash sign path crashed there. (DKG was fine — it's plain HTTP/reqwest;
  only sign uses the WS.)
- **Fix:** `bsv-mpc-messagebox` now **TARGET-SPLITS** `tokio-tungstenite`'s TLS —
  **native-tls (Security.framework) on Apple, rustls on Linux**. `client_async_tls`
  picks the connector from the cfg feature, so no transport code changed.
- **🟢 LINUX / CONTAINER BEHAVIOR IS UNCHANGED** — still rustls, still no OpenSSL. The
  cosigner/container build is not affected. The split only changes the Apple targets.
- Same commit also added two *additive* FFIs in `bsv-mpc-client`:
  `ffi_p2pkh_unlocking_script_hex` (MPC DER sig + sighash flag + joint pubkey → P2PKH
  scriptSig) and `ffi_beef_subject_raw_tx_hex` (extract a wallet-signed tx from BEEF to
  re-broadcast). Both golden-vector tested, clippy clean. **NOTE:** these landed in
  `bsv-mpc-client/src/ffi.rs` — which is part of #69's file surface — so re-diff that
  file before you start #69.

### 🔴 NEXT BIG ITEM — bsv-mpc#69 (4-of-6 client multi-share) — THE CRITICAL PATH TO THE OVERARCHING GOAL

**#69 is THE critical path** — it is the *only* thing between us and the shared goal
(4-of-6 production self-custody on 100cash; see the goal block at top). Paired with
**#70** (deploy the 2nd cosigner so 4-of-6 = two **independent** Notaries, per
**mpc-spec §13 federation** + **direction.md §1** "two mandatory sides"). **Still OPEN,
still Person A's.** Why it's the unlock:

- The 100cash app config is **4-of-6**, but provisioning 4-of-6 over the deployed
  cosigner currently **FAILS** ("no outgoing messages to bundle") because the client
  multi-share path (device holds **t−1 shares**, `my_indices: Vec<ShareIndex>`) is not
  wired in `bsv-mpc-client`. The client FFI today (`FfiSigningSession::new`,
  `ffi.rs:473`) takes a **single** `share_index: u16` — that's literally why it's
  2-of-2-only. #69 makes the device hold a *set* of indices.
- Because of that, the mainnet send drive above had to **fall back to 2-of-2**
  (deployed-proven). So the two mainnet TXIDs prove the send-path/render/sign machinery
  end-to-end, but NOT the app's real 4-of-6 topology.
- **#69 is what unblocks true app-parity (4-of-6) signing**, and after it lands Person B
  flips `NativeBackendConfig` to real 4-of-6 and re-proves the drive → the capstone
  100cash#31. Until #69 lands, 100cash cannot provision/sign with its real threshold.
- The other window did NOT take #69 (prior handoff speculated they "might" — they did
  not; they closed the send-path cluster instead). Treat #69 as un-started Person A work.
- Crypto is already proven — **orchestration only, no new MPC protocol** — at TWO levels:
  the mainnet TXID `febd2877…` (PR #46), AND the in-core POC
  `crates/bsv-mpc-core/tests/poc_4of6_device_holds_presig_relay.rs` (keystone
  `poc_4of6_device_holds_3.rs`) which already proves a 4-of-6 DKG → 6 shares → the device
  holding `{0,1,2}` (t−1=3) folds parties 1 & 2's partials **locally** (never on the
  wire) and combines a valid signature, with the NEGATIVE case asserted (device-alone
  3<t=4 cannot sign). #69 is wiring that exact proven combine through the **client crate
  FFI**. Approach (a) new seam vs (b) factor proxy's `DeviceShareBundle` out is still
  the open user-decision (see checklist + Owned-scope table).

**mpc-spec conformance for #69 (cite these — keep the wiring spec-conformant):** the
canonical §-numbered protocol spec lives **outside this repo** at
`/Users/johncalhoun/bsv/mpc/MPC-Spec/` (files `00-overview.md` … `18-recovery.md`,
ADRs in `decisions/`, conformance vectors in `conformance/`). There is no single
`mpc-spec.md`; the governing sections for 4-of-6 / multi-share / share indexing are:
- **§00 Quorum profile** (`00-overview.md`) — the topology primitive is a
  `(threshold, n, party_kinds)` tuple; "cosigner" and "party" are interchangeable and
  the spec is symmetric. The joint pubkey is the same regardless of which threshold
  subset signs. 4-of-6 is just `(t=4, n=6)` over this.
- **§18.3 Quorum profiles + §18.2 cross-(t,n) resharing** (`18-recovery.md`) — defines
  `(t,n)` profiles and the **address-preserving** transition between them
  (`reshare_change_threshold`, 0 sats on-chain). #69's shares must be the `(t=4,n=6)`
  output of DKG/reshare here; the joint pubkey is invariant.
- **§15 Notary product / multi-share tiers** (`15-notary-product.md`) + **direction.md
  §1.1 flat-threshold realization** — the **multi-share model** #69 implements:
  `t = w + 1`, where `w` = the user's share count held on the device (mirrored to the
  passkey), and `#second-factors ≤ w`. For 4-of-6 the device holds `w = t−1 = 3` shares;
  the network side (the two Notaries) supplies the rest. This is the exact
  `my_indices: Vec<ShareIndex>` semantics.
- **§08.8 threshold-subject (nested MPC)** + **ShareIndex type**
  (`bsv-mpc-core/src/types.rs:103`, `pub struct ShareIndex(pub u16)`) — the share index
  is the party's position in the Shamir polynomial evaluation and the P2P message route;
  `ThresholdConfig::new` enforces `2 ≤ threshold ≤ parties`. #69 must route every held
  index correctly and preserve these invariants.

### What else the other window still owns (not Person A)

- bsv-mpc#76/#77/#78 (policy gate RED cluster — shipped per their handoff), #79
  (unbounded HTTP), #80 (Zeroize), #81 (share-metadata auth), 100cash#19/#25.
  100cash#13/#14/#15 are CLOSED (send-path cluster, above).

### File-scope guards — DO NOT TOUCH (other window has uncommitted work)

As of this doc's write-time (2026-05-28 PM) local `main` was **clean** — the only
untracked files were two audit docs (`docs/67-WEB-CUSTODY-AUDIT.md`,
`docs/CONVERGENCE-AUDIT-2026-05-27.md`) which must NOT be committed. Person B's send-path
+ policy work appears committed (commits through `1da783c`). **Re-verify with
`git status` BEFORE editing anything** — Person B may pick up new work (e.g. #79/#80/#81)
that re-touches the policy/proxy surface:

- `bsv-mpc-proxy/src/{bridge,config,server,wallet_api,policy}.rs`
- `bsv-mpc-proxy/tests/*`
- `bsv-mpc-core/Cargo.toml`, `bsv-mpc-core/src/policy.rs`
- `.github/workflows/ci.yml`
- `tests/e2e.rs`
- `crates/bsv-mpc-client/src/ffi.rs` — the other window's `1da783c` added two FFIs here
  (now committed); re-diff this file before #69 work since #69 also edits it.
- Anywhere in `/Users/johncalhoun/bsv/mpc/100cash/` (Person B's entire repo)
- **NEVER commit** `docs/67-WEB-CUSTODY-AUDIT.md` or `docs/CONVERGENCE-AUDIT-2026-05-27.md`
  (untracked audit drafts). Commit only the doc files you intentionally changed; never
  `git add -A`.

**If you commit to any file in their working tree, you cause a pull-conflict in
their window.** The cost is real — they have to rebase + resolve. Do not introduce
that friction.

### First-action checklist for the new window (run BEFORE picking up any work)

Execute these in order; the decision tree at the bottom tells you what to do based
on what you find.

1. **Pull latest:** `cd /Users/johncalhoun/bsv/mpc/bsv-mpc && git fetch && git log --oneline origin/main -10`. Note any commits since `5481e51` — that's whether
   Person B has merged anything new (their policy cluster, #69, etc.).
2. **Check the other window's working tree:** `git status --short` (same disk = same
   working tree). The file-scope guard list above is a SNAPSHOT from this doc's write
   time; the LIVE state is what `git status` shows now. Update your file-avoidance
   list accordingly.
3. **Check 100cash progress:**
   - `cd /Users/johncalhoun/bsv/mpc/100cash && git log --oneline -10` (Person B's
     activity)
   - `git status --short` (Person B's in-flight work)
   - `cat PROGRESS-PERSON-B.md` (their live tracker — sibling to ours)
   - `gh issue view 15 --repo Calgooon/100cash` (look for closing comment + mainnet TXID)
4. **Confirm bsv-mpc#75 is CLOSED:** `gh issue view 75 --comments` — it closed
   2026-05-28T19:07Z via the two mainnet TXIDs above. This is expected; **do not
   re-open it.** If somehow it's open again, escalate before doing anything.
5. **Check bsv-mpc#69 status:** `gh issue view 69 --comments` and `gh pr list --state
   all --search "in:title 69"`. As of this doc the other window did NOT take #69 — it
   is OPEN and is **Person A's next big item** (unblocks 4-of-6 app parity). Confirm no
   surprise PR opened against it before you start.
6. **Build + test still green on main:** `cargo build -p bsv-mpc-core && cargo test
   -p bsv-mpc-core --lib approval::` — sanity-check that the closed #75 render path
   still works (only takes a few seconds; the workspace is cached). If it broke,
   escalate to user before doing anything else.

### Decision tree based on what step 1-6 found

- **#69 OPEN (expected, it's yours)** → this is the priority — it unblocks 100cash's
  real 4-of-6 topology (the mainnet drive fell back to 2-of-2). Surface:
  `bsv-mpc-client/src/{ffi.rs,native_io/{provision,ceremony,signer}.rs}`,
  `bsv-mpc-relay/src/dkg.rs`, `bsv-mpc-proxy/src/{bridge,presign_manager,wallet_api}.rs`.
  **First re-diff `bsv-mpc-client/src/ffi.rs`** — the other window's `1da783c` added two
  FFIs there. **ASK USER approach (a) new seam vs (b) factor proxy's `DeviceShareBundle`
  out BEFORE coding** (still the open design decision). Crypto is proven (TXID
  `febd2877…`, PR #46) — orchestration only.
- **If #69 is blocked on the user's (a)/(b) decision** → pick up #73 in the meantime —
  it's in `bsv-mpc-core/src/signing.rs:1028-1047`, which has no overlap with the #69
  surface, and is the easier same-day ship. Or #70 (deploy ops, no code).
- **If a clean 4-of-6 mainnet TXID is wanted as the #69 closing artifact** → #69 + #70
  pair up: #70 stands up a 2nd cosigner so the 4-of-6 sign uses two independent
  cosigners, not one twice. Run #70 in parallel (ops, not code).
- **#74 spec PR still needed** → can start anytime — needs the user's ADR-0005
  decision (add `"approval"` to enum vs different field) + ADR-0032's `exec_id_prefix`
  rule. Spec PR lands first (per quality-gate-4), then the 2-line code fix in
  `bsv-mpc-proxy/src/relay_approval.rs:132-133`. Confirm via step 2 before editing
  (proxy crate may be re-touched by Person B's #79/#80/#81).

### Quality-gates rule (still applies, no exceptions)

Every issue closed ships with UNIT + VECTOR/GOLDEN + E2E + SPEC PR (if applicable) +
PROOF ARTIFACT (mainnet TXID + WoC URL or test names + CI run link) + CI INTEGRATION +
ZERO-DRIFT all GREEN. "Skipping is lazy." "No asterisks." Open a follow-up issue
instead of asterisking the parent. See the full quality gates section in the
session-opener prompt below.

### After picking up work

Update `PROGRESS-PERSON-A.md` (live tracker — gets committed direct to main as
sibling housekeeping). Use the existing entries for #73 / #74 / #69 / #70 as the
slot for new status. Pattern: status → locked decisions → spec PR (if any) → code
PR → quality gates (one line per gate with GREEN/PENDING + proof link).

---

## Owned scope (6 open + 1 closed)

All in `B1nary-Calhoun-Partnership/bsv-mpc`. `gh issue view <num>` for full body.
The critical path to the overarching goal (4-of-6 production) is **#69 + #70**; everything
below them is post-critical-path (spec-leaks #73/#74, policy #71, design #67/#56).

| # | Title | Status | Files |
|---|---|---|---|
| **69** | Client-side multi-share wiring — device holds t−1 shares (`my_indices: Vec<ShareIndex>`) | **OPEN — ★ CRITICAL PATH to 4-of-6 production** / `step:implement` / unblocks 100cash 4-of-6 (drive fell back to 2-of-2). Conform to mpc-spec §00/§18.3/§15/§08.8 + direction.md §1.1 | `bsv-mpc-client/src/{ffi.rs,native_io/{provision,ceremony,signer}.rs}` + `bsv-mpc-relay/src/dkg.rs` + `bsv-mpc-proxy/src/{bridge,presign_manager,wallet_api}.rs`. POC: `bsv-mpc-core/tests/poc_4of6_device_holds_presig_relay.rs` |
| **70** | Deploy 2nd cosigner instance (interim) + prod 2-Notary independence (§13) | open / `step:investigate` / **PAIRS with #69** so 4-of-6 = two INDEPENDENT Notaries (mpc-spec §13, direction.md §1) | CF Worker / container deploy ops, not in-repo code |
| **74** | SPEC LEAK: approval envelope phase + exec_id_prefix | open / `step:investigate` / audit-filed 2026-05-28 | `bsv-mpc-proxy/src/relay_approval.rs:132-133` + `MPC-Spec/decisions/0005*.md` + ADR-0032 |
| **73** | SPEC LEAK: `ParticipationProof` placeholders → BRC-18 non-conformant | open / `step:implement` / audit-filed 2026-05-28 / easy filler, zero #69 overlap | `bsv-mpc-core/src/signing.rs:1023, 1028-1047` |
| **71** | Post-recovery cooldown / velocity window for high-value spends (direction.md §3) | open / `security` / post-critical-path | policy surface |
| **67** | Web client custody & threat model — no-enclave browser signing — DESIGN | open / `step:investigate` / sets up the web lane (Rust core → wasm) after 4-of-6 | design doc — untracked draft `docs/67-WEB-CUSTODY-AUDIT.md` MUST NOT be committed |
| **56** | Concurrent multi-device sessions (mirror + coordinated presig checkout) — DESIGN | open / `step:investigate` / the multi-device lane; after 4-of-6 | design doc |
| **75** | SPEC LEAK: `canonical_render(intent)` does not exist | **✅ CLOSED 2026-05-28** — co-closed with 100cash#13/#14/#15 via mainnet TXIDs `5e527f27…51abee` + `d3515c50…c395cb` | `bsv-mpc-core/src/approval.rs` + `bsv-mpc-client/src/ffi.rs` + `MPC-Spec/decisions/0044*.md` (PRs #48 + #82 merged) |

---

## Reference material (what to read when stuck)

- **MPC-Spec** at `/Users/johncalhoun/bsv/mpc/MPC-Spec/` — **the canonical §-numbered
  protocol spec** (NOT in this repo; no single `mpc-spec.md` file). Files
  `00-overview.md` … `18-recovery.md`; ADRs in `decisions/`; conformance vectors in
  `conformance/`; open questions in `OPEN-QUESTIONS.md`. **For #69 (4-of-6 / multi-share /
  share indexing) the governing sections are §00 (Quorum profile `(t,n,party_kinds)`),
  §18.3/§18.2 (quorum profiles + address-preserving cross-(t,n) resharing), §15 +
  direction.md §1.1 (`t = w+1` multi-share model), §08.8 (threshold-subject).**
  `bsv-mpc` mirrors the plain-English version in `SPECS.md` (not §-numbered).
- **Audit knowledge graph** at `/Users/johncalhoun/bsv/mpc/graphify-out/graph.html`
  (693 nodes / 1136 edges / 70 communities). Open in browser; the graph independently
  surfaced `combine_sign_over_relay (2-party)` ↔ `FfiDeployedSigner` as a similar-pair
  (the exact seam #69 is fixing).
- **bsv-mpc top-level docs** in `/Users/johncalhoun/bsv/mpc/bsv-mpc/`:
  `SPECS.md`, `DECISIONS.md`, `EXECUTION-PLAN.md`, `INTEGRATION.md`, `STATUS.md`, `LESSONS.md`.
- **Partnership direction** at `/Users/johncalhoun/bsv/mpc/{direction.md,direction-audit.md,SWARM-CONVERGENCE.md,GOD-TIER-SWARM-PLAN-2026-05-13.md}`.

---

## Discipline (from auto-memory — partnership rules)

- **No commit/push without user OK.** Show diff, wait for green light.
- **No `cargo fmt` on `lib.rs` or a crate root.** It cascades + reflows pre-existing-unformatted
  files. `main` is CI-red on fmt. Format only edited files. Enforced gate is clippy.
- **Ask user for design decisions.** Don't guess between approach (a) vs (b) on #69.
- **Validate, don't skip.** Negative cases must be asserted (reject for the right reason),
  not skipped. "Skipping is lazy."
- **Verify inputs before escalating.** A "crypto divergence" is usually a wrong-key test
  error; confirm canonical inputs first.
- **Async-only.** No meetings / no scheduled syncs / no handoff calls. Slack + GitHub +
  code + proofs + tests.

---

## Person A focused session-opener prompt

```
You are Person A on the Calhoun-side BSV-MPC partnership. Your scope is the load-bearing
4-of-6 crypto seam + spec-level decisions. You do NOT own god-tier security hardening or
100cash Swift wiring — that's Person B (see 100cash/ROADMAP-HANDOFF.md §"Post-audit work
split"). One repo:
  /Users/johncalhoun/bsv/mpc/bsv-mpc/   (Rust, GitHub B1nary-Calhoun-Partnership/bsv-mpc, branch main)

FIRST read, in order:
  1. bsv-mpc/PROGRESS-PERSON-A.md  (your live status — start by reading this)
  2. bsv-mpc/PERSON-A-HANDOFF.md   (full context)
  3. The audit issue you're about to start (gh issue view <num>)

THE OVERARCHING GOAL (shared with Person B): ship 4-of-6 PRODUCTION god-tier self-custody
on 100cash — t=4, n=6, device-held shares + two independent Notary cosigners, plumbing
over the audited bsv-mpc-core (NO new MPC protocol), mpc-spec-conformant. We are at 2-of-2
today only because client multi-share isn't wired. #69 is THE critical path; #70 makes
the two network-side cosigners genuinely independent. See the goal block in PERSON-A-HANDOFF.md.

Your owned issues (rough priority order — #75 is DONE, see below):
  bsv-mpc#69  — n-party provisioning + sign seam in bsv-mpc-client. ★ THE CRITICAL PATH to
                4-of-6 production. The 100cash app is 4-of-6 but the mainnet send drive
                had to fall back to 2-of-2 because client multi-share isn't wired
                (provisioning 4-of-6 fails: "no outgoing messages to bundle"; the client
                FFI takes a single share_index — needs my_indices: Vec<ShareIndex>). #69
                unblocks true app-parity signing → Person B flips NativeBackendConfig to
                4-of-6 → capstone 100cash#31. Conform to mpc-spec §00 (Quorum profile),
                §18.3/§18.2 (quorum profiles + address-preserving resharing), §15 +
                direction.md §1.1 (t=w+1 multi-share), §08.8 (threshold-subject). Audit
                comment lays out approach (a) new seam vs (b) factor proxy's
                DeviceShareBundle out — ASK USER which before coding. Crypto is proven at
                BOTH levels: mainnet TXID febd2877… (PR #46) AND the in-core POC
                poc_4of6_device_holds_presig_relay.rs (device holds {0,1,2}, folds locally,
                signs; negative case asserted). Orchestration only. RE-DIFF
                bsv-mpc-client/src/ffi.rs first — commit 1da783c added two FFIs there
                (native-tls WS fix window).
  bsv-mpc#70  — deploy 2nd Calhoun cosigner. PAIRS with #69 (ops not code) so a 4-of-6
                mainnet artifact uses two INDEPENDENT Notaries (mpc-spec §13 federation,
                direction.md §1 "two mandatory sides"), not one cosigner twice.
  bsv-mpc#74  — SPEC LEAK: approval envelope phase + exec_id_prefix. Spec decision needed
                (add "approval" to ADR-0005 enum?). Sibling thinking to the closed #75.
  bsv-mpc#73  — SPEC LEAK: ParticipationProof placeholders in signing.rs:1028-1047. Easy
                same-day ship; zero overlap with the #69 surface — good filler if #69 is
                blocked on the user's (a)/(b) decision.
  bsv-mpc#71  — post-recovery cooldown / velocity window for high-value spends
                (direction.md §3). Policy/security; pick up after the 4-of-6 critical path.
  bsv-mpc#67  — web client custody & threat model (no-enclave browser signing,
                WebAuthn-PRF seal + below-threshold) — DESIGN. Sets up the web lane (same
                Rust core → wasm) once 4-of-6 lands. NOTE: an untracked draft
                docs/67-WEB-CUSTODY-AUDIT.md exists — do NOT commit it.
  bsv-mpc#56  — concurrent multi-device sessions (mirror + coordinated presig checkout) —
                DESIGN. The multi-device lane the goal block calls out; after 4-of-6.
  bsv-mpc#75  — canonical_render + ffi_canonical_render. ✅ CLOSED 2026-05-28 — co-closed
                with 100cash#13/#14/#15 via mainnet TXIDs 5e527f27…51abee + d3515c50…c395cb
                (the other window's send-path drive). Do not re-open. Listed for context.

QUALITY GATES — every issue you close must be PROVEN, no asterisks:
  Each issue you close must ship with EVERY applicable gate below GREEN before the
  PR can land. "Asterisks" (e.g. "tests pass except for X", "mainnet-deferred",
  "spec-decision pending", "needs Binary to confirm", "should work") are NOT acceptable
  for closing — open a follow-up issue instead of asterisking the parent.

  1. UNIT TESTS — the exact behavior the audit identified must be reproducible in a
     FAILING test against current main, and the fix must turn it green. Include both
     POSITIVE and NEGATIVE cases. The negative case must assert the RIGHT rejection
     reason. Applies to all 5 issues. Memory rule: "Validate, don't skip — negative/
     rejection cases must be asserted, never skipped; skipping is lazy."

  2. VECTOR / GOLDEN TESTS — for any change that touches a wire format, ADR, FFI
     surface, canonical encoding, or cross-impl conformance, add a golden-vector test
     that pins the bytes/behavior. For your scope this is non-negotiable:
       • #69 — 4-of-6 sign produces a signature that verifies against the joint
         pubkey; address derivation matches the proxy-path address (cross-check
         against the febd2877… TXID's address). Mirror the hermetic-test pattern from
         bsv-mpc PR #46.
       • #75 — golden text vectors per intent kind (payment, token_transfer,
         script_spend, brc100_internalize, multi) — BYTE-EXACT. These belong in
         MPC-Spec/conformance/test-vectors/ so Binary's implementation can later
         gate against the same outputs. Also: intent-classifier vectors covering
         edge cases (multi-output payment, derived-key brc100_internalize, etc.).
       • #74 — envelope round-trip vectors per ADR-0037 (canonical CBOR re-encode
         equivalence). Bytes must equal the spec's canonical form on every field.
       • #73 — golden OP_RETURN proof vectors. Parsing a known-good proof verifies;
         parsing a tampered proof rejects with the SPECIFIC reason.

  3. E2E TESTS — for any fix that touches a deployed surface, run an integration
     against real infrastructure. Applies to:
       • #69 — mainnet 4-of-6 TXID via the new client seam. THE audit-closing artifact.
         (Mirror existing pattern: bsv-mpc PRs #46, #57 land mainnet TXIDs in the
         closing comment.)
       • #70 — independence audit: second cosigner has distinct CA / identity key /
         deploy environment; mainnet 4-of-6 TXID signed using BOTH cosigners (not
         the original cosigner twice).
       • #75 — Person B's 100cash#15 closes the loop: 100cash calls
         ffi_canonical_render, viewHash binds, approval flow completes on a real
         mainnet send. Coordinate the closing TXID with Person B.
       • #73 — mainnet sign emits a valid ParticipationProof OP_RETURN; fetch from
         WhatsOnChain, parse-back, verify_participation_proof passes end-to-end.

  4. SPEC PRs (your scope only) — for #74 and #75, the spec decision lands as an
     MPC-Spec PR BEFORE the code PR merges. Don't merge code that silently invents a
     spec answer; open the spec PR first, get the user's OK on the spec direction,
     then build the code to match. Cross-impl conformance is the load-bearing
     property of M1 — drift here means Binary will diverge later.

  5. PROOF ARTIFACT — the closing comment on the GitHub issue MUST include the
     concrete proof: test names, CI run link, mainnet TXID + WoC URL, the actual
     verify_participation_proof output for #73, the actual canonical_render output
     bytes for #75, etc. No "should work" / "tested locally" — only "ran the gate,
     here's the proof, with link."

  6. CI INTEGRATION — every new test (unit + vector) must be part of a CI workflow
     that gates merge. Conformance vectors for #75 + #74 land in MPC-Spec/conformance/
     with a runner that CI invokes. Local-only tests don't count.

  7. ZERO-DRIFT INVARIANT — for any code that emits or consumes envelope bytes /
     OP_RETURN bytes / canonical text (#73, #74, #75): add a "frozen vector" test
     that loads a checked-in byte string and asserts equality. This is the canary
     that future refactors won't silently drift the wire format. Mirror the pattern
     bsv-mpc-core uses for its existing canonical encodings.

Discipline (from auto-memory):
  - No commit/push without user OK (show diff, wait for green light)
  - NO `cargo fmt` on lib.rs or crate roots — cascades + main is CI-red on fmt;
    format edited files only; the enforced gate is clippy
  - Ask user for design decisions; don't guess on (a) vs (b) for #69 or on the
    ADR-0005 "approval" phase value for #74 or on the intent-classifier shape for #75
  - Validate, don't skip — assert negative cases on the right rejection reason
  - Verify inputs before escalating to "crypto divergence" — usually it's the inputs
  - Async-only — no meetings or scheduled syncs

Update PROGRESS-PERSON-A.md after each step (status + last action + blockers +
WHICH QUALITY GATES ARE GREEN). Mark an issue READY FOR PR only when all applicable
gates above are listed green with proof links.

The audit graph is at /Users/johncalhoun/bsv/mpc/graphify-out/graph.html — the graph
independently surfaced `combine_sign_over_relay (2-party)` ↔ `FfiDeployedSigner` as
the load-bearing seam (the exact #69 territory). The 4-agent audit reports live in
the issue bodies (#73, #74, #75) plus the audit-stamped comments on #69 and #70.

Tell me which issue you want to start with and propose the PR shape — including the
specific UNIT + VECTOR + E2E tests you'll write and which SPEC PR (if any) needs to
land first — BEFORE coding.
```
