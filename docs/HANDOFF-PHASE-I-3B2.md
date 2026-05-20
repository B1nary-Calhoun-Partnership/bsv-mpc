# Handoff — Phase I Step 3, pickup at I-3b2 (relay-handshake-from-DO)

> For the next session continuing Phase I. Read this +
> `docs/PHASE-I-AUDIT.md` + GitHub issue **bsv-mpc#4** first.
>
> **Status:** Phase H CLOSED. Phase I Steps 1–2 done; Step 3 I-3a + I-3b
> done **and deployed-proven**. Pick up at **I-3b2**.

## TL;DR — the next concrete action

**I-3b2**: wire the relay-handshake INTO the deployed worker's
`CosignerSessionDo` (`crates/bsv-mpc-worker/src/poc.rs`) — outbound
Socket.IO + BRC-103 handshake + canonical envelope round-trip, lifting
poc17's proven flow onto this crate's `transport_wasm`. Then redeploy +
live-prove against the live relay. The DO-SQLite + hibernation half is
already deployed-proven; this adds the transport half.

## What's done (this session, 2026-05-20)

### Phase H — CLOSED (Step 4 + real-sats capstone)
- H-4.1→H-4.6 native unification onto Socket.IO + BRC-103; `ws.rs` (948 LOC)
  deleted; `subscribe.rs` over `Peer<ProtoWallet, SocketIoTransport>`.
- **`bsv-rs 0.3.10` published** (PR Calhooon/bsv-rs#4, `9a081dc`) — upstream
  `SocketIoTransport` + `SocketIoSink`/`SocketIoFrameSource` + `run_dispatch`.
- **Real-sats capstone:** mainnet TXID `815971328f3426b2659443d20270b13839727ce239ae02d7fe434f9c818069e7`
  (2-of-2 MPC over the unified path, SEEN_ON_NETWORK).
- Tracker #3 finalized; umbrella #2 updated.

### Phase I — Steps 1–2 + I-3a + I-3b
- Step 1 (3-agent swarm) + Step 2 audit → `docs/PHASE-I-AUDIT.md`.
- **Decisions locked:** OQ-I1 relay REPLACES proxy↔KSS HTTP (Phase I also
  migrates `bsv-mpc-proxy/bridge.rs`); OQ-I2 wake-on-HTTP + Alarm reconnect;
  OQ-I3 `worker` → 0.8.x; OQ-I4 proxy's party = merge-gate second cosigner.
- **I-3a** (`db7f373`) — `worker` 0.7.5→0.8.3 (bsv-mpc-worker + messagebox
  wasm block). 0.7→0.8 is near-zero churn (DO/SQLite/WS APIs byte-identical;
  only `#[event]` signature validation is new). CI green.
- **I-3b** (`55e0a42`) — `CosignerSessionDo` in `src/poc.rs`: DO-SQLite
  persistence + hibernation POC. **DEPLOYED + eviction-proven** (see below).
  CI green.

### Deployed proof (already done — do NOT redo)
Worker live at **`https://bsv-mpc-kss.dev-a3e.workers.dev`** (dev-a3e CF
account). `SERVER_PRIVATE_KEY` secret set (throwaway). Local gitignored
`crates/bsv-mpc-worker/wrangler.toml` has the `COSIGNER_DO` /
`CosignerSessionDo` binding + a `[[migrations]] tag=v2 new_sqlite_classes`.
- `POST /poc/persist` → DO SQLite write+read-back, `reload_matches: true`.
- **Forced-hibernation gate:** two `/poc/identity` curls across ~150s idle —
  `instance_constructed_at_ms` advanced **+179s** (real eviction) while
  `client_identity` (`03cc87ed…`, from the secret) + the SQLite `share_hex`
  (`6d0030f2…`) stayed **byte-identical**. The fund-safety primitive is
  proven on real CF. (Evidence in issue #4 comment.)

## Current crate / module state — `crates/bsv-mpc-worker/`

- `Cargo.toml`: `worker = "0.8"` (resolves 0.8.3), `bsv.workspace`, getrandom/js.
  **I-3b2 must ADD:** `bsv-mpc-messagebox = { path = "../bsv-mpc-messagebox" }`,
  a wasm32 `bsv` override with the `socketio`+`auth`+`wasm` features (mirror
  messagebox's wasm block: `bsv = { package="bsv-rs", version="0.3.10",
  default-features=false, features=["auth","wallet","transaction","wasm","socketio"] }`),
  `futures.workspace`, `wasm-bindgen-futures = "0.4"`.
- `src/poc.rs`: `CosignerSessionDo` (state/env/instance_constructed_at_ms),
  routes `/poc/identity` + `/poc/persist`, `forward_to_cosigner_do` (via
  `id_from_name(POC_DO_NAME="cosigner-poc-2")`). Identity from
  `SERVER_PRIVATE_KEY` every call. SQLite `shares(agent_id PK, ciphertext
  TEXT[hex], created_at)`. **NOTE:** the share blob is stored as **hex TEXT**
  (a BLOB column fails `cursor.to_array::<T>()` deserialization into Vec<u8>
  — serde wants a seq; hex TEXT sidesteps it).
- `src/lib.rs`: declares `mod poc;` + routes `/poc/identity` (GET) +
  `/poc/persist` (POST) → `poc::forward_to_cosigner_do`. Existing MpcStorage
  stub DO + the BRC-31 HTTP KSS routes unchanged.

## I-3b2 plan (add the relay route)

In `CosignerSessionDo::fetch`, add `"/poc/handshake" => self.handle_handshake().await`.
`handle_handshake` mirrors the H-4.3 native test + poc17 `/envelope-roundtrip`,
but wasm32 (use `wasm_bindgen_futures::spawn_local`, NOT tokio::spawn):

1. `let relay = self.env.var("RELAY_URL")?...` (or const the live relay).
2. `let handshake = bsv_mpc_messagebox::transport_wasm::polling_handshake(&relay).await?;`
3. `let mut ws = transport_wasm::WsHandle::open_and_upgrade(&relay, &handshake.sid).await?;`
4. Socket.IO CONNECT: `let sink = ws.sender(); sink.send_socketio(&SocketIoPacket::Connect{nsp:"/".into(),data:None})?;`
   then loop `ws.recv_engineio()` (trait `bsv::auth::SocketIoFrameSource`) replying Pong via
   `sink.send_engineio` (trait `bsv::auth::SocketIoSink`) until `Connect` ack.
5. `let transport = bsv::auth::SocketIoTransport::new(sink.clone());`
   `let cb = transport.callback_handle();`
   `let wallet = ProtoWallet from SERVER_PRIVATE_KEY;`
   `let peer = bsv::auth::Peer::new(PeerOptions{ wallet, transport, ..., auto_persist_last_session:true });`
   `peer.start();`
   `let (mut events,_) = bsv::auth::install_app_event_listener(&peer).await;`
   `spawn_local(bsv::auth::run_dispatch(ws, sink.clone(), cb));`  // 3 args, no snoop
6. `peer.to_peer(&bsv::auth::transports::socketio::build_envelope_payload("joinRoom", &json!(room_id)), None, Some(20_000)).await?;`
   (first `to_peer(None)` auto-initiates the BRC-103 handshake + signs.)
   `room_id = "{client_pub}-{message_box}"`.
7. Server identity = first inbound `AppEvent.sender` (the `authenticated` General).
   For an envelope round-trip: `to_peer(build_envelope_payload("sendMessage",
   &json!({"messageBox":box,"message":{"messageId":id,"recipient":client_pub,"body":body}})),
   Some(&server_id), _)` then await the `sendMessage-{room_id}` / `sendMessageAck-{room_id}`
   AppEvent. Return `{server_identity, handshake_rtt_ms, ...}`.

**Reuse the H-4.3 native test** `crates/bsv-mpc-messagebox/tests/transport_native_handshake.rs`
as the reference flow (it does exactly this, native). The wasm差 is spawn_local
vs tokio::spawn + the worker's secret-loaded wallet.

**Gates (110%, no asterisks):** `cargo build --target wasm32-unknown-unknown
-p bsv-mpc-worker` clean; `cargo clippy --workspace --all-targets -- -D
warnings` clean; `cargo fmt --all -- --check`; commit; **redeploy**
(`worker-build --release` then `wrangler deploy`); curl
`/poc/handshake` against the live relay → `server_identity` printed
(`02d7c923…` is the relay's stable identity, seen in H-4.3/H-4.4).

## Then: Step 4 + Step 5

- **I-3 wrap:** tick #4 Step 3 once relay POC proven.
- **Step 4 (Implement)** — full wasm32 cosigner loop driving `bsv-mpc-core`
  `DkgCoordinator`/`SigningCoordinator` (sync, wasm32-ready — `drive_inline`)
  over the relay; replace the in-memory `static STORAGE` with DO SQLite for
  real shares; **migrate `bsv-mpc-proxy/bridge.rs`** HTTP→MessageBox (OQ-I1).
- **Step 5 (merge gate)** — deployed-cosigner real-sats mainnet TXID:
  proxy's party (native, over relay) co-signs with the *deployed* worker,
  shape-matching G-5d (`442bd391…`). Wallet at `localhost:3321` (Origin
  `http://admin.com`), `E2E_MAINNET=1`.

## Locked discipline (carry forward)
- **110% no asterisks**: every commit's gate empirically verified; runtime
  proof for deployed work (not just build-clean).
- Each sub-gate lands on `main` BEFORE the next begins.
- `cd ~/bsv/mpc/bsv-mpc/` for commits (NEVER `bsv-mpc-old-unscrubbed/`).
- `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings` before push.
- `gh auth switch -u Calgooon` for pushes (jcalhoun-trifinlabs lacks perms).
- Pure Rust + WASM; Path A (conform to canonical TS).
- god-tier + full-stack: consult `~/bsv/` reference stack before fixes.
- Swarm + orchestrate: parallel agents for research; verify their output
  (they describe intent, not necessarily reality — caught the Option-B vs
  shipped-API drift this session).

## Deploy harness
- CF auth: `eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)"`
  sets `CLOUDFLARE_API_TOKEN` (len 40) + `CLOUDFLARE_ACCOUNT_ID` (len 32).
  **secrets.md gitignored — NEVER commit; redact `[a-f0-9]{16,}` from output.**
- `worker-build` is now **0.8.3** (must match `worker` major).
- `wrangler` 4.54 (npm). Deploy: `cd crates/bsv-mpc-worker && wrangler deploy`
  (runs `worker-build --release`). Deployed URL: `https://bsv-mpc-kss.dev-a3e.workers.dev`.
- Set secrets: `printf '%s' "$PRIV" | wrangler secret put SERVER_PRIVATE_KEY`.
- `wrangler.toml` is gitignored (local has the DO bindings + sqlite migration).
  The committed template `wrangler.toml.example` does NOT yet have the
  COSIGNER_DO binding — the pre-commit hook (`.git/hooks/pre-commit`)
  substring-matches `wrangler\.toml` and blocks committing it. **Hygiene
  follow-up:** rename `wrangler.toml.example` → `wrangler.example.toml`
  (avoids the substring) + add the COSIGNER_DO binding; that rename commit
  needs `--no-verify` (the deletion path still matches) — only do it if the
  user OKs --no-verify, else leave it (the binding is documented in the audit).
- Forced-hibernation harness: deploy → ~150s idle (NO traffic) → curl
  `/poc/identity` → compare `instance_constructed_at_ms` (advances) vs
  identity/share (stable). `wrangler dev` does NOT hibernate DOs — must be
  the deployed worker. `wrangler tail bsv-mpc-kss --format json` for errors
  (no `timeout` on macOS — background it + `kill`).

## Key references
1. `docs/PHASE-I-AUDIT.md` — topology, DO-SQLite fund-safety gate, wake/liveness, merge gate.
2. GitHub **bsv-mpc#4** (Phase I tracker) — Steps 1–2 ticked; I-3a/I-3b + hibernation proof in comments.
3. `crates/bsv-mpc-worker/src/poc.rs` — the DO POC to extend.
4. `crates/bsv-mpc-messagebox/tests/transport_native_handshake.rs` — the canonical handshake flow to mirror (native).
5. `crates/bsv-mpc-messagebox/src/{transport_wasm.rs,subscribe.rs}` — the wasm32 transport + the native subscribe (for the round-message ↔ AppEvent glue).
6. bsv-rs 0.3.10 socketio API: `bsv::auth::{SocketIoTransport, SocketIoSink, SocketIoFrameSource, run_dispatch, install_app_event_listener, AppEvent, Peer, PeerOptions}`, `bsv::auth::transports::socketio::{build_envelope_payload, parse_app_event_payload, codec::{EngineIoPacket, SocketIoPacket}}`. `Peer::to_peer(&[u8], Option<&str>, Option<u64>)`.

---
**Last green commit on main:** `55e0a42` (I-3b). **bsv-rs:** 0.3.10. **Worker:** deployed, DO-SQLite+hibernation proven. **Next:** I-3b2.
