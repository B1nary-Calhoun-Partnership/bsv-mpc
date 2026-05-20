# Phase I Step 4 — Implement (plan)

> Tracking: **bsv-mpc#4**. Predecessor: Step 3 COMPLETE (I-3a/I-3b/I-3b2,
> deployed-proven; bsv-rs **0.3.11** released with the wasm `to_peer` timer fix).
> This plan sequences Step 4 into landable, individually-gated sub-steps.
> Discipline unchanged: 110% (runtime proof for deployed work), each sub-gate
> lands on `main` before the next, `-D warnings` + fmt + wasm build every push.

## Verified starting facts (3-agent research swarm, 2026-05-20)

- **Coordinators** (`bsv-mpc-core`) are synchronous and wasm32-proven
  (`tests/wasm32_dkg.rs` drives two `DkgCoordinator`s to completion on
  `wasm32-unknown-unknown`). Lifecycle is identical for DKG/sign/presign:
  `new(..)` → `init()/init_round()` → `loop { process_round(Vec<RoundMessage>)
  → NextRound(..) | Complete(..) }`. **`!Send`** (cggmp24 `Rc<RefCell>`), with a
  documented single-threaded `unsafe impl Send` — fine for one DO isolate.
  **1-round presigned signing is NOT implemented** — `sign()` always falls to
  the 4-round `init_round` path. Treat signing as multi-round like DKG.
- **Envelope glue** is `crates/bsv-mpc-core/src/envelope.rs`:
  `wrap_round_message(round, WrapParams, recipient_pub, our_priv)` (BRC-78
  ECIES + BRC-31 sign; 0-based→1-based round; broadcast `to=None`→`0xFFFF`,
  caller fans out N unicast) and `unwrap_envelope_to_round_message(env,
  our_priv, expected_sender)`. `WrapParams { to_party, joint_pubkey:[u8;33],
  phase, execution_id_prefix:[u8;8], correlation_id, traceparent }`.
- **Worker storage today** (`bsv-mpc-worker`): in-memory `static STORAGE`
  (`storage.rs:30`) + live coordinators in `static LazyLock<Mutex<HashMap>>`
  (`api.rs:68-77`). `MpcStorage` DO is an unrouted stub. Handlers run in the
  request, not a DO. **Live coordinators are NOT serializable** (threads/
  channels) → mid-ceremony durability = keep the coordinator in ONE DO
  isolate's RAM for the (short) ceremony; SQLite backs shares + per-round
  transcript for eviction recovery. Known bug: `handle_dkg_round` keys the
  stored share by `session_id.hex()` not `agent_id` (`api.rs:418` TODO).
- **Proxy↔KSS** (`bsv-mpc-proxy/bridge.rs`) is HTTP today. The **native relay
  pattern is fully built in `bsv-mpc-service`** (`MessageBoxClient` +
  `MessageBoxListener` + `DkgHandler`/`SigningHandler`, handlers run
  `process_round` in `tokio::task::spawn_blocking`) and E2E-test-proven, but
  **not wired into `bsv-mpc-service/src/main.rs`** (still `build_router`, legacy
  axum). `MessageBoxClient`: `new(relay, priv)`, `send_round_message(recipient,
  box, &RoundMessage, WrapParams)`, `subscribe_round_messages(box) ->
  RoundMessageSubscription`, `acknowledge(&[id])`. Boxes: `mpc-dkg`/`mpc-sign`/
  `mpc-presign`/`mpc-ecdh`; relay room = `"{identity_hex}-{box}"`; ceremony
  correlation rides `RoundMessage.session_id` + `execution_id_prefix`.
  **Gaps:** no presign/ECDH relay handlers exist yet (only DKG + signing).

## Sub-gate sequence

### I-4a — DO-SQLite share/state storage (FUND-SAFETY prerequisite)
Replace the in-memory `static STORAGE` with a DO-SQLite store and route the KSS
handlers through a per-identity `CosignerSessionDo` (extend the proven I-3b POC
DO; same `state.storage().sql()`, hex-TEXT-not-BLOB lesson). Tables:
`shares(agent_id PK, ciphertext, nonce, session_id, share_index, config,
joint_pubkey, created_at, updated_at)`, `protocol_state(session_id PK, blob,
updated_at)`, `presignatures(id PK, agent_id, session_id, data, created_at)`.
Ciphertext-only at rest; identity from `SERVER_PRIVATE_KEY` every wake. Fix the
agent_id keying bug. **Gate:** deploy + prove a stored share survives a forced
eviction AND a routed handler reads it back byte-identical (extend the I-3b
hibernation harness). No funded share on in-memory storage — ever.

### I-4b — wasm32 cosigner loop (worker drives ceremonies over the relay)
Inside the DO: wake-on-HTTP → dial relay (proven in I-3b2) → subscribe to the
`mpc-dkg`/`mpc-sign` room → drive the coordinator: `init` → `loop { inbound
General → unwrap_envelope_to_round_message → process_round → wrap_round_message
each outbound → peer.to_peer(sendMessage) }` → `Complete` (DKG: persist share to
DO SQLite; sign: return `SigningResult`). Coordinator held in DO RAM for the
ceremony; `protocol_state` persisted per round (belt-and-suspenders). Add a DO
`alarm()` reconnect hook (OQ-I2). **Gate:** a 2-of-2 DKG completes between the
**deployed** worker (share_A) and a native test party over the relay (both
agree on the joint pubkey), proven at runtime; then a sign over the same.

**Verified wire format (mirror `bsv-mpc-service::dkg_handler` exactly):**
- **Outbound** per coordinator `RoundMessage`: `wrap_round_message(&rm, params,
  &recipient_pub, &our_priv)` → `MessageEnvelope`; `wire::wrap_envelope_to_body`
  → `Value::String(lowercase-hex of canonical CBOR)`; then
  `build_envelope_payload("sendMessage", {messageBox, message:{messageId,
  recipient, body}})` → `peer.to_peer(payload, Some(server_id), _)`. Broadcast
  (`to=None`) fans out to N unicast (one per peer).
- **Inbound** `sendMessage-{our_room}` AppEvent: take `data.body`, wrap as
  `{"message": <body>}`, `wire::unwrap_inbound_body` → `MessageEnvelope`;
  `unwrap_envelope_to_round_message(&env, &our_priv, Some(&sender_pub))` →
  `RoundMessage` → `coordinator.process_round(vec![rm])`.
- **`WrapParams` (DKG):** `execution_id_prefix = canonical_execution_id(
  ExecutionParams::new_v1(PhaseTag::DkgKeygen, session_id, [0u8;33]))[..8]`;
  `joint_pubkey=[0;33]` (§05.4.3 keygen carve-out); `phase="dkg"`; box `mpc-dkg`;
  `to_party = peer_party_index`. (Signing: `PhaseTag::Sign`, real joint_pubkey,
  `phase="sign"`, box `mpc-sign`.)
- **Routing:** send to peer's room `{peer_id}-{box}`; subscribe to own room
  `{worker_id}-{box}`. Worker is party 0; peer (proxy/native) is party 1.

**Paillier primes (DECISION 2026-05-20 — seed via endpoint):** CGGMP'24 auxinfo
safe-prime generation is ~30–60s/party on native and far slower on wasm32 (would
blow the DO CPU/request limit). `PregeneratedPrimes<SecurityLevel128>` derives
serde, so:
- **I-4b.1** — `POST /ceremony/seed-primes {session_id, primes_json}`: primes are
  generated OFF-worker (native), validated by deserializing
  `PregeneratedPrimes`, and persisted to a DO-SQLite `mpc_primes(session_id PK,
  primes_json, created_at)` table (survives eviction between seed + ceremony).
  Consumed at coordinator init via `DkgCoordinator::set_pregenerated_primes`.
  Gate: seed → reload byte-identical across eviction.
- **I-4b.2** — the cosigner loop above, loading seeded primes at DKG init. Gate:
  2-of-2 DKG (deployed worker ↔ native party) over the relay, joint-pubkey
  agreement; then a sign.

### I-4c — proxy `bridge.rs` HTTP→relay migration (OQ-I1)
Swap `bridge.rs`'s `reqwest`/`BridgeAuth`/`kss_post` for `MessageBoxClient` +
the `bsv-mpc-service` listener/handler pattern. Delete the HTTP request/response
structs + handshake; **reuse** share loading/decryption, BRC-42 offset/derive,
`partial_ecdh` combine, session/agent ids. Author the missing **presign +
ECDH relay handlers** (mirror `DkgHandler`). Optionally wire the relay listener
into `bsv-mpc-service/main.rs`. **Gate:** the proxy drives a DKG + sign ceremony
end-to-end against a relay cosigner (native first, then the deployed worker).

### I-5 — Merge gate (Step 5): deployed-cosigner real-sats mainnet TXID
2-of-2 DKG + sign + broadcast with the **proxy's native party (share_B)
co-signing with the deployed CF Worker (share_A)** over the relay; shape-match
G-5d (`442bd391…`: DER + `SIGHASH_ALL|FORKID`, joint P2PKH, low-s, pre-flight
verify). Wallet at `localhost:3321` (Origin `http://admin.com`), `E2E_MAINNET=1`.
Cite the TXID in the commit. + `cargo build --workspace --all-targets` + clippy
`-D warnings` + fmt + CI green.

## Risks / decisions carried
- **R1 mid-ceremony eviction** — accepted: ceremonies are short (DKG ~19s, sign
  ~6s) with continuous WS traffic keeping the DO warm; failure → retry, share is
  durable. Persist `protocol_state` per round as belt-and-suspenders.
- **Coordinator !Send / not serializable** — per-session DO pinning, not
  transcript replay, is the primary durability mechanism.
- **No presign 1-round path** — all signing is 4-round today; fine for the
  merge gate. Presign optimization is out of Step-4 scope unless needed.
- `futures-timer/wasm-bindgen` (via bsv-rs 0.3.11) is now load-bearing for ALL
  wasm relay traffic, not just the POC.
