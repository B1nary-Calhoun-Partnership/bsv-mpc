# CF Containers probe — live progress log

> **Goal:** de-risk ADR-018's *native half* — can the native `bsv-mpc-service`
> (heavy CGGMP'24: DKG + presig gen) run on **Cloudflare Containers**, reachable
> from a Worker/DO, all on Cloudflare? This is the same "validate the unproven
> deployment assumption early" discipline that the DKG-on-wasm probe applied.
>
> **Strategy:** platform-first. Prove a *minimal Rust axum* service runs on CF
> Containers + is reachable (isolates platform/account/deploy issues from the
> heavy full-workspace Docker build). THEN swap in `bsv-mpc-service`.
>
> Update this file after every step so the probe survives a context loss.

## Environment (verified 2026-05-20)
- Docker 28.0.1 running locally.
- `wrangler` 4.54 — `wrangler containers` is **open-beta** (build/push/images/info/list/delete).
- CF Containers needs **Workers Paid plan** (per docs). dev-a3e plan status: UNVERIFIED (deploy will reveal).
- CF auth: `eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)"`.

## CF Containers model (from docs/index.md)
- `wrangler.toml`: `[[containers]]` { `class_name`, `image = "./Dockerfile"`, `max_instances` }.
- Worker DO extends `Container` (npm `@cloudflare/containers`): `defaultPort` (port the
  container listens on), `sleepAfter`. Worker routes via `getContainer(env.BINDING, id).fetch(req)`.
- `wrangler deploy` builds the image from the Dockerfile + deploys.
- The proxy DO/Worker is JS/TS (the `@cloudflare/containers` helper is JS). The
  CONTAINER runs any image (our native Rust binary) — so the heavy logic stays Rust.

## Plan
- [x] **P1 — minimal platform probe — DONE + PROVEN (2026-05-20).** Deployed
  after the token got `Workers Scripts:Edit` + `Containers:Edit` + `User
  Details:Read`. App `bsv-mpc-container-probe-bsvmpccontainer`; image in
  `registry.cloudflare.com/.../:b214e6fe` (instance_type `lite`); worker
  `https://bsv-mpc-container-probe.dev-a3e.workers.dev`. **Runtime proof:**
  `GET /health` → `{"runtime":"native-rust-on-cf-container","status":"ok"}`,
  cold start **~1.75s**, warm **~130ms**. ⇒ native Rust deploys + runs +
  is reachable on CF Containers. ADR-018 native half VALIDATED.
- [ ] ~~P1 (orig)~~ `poc/poc-cf-container/`: tiny Rust axum
  `/health` binary + Dockerfile + minimal JS Worker (`@cloudflare/containers`) +
  `[[containers]]`. `wrangler deploy` → curl the Worker URL → routes to container
  → `/health` 200. Validates: account plan, deploy pipeline, Rust-in-CF-Container,
  DO→container reachability.
- [x] **P2 — full service — DONE + PROVEN (2026-05-20).** Workspace-root
  `Dockerfile` (build context = repo root via `image_build_context`) builds
  `cargo build --release -p bsv-mpc-service --locked`; cggmp24/bsv-rs fetched
  from the public network during build (no submodule). `.dockerignore` excludes
  `target/`, `.git`, `**/node_modules`, **and `secrets.md`**. Container
  `defaultPort=8080` ← `MPC_SERVICE_PORT=8080`, `MPC_DATA_DIR=/data`. Wrangler
  app at `poc/cf-container-p2/` (reuses the `@cloudflare/containers` proxy
  shape). Deployed via `CLOUDFLARE_CONTAINERS_TOKEN` as `CLOUDFLARE_API_TOKEN`.
  **Runtime proof:** `https://bsv-mpc-service-container.dev-a3e.workers.dev/health`
  → `{"status":"ok","version":"0.1.0","share_count":0,"total_presignatures":0,
  "uptime_seconds":6,"data_dir":"/data"}` (the REAL `bsv-mpc-service` handler,
  not the probe stub). Image 113MB; version `b1511a83`.
  - **Gotcha 1 (openssl):** `bsv-rs`/`reqwest` pull `native-tls → openssl-sys`,
    so the build stage needs `libssl-dev`+`pkg-config` and the runtime needs
    `libssl3`. (Workspace nominally wants rustls; `bsv-rs` default-feature
    `reqwest` forces native-tls graph-wide — real fix lives in the `bsv-rs`
    repo; see hardening backlog #5.)
  - **Gotcha 2 (platform):** CF Containers run **linux/amd64**; on an arm64 Mac
    `wrangler deploy` cross-builds (emulated) — it completed fine here.
- [x] **P3 — decision.** ADR-018's native half is CONFIRMED end-to-end: the full
  native `bsv-mpc-service` builds, deploys, runs, and is reachable on CF
  Containers. This is the home for heavy DKG + presig generation. No ADR change
  needed.

## Log
- 2026-05-20: probe started. Env verified (Docker + wrangler containers beta). Model captured.
- 2026-05-20: P1 files written under `poc/poc-cf-container/` — minimal Rust axum
  `/health` (`src/main.rs`, `cargo check --release` ✅), `Dockerfile` (multi-stage),
  `worker.js` (`@cloudflare/containers@0.3.4`), `wrangler.jsonc` (`[[containers]]` +
  DO binding + `new_sqlite_classes` migration), `package.json`, `.dockerignore`.
- 2026-05-20: `wrangler deploy` — **Docker image BUILT successfully** (Rust axum
  compiled + image exported: `bsvmpccontainer:aa620391`), but deploy **FAILED** at
  `GET /accounts/<id>/containers/me` → **403 Forbidden ("Authentication error")**.

## ⛔ BLOCKER (needs user action — credentials/account, not code)
The `CLOUDFLARE_API_TOKEN` in `secrets.md` works for Workers/DO but is **403 on
the Containers API**. CF Containers is open-beta + needs **Workers Paid plan** +
a token with **Containers** permissions. Account in use: `Dev@calhounjohn.com`
(the token's account — NOTE: may differ from the `dev-a3e` worker account).

**What the user needs to do (pick one):**
1. **Create/replace the API token** with Containers permissions (dash →
   profile/api-tokens → add "Workers Scripts: Edit" + the Containers/"Cloudflare
   Images"/"Workers R2"? — specifically the **Containers** scope), update
   `secrets.md`'s `CLOUDFLARE_API_TOKEN`; OR
2. **`wrangler login`** (OAuth) for the probe — full-perms interactive session
   (run `! wrangler login` in the prompt); OR
3. Confirm the **account is on Workers Paid** + Containers open-beta is enabled
   for it (dashboard → Workers & Pages → Containers).

**Then resume:** `cd poc/poc-cf-container && eval "$(grep '^export CLOUDFLARE'
~/bsv/mpc/bsv-mpc/secrets.md)" && wrangler deploy` → curl the returned URL
`/health` → expect `{"status":"ok","service":"poc-cf-container",...}`. That
closes P1. Then P2 (swap image to build+run `bsv-mpc-service`).

## Update 2 — token perms split (2026-05-20)
Tried a second token (`CLOUDFLARE_CONTAINERS_TOKEN`, `cfut_…`, saved in secrets.md).
Result: it **passed the Containers gate** (`/containers/me` OK) but **failed on
Workers** (`/accounts/<id>/workers/services/bsv-mpc-container-probe` → code 10000
"Authentication error") + missing `User->User Details->Read`.

So: **old `CLOUDFLARE_API_TOKEN`** = Workers ✅ / Containers ❌; **new `cfut_`
token** = Containers ✅ / Workers ❌. `wrangler deploy` is atomic on ONE token →
**need a single token with BOTH**.

**User action:** in the dashboard, edit ONE token to have all of:
`Workers Scripts: Edit` + `Containers: Edit` + `User Details: Read` (+ the deploy
also touches the managed registry, covered by Containers). Easiest: open the
`cfut_` token and ADD `Workers Scripts: Edit` + `User Details: Read` (it already
has Containers). Put the resulting all-in-one token in secrets.md as
`CLOUDFLARE_API_TOKEN` (replace), then resume `wrangler deploy`.

## Findings so far
- ✅ The Rust→Docker→CF build pipeline works (image built); the code/Dockerfile
  shape is correct.
- ⛔ Deploy is gated purely on **token/account Containers entitlement** — a
  provisioning step outside the code. Everything else (image, worker proxy,
  wrangler config) is staged + ready to deploy the moment the token is fixed.
