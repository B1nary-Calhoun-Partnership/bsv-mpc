//! # bsv-mpc-worker
//!
//! Cloudflare Worker Key Share Service for MPC threshold signing.
//!
//! This Worker holds **share_A** — one half of a 2-of-2 threshold signing setup.
//! The MPC Signing Proxy (running in the agent's container) holds **share_B**.
//! Together, the two parties can produce a valid ECDSA signature over a BSV
//! sighash. Neither party alone can reconstruct the private key or forge a
//! signature.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────┐        ┌──────────────────────┐
//! │  Agent Container    │  HTTP  │  CF Worker (this)     │
//! │  ┌───────────────┐  │◄──────►│  ┌────────────────┐  │
//! │  │ MPC Proxy     │  │ BRC-31 │  │ Key Share Svc  │  │
//! │  │ (share_B)     │  │  auth  │  │ (share_A)      │  │
//! │  └───────────────┘  │        │  └────────────────┘  │
//! └─────────────────────┘        │  ┌────────────────┐  │
//!                                │  │ DO SQLite      │  │
//!                                │  │ (encrypted     │  │
//!                                │  │  shares)       │  │
//!                                │  └────────────────┘  │
//!                                └──────────────────────┘
//! ```
//!
//! ## Endpoints
//!
//! | Method  | Path              | Auth   | Description                          |
//! |---------|-------------------|--------|--------------------------------------|
//! | POST    | `/.well-known/auth` | none | BRC-31 Authrite handshake            |
//! | OPTIONS | `*`               | none   | CORS preflight                       |
//! | POST    | `/dkg/init`       | BRC-31 | Start DKG ceremony                   |
//! | POST    | `/dkg/round`      | BRC-31 | Process DKG round                    |
//! | POST    | `/presign/init`   | BRC-31 | Start presigning protocol            |
//! | POST    | `/presign/round`  | BRC-31 | Process presigning round             |
//! | GET     | `/health`         | none   | Liveness check + share count         |
//! | GET     | `/shares/:agent`  | BRC-31 | Share metadata (no secrets exposed)  |
//!
//! ## Security Model
//!
//! - All mutation endpoints require BRC-31 Authrite mutual authentication.
//! - Only the agent that owns a share can request signing with that share.
//! - Shares are encrypted with AES-256-GCM (BRC-42 derived keys) at rest.
//! - The Worker never sees the full private key — only its share.
//! - Durable Object SQLite provides per-agent isolation.

mod api;
pub mod auth;
mod do_storage;
mod poc;
mod storage;

use worker::*;

// ── Durable Object: MpcStorage ──────────────────────────────────────────────
//
// Stores key shares and protocol state in DO storage.
// Required by wrangler for the MPC_STORAGE binding declared in wrangler.toml.
// Currently a stub — protocol state is held in-memory (static HashMap/Mutex).
// Future: migrate to DO SQLite for persistence across Worker restarts.

#[durable_object]
pub struct MpcStorage {
    #[allow(dead_code)]
    state: State,
    #[allow(dead_code)]
    env: Env,
}

impl DurableObject for MpcStorage {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, _req: Request) -> Result<Response> {
        Response::from_json(&serde_json::json!({
            "status": "ok",
            "message": "MpcStorage Durable Object"
        }))
    }
}

/// CF Worker fetch event handler.
///
/// Routes incoming HTTP requests to the appropriate MPC protocol handler.
/// All mutation endpoints (DKG, signing, presigning) require BRC-31 auth.
/// The handshake endpoint and health check are open.
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // Handle CORS preflight for any path
    if req.method() == Method::Options {
        return auth::handle_cors_preflight();
    }

    let router = Router::new();

    // I-4a.2 + #5 step 3: the Worker entrypoint is a thin forwarder. ALL
    // auth (the BRC-31 `/.well-known/auth` handshake AND per-request
    // verification) now runs INSIDE the per-identity `CosignerSessionDo`,
    // backed by its durable SQLite session store — so the handshake-write and
    // the request-read hit the same store regardless of which entrypoint
    // isolate served them (the auth-session-isolate fix). The DO's `fetch`
    // gates authed paths (`is_authed_path`) before dispatching; `/health` and
    // the `/poc/*` deterministic-proof routes stay open per §07.6.
    router
        // ── BRC-31 Authrite handshake (verified + stored in the DO) ────
        .post_async("/.well-known/auth", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // ── KSS protocol endpoints (BRC-31 gated inside the DO) ────────
        .post_async("/dkg/init", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        .post_async("/dkg/round", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // Signing is relay-only (#13): the legacy 4-round HTTP `/sign/{init,round}`
        // routes were retired; online signing runs over the relay (`/sign-relay`).
        .post_async("/presign/init", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        .post_async("/presign/round", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        .post_async("/ecdh", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // I-4b.1: seed off-worker-generated Paillier primes for DKG (auth'd).
        .post_async("/ceremony/seed-primes", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // #14: ingest a native-generated presignature into the DO pool (auth'd).
        .post_async("/ceremony/ingest-presig", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // #6/#5 step 4: production relay sign — BRC-31 + owner-authz gated; the
        // DO issues its partial from a pooled presig and relays it (§07.6
        // production sibling of `/poc/sign-relay`).
        .post_async("/sign-relay", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // #9: durable custody of a cosigner's KEK-wrapped share_A (BRC-31 +
        // owner-authz; the DO stores only sealed bytes).
        .post_async("/custody/put-share", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        .post_async("/custody/get-share", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // ── Read-only endpoints (no auth required) ──────────────────
        .get_async("/health", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        .get_async("/shares/:agent_id", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // ── Phase I-3b POC: DO SQLite persistence + hibernation ─────
        // Forwarded to the per-identity CosignerSessionDo (DO SQLite +
        // stable identity from SERVER_PRIVATE_KEY). Proves the fund-safety
        // persistence primitive on the deployed Worker (gated at runtime by
        // the I-3c deploy + forced-hibernation harness).
        .get_async("/poc/identity", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        .post_async("/poc/persist", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // I-4a: DO-SQLite real-EncryptedShare round-trip (fund-safety store).
        .get_async("/poc/share-roundtrip", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // #5 step 3: DO-SQLite auth-session round-trip (auth-session-isolate fix).
        .get_async("/poc/auth-session-roundtrip", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // I-4b probe: full 2-party DKG in one wasm isolate, timed (CF CPU fit).
        .get_async("/poc/dkg-bench", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // ADR-018: the wasm DO's light online-sign op — issue a partial from a
        // posted presignature. Proves the hybrid hot path on deployed wasm.
        .post_async("/poc/issue-partial", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // #14: deployed runtime proof of provision → consume → light-sign.
        .post_async("/poc/presig-pool", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // #15 (I-4b.2): DO relay sign loop — issue partial → wrap §05 → send
        // over the live relay (self-addressed round-trip proof when no recipient).
        .post_async("/poc/sign-relay", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // I-3b2: relay-handshake-from-DO — outbound Socket.IO + BRC-103 +
        // envelope round-trip against the live MessageBox relay, driven from
        // inside the per-identity CosignerSessionDo (wasm32 transport).
        .get_async("/poc/handshake", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        .run(req, env)
        .await
}
