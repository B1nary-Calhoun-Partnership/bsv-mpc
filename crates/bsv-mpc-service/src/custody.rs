//! #9 — durable share custody (cosigner side): KEK-seal `share_A` and persist it
//! to the worker DO so an ephemeral-container restart can never permanently lock
//! funds. The DO only ever holds the sealed blob; the KEK lives only here.
//!
//! Flow: at DKG-complete the cosigner [`CustodyConfig::put_share`]s its
//! KEK-wrapped share; after a restart, on a cache miss, it [`CustodyConfig::get_share`]s
//! it back and unwraps it. Auth is a stable BRC-31 identity (the custody-record
//! owner), so only this cosigner can read its own blob back (§08.1) — and even
//! then the blob is useless without the KEK.

use bsv_mpc_core::brc31_client::headers;
use bsv_mpc_core::custody::{unwrap_custody_share, wrap_share_for_custody};
use bsv_mpc_core::types::EncryptedShare;

use crate::CustodyConfig;

impl CustodyConfig {
    /// Perform the lazy BRC-31 handshake with the worker (cached on the client).
    async fn ensure_handshake(
        &self,
        auth: &mut bsv_mpc_core::brc31_client::Brc31Client,
    ) -> anyhow::Result<()> {
        if auth.is_authenticated() {
            return Ok(());
        }
        let init_body = auth
            .initial_request_body()
            .map_err(|e| anyhow::anyhow!("BRC-31 InitialRequest body: {e}"))?;
        let mut req = self
            .http
            .post(format!("{}/.well-known/auth", self.worker_url))
            .body(init_body);
        for (name, value) in auth.initial_request_headers() {
            req = req.header(name, value);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("custody BRC-31 handshake failed: {}", resp.status());
        }
        let header = |name: &str| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let server_identity = header(headers::IDENTITY_KEY)
            .ok_or_else(|| anyhow::anyhow!("handshake response missing server identity"))?;
        let server_nonce = header(headers::NONCE)
            .ok_or_else(|| anyhow::anyhow!("handshake response missing server nonce"))?;
        if !auth.complete_handshake(server_identity, server_nonce) {
            anyhow::bail!("handshake response carried an invalid server identity key");
        }
        Ok(())
    }

    /// Seal `share` + its `owner_identity` (§08.1) under the KEK and persist to
    /// the worker DO custody store, keyed by the joint-key `agent_id`. Idempotent
    /// (upsert). Sealing the owner means a restart-recovery restores the
    /// owner-authz binding too — not just the key material.
    pub async fn put_share(
        &self,
        agent_id: &str,
        share: &EncryptedShare,
        owner_identity: &str,
    ) -> anyhow::Result<()> {
        let sealed = wrap_share_for_custody(share, owner_identity, &self.kek)
            .map_err(|e| anyhow::anyhow!("seal share for custody: {e}"))?;
        let mut auth = self.auth.lock().await;
        self.ensure_handshake(&mut auth).await?;
        // Serialize the body ONCE; sign over the exact bytes; send those exact
        // bytes (NOT `.json()`, which would re-serialize and could diverge).
        let path = "/custody/put-share";
        let body =
            serde_json::to_vec(&serde_json::json!({ "agent_id": agent_id, "share": sealed }))?;
        let mut req = self
            .http
            .post(format!("{}{path}", self.worker_url))
            .header("content-type", "application/json")
            .body(body.clone());
        for (name, value) in auth
            .request_headers("POST", path, &body)
            .map_err(|e| anyhow::anyhow!("auth headers: {e}"))?
        {
            req = req.header(name, value);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("custody put-share returned {status}: {body}");
        }
        Ok(())
    }

    /// Fetch + unwrap this cosigner's `(share_A, owner_identity)` from the worker
    /// DO custody store. `Ok(None)` if no blob is stored (404). A wrong KEK /
    /// tamper fails closed.
    pub async fn get_share(
        &self,
        agent_id: &str,
    ) -> anyhow::Result<Option<(EncryptedShare, String)>> {
        let mut auth = self.auth.lock().await;
        self.ensure_handshake(&mut auth).await?;
        let path = "/custody/get-share";
        let body = serde_json::to_vec(&serde_json::json!({ "agent_id": agent_id }))?;
        let mut req = self
            .http
            .post(format!("{}{path}", self.worker_url))
            .header("content-type", "application/json")
            .body(body.clone());
        for (name, value) in auth
            .request_headers("POST", path, &body)
            .map_err(|e| anyhow::anyhow!("auth headers: {e}"))?
        {
            req = req.header(name, value);
        }
        let resp = req.send().await?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("custody get-share returned {status}: {body}");
        }
        #[derive(serde::Deserialize)]
        struct GetResp {
            share: EncryptedShare,
        }
        let parsed: GetResp = resp.json().await?;
        let (restored, owner) = unwrap_custody_share(&parsed.share, &self.kek)
            .map_err(|e| anyhow::anyhow!("unwrap custody share: {e}"))?;
        Ok(Some((restored, owner)))
    }
}
