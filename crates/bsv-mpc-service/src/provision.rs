//! #4 — presignature provisioning: ship this party's `Presignature_A` to the
//! cosigner DO's pool over the authed `/ceremony/ingest-presig` route.
//!
//! **SECURITY (ADR-018):** a presignature alone issues that party's partial
//! (`issue_partial_signature_json` takes no key share). So `Presignature_A` must
//! flow **here (the share_A holder) → DO directly**, never via the proxy. A
//! proxy holding both presignatures could forge a full signature alone. This
//! module is the only path that ships `Presignature_A`, and it goes straight to
//! the DO authenticated as the service's own identity.

use bsv_mpc_core::brc31_client::headers;

use crate::ProvisionConfig;

impl ProvisionConfig {
    /// Ship a serialized `Presignature_A` into the cosigner DO pool. Performs a
    /// lazy BRC-31 handshake (cached) then an authed POST to
    /// `/ceremony/ingest-presig`. Errors propagate so the caller can fail-closed
    /// (keep the proxy/DO pools in FIFO lockstep — never add a proxy `box_B`
    /// without its DO `Presignature_A`).
    pub async fn ship_presignature(
        &self,
        agent_id: &str,
        presig_json: &[u8],
        session_id: &str,
        presig_id: &str,
    ) -> anyhow::Result<()> {
        let mut auth = self.auth.lock().await;

        // Lazy handshake.
        if !auth.is_authenticated() {
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
                let status = resp.status();
                anyhow::bail!("BRC-31 handshake to worker failed: {status}");
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
        }

        // Serialize the body ONCE; sign over + send the exact bytes.
        let path = "/ceremony/ingest-presig";
        let body = serde_json::to_vec(&serde_json::json!({
            "agent_id": agent_id,
            "session_id": session_id,
            "presig_id": presig_id,
            "presignature_hex": hex::encode(presig_json),
        }))?;
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
            anyhow::bail!("ingest-presig returned {status}: {body}");
        }
        Ok(())
    }
}
