//! BRC-31 mutual auth for the MessageBox HTTP routes, wrapping
//! `bsv_rs::auth::Peer` with `SimplifiedFetchTransport`.
//!
//! ## Why we use bsv-rs's Peer instead of porting `bridge.rs::BridgeAuth`
//!
//! Two distinct BRC-31 signing flavors exist in this stack:
//!
//! 1. **Simple per-request signing** (`bsv-mpc-proxy/src/bridge.rs`):
//!    `ECDSA(SHA-256(per_request_nonce))` with a BRC-42-derived child key.
//!    Server-side counterpart is `bsv-mpc-worker/src/auth.rs`. Works for
//!    the internal proxy↔KSS path only.
//!
//! 2. **BRC-104 SimplifiedFetchTransport** (any
//!    `bsv-middleware-cloudflare-public`-style server, including the live
//!    Calhoun MessageBox relay): the signature covers a serialized
//!    `(request_id, method, path, search, signable_headers, body)`
//!    payload per BRC-104. This is what `Peer + SimplifiedFetchTransport`
//!    implements; the canonical Rust consumer is `~/bsv/
//!    bsv-wallet-toolbox-rs/src/storage/client/storage_client.rs`.
//!
//! Flavor 1 returns 500 against MessageBox. Flavor 2 is what this wraps,
//! used by [`crate::http`] for `POST /sendMessage` / `/listMessages` /
//! `/acknowledgeMessage`.
//!
//! ## Relationship to the WebSocket path
//!
//! The live (`subscribe`) path no longer touches this module: as of
//! H-4.4b it runs over Socket.IO + BRC-103 via a `Peer` over
//! `bsv::auth::SocketIoTransport` (see [`crate::subscribe`]), built from
//! the same identity priv exposed here via [`MessageBoxAuth::wallet`].
//! The former raw-`/ws` upgrade signer (`sign_ws_upgrade` + the BRC-104
//! request serializer) was deleted with `ws.rs`.
//!
//! ## Surface
//!
//! Construct via [`MessageBoxAuth::new`] with a stable identity priv;
//! call [`MessageBoxAuth::peer`] to access the underlying `Peer` for
//! request dispatch (see `crate::http`). [`MessageBoxAuth::start`] kicks
//! off the transport callback once at startup (per bsv-rs Peer protocol).

use std::sync::Arc;

use bsv::auth::{Peer, PeerOptions, SimplifiedFetchTransport};
use bsv::primitives::ec::PrivateKey;
use bsv::wallet::ProtoWallet;

use crate::error::{MessageBoxError, Result};

/// `Peer` parameterized to the way `bsv_rs` expects: ProtoWallet identity
/// over the SimplifiedFetchTransport HTTP transport.
pub type MessageBoxPeer = Peer<ProtoWallet, SimplifiedFetchTransport>;

/// BRC-31 client for one `(our_identity, relay_url)` pair. Wraps the
/// bsv-rs `Peer` lifecycle so the rest of this crate uses a stable
/// interface.
pub struct MessageBoxAuth {
    relay_url: String,
    peer: Arc<MessageBoxPeer>,
    wallet: ProtoWallet,
}

impl MessageBoxAuth {
    /// Construct an auth client for `relay_url`. The identity priv is
    /// stable across restarts — other cosigners route to this identity's
    /// public key per §06.7. `start` MUST be called once before any
    /// request dispatch.
    pub fn new(relay_url: impl Into<String>, our_priv: PrivateKey) -> Result<Self> {
        let relay_url = relay_url.into();
        let wallet = ProtoWallet::new(Some(our_priv));
        let transport = SimplifiedFetchTransport::new(&relay_url);
        let peer = Peer::new(PeerOptions {
            wallet: wallet.clone(),
            transport,
            certificates_to_request: None,
            session_manager: None,
            auto_persist_last_session: true,
            originator: Some("bsv-mpc-messagebox".to_string()),
        });
        Ok(Self {
            relay_url,
            peer: Arc::new(peer),
            wallet,
        })
    }

    /// Initialize the transport callback. MUST be called once before any
    /// `to_peer` round-trip; see `bsv_rs::auth::Peer::start`.
    pub fn start(&self) {
        self.peer.start();
    }

    /// The underlying `Peer` — used by [`crate::http`] for request
    /// dispatch + response listener management.
    pub fn peer(&self) -> &Arc<MessageBoxPeer> {
        &self.peer
    }

    /// Our wallet — used by [`crate::subscribe`] to build a second `Peer`
    /// over the Socket.IO transport with the same identity, and by
    /// callers that need to read our identity pub.
    pub fn wallet(&self) -> &ProtoWallet {
        &self.wallet
    }

    /// Our identity pubkey as lowercase hex — what cosigners route to.
    pub async fn identity_hex(&self) -> Result<String> {
        let key =
            self.peer.get_identity_key().await.map_err(|e| {
                MessageBoxError::Auth(format!("Peer.get_identity_key failed: {e:?}"))
            })?;
        Ok(key.to_hex())
    }

    /// The relay base URL this client is bound to.
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn fresh_priv() -> PrivateKey {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b[0] |= 0x01;
        PrivateKey::from_bytes(&b).unwrap()
    }

    #[test]
    fn construct_does_not_panic() {
        let auth = MessageBoxAuth::new("https://relay.example/", fresh_priv()).unwrap();
        assert_eq!(auth.relay_url(), "https://relay.example/");
    }

    #[tokio::test]
    async fn identity_hex_round_trips_pub() {
        let priv_ = fresh_priv();
        let expected = priv_.public_key().to_hex();
        let auth = MessageBoxAuth::new("https://relay.example/", priv_).unwrap();
        let actual = auth.identity_hex().await.unwrap();
        assert_eq!(actual, expected);
    }
}
