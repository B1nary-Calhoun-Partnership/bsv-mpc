//! Storage backend abstraction for the MPC signing proxy.
//!
//! Provides a trait [`StorageBackend`] that decouples UTXO tracking from a
//! specific implementation. Two backends ship out of the box:
//!
//! - [`InMemoryBackend`] — wraps the existing [`UtxoTracker`] for standalone/dev
//!   mode. Used by default if no backend is specified via [`ProxyBuilder`].
//!
//! - [`WalletInfraBackend`] — stub for hosted mode where UTXOs live in
//!   rust-wallet-infra's `StorageClient`. The trait surface is implemented but
//!   the internal calls are TODO pending integration with `StorageClient`.
//!
//! [`UtxoTracker`]: crate::utxo_tracker::UtxoTracker
//! [`ProxyBuilder`]: crate::server::ProxyBuilder

use std::future::Future;
use std::pin::Pin;

use tokio::sync::RwLock;

use crate::error::ProxyError;
use crate::utxo_tracker::{TrackedOutput, UtxoTracker};

// ─── Trait ──────────────────────────────────────────────────────────────────

/// Async storage backend for UTXO management.
///
/// All methods are async to support both local (in-memory) and remote
/// (wallet-infra HTTP/SQLite) implementations. Implementations must be
/// `Send + Sync` so the backend can be shared across Tokio tasks via
/// `Arc<dyn StorageBackend>`.
///
/// Methods return boxed futures for dyn-compatibility (so the backend can
/// be stored as `Arc<dyn StorageBackend>` in `AppState`).
pub trait StorageBackend: Send + Sync {
    /// Persist a new tracked output.
    fn add_output(
        &self,
        output: TrackedOutput,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send + '_>>;

    /// Mark an output as spent by a given transaction.
    ///
    /// Returns `true` if the output was found and marked, `false` if it was
    /// not found or already spent.
    fn mark_spent(
        &self,
        txid: &str,
        vout: u32,
        spending_txid: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ProxyError>> + Send + '_>>;

    /// List unspent outputs, optionally filtered by basket and/or tags.
    ///
    /// Tag filtering uses "any" mode — an output matches if it has at least
    /// one of the requested tags.
    fn list_unspent(
        &self,
        basket: Option<&str>,
        tags: Option<&[String]>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<TrackedOutput>, ProxyError>> + Send + '_>>;

    /// Select UTXOs to cover a target amount using a greedy algorithm.
    ///
    /// Returns the selected outputs and the total selected amount. If
    /// insufficient funds are available, returns whatever is available —
    /// callers must check whether `total >= target`.
    #[allow(clippy::type_complexity)]
    fn select_utxos(
        &self,
        target_sats: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<TrackedOutput>, u64), ProxyError>> + Send + '_>>;

    /// Total balance of all unspent outputs in satoshis.
    fn total_balance(&self) -> Pin<Box<dyn Future<Output = Result<u64, ProxyError>> + Send + '_>>;
}

// ─── InMemoryBackend ────────────────────────────────────────────────────────

/// In-memory storage backend wrapping [`UtxoTracker`].
///
/// Thread-safety is handled internally via a `RwLock`, so callers don't need
/// external synchronization. This is the default backend for standalone/dev
/// deployments where the proxy manages its own UTXO set.
pub struct InMemoryBackend {
    tracker: RwLock<UtxoTracker>,
}

impl InMemoryBackend {
    /// Create a new in-memory backend with an empty UTXO set.
    pub fn new() -> Self {
        Self {
            tracker: RwLock::new(UtxoTracker::new()),
        }
    }

    /// Create a new in-memory backend from an existing [`UtxoTracker`].
    pub fn from_tracker(tracker: UtxoTracker) -> Self {
        Self {
            tracker: RwLock::new(tracker),
        }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for InMemoryBackend {
    fn add_output(
        &self,
        output: TrackedOutput,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send + '_>> {
        Box::pin(async move {
            let mut tracker = self.tracker.write().await;
            tracker.add_output(output);
            Ok(())
        })
    }

    fn mark_spent(
        &self,
        txid: &str,
        vout: u32,
        spending_txid: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ProxyError>> + Send + '_>> {
        let txid = txid.to_string();
        let spending_txid = spending_txid.to_string();
        Box::pin(async move {
            let mut tracker = self.tracker.write().await;
            Ok(tracker.mark_spent(&txid, vout, &spending_txid))
        })
    }

    fn list_unspent(
        &self,
        basket: Option<&str>,
        tags: Option<&[String]>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<TrackedOutput>, ProxyError>> + Send + '_>> {
        let basket = basket.map(String::from);
        let tags = tags.map(|t| t.to_vec());
        Box::pin(async move {
            let tracker = self.tracker.read().await;
            Ok(tracker
                .list_unspent(basket.as_deref(), tags.as_deref())
                .into_iter()
                .cloned()
                .collect())
        })
    }

    fn select_utxos(
        &self,
        target_sats: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<TrackedOutput>, u64), ProxyError>> + Send + '_>>
    {
        Box::pin(async move {
            let tracker = self.tracker.read().await;
            Ok(tracker.select_utxos(target_sats))
        })
    }

    fn total_balance(&self) -> Pin<Box<dyn Future<Output = Result<u64, ProxyError>> + Send + '_>> {
        Box::pin(async move {
            let tracker = self.tracker.read().await;
            Ok(tracker.total_balance())
        })
    }
}

// ─── WalletInfraBackend ─────────────────────────────────────────────────────

/// Storage backend that delegates to rust-wallet-infra's `StorageClient`.
///
/// In hosted mode, UTXOs live in the wallet infrastructure database and are
/// accessed via the `StorageClient` API. This keeps the proxy stateless and
/// lets multiple proxy instances share the same UTXO set.
///
/// # Current status
///
/// This is a stub implementation. The trait methods are defined and will
/// compile, but the internal calls to `StorageClient` are TODO pending
/// integration with `rust-wallet-toolbox`.
pub struct WalletInfraBackend {
    /// Base URL for the wallet infrastructure API (e.g., `https://wallet-infra.example.com`).
    #[allow(dead_code)]
    base_url: String,
    /// HTTP client for wallet-infra API calls.
    #[allow(dead_code)]
    client: reqwest::Client,
}

impl WalletInfraBackend {
    /// Create a new wallet infrastructure backend.
    ///
    /// # Arguments
    ///
    /// * `base_url` — Base URL for the wallet infrastructure API.
    /// * `client` — HTTP client (reuse the proxy's shared client for connection pooling).
    pub fn new(base_url: String, client: reqwest::Client) -> Self {
        Self { base_url, client }
    }
}

impl StorageBackend for WalletInfraBackend {
    fn add_output(
        &self,
        _output: TrackedOutput,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send + '_>> {
        // TODO: Delegate to StorageClient::insert_output()
        // The StorageClient API accepts an output record with txid, vout,
        // satoshis, locking_script, basket, and tags. It persists to the
        // wallet-infra database so all proxy instances see the same UTXO set.
        Box::pin(async {
            Err(ProxyError::Internal(
                "WalletInfraBackend::add_output not yet implemented".into(),
            ))
        })
    }

    fn mark_spent(
        &self,
        _txid: &str,
        _vout: u32,
        _spending_txid: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ProxyError>> + Send + '_>> {
        // TODO: Delegate to StorageClient::mark_output_spent()
        // Marks the output identified by (txid, vout) as spent by spending_txid.
        // Returns whether the output was found and updated.
        Box::pin(async {
            Err(ProxyError::Internal(
                "WalletInfraBackend::mark_spent not yet implemented".into(),
            ))
        })
    }

    fn list_unspent(
        &self,
        _basket: Option<&str>,
        _tags: Option<&[String]>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<TrackedOutput>, ProxyError>> + Send + '_>> {
        // TODO: Delegate to StorageClient::list_outputs()
        // Query wallet-infra for unspent outputs, optionally filtered by
        // basket name and tags. Map the StorageClient response rows into
        // TrackedOutput structs.
        Box::pin(async {
            Err(ProxyError::Internal(
                "WalletInfraBackend::list_unspent not yet implemented".into(),
            ))
        })
    }

    fn select_utxos(
        &self,
        _target_sats: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<TrackedOutput>, u64), ProxyError>> + Send + '_>>
    {
        // TODO: Delegate to StorageClient's UTXO selection
        // Either use server-side selection if StorageClient supports it, or
        // call list_unspent() and apply the greedy largest-first algorithm
        // locally (same logic as UtxoTracker::select_utxos).
        Box::pin(async {
            Err(ProxyError::Internal(
                "WalletInfraBackend::select_utxos not yet implemented".into(),
            ))
        })
    }

    fn total_balance(&self) -> Pin<Box<dyn Future<Output = Result<u64, ProxyError>> + Send + '_>> {
        // TODO: Delegate to StorageClient::get_balance() or sum unspent outputs
        // If StorageClient exposes a balance endpoint, use it. Otherwise,
        // call list_unspent(None, None) and sum satoshis.
        Box::pin(async {
            Err(ProxyError::Internal(
                "WalletInfraBackend::total_balance not yet implemented".into(),
            ))
        })
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_output(txid: &str, vout: u32, sats: u64) -> TrackedOutput {
        TrackedOutput {
            txid: txid.to_string(),
            vout,
            satoshis: sats,
            locking_script: vec![0x76, 0xa9],
            spending_txid: None,
            basket: None,
            tags: vec![],
            created_at: Utc::now(),
        }
    }

    fn make_output_with_basket(
        txid: &str,
        vout: u32,
        sats: u64,
        basket: &str,
        tags: Vec<&str>,
    ) -> TrackedOutput {
        TrackedOutput {
            txid: txid.to_string(),
            vout,
            satoshis: sats,
            locking_script: vec![0x76, 0xa9],
            spending_txid: None,
            basket: Some(basket.to_string()),
            tags: tags.into_iter().map(String::from).collect(),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn in_memory_empty() {
        let backend = InMemoryBackend::new();
        assert_eq!(backend.total_balance().await.unwrap(), 0);
        let unspent = backend.list_unspent(None, None).await.unwrap();
        assert!(unspent.is_empty());
    }

    #[tokio::test]
    async fn in_memory_add_and_list() {
        let backend = InMemoryBackend::new();
        backend
            .add_output(make_output("aabb", 0, 1000))
            .await
            .unwrap();
        backend
            .add_output(make_output("ccdd", 1, 2000))
            .await
            .unwrap();

        assert_eq!(backend.total_balance().await.unwrap(), 3000);
        let unspent = backend.list_unspent(None, None).await.unwrap();
        assert_eq!(unspent.len(), 2);
    }

    #[tokio::test]
    async fn in_memory_mark_spent() {
        let backend = InMemoryBackend::new();
        backend
            .add_output(make_output("aabb", 0, 1000))
            .await
            .unwrap();
        backend
            .add_output(make_output("ccdd", 1, 2000))
            .await
            .unwrap();

        assert!(backend.mark_spent("aabb", 0, "eeff").await.unwrap());
        assert_eq!(backend.total_balance().await.unwrap(), 2000);

        let unspent = backend.list_unspent(None, None).await.unwrap();
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].txid, "ccdd");
    }

    #[tokio::test]
    async fn in_memory_mark_spent_not_found() {
        let backend = InMemoryBackend::new();
        backend
            .add_output(make_output("aabb", 0, 1000))
            .await
            .unwrap();
        assert!(!backend.mark_spent("nonexistent", 0, "eeff").await.unwrap());
    }

    #[tokio::test]
    async fn in_memory_basket_filter() {
        let backend = InMemoryBackend::new();
        backend
            .add_output(make_output_with_basket("aa", 0, 1000, "default", vec![]))
            .await
            .unwrap();
        backend
            .add_output(make_output_with_basket("bb", 0, 2000, "custom", vec![]))
            .await
            .unwrap();

        let default = backend.list_unspent(Some("default"), None).await.unwrap();
        assert_eq!(default.len(), 1);
        assert_eq!(default[0].satoshis, 1000);

        let custom = backend.list_unspent(Some("custom"), None).await.unwrap();
        assert_eq!(custom.len(), 1);
        assert_eq!(custom[0].satoshis, 2000);
    }

    #[tokio::test]
    async fn in_memory_tag_filter() {
        let backend = InMemoryBackend::new();
        backend
            .add_output(make_output_with_basket(
                "aa",
                0,
                1000,
                "default",
                vec!["state"],
            ))
            .await
            .unwrap();
        backend
            .add_output(make_output_with_basket(
                "bb",
                0,
                2000,
                "default",
                vec!["memory"],
            ))
            .await
            .unwrap();
        backend
            .add_output(make_output_with_basket(
                "cc",
                0,
                3000,
                "default",
                vec!["state", "memory"],
            ))
            .await
            .unwrap();

        let state_outputs = backend
            .list_unspent(None, Some(&[String::from("state")]))
            .await
            .unwrap();
        assert_eq!(state_outputs.len(), 2);

        let any = backend
            .list_unspent(None, Some(&[String::from("state"), String::from("memory")]))
            .await
            .unwrap();
        assert_eq!(any.len(), 3);
    }

    #[tokio::test]
    async fn in_memory_select_utxos() {
        let backend = InMemoryBackend::new();
        backend.add_output(make_output("aa", 0, 500)).await.unwrap();
        backend
            .add_output(make_output("bb", 0, 3000))
            .await
            .unwrap();
        backend
            .add_output(make_output("cc", 0, 1000))
            .await
            .unwrap();

        let (selected, total) = backend.select_utxos(3500).await.unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(total, 4000);
        assert_eq!(selected[0].satoshis, 3000);
        assert_eq!(selected[1].satoshis, 1000);
    }

    #[tokio::test]
    async fn in_memory_from_tracker() {
        let mut tracker = UtxoTracker::new();
        tracker.add_output(make_output("aa", 0, 5000));

        let backend = InMemoryBackend::from_tracker(tracker);
        assert_eq!(backend.total_balance().await.unwrap(), 5000);
    }

    #[tokio::test]
    async fn wallet_infra_stubs_return_error() {
        let backend = WalletInfraBackend::new("https://example.com".into(), reqwest::Client::new());
        assert!(backend.add_output(make_output("aa", 0, 100)).await.is_err());
        assert!(backend.mark_spent("aa", 0, "bb").await.is_err());
        assert!(backend.list_unspent(None, None).await.is_err());
        assert!(backend.select_utxos(100).await.is_err());
        assert!(backend.total_balance().await.is_err());
    }

    #[tokio::test]
    async fn dyn_compatible() {
        // Verify the trait can be used as Arc<dyn StorageBackend>
        let backend: std::sync::Arc<dyn StorageBackend> =
            std::sync::Arc::new(InMemoryBackend::new());
        backend
            .add_output(make_output("aa", 0, 1000))
            .await
            .unwrap();
        assert_eq!(backend.total_balance().await.unwrap(), 1000);
    }
}
