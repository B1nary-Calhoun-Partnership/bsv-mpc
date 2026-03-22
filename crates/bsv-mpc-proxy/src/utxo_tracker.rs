//! In-memory UTXO tracker for the MPC signing proxy.
//!
//! Tracks outputs that the proxy controls (outputs payable to keys derived
//! from the joint MPC public key). Used by `listOutputs`, `createAction`,
//! and `internalizeAction` to manage the proxy's local UTXO set.
//!
//! This is an in-memory implementation. Production will use SQLite via
//! rust-wallet-toolbox's `StorageSqlx`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A tracked output in the proxy's UTXO set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedOutput {
    /// Transaction ID (hex, display byte order).
    pub txid: String,
    /// Output index within the transaction.
    pub vout: u32,
    /// Amount in satoshis.
    pub satoshis: u64,
    /// Raw locking script bytes.
    #[serde(with = "hex_serde")]
    pub locking_script: Vec<u8>,
    /// If spent, the txid of the spending transaction.
    pub spending_txid: Option<String>,
    /// BRC-46 basket name.
    pub basket: Option<String>,
    /// Tags for filtering.
    pub tags: Vec<String>,
    /// When the output was first tracked.
    pub created_at: DateTime<Utc>,
}

impl TrackedOutput {
    /// Returns the outpoint string in `txid.vout` format (BRC-100 convention).
    pub fn outpoint(&self) -> String {
        format!("{}.{}", self.txid, self.vout)
    }

    /// Whether this output is unspent.
    pub fn is_unspent(&self) -> bool {
        self.spending_txid.is_none()
    }
}

/// In-memory UTXO tracker.
///
/// Thread-safety is handled externally via `Arc<RwLock<UtxoTracker>>` in
/// `AppState`.
pub struct UtxoTracker {
    outputs: Vec<TrackedOutput>,
}

impl UtxoTracker {
    /// Create an empty UTXO tracker.
    pub fn new() -> Self {
        Self {
            outputs: Vec::new(),
        }
    }

    /// Add a new tracked output.
    pub fn add_output(&mut self, output: TrackedOutput) {
        self.outputs.push(output);
    }

    /// Mark an output as spent.
    ///
    /// Returns `true` if the output was found and marked, `false` if not found.
    pub fn mark_spent(&mut self, txid: &str, vout: u32, spending_txid: &str) -> bool {
        for output in &mut self.outputs {
            if output.txid == txid && output.vout == vout && output.is_unspent() {
                output.spending_txid = Some(spending_txid.to_string());
                return true;
            }
        }
        false
    }

    /// List unspent outputs, optionally filtered by basket and/or tags.
    ///
    /// Tag filtering uses "any" mode — an output matches if it has at least
    /// one of the requested tags.
    pub fn list_unspent(
        &self,
        basket: Option<&str>,
        tags: Option<&[String]>,
    ) -> Vec<&TrackedOutput> {
        self.outputs
            .iter()
            .filter(|o| {
                if !o.is_unspent() {
                    return false;
                }
                if let Some(b) = basket {
                    if o.basket.as_deref() != Some(b) {
                        return false;
                    }
                }
                if let Some(required_tags) = tags {
                    if !required_tags.is_empty()
                        && !required_tags.iter().any(|t| o.tags.contains(t))
                    {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    /// Select UTXOs to cover a target amount using a simple greedy algorithm.
    ///
    /// Picks the largest unspent outputs first until the target is reached.
    /// Returns the selected outputs (cloned) and the total selected amount.
    /// Returns an empty vec if insufficient funds.
    pub fn select_utxos(&self, target_sats: u64) -> (Vec<TrackedOutput>, u64) {
        let mut unspent: Vec<&TrackedOutput> = self
            .outputs
            .iter()
            .filter(|o| o.is_unspent())
            .collect();

        // Sort by satoshis descending (largest first)
        unspent.sort_by(|a, b| b.satoshis.cmp(&a.satoshis));

        let mut selected = Vec::new();
        let mut total = 0u64;

        for output in unspent {
            if total >= target_sats {
                break;
            }
            total += output.satoshis;
            selected.push(output.clone());
        }

        (selected, total)
    }

    /// Total balance of all unspent outputs.
    pub fn total_balance(&self) -> u64 {
        self.outputs
            .iter()
            .filter(|o| o.is_unspent())
            .map(|o| o.satoshis)
            .sum()
    }

    /// Number of tracked outputs (both spent and unspent).
    pub fn len(&self) -> usize {
        self.outputs.len()
    }

    /// Whether the tracker has no outputs.
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }

    /// Number of unspent outputs.
    pub fn unspent_count(&self) -> usize {
        self.outputs.iter().filter(|o| o.is_unspent()).count()
    }
}

impl Default for UtxoTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Serde helper for hex-encoded byte vectors.
mod hex_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn empty_tracker() {
        let tracker = UtxoTracker::new();
        assert!(tracker.is_empty());
        assert_eq!(tracker.len(), 0);
        assert_eq!(tracker.total_balance(), 0);
        assert_eq!(tracker.unspent_count(), 0);
    }

    #[test]
    fn add_and_list() {
        let mut tracker = UtxoTracker::new();
        tracker.add_output(make_output("aabb", 0, 1000));
        tracker.add_output(make_output("ccdd", 1, 2000));

        assert_eq!(tracker.len(), 2);
        assert_eq!(tracker.total_balance(), 3000);
        assert_eq!(tracker.unspent_count(), 2);

        let unspent = tracker.list_unspent(None, None);
        assert_eq!(unspent.len(), 2);
    }

    #[test]
    fn mark_spent() {
        let mut tracker = UtxoTracker::new();
        tracker.add_output(make_output("aabb", 0, 1000));
        tracker.add_output(make_output("ccdd", 1, 2000));

        assert!(tracker.mark_spent("aabb", 0, "eeff"));
        assert_eq!(tracker.total_balance(), 2000);
        assert_eq!(tracker.unspent_count(), 1);
        assert_eq!(tracker.len(), 2); // still tracked, just spent

        let unspent = tracker.list_unspent(None, None);
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].txid, "ccdd");
    }

    #[test]
    fn mark_spent_not_found() {
        let mut tracker = UtxoTracker::new();
        tracker.add_output(make_output("aabb", 0, 1000));

        assert!(!tracker.mark_spent("nonexistent", 0, "eeff"));
        assert_eq!(tracker.total_balance(), 1000);
    }

    #[test]
    fn mark_spent_already_spent() {
        let mut tracker = UtxoTracker::new();
        tracker.add_output(make_output("aabb", 0, 1000));

        assert!(tracker.mark_spent("aabb", 0, "eeff"));
        // Trying to spend again should return false
        assert!(!tracker.mark_spent("aabb", 0, "1122"));
    }

    #[test]
    fn list_unspent_filter_basket() {
        let mut tracker = UtxoTracker::new();
        tracker.add_output(make_output_with_basket("aa", 0, 1000, "default", vec![]));
        tracker.add_output(make_output_with_basket("bb", 0, 2000, "custom", vec![]));
        tracker.add_output(make_output_with_basket("cc", 0, 3000, "default", vec![]));

        let default_outputs = tracker.list_unspent(Some("default"), None);
        assert_eq!(default_outputs.len(), 2);

        let custom_outputs = tracker.list_unspent(Some("custom"), None);
        assert_eq!(custom_outputs.len(), 1);
        assert_eq!(custom_outputs[0].satoshis, 2000);

        let none_outputs = tracker.list_unspent(Some("nonexistent"), None);
        assert_eq!(none_outputs.len(), 0);
    }

    #[test]
    fn list_unspent_filter_tags() {
        let mut tracker = UtxoTracker::new();
        tracker.add_output(make_output_with_basket(
            "aa",
            0,
            1000,
            "default",
            vec!["state"],
        ));
        tracker.add_output(make_output_with_basket(
            "bb",
            0,
            2000,
            "default",
            vec!["memory"],
        ));
        tracker.add_output(make_output_with_basket(
            "cc",
            0,
            3000,
            "default",
            vec!["state", "memory"],
        ));

        let state_outputs = tracker.list_unspent(
            None,
            Some(&[String::from("state")]),
        );
        assert_eq!(state_outputs.len(), 2); // aa and cc

        let memory_outputs = tracker.list_unspent(
            None,
            Some(&[String::from("memory")]),
        );
        assert_eq!(memory_outputs.len(), 2); // bb and cc

        let any_outputs = tracker.list_unspent(
            None,
            Some(&[String::from("state"), String::from("memory")]),
        );
        assert_eq!(any_outputs.len(), 3); // all match at least one tag
    }

    #[test]
    fn select_utxos_greedy() {
        let mut tracker = UtxoTracker::new();
        tracker.add_output(make_output("aa", 0, 500));
        tracker.add_output(make_output("bb", 0, 3000));
        tracker.add_output(make_output("cc", 0, 1000));

        // Should pick largest first: 3000, then 1000
        let (selected, total) = tracker.select_utxos(3500);
        assert_eq!(selected.len(), 2);
        assert_eq!(total, 4000);
        assert_eq!(selected[0].satoshis, 3000); // largest first
        assert_eq!(selected[1].satoshis, 1000);
    }

    #[test]
    fn select_utxos_exact_amount() {
        let mut tracker = UtxoTracker::new();
        tracker.add_output(make_output("aa", 0, 1000));

        let (selected, total) = tracker.select_utxos(1000);
        assert_eq!(selected.len(), 1);
        assert_eq!(total, 1000);
    }

    #[test]
    fn select_utxos_insufficient() {
        let mut tracker = UtxoTracker::new();
        tracker.add_output(make_output("aa", 0, 500));

        let (selected, total) = tracker.select_utxos(1000);
        // Returns what's available — caller checks if total >= target
        assert_eq!(selected.len(), 1);
        assert_eq!(total, 500);
    }

    #[test]
    fn select_utxos_skips_spent() {
        let mut tracker = UtxoTracker::new();
        tracker.add_output(make_output("aa", 0, 5000));
        tracker.add_output(make_output("bb", 0, 1000));
        tracker.mark_spent("aa", 0, "spending_tx");

        let (selected, total) = tracker.select_utxos(1000);
        assert_eq!(selected.len(), 1);
        assert_eq!(total, 1000);
        assert_eq!(selected[0].txid, "bb");
    }

    #[test]
    fn outpoint_format() {
        let output = make_output("abcdef1234", 3, 0);
        assert_eq!(output.outpoint(), "abcdef1234.3");
    }
}
