//! MPC signing fee injection.
//!
//! Every `createAction` transaction can optionally include an additional output
//! that pays the MPC node operators for their participation in the signing
//! ceremony. This module handles constructing and injecting that fee output.
//!
//! ## Fee distribution models
//!
//! ### Multisig (when `fee_threshold` is set)
//!
//! The fee output is a bare P2MS (pay-to-multisig) script requiring `t` of
//! the `n` fee addresses to spend. This is appropriate when the MPC node
//! operators are a known, fixed set and want shared custody of accumulated fees.
//!
//! Example: With `fee_threshold = "2-of-3"` and three addresses, the output
//! script is `OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG`.
//!
//! ### Split P2PKH (default)
//!
//! When no threshold is set, the fee is split equally among the fee addresses
//! as individual P2PKH outputs. Each operator gets their share independently.
//!
//! ## Usage
//!
//! The `FeeInjector` is constructed once at proxy startup and called from
//! the `createAction` handler after transaction construction but before
//! MPC signing.

/// Injects MPC signing fee output(s) into a transaction before signing.
///
/// The fee compensates MPC node operators for their participation in the
/// threshold signing ceremony. It is transparent to the calling application
/// (bsv-worm) — the fee appears as an additional output in the transaction.
pub struct FeeInjector {
    /// Fee amount in satoshis per signing operation.
    ///
    /// This is the total fee — if split across multiple addresses, each
    /// address receives `fee_sats / n` satoshis.
    fee_sats: u64,

    /// Public keys or addresses of the MPC node operators who receive fees.
    ///
    /// These are BSV addresses (P2PKH) or compressed public key hex strings.
    fee_addresses: Vec<String>,

    /// Multisig threshold configuration (e.g., `"2-of-3"`).
    ///
    /// When set, the fee output uses a bare P2MS script. When `None`,
    /// the fee is split into individual P2PKH outputs.
    fee_threshold: Option<String>,
}

impl FeeInjector {
    /// Create a new fee injector.
    ///
    /// # Arguments
    ///
    /// - `fee_sats` — Total fee per signing in satoshis.
    /// - `fee_addresses` — Addresses of MPC node operators.
    /// - `fee_threshold` — Optional multisig threshold (e.g., `"2-of-3"`).
    pub fn new(
        fee_sats: u64,
        fee_addresses: Vec<String>,
        fee_threshold: Option<String>,
    ) -> Self {
        Self {
            fee_sats,
            fee_addresses,
            fee_threshold,
        }
    }

    /// Add fee output(s) to a serialized transaction.
    ///
    /// Returns the modified transaction bytes with the fee output(s) appended.
    /// The caller must recalculate the miner fee after injection (the
    /// transaction is now larger).
    ///
    /// # Arguments
    ///
    /// - `tx_bytes` — The serialized unsigned transaction.
    ///
    /// # Errors
    ///
    /// - Invalid fee addresses (not valid BSV addresses or public keys).
    /// - Fee threshold format is invalid (must be `"t-of-n"`).
    /// - Fee threshold `t` exceeds the number of fee addresses.
    ///
    /// # Returns
    ///
    /// The modified transaction bytes with fee output(s) appended. If fee
    /// injection is disabled (`!is_enabled()`), returns the input unchanged.
    pub fn inject_fee(&self, tx_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        if !self.is_enabled() {
            return Ok(tx_bytes.to_vec());
        }

        let _ = tx_bytes;
        todo!(
            "1. Deserialize transaction from tx_bytes\n\
             2. Parse fee_threshold if set:\n\
                a. Split on '-of-' to get (t, n)\n\
                b. Validate t <= fee_addresses.len() and t >= 1\n\
             3. If fee_threshold is set (multisig):\n\
                a. Convert fee_addresses to public keys\n\
                b. Build P2MS script: OP_{{t}} <pk1> ... <pkn> OP_{{n}} OP_CHECKMULTISIG\n\
                c. Add single output: fee_sats to the P2MS script\n\
             4. If no threshold (split P2PKH):\n\
                a. Calculate per-address amount: fee_sats / fee_addresses.len()\n\
                b. Handle remainder: first address gets the extra satoshis\n\
                c. For each address, add a P2PKH output\n\
             5. Re-serialize the modified transaction\n\
             6. Return the new bytes"
        )
    }

    /// Check if fee injection is enabled.
    ///
    /// Fee injection requires both a non-zero fee amount and at least one
    /// fee address. If either is missing, fee injection is silently skipped.
    pub fn is_enabled(&self) -> bool {
        self.fee_sats > 0 && !self.fee_addresses.is_empty()
    }

    /// Get the total fee in satoshis.
    pub fn fee_sats(&self) -> u64 {
        self.fee_sats
    }

    /// Get the fee addresses.
    pub fn fee_addresses(&self) -> &[String] {
        &self.fee_addresses
    }

    /// Parse the threshold string (e.g., `"2-of-3"`) into `(t, n)`.
    ///
    /// Returns `None` if no threshold is configured.
    /// Returns an error if the format is invalid.
    pub fn parse_threshold(&self) -> anyhow::Result<Option<(u16, u16)>> {
        match &self.fee_threshold {
            None => Ok(None),
            Some(s) => {
                let parts: Vec<&str> = s.split("-of-").collect();
                if parts.len() != 2 {
                    anyhow::bail!(
                        "Invalid fee threshold format '{}' — expected 't-of-n' (e.g., '2-of-3')",
                        s
                    );
                }
                let t: u16 = parts[0]
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid threshold 't' in '{}'", s))?;
                let n: u16 = parts[1]
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid threshold 'n' in '{}'", s))?;

                if t == 0 {
                    anyhow::bail!("Threshold t must be >= 1, got 0");
                }
                if t > n {
                    anyhow::bail!("Threshold t ({t}) cannot exceed n ({n})");
                }
                if n as usize != self.fee_addresses.len() {
                    anyhow::bail!(
                        "Threshold n ({n}) does not match fee_addresses count ({})",
                        self.fee_addresses.len()
                    );
                }

                Ok(Some((t, n)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_when_no_fee() {
        let injector = FeeInjector::new(0, vec!["addr1".into()], None);
        assert!(!injector.is_enabled());
    }

    #[test]
    fn disabled_when_no_addresses() {
        let injector = FeeInjector::new(1000, vec![], None);
        assert!(!injector.is_enabled());
    }

    #[test]
    fn enabled_with_fee_and_addresses() {
        let injector = FeeInjector::new(1000, vec!["addr1".into()], None);
        assert!(injector.is_enabled());
    }

    #[test]
    fn parse_threshold_valid() {
        let injector = FeeInjector::new(
            1000,
            vec!["a".into(), "b".into(), "c".into()],
            Some("2-of-3".into()),
        );
        let (t, n) = injector.parse_threshold().unwrap().unwrap();
        assert_eq!(t, 2);
        assert_eq!(n, 3);
    }

    #[test]
    fn parse_threshold_none() {
        let injector = FeeInjector::new(1000, vec!["a".into()], None);
        assert!(injector.parse_threshold().unwrap().is_none());
    }

    #[test]
    fn parse_threshold_invalid_format() {
        let injector = FeeInjector::new(1000, vec!["a".into()], Some("2/3".into()));
        assert!(injector.parse_threshold().is_err());
    }

    #[test]
    fn parse_threshold_t_exceeds_n() {
        let injector = FeeInjector::new(
            1000,
            vec!["a".into(), "b".into()],
            Some("3-of-2".into()),
        );
        assert!(injector.parse_threshold().is_err());
    }

    #[test]
    fn parse_threshold_n_mismatch() {
        let injector = FeeInjector::new(
            1000,
            vec!["a".into(), "b".into()],
            Some("2-of-3".into()),
        );
        assert!(injector.parse_threshold().is_err());
    }

    #[test]
    fn inject_fee_noop_when_disabled() {
        let injector = FeeInjector::new(0, vec![], None);
        let tx_bytes = vec![1, 2, 3, 4];
        let result = injector.inject_fee(&tx_bytes).unwrap();
        assert_eq!(result, tx_bytes);
    }
}
