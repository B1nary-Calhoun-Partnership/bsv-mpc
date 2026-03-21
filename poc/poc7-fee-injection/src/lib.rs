//! POC 7: Fee injection logic
//!
//! Validates that an MPC signing fee output can be injected into a transaction
//! before signing without breaking validity. This logic will inform the
//! implementation of `bsv-mpc-proxy/src/fee_injector.rs`.

/// Result of fee injection into a transaction's output set.
#[derive(Debug)]
pub struct FeeInjectionResult {
    /// Index of the newly added fee output.
    pub fee_output_index: usize,
    /// Original change amount before fee deduction.
    pub original_change: u64,
    /// New change amount after fee deduction.
    pub new_change: u64,
}

/// Inject a fee output into a transaction's output list.
///
/// Adds a new output paying `fee_sats` to `fee_locking_script` and reduces
/// the change output at `change_index` by the same amount. The fee output
/// is appended at the end of the outputs list.
///
/// # Errors
///
/// Returns an error if the change output has insufficient funds to cover
/// the fee amount.
pub fn inject_fee_output(
    outputs: &mut Vec<(u64, Vec<u8>)>,
    change_index: usize,
    fee_sats: u64,
    fee_locking_script: Vec<u8>,
) -> Result<FeeInjectionResult, FeeInjectionError> {
    if change_index >= outputs.len() {
        return Err(FeeInjectionError::InvalidChangeIndex {
            index: change_index,
            output_count: outputs.len(),
        });
    }

    let original_change = outputs[change_index].0;

    if original_change < fee_sats {
        return Err(FeeInjectionError::InsufficientChange {
            change_sats: original_change,
            fee_sats,
        });
    }

    // Reduce change by fee amount
    let new_change = original_change - fee_sats;
    outputs[change_index].0 = new_change;

    // Append fee output
    let fee_output_index = outputs.len();
    outputs.push((fee_sats, fee_locking_script));

    Ok(FeeInjectionResult {
        fee_output_index,
        original_change,
        new_change,
    })
}

/// Split fee equally among multiple addresses.
///
/// Returns a list of (satoshis, locking_script) tuples. The first address
/// receives any remainder from integer division.
pub fn split_fee_outputs(
    fee_sats: u64,
    fee_locking_scripts: &[Vec<u8>],
) -> Result<Vec<(u64, Vec<u8>)>, FeeInjectionError> {
    if fee_locking_scripts.is_empty() {
        return Err(FeeInjectionError::NoFeeAddresses);
    }

    let n = fee_locking_scripts.len() as u64;
    let per_address = fee_sats / n;
    let remainder = fee_sats % n;

    if per_address == 0 {
        return Err(FeeInjectionError::FeeTooSmallToSplit {
            fee_sats,
            address_count: fee_locking_scripts.len(),
        });
    }

    let mut outputs = Vec::with_capacity(fee_locking_scripts.len());
    for (i, script) in fee_locking_scripts.iter().enumerate() {
        let amount = if i == 0 { per_address + remainder } else { per_address };
        outputs.push((amount, script.clone()));
    }

    Ok(outputs)
}

/// Inject split fee outputs into a transaction, reducing change accordingly.
///
/// This is the high-level function that combines `split_fee_outputs` with
/// change adjustment. All fee outputs are appended after the existing outputs.
pub fn inject_split_fee(
    outputs: &mut Vec<(u64, Vec<u8>)>,
    change_index: usize,
    fee_sats: u64,
    fee_locking_scripts: &[Vec<u8>],
) -> Result<Vec<FeeInjectionResult>, FeeInjectionError> {
    if change_index >= outputs.len() {
        return Err(FeeInjectionError::InvalidChangeIndex {
            index: change_index,
            output_count: outputs.len(),
        });
    }

    let original_change = outputs[change_index].0;
    if original_change < fee_sats {
        return Err(FeeInjectionError::InsufficientChange {
            change_sats: original_change,
            fee_sats,
        });
    }

    let fee_outputs = split_fee_outputs(fee_sats, fee_locking_scripts)?;
    let total_fee: u64 = fee_outputs.iter().map(|(s, _)| s).sum();

    // Reduce change
    let new_change = original_change - total_fee;
    outputs[change_index].0 = new_change;

    // Append fee outputs
    let mut results = Vec::new();
    for (amount, script) in fee_outputs {
        let idx = outputs.len();
        outputs.push((amount, script));
        results.push(FeeInjectionResult {
            fee_output_index: idx,
            original_change,
            new_change,
        });
    }

    Ok(results)
}

#[derive(Debug)]
pub enum FeeInjectionError {
    InsufficientChange { change_sats: u64, fee_sats: u64 },
    InvalidChangeIndex { index: usize, output_count: usize },
    NoFeeAddresses,
    FeeTooSmallToSplit { fee_sats: u64, address_count: usize },
}

impl std::fmt::Display for FeeInjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientChange { change_sats, fee_sats } => {
                write!(f, "Insufficient change ({change_sats} sats) to cover fee ({fee_sats} sats)")
            }
            Self::InvalidChangeIndex { index, output_count } => {
                write!(f, "Change index {index} out of bounds (have {output_count} outputs)")
            }
            Self::NoFeeAddresses => write!(f, "No fee addresses provided"),
            Self::FeeTooSmallToSplit { fee_sats, address_count } => {
                write!(f, "Fee {fee_sats} sats too small to split among {address_count} addresses")
            }
        }
    }
}

impl std::error::Error for FeeInjectionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_script(id: u8) -> Vec<u8> {
        vec![0x76, 0xa9, 0x14, id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac]
    }

    #[test]
    fn inject_single_fee_output() {
        let mut outputs = vec![
            (5000u64, dummy_script(1)),  // recipient
            (4900u64, dummy_script(2)),  // change
        ];
        let result = inject_fee_output(&mut outputs, 1, 1000, dummy_script(3)).unwrap();

        assert_eq!(outputs.len(), 3);
        assert_eq!(outputs[0].0, 5000); // recipient unchanged
        assert_eq!(outputs[1].0, 3900); // change reduced by 1000
        assert_eq!(outputs[2].0, 1000); // fee output
        assert_eq!(result.fee_output_index, 2);
        assert_eq!(result.original_change, 4900);
        assert_eq!(result.new_change, 3900);
    }

    #[test]
    fn inject_fee_exact_change() {
        let mut outputs = vec![
            (5000u64, dummy_script(1)),
            (1000u64, dummy_script(2)), // change exactly equals fee
        ];
        let result = inject_fee_output(&mut outputs, 1, 1000, dummy_script(3)).unwrap();

        assert_eq!(outputs[1].0, 0); // change goes to zero — valid edge case
        assert_eq!(result.new_change, 0);
    }

    #[test]
    fn inject_fee_insufficient_change() {
        let mut outputs = vec![
            (5000u64, dummy_script(1)),
            (999u64, dummy_script(2)), // not enough
        ];
        let result = inject_fee_output(&mut outputs, 1, 1000, dummy_script(3));

        assert!(result.is_err());
        match result.unwrap_err() {
            FeeInjectionError::InsufficientChange { change_sats, fee_sats } => {
                assert_eq!(change_sats, 999);
                assert_eq!(fee_sats, 1000);
            }
            _ => panic!("wrong error variant"),
        }
    }

    #[test]
    fn inject_fee_invalid_change_index() {
        let mut outputs = vec![(5000u64, dummy_script(1))];
        let result = inject_fee_output(&mut outputs, 5, 1000, dummy_script(2));

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FeeInjectionError::InvalidChangeIndex { .. }));
    }

    #[test]
    fn split_fee_even() {
        let scripts = vec![dummy_script(1), dummy_script(2)];
        let outputs = split_fee_outputs(1000, &scripts).unwrap();

        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].0, 500);
        assert_eq!(outputs[1].0, 500);
    }

    #[test]
    fn split_fee_with_remainder() {
        let scripts = vec![dummy_script(1), dummy_script(2), dummy_script(3)];
        let outputs = split_fee_outputs(1000, &scripts).unwrap();

        assert_eq!(outputs.len(), 3);
        assert_eq!(outputs[0].0, 334); // 333 + 1 remainder
        assert_eq!(outputs[1].0, 333);
        assert_eq!(outputs[2].0, 333);
        assert_eq!(outputs[0].0 + outputs[1].0 + outputs[2].0, 1000);
    }

    #[test]
    fn split_fee_no_addresses() {
        let result = split_fee_outputs(1000, &[]);
        assert!(matches!(result.unwrap_err(), FeeInjectionError::NoFeeAddresses));
    }

    #[test]
    fn split_fee_too_small() {
        let scripts = vec![dummy_script(1), dummy_script(2), dummy_script(3)];
        let result = split_fee_outputs(2, &scripts);
        assert!(matches!(result.unwrap_err(), FeeInjectionError::FeeTooSmallToSplit { .. }));
    }

    #[test]
    fn inject_split_fee_reduces_change() {
        let mut outputs = vec![
            (5000u64, dummy_script(1)),  // recipient
            (4000u64, dummy_script(2)),  // change
        ];
        let scripts = vec![dummy_script(3), dummy_script(4)];
        let results = inject_split_fee(&mut outputs, 1, 1000, &scripts).unwrap();

        assert_eq!(outputs.len(), 4); // recipient + change + 2 fee outputs
        assert_eq!(outputs[0].0, 5000); // recipient unchanged
        assert_eq!(outputs[1].0, 3000); // change reduced by 1000
        assert_eq!(outputs[2].0, 500);  // fee split
        assert_eq!(outputs[3].0, 500);  // fee split
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn balance_equation_holds() {
        // Verify: total_inputs == total_outputs + mining_fee
        let input_sats: u64 = 10000;
        let mining_fee: u64 = 100;
        let recipient_sats: u64 = 5000;
        let fee_sats: u64 = 1000;
        let change_sats: u64 = input_sats - recipient_sats - mining_fee; // 4900

        let mut outputs = vec![
            (recipient_sats, dummy_script(1)),
            (change_sats, dummy_script(2)),
        ];

        inject_fee_output(&mut outputs, 1, fee_sats, dummy_script(3)).unwrap();

        let total_outputs: u64 = outputs.iter().map(|(s, _)| s).sum();
        assert_eq!(input_sats, total_outputs + mining_fee);
        assert_eq!(total_outputs, 5000 + 3900 + 1000); // 9900
    }
}
