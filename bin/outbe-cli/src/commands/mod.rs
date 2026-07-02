pub mod chain;
pub mod epoch;
pub mod monitor;
pub mod oracle;
pub mod rewards;
pub mod slash;
pub mod staking;
pub mod tee;
pub mod tribute;
pub mod vote;
pub mod validator;
pub mod zerofee;

use crate::tx::TxSigner;
use eyre::Result;

pub fn require_signer(private_key: Option<&str>) -> Result<TxSigner> {
    let key =
        private_key.ok_or_else(|| eyre::eyre!("--private-key required for this operation"))?;
    TxSigner::new(key)
}

/// Format a U256 value in base units as a human-readable COEN amount (18 decimals).
pub fn format_unit(value: alloy_primitives::U256) -> String {
    use alloy_primitives::U256;

    if value.is_zero() {
        return "0".to_string();
    }

    let divisor = U256::from(10u64).pow(U256::from(18));
    let whole = value / divisor;
    let frac = value % divisor;

    if frac.is_zero() {
        format!("{whole}")
    } else {
        // Pad fractional part to 18 digits, then trim trailing zeros
        let frac_str = format!("{frac:0>18}");
        let trimmed = frac_str.trim_end_matches('0');
        format!("{whole}.{trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    #[test]
    fn test_format_unit_zero() {
        assert_eq!(format_unit(U256::ZERO), "0");
    }

    #[test]
    fn test_format_unit_one_coen() {
        let one = U256::from(10u64).pow(U256::from(18));
        assert_eq!(format_unit(one), "1");
    }

    #[test]
    fn test_format_unit_large_whole() {
        let val = U256::from(1000u64) * U256::from(10u64).pow(U256::from(18));
        assert_eq!(format_unit(val), "1000");
    }

    #[test]
    fn test_format_unit_fractional() {
        let val = U256::from(1_500_000_000_000_000_000u128);
        assert_eq!(format_unit(val), "1.5");
    }

    #[test]
    fn test_format_unit_pure_fraction() {
        let val = U256::from(500_000_000_000_000_000u128);
        assert_eq!(format_unit(val), "0.5");
    }

    #[test]
    fn test_format_unit_one_wei() {
        assert_eq!(format_unit(U256::from(1u64)), "0.000000000000000001");
    }

    #[test]
    fn test_format_unit_trailing_zeros_trimmed() {
        let val = U256::from(1_200_000_000_000_000_000u128);
        assert_eq!(format_unit(val), "1.2");
    }

    #[test]
    fn test_format_unit_all_decimal_places() {
        let val = U256::from(999_999_999_999_999_999u128);
        assert_eq!(format_unit(val), "0.999999999999999999");
    }

    #[test]
    fn test_format_unit_max_u256_does_not_panic() {
        let result = format_unit(U256::MAX);
        assert!(!result.is_empty());
        assert!(result.contains('.'));
    }
}
