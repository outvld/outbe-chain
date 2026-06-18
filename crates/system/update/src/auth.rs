use alloy_primitives::Address;

use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;
use outbe_validatorset::contract::ValidatorSet;
use outbe_validatorset::logic::status;

use crate::errors::UpdateError;

/// Returns `Ok(())` when `caller` is a registered validator with `status == ACTIVE`.
pub fn ensure_active_validator(storage: StorageHandle, caller: Address) -> Result<()> {
    let vs = ValidatorSet::new(storage);
    if !matches!(vs.get_validator(caller)?, Some(record) if record.status == status::ACTIVE) {
        return Err(UpdateError::NotValidator.into());
    }
    Ok(())
}
