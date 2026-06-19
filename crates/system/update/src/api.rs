use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::schema::Update;
use crate::ProtocolVersion;

/// Returns the currently active protocol version, if any.
pub fn get_active_version(storage: StorageHandle) -> Result<Option<ProtocolVersion>> {
    Update::new(storage).get_active_version()
}

/// Returns the version recorded at `height`, if any.
pub fn version_at_height(storage: StorageHandle, height: u64) -> Result<Option<ProtocolVersion>> {
    Update::new(storage).version_at_height(height)
}

/// Returns `true` when `version` matches the active on-chain version.
pub fn is_version_active_eq(storage: StorageHandle, version: ProtocolVersion) -> Result<bool> {
    let update = Update::new(storage);
    let Some(active) = update.get_active_version()? else {
        return Ok(false);
    };
    Ok(active == version)
}

/// Returns `true` when the active on-chain version is >= `version`.
pub fn is_version_active_gte(storage: StorageHandle, version: ProtocolVersion) -> Result<bool> {
    let update = Update::new(storage);
    let Some(active) = update.get_active_version()? else {
        return Ok(false);
    };
    Ok(active >= version)
}
