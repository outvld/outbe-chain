//! Upgrade migration handler types and registry lookup.
//!
//! The concrete handler list is owned by the node execution layer (`outbe-evm`).

use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::Result;

use crate::state::ProposalInfo;
use crate::ProtocolVersion;

/// Migration invoked when an approved proposal reaches its activation height.
pub type UpgradeHandler = fn(&BlockRuntimeContext, &ProposalInfo) -> Result<()>;

/// Static registration entry for one protocol version migration.
#[derive(Clone, Copy)]
pub struct UpgradeHandlerSpec {
    /// If version is `None`, the handler is invoked for all versions.
    pub version: Option<ProtocolVersion>,
    pub label: &'static str,
    pub handler: UpgradeHandler,
}

/// Read-only view over a compile-time handler table.
#[derive(Clone, Copy)]
pub struct UpgradeHandlerRegistry {
    handlers: &'static [UpgradeHandlerSpec],
}

impl UpgradeHandlerRegistry {
    /// Builds a registry from a static handler slice.
    pub const fn new(handlers: &'static [UpgradeHandlerSpec]) -> Self {
        Self { handlers }
    }

    /// Returns the handler registered for `version`, if any.
    pub fn lookup(&self, version: ProtocolVersion) -> Option<&UpgradeHandlerSpec> {
        self.handlers
            .iter()
            .find(|spec| spec.version.map_or(true, |v| v == version))
    }
}

/// Default empty registry for tests and no-migration activation paths.
pub const EMPTY_UPGRADE_HANDLER_REGISTRY: UpgradeHandlerRegistry = UpgradeHandlerRegistry::new(&[]);
