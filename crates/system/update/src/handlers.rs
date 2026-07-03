//! Upgrade migration handler types and registry lookup.
//!
//! The concrete handler list is owned by the node execution layer (`outbe-evm`).

use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::Result;

use crate::state::ScheduledUpdateInfo;
use crate::ProtocolVersion;

/// Static handler table entry type.
pub type UpgradeHandlers = &'static [&'static dyn UpgradeHandler];

/// Migration invoked when a scheduled update reaches its activation height.
pub trait UpgradeHandler: Send + Sync {
    /// The protocol version which should trigger this handler.
    fn version(&self) -> ProtocolVersion;

    /// A human-readable label for the handler.
    fn label(&self) -> &'static str;

    /// The handler logic.
    fn handle(&self, ctx: &BlockRuntimeContext, scheduled: &ScheduledUpdateInfo) -> Result<()>;
}

/// Read-only view over a compile-time handler table.
#[derive(Clone, Copy)]
pub struct UpgradeHandlerRegistry {
    handlers: UpgradeHandlers,
}

impl UpgradeHandlerRegistry {
    /// Builds a registry from a static handler table.
    pub const fn new(handlers: UpgradeHandlers) -> Self {
        Self { handlers }
    }

    /// Returns all handlers registered for `version`.
    pub fn lookup(
        &self,
        version: ProtocolVersion,
    ) -> impl Iterator<Item = &'static dyn UpgradeHandler> {
        self.handlers
            .iter()
            .copied()
            .filter(move |handler| handler.version() == version)
    }
}
