//! Block lifecycle hook for upgrade proposal tally and activation.

use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::Result;

use crate::handlers::UpgradeHandlerRegistry;
use crate::schema::Update;

/// Lifecycle hooks for runtime processing.
pub struct UpdateLifecycle;

impl UpdateLifecycle {
    /// Tally pending proposals and activate approved ones at the current block.
    ///
    /// Unlike other lifecycle modules, Update does not implement
    /// [`BlockLifecycle`](outbe_primitives::block::BlockLifecycle) directly. Callers
    /// must pass the node-level upgrade handler registry explicitly — in production
    /// this is `outbe_evm::upgrade_handlers::registry()`.
    ///
    /// The registry is owned outside `outbe-update` so migration handlers can live
    /// in their owning crates without creating a dependency cycle.
    pub fn begin_block_with_handlers(
        ctx: &BlockRuntimeContext,
        registry: &UpgradeHandlerRegistry,
    ) -> Result<()> {
        let mut update = Update::new(ctx.storage.clone());
        update.process_begin_block_with_handlers(ctx, registry)
    }
}
