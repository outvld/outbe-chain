//! Block lifecycle hook for proposal tally.

use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::Result;

use crate::handlers::VoteTargetRegistry;
use crate::schema::Vote;

/// Lifecycle hooks for vote runtime processing.
pub struct VoteLifecycle;

impl VoteLifecycle {
    /// Tally expired proposals and dispatch approved ones at the current block.
    ///
    /// The registry is owned outside `outbe-vote` so target handlers can live
    /// in their owning crates without creating a dependency cycle — in production
    /// this is `outbe_evm::handlers::vote::registry()`.
    pub fn begin_block_with_handlers(
        ctx: &BlockRuntimeContext,
        registry: &VoteTargetRegistry,
    ) -> Result<()> {
        let mut governance = Vote::new(ctx.storage.clone());
        governance.process_begin_block(ctx, registry)
    }
}
