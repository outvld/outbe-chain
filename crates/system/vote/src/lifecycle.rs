//! Block lifecycle hook for proposal tally.

use outbe_primitives::block::{BlockLifecycle, BlockRuntimeContext};
use outbe_primitives::error::Result;

use crate::schema::Vote;

/// Lifecycle hooks for vote runtime processing.
pub struct VoteLifecycle;

impl BlockLifecycle for VoteLifecycle {
    fn begin_block(ctx: &BlockRuntimeContext) -> Result<()> {
        let mut governance = Vote::new(ctx.storage.clone());
        governance.process_begin_block(ctx)
    }
}
