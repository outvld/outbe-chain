//! Block lifecycle hook for upgrade proposal tally and activation.

use outbe_primitives::block::{BlockLifecycle, BlockRuntimeContext};
use outbe_primitives::error::Result;

use crate::schema::Update;

/// Zero-sized marker implementing the block-lifecycle contract for the Update module.
pub struct UpdateLifecycle;

impl BlockLifecycle for UpdateLifecycle {
    fn begin_block(ctx: &BlockRuntimeContext) -> Result<()> {
        let block_number = ctx.block.block_number;
        let mut update = Update::new(ctx.storage.clone());
        update.process_begin_block(block_number)
    }
}
