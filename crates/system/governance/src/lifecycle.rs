//! Block lifecycle hook for governance proposal tally.

use outbe_primitives::block::{BlockLifecycle, BlockRuntimeContext};
use outbe_primitives::error::Result;

use crate::schema::Governance;

/// Lifecycle hooks for governance runtime processing.
pub struct GovernanceLifecycle;

impl BlockLifecycle for GovernanceLifecycle {
    fn begin_block(ctx: &BlockRuntimeContext) -> Result<()> {
        let mut governance = Governance::new(ctx.storage.clone());
        governance.process_begin_block(ctx)
    }
}
