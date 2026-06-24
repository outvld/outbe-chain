//! Compile-time registry of governance target-module handlers.

use alloy_primitives::{B256, U256};
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::Result;
use outbe_update::schema::Update;

use crate::errors::GovernanceError;
use crate::schema::ProposalRecord;

/// Target module id for protocol update scheduling (`keccak256("outbe.module.update")`).
pub const UPDATE_TARGET_MODULE: B256 =
    alloy_primitives::b256!("408215974421bccd1eba2bf03d2cac57c948ef02be50d99e89e7ff15ea7775c2");

/// Action id for scheduling a protocol update (`keccak256("outbe.action.schedule_update")`).
pub const SCHEDULE_UPDATE_ACTION: B256 =
    alloy_primitives::b256!("fcd8b0a2d4d2249dc5834ceb5c5badf181b783e542f4fe68eacdfeb427b145d2");

/// TODO: change type of target module -> address?
/// TODO: move dispatch to blockchain/evm near precompile declaration (like update crate?)

/// Dispatches an approved proposal to its registered target-module handler.
pub fn dispatch_approved_proposal(
    ctx: &BlockRuntimeContext,
    proposal_id: U256,
    proposal: &ProposalRecord,
) -> Result<()> {
    if proposal.target_module != UPDATE_TARGET_MODULE {
        return Err(GovernanceError::UnknownTargetModule.into());
    }
    if proposal.action != SCHEDULE_UPDATE_ACTION {
        return Err(GovernanceError::UnknownAction.into());
    }

    Update::new(ctx.storage.clone()).schedule_update_from_governance(
        proposal_id,
        &proposal.payload,
        ctx.block.block_number,
    )
}
