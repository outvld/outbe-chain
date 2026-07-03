//! Vote target-module handler for scheduling protocol updates.

use alloy_primitives::{Address, U256};
use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::Result;
use outbe_vote::handlers::VoteTarget;
use serde_json::Value;

use crate::payload::validate_schedule_update_json;
use crate::schema::Update;

/// Vote target handler wired to the Update precompile address.
pub struct UpdateVoteTarget;

impl VoteTarget for UpdateVoteTarget {
    fn target_module(&self) -> Address {
        UPDATE_ADDRESS
    }

    fn validate(&self, payload: &Value, current_height: u64) -> Result<()> {
        validate_schedule_update_json(payload, current_height).map_err(Into::into)
    }

    fn handle_approved(
        &self,
        ctx: &BlockRuntimeContext,
        proposal_id: U256,
        payload: &Value,
    ) -> Result<()> {
        Update::new(ctx.storage.clone()).schedule_update_from_propose(
            proposal_id,
            payload,
            ctx.block.block_number,
        )
    }
}
