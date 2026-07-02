//! Compile-time registry of vote target-module handlers.

use alloy_primitives::{Address, U256};
use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::Result;
use outbe_update::payload::validate_schedule_update_json;
use outbe_update::schema::Update;
use serde_json::Value;

use crate::errors::VoteError;
use crate::schema::{ProposalRecord, ProposalStatus};

/// Registered update precompile address used as vote target module.
pub use outbe_primitives::addresses::UPDATE_ADDRESS as UPDATE_TARGET;

/// Target-module handler for approved vote proposals.
pub trait VoteTarget {
    /// Fail-fast validation used during proposal creation.
    fn validate(&self, payload: &Value, current_height: u64) -> Result<()>;

    /// Applies side effects when a proposal is approved.
    fn handle_approved(
        &self,
        ctx: &BlockRuntimeContext,
        proposal_id: U256,
        payload: &Value,
    ) -> Result<()>;

    /// Dispatches terminal proposal outcomes to the target module.
    /// Only result of tally is possible (Expired or Approved).
    fn handle_tally(
        &self,
        ctx: &BlockRuntimeContext,
        proposal_id: U256,
        payload: &Value,
        status: ProposalStatus,
    ) -> Result<()> {
        match status {
            ProposalStatus::Approved => self.handle_approved(ctx, proposal_id, payload),
            ProposalStatus::Rejected | ProposalStatus::Expired | ProposalStatus::Pending => Ok(()),
        }
    }
}

struct UpdateVoteTarget;

impl VoteTarget for UpdateVoteTarget {
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

fn lookup_target(target_module: Address) -> Result<&'static dyn VoteTarget> {
    if target_module == UPDATE_ADDRESS {
        Ok(&UpdateVoteTarget)
    } else {
        Err(VoteError::UnknownTargetModule.into())
    }
}

fn parse_payload_json(payload: &str) -> Result<Value> {
    serde_json::from_str(payload).map_err(|_| VoteError::InvalidPayload.into())
}

/// Validates a target payload during proposal creation.
pub fn validate_target_payload(
    target_module: Address,
    payload: &str,
    current_height: u64,
) -> Result<()> {
    let target = lookup_target(target_module)?;
    let json = parse_payload_json(payload)?;
    target.validate(&json, current_height)
}

/// Dispatches a terminal proposal outcome to its target module.
pub fn handle_target_tally(
    ctx: &BlockRuntimeContext,
    proposal_id: U256,
    proposal: &ProposalRecord,
    status: ProposalStatus,
) -> Result<()> {
    let target = lookup_target(proposal.target_module)?;
    let json = parse_payload_json(proposal.payload.as_str())?;
    target.handle_tally(ctx, proposal_id, &json, status)
}
