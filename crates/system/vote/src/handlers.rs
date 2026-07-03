//! Compile-time registry of vote target-module handlers.

use alloy_primitives::{Address, U256};
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::Result;
use serde_json::Value;

use crate::errors::VoteError;
use crate::schema::{ProposalRecord, ProposalStatus};

/// Static handler table entry type.
pub type VoteTargetHandlers = &'static [&'static dyn VoteTarget];

/// Target-module handler for approved vote proposals.
pub trait VoteTarget: Send + Sync {
    /// Precompile address this handler serves.
    fn target_module(&self) -> Address;

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

/// Read-only view over a compile-time handler table.
#[derive(Clone, Copy)]
pub struct VoteTargetRegistry {
    handlers: VoteTargetHandlers,
}

impl VoteTargetRegistry {
    /// Builds a registry from a static handler table.
    pub const fn new(handlers: VoteTargetHandlers) -> Self {
        Self { handlers }
    }

    /// Returns the handler registered for `target_module`, if any.
    ///
    /// Returns an error when more than one handler is registered for the same address.
    pub fn lookup(&self, target_module: Address) -> Result<&'static dyn VoteTarget> {
        let mut matches = self
            .handlers
            .iter()
            .filter(|handler| handler.target_module() == target_module);
        let Some(first) = matches.next() else {
            return Err(VoteError::UnknownTargetModule.into());
        };
        if matches.next().is_some() {
            return Err(VoteError::DuplicateTargetModule.into());
        }
        Ok(*first)
    }
}

fn parse_payload_json(payload: &str) -> Result<Value> {
    serde_json::from_str(payload).map_err(|_| VoteError::InvalidPayload.into())
}

/// Validates a target payload during proposal creation.
pub fn validate_target_payload(
    registry: &VoteTargetRegistry,
    target_module: Address,
    payload: &str,
    current_height: u64,
) -> Result<()> {
    let target = registry.lookup(target_module)?;
    let json = parse_payload_json(payload)?;
    target.validate(&json, current_height)
}

/// Dispatches a terminal proposal outcome to its target module.
pub fn handle_target_tally(
    registry: &VoteTargetRegistry,
    ctx: &BlockRuntimeContext,
    proposal_id: U256,
    proposal: &ProposalRecord,
    status: ProposalStatus,
) -> Result<()> {
    let target = registry.lookup(proposal.target_module)?;
    let json = parse_payload_json(proposal.payload.as_str())?;
    target.handle_tally(ctx, proposal_id, &json, status)
}
