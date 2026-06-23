use alloy_primitives::{Address, B256, U256};
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;
use outbe_validatorset::contract::ValidatorSet;
use outbe_validatorset::logic::status;

use crate::constants::{
    MAX_PENDING_PROPOSALS, QUORUM_DENOMINATOR, QUORUM_NUMERATOR, VOTING_WINDOW_BLOCKS,
};
use crate::errors::GovernanceError;
use crate::schema::Governance;
use crate::state::{ProposalStatus, VoteKind};

/// Returns `Ok(())` when `caller` is a registered validator with `status == ACTIVE`.
pub fn ensure_active_validator(storage: StorageHandle<'_>, caller: Address) -> Result<()> {
    let vs = ValidatorSet::new(storage);
    if !matches!(vs.get_validator(caller)?, Some(record) if record.status == status::ACTIVE) {
        return Err(GovernanceError::NotValidator.into());
    }
    Ok(())
}

/// Returns `true` when `yes_votes` reaches the configured 2/3 quorum.
pub const fn quorum_reached(yes_votes: u64, active_validator_count: u32) -> bool {
    if active_validator_count == 0 {
        return false;
    }
    let yes = yes_votes as u128;
    let active = active_validator_count as u128;
    yes * QUORUM_DENOMINATOR as u128 >= active * QUORUM_NUMERATOR as u128
}

impl Governance<'_> {
    /// Creates a pending generic governance proposal.
    pub fn create_proposal(
        &mut self,
        proposer: Address,
        target_module: B256,
        action: B256,
        payload: &[u8],
        current_height: u64,
    ) -> Result<U256> {
        ensure_active_validator(self.storage.clone(), proposer)?;

        let pending_len = self.pending_proposal_ids.len()? as u32;
        if pending_len >= MAX_PENDING_PROPOSALS {
            return Err(GovernanceError::TooManyPending.into());
        }

        let voting_deadline = current_height.saturating_add(VOTING_WINDOW_BLOCKS);
        self.write_proposal(
            proposer,
            target_module,
            action,
            payload,
            current_height,
            voting_deadline,
            ProposalStatus::Pending,
        )
    }

    /// ABI entry: `castVote(uint256 proposalId, bool approve)`.
    pub fn cast_vote_approve(
        &mut self,
        proposal_id: U256,
        voter: Address,
        approve: bool,
        block_number: u64,
    ) -> Result<()> {
        ensure_active_validator(self.storage.clone(), voter)?;

        let proposal = self
            .read_proposal(proposal_id)?
            .ok_or(GovernanceError::ProposalNotFound)?;
        if proposal.status != ProposalStatus::Pending {
            return Err(GovernanceError::NotPending.into());
        }
        if block_number > proposal.voting_deadline_height {
            return Err(GovernanceError::VotingClosed.into());
        }
        if self.read_vote(proposal_id, voter)?.is_some() {
            return Err(GovernanceError::AlreadyVoted.into());
        }

        self.write_vote(
            proposal_id,
            voter,
            VoteKind::from_approve(approve),
            block_number,
        )
    }

    /// Tally proposals whose voting windows have closed.
    ///
    /// Transitions `Pending` -> `Approved` | `Rejected` | `Expired`. On `Approved`,
    /// the registered target-module handler is invoked in the same pass (not wired yet).
    pub fn process_begin_block(&mut self, ctx: &BlockRuntimeContext) -> Result<()> {
        let block_number = ctx.block.block_number;
        let pending_ids = self.list_pending_proposal_ids()?;
        for proposal_id in pending_ids {
            let Some(proposal) = self.read_proposal(proposal_id)? else {
                return Err(GovernanceError::ProposalNotFound.into());
            };
            if proposal.status == ProposalStatus::Pending
                && block_number > proposal.voting_deadline_height
            {
                self.finalize_voting(proposal_id)?;
            }
        }
        Ok(())
    }

    fn finalize_voting(&mut self, proposal_id: U256) -> Result<()> {
        let proposal = self
            .read_proposal(proposal_id)?
            .ok_or(GovernanceError::ProposalNotFound)?;
        if proposal.status != ProposalStatus::Pending {
            return Ok(());
        }

        let vs = ValidatorSet::new(self.storage.clone());
        let active_count = vs.active_validator_count()?;
        if quorum_reached(proposal.yes_votes, active_count) {
            self.set_proposal_status(proposal_id, ProposalStatus::Approved)
        } else {
            self.set_proposal_status(proposal_id, ProposalStatus::Expired)
        }
    }
}
