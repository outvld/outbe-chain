use alloy_primitives::{Address, B256, U256};
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;
use outbe_validatorset::contract::ValidatorSet;
use outbe_validatorset::logic::status;

use crate::constants::{
    MAX_PENDING_PROPOSALS, QUORUM_DENOMINATOR, QUORUM_NUMERATOR, VOTING_WINDOW_BLOCKS,
};
use crate::errors::VoteError;
use crate::precompile::IVote;
use crate::schema::Vote;
use crate::state::{active_validator_addresses, calculate_vote_tally, ProposalStatus, VoteKind};
use crate::targets;

/// Returns `Ok(())` when `caller` is a registered validator with `status == ACTIVE`.
pub fn ensure_active_validator(storage: StorageHandle<'_>, caller: Address) -> Result<()> {
    let vs = ValidatorSet::new(storage);
    if !matches!(vs.get_validator(caller)?, Some(record) if record.status == status::ACTIVE) {
        return Err(VoteError::NotValidator.into());
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

impl Vote<'_> {
    /// Creates a pending generic proposal.
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
            return Err(VoteError::TooManyPending.into());
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
            .proposals
            .get(proposal_id)?
            .ok_or(VoteError::ProposalNotFound)?;
        if proposal.proposal_status()? != ProposalStatus::Pending {
            return Err(VoteError::NotPending.into());
        }
        if block_number > proposal.voting_deadline_height {
            return Err(VoteError::VotingClosed.into());
        }
        if self.read_vote(proposal_id, voter)?.is_some() {
            return Err(VoteError::AlreadyVoted.into());
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
            let Some(proposal) = self.proposals.get(proposal_id)? else {
                return Err(VoteError::ProposalNotFound.into());
            };
            if proposal.proposal_status()? == ProposalStatus::Pending
                && block_number > proposal.voting_deadline_height
            {
                self.finalize_voting(ctx, proposal_id)?;
            }
        }
        Ok(())
    }

    fn finalize_voting(&mut self, ctx: &BlockRuntimeContext, proposal_id: U256) -> Result<()> {
        let proposal = self
            .proposals
            .get(proposal_id)?
            .ok_or(VoteError::ProposalNotFound)?;
        if proposal.proposal_status()? != ProposalStatus::Pending {
            return Ok(());
        }

        let active = active_validator_addresses(self.storage.clone())?;
        let tally = calculate_vote_tally(self, &proposal, &active)?;
        let vs = ValidatorSet::new(self.storage.clone());
        let active_count = vs.active_validator_count()?;
        let vote_tally = IVote::VoteTally {
            yes: tally.yes,
            no: tally.no,
        };

        if quorum_reached(tally.yes, active_count) {
            match targets::dispatch_approved_proposal(ctx, proposal_id, &proposal) {
                Ok(()) => {
                    self.set_proposal_status(proposal_id, ProposalStatus::Approved)?;
                    self.emit(IVote::ProposalApproved {
                        proposalId: proposal_id,
                        state: vote_tally,
                    })?;
                }
                Err(PrecompileError::Revert(_)) => {
                    self.set_proposal_status(proposal_id, ProposalStatus::Rejected)?;
                    self.emit(IVote::ProposalRejected {
                        proposalId: proposal_id,
                        state: vote_tally,
                        conflictingproposalId: U256::ZERO,
                    })?;
                }
                Err(err) => return Err(err),
            }
        } else {
            self.set_proposal_status(proposal_id, ProposalStatus::Expired)?;
            self.emit(IVote::ProposalExpired {
                proposalId: proposal_id,
                state: vote_tally,
            })?;
        }
        Ok(())
    }
}
