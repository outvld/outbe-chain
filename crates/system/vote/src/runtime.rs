use alloy_primitives::{Address, U256};
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;
use outbe_validatorset::contract::ValidatorSet;
use outbe_validatorset::logic::status;

use crate::constants::{
    MAX_PENDING_PROPOSALS, MAX_PENDING_PROPOSALS_PER_VALIDATOR, QUORUM_DENOMINATOR,
    QUORUM_NUMERATOR, VOTING_WINDOW_BLOCKS,
};
use crate::errors::VoteError;
use crate::notify::ProposalFinalization;
use crate::schema::Vote;
use crate::state::{active_validator_addresses, calculate_vote_tally, ProposalStatus, VoteKind};
use crate::targets;

const LOCALNET_CHAIN_ID: u64 = 54_322_345;

fn voting_window_blocks(chain_id: u64) -> u64 {
    if chain_id != LOCALNET_CHAIN_ID {
        return VOTING_WINDOW_BLOCKS;
    }

    std::env::var("OUTBE_TEST_VOTING_WINDOW_BLOCKS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(VOTING_WINDOW_BLOCKS)
}

/// Returns `Ok(())` when `caller` is a registered validator with `status == ACTIVE`.
pub fn ensure_active_validator(storage: StorageHandle<'_>, caller: Address) -> Result<()> {
    let vs = ValidatorSet::new(storage);
    if !matches!(vs.get_validator(caller)?, Some(record) if record.status == status::ACTIVE) {
        return Err(VoteError::NotValidator.into());
    }
    Ok(())
}

/// Returns `Ok(())` when `caller` is a registered validator with `status ∈ {PENDING, ACTIVE}`.
pub fn ensure_voting_validator(storage: StorageHandle<'_>, caller: Address) -> Result<()> {
    let vs = ValidatorSet::new(storage);
    if !matches!(
        vs.get_validator(caller)?,
        Some(record) if record.status == status::ACTIVE || record.status == status::PENDING
    ) {
        return Err(VoteError::NotEligibleValidator.into());
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
        target_module: Address,
        payload: &str,
        current_height: u64,
    ) -> Result<U256> {
        let chain_id = self.storage.chain_id()?;
        ensure_active_validator(self.storage.clone(), proposer)?;

        let pending_len = self.pending_proposal_ids.len()? as u32;
        if pending_len >= MAX_PENDING_PROPOSALS {
            return Err(VoteError::TooManyPending.into());
        }

        let proposer_pending = self.pending_proposal_count_by_proposer(proposer)?;
        if proposer_pending >= MAX_PENDING_PROPOSALS_PER_VALIDATOR {
            return Err(VoteError::TooManyPendingByValidator.into());
        }

        targets::validate_target_payload(target_module, payload, current_height)?;

        let voting_deadline = current_height.saturating_add(voting_window_blocks(chain_id));
        let proposal_id = self.write_proposal(
            proposer,
            target_module,
            payload,
            current_height,
            voting_deadline,
            ProposalStatus::Pending,
        )?;
        self.notify_proposal_created(
            current_height,
            proposal_id,
            proposer,
            target_module,
            payload,
            voting_deadline,
        )?;
        Ok(proposal_id)
    }

    /// ABI entry: `castVote(uint256 proposalId, bool approve)`.
    pub fn cast_vote_approve(
        &mut self,
        proposal_id: U256,
        voter: Address,
        approve: bool,
        block_number: u64,
    ) -> Result<()> {
        ensure_voting_validator(self.storage.clone(), voter)?;

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
        )?;
        self.notify_vote_cast(block_number, proposal_id, voter, approve)?;
        Ok(())
    }

    /// Tally proposals whose voting windows have closed.
    ///
    /// Transitions `Pending` -> `Approved` | `Rejected` | `Expired`. Dispatches the
    /// terminal outcome to the registered target-module handler in the same pass.
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
        let block_number = ctx.block.block_number;

        let status = if quorum_reached(tally.yes, active_count) {
            ProposalStatus::Approved
        } else {
            ProposalStatus::Expired
        };

        let outcome = match targets::handle_target_tally(ctx, proposal_id, &proposal, status) {
            Ok(()) => {
                self.set_proposal_status(proposal_id, status)?;
                match status {
                    ProposalStatus::Approved => ProposalFinalization::Approved,
                    ProposalStatus::Expired => ProposalFinalization::Expired,
                    ProposalStatus::Pending | ProposalStatus::Rejected => unreachable!(),
                }
            }
            Err(e) if status == ProposalStatus::Approved => {
                self.set_proposal_status(proposal_id, ProposalStatus::Rejected)?;
                ProposalFinalization::Rejected {
                    reason: e.to_string(),
                }
            }
            Err(err) => return Err(err),
        };

        self.notify_proposal_finalized(block_number, &proposal, &tally, active_count, outcome)
    }
}
