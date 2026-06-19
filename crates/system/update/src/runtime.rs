use alloy_primitives::{Address, U256};

use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;
use outbe_validatorset::contract::ValidatorSet;
use outbe_validatorset::logic::status;

use crate::constants::{
    MAX_PENDING_PLANS, MIN_ACTIVATION_BUFFER, QUORUM_DENOMINATOR, QUORUM_NUMERATOR,
    VOTING_WINDOW_BLOCKS,
};
use crate::errors::UpdateError;
use crate::handlers::UpgradeHandlerRegistry;
use crate::precompile::IUpdate;
use crate::schema::Update;
use crate::state::{version_gt, ProposalStatus, VoteKind, VoteTally};
use crate::ProtocolVersion;

/// Returns `Ok(())` when `caller` is a registered validator with `status == ACTIVE`.
pub fn ensure_active_validator(storage: StorageHandle, caller: Address) -> Result<()> {
    let vs = ValidatorSet::new(storage);
    if !matches!(vs.get_validator(caller)?, Some(record) if record.status == status::ACTIVE) {
        return Err(UpdateError::NotValidator.into());
    }
    Ok(())
}

fn vote_tally_result(proposal: &crate::state::ProposalInfo) -> IUpdate::VoteTally {
    let tally = VoteTally::from(proposal);
    IUpdate::VoteTally {
        yes: tally.yes,
        no: tally.no,
    }
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

impl Update<'_> {
    /// Creates a pending upgrade proposal after deterministic validation.
    pub fn create_proposal(
        &mut self,
        proposer: Address,
        version: ProtocolVersion,
        activation_height: u64,
        info: &[u8],
        current_height: u64,
    ) -> Result<U256> {
        ensure_active_validator(self.storage.clone(), proposer)?;

        let min_activation = current_height
            .saturating_add(VOTING_WINDOW_BLOCKS)
            .saturating_add(MIN_ACTIVATION_BUFFER);
        if activation_height < min_activation {
            return Err(UpdateError::HeightInPast.into());
        }

        if let Some(active) = self.get_active_version()? {
            if !version_gt(version, active) {
                return Err(UpdateError::DowngradeNotAllowed.into());
            }
        }

        let pending_len = self.pending_proposal_ids.len()? as u32;
        if pending_len >= MAX_PENDING_PLANS {
            return Err(UpdateError::TooManyPending.into());
        }

        let voting_deadline = current_height.saturating_add(VOTING_WINDOW_BLOCKS);
        self.write_proposal(
            version,
            activation_height,
            voting_deadline,
            info,
            proposer,
            current_height,
            ProposalStatus::Pending,
        )
    }

    /// Records a vote on a pending proposal (`VoteKind` storage representation).
    pub fn cast_vote(
        &mut self,
        proposal_id: U256,
        voter: Address,
        kind: VoteKind,
        block_number: u64,
    ) -> Result<()> {
        self.cast_vote_approve(proposal_id, voter, kind.to_approve(), block_number)
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
            .ok_or(UpdateError::ProposalNotFound)?;

        if proposal.status != ProposalStatus::Pending {
            return Err(UpdateError::NotPending.into());
        }
        if block_number > proposal.voting_deadline_height {
            return Err(UpdateError::VotingClosed.into());
        }
        if self.read_vote(proposal_id, voter)?.is_some() {
            return Err(UpdateError::AlreadyVoted.into());
        }

        self.write_vote(
            proposal_id,
            voter,
            VoteKind::from_approve(approve),
            block_number,
        )
    }

    /// Cancels a pending proposal. Only the proposer may cancel before deadline.
    pub fn cancel_proposal(
        &mut self,
        proposal_id: U256,
        caller: Address,
        block_number: u64,
    ) -> Result<()> {
        let proposal = self
            .read_proposal(proposal_id)?
            .ok_or(UpdateError::ProposalNotFound)?;

        if proposal.status != ProposalStatus::Pending {
            return Err(UpdateError::NotPending.into());
        }
        if caller != proposal.proposer {
            return Err(UpdateError::NotProposer.into());
        }
        if block_number > proposal.voting_deadline_height {
            return Err(UpdateError::VotingClosed.into());
        }

        self.set_proposal_status(proposal_id, ProposalStatus::Cancelled)
    }

    /// Tally pending proposals and activate approved ones using `registry`.
    pub fn process_begin_block_with_handlers(
        &mut self,
        ctx: &BlockRuntimeContext,
        registry: &UpgradeHandlerRegistry,
    ) -> Result<()> {
        let block_number = ctx.block.block_number;
        let pending_ids = self.list_pending_proposal_ids()?;
        for proposal_id in pending_ids {
            let Some(proposal) = self.read_proposal(proposal_id)? else {
                return Err(UpdateError::ProposalNotFound.into());
            };
            if proposal.status == ProposalStatus::Pending
                && block_number > proposal.voting_deadline_height
            {
                self.finalize_voting(proposal_id)?;
            }
        }

        let waiting_ids = self.list_waiting_for_activation_proposal_ids()?;
        for proposal_id in waiting_ids {
            let Some(proposal) = self.read_proposal(proposal_id)? else {
                return Err(UpdateError::ProposalNotFound.into());
            };
            if proposal.status == ProposalStatus::Approved
                && block_number >= proposal.activation_height
            {
                self.activate_proposal(ctx, registry, proposal_id)?;
            }
        }
        Ok(())
    }

    fn finalize_voting(&mut self, proposal_id: U256) -> Result<()> {
        let proposal = self
            .read_proposal(proposal_id)?
            .ok_or(UpdateError::ProposalNotFound)?;
        if proposal.status != ProposalStatus::Pending {
            return Ok(());
        }

        let vs = ValidatorSet::new(self.storage.clone());
        let active_count = vs.active_validator_count()?;
        let state = vote_tally_result(&proposal);
        if quorum_reached(proposal.yes_votes, active_count) {
            if let Some(conflicting_proposal_id) =
                self.approved_activation_conflict(proposal_id, proposal.activation_height)?
            {
                self.set_proposal_status(proposal_id, ProposalStatus::Rejected)?;
                self.emit(IUpdate::ProposalRejected {
                    proposalId: proposal_id,
                    state,
                    conflictingproposalId: conflicting_proposal_id,
                })
            } else {
                let activation_height = proposal.activation_height;
                let version = proposal.version;
                self.set_proposal_status(proposal_id, ProposalStatus::Approved)?;
                self.emit(IUpdate::ProposalApproved {
                    proposalId: proposal_id,
                    state,
                    activationHeight: activation_height,
                    version,
                })
            }
        } else {
            self.set_proposal_status(proposal_id, ProposalStatus::Expired)?;
            self.emit(IUpdate::ProposalExpired {
                proposalId: proposal_id,
                state,
            })
        }
    }

    fn activate_proposal(
        &mut self,
        ctx: &BlockRuntimeContext,
        registry: &UpgradeHandlerRegistry,
        proposal_id: U256,
    ) -> Result<()> {
        let proposal = self
            .read_proposal(proposal_id)?
            .ok_or(UpdateError::ProposalNotFound)?;
        if proposal.status != ProposalStatus::Approved {
            return Ok(());
        }

        ctx.with_checkpoint(|| {
            if let Some(spec) = registry.lookup(proposal.version) {
                (spec.handler)(ctx, &proposal).map_err(|err| match err {
                    PrecompileError::Fatal(message) => PrecompileError::Fatal(message),
                    other => PrecompileError::Fatal(format!(
                        "upgrade handler '{}' failed: {other}",
                        spec.label
                    )),
                })?;
            }

            self.set_active_version(proposal.version, proposal.activation_height)?;
            self.set_proposal_status(proposal_id, ProposalStatus::Activated)?;
            self.emit(IUpdate::UpgradeActivated {
                version: proposal.version,
                activationHeight: proposal.activation_height,
            })
        })
    }

    fn approved_activation_conflict(
        &self,
        proposal_id: U256,
        activation_height: u64,
    ) -> Result<Option<U256>> {
        for tracked_id in self.list_waiting_for_activation_proposal_ids()? {
            if tracked_id == proposal_id {
                continue;
            }
            let Some(other) = self.read_proposal(tracked_id)? else {
                continue;
            };
            if other.activation_height == activation_height {
                return Ok(Some(tracked_id));
            }
        }
        Ok(None)
    }
}
