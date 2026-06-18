use alloy_primitives::{Address, U256};

use outbe_primitives::error::Result;

use crate::constants::{MAX_PENDING_PLANS, MIN_ACTIVATION_BUFFER, VOTING_WINDOW_BLOCKS};
use crate::ProtocolVersion;
use crate::errors::UpdateError;
use crate::schema::Update;
use crate::state::{version_gt, ProposalStatus, VoteKind};

impl Update<'_> {
    /// Creates a pending upgrade proposal after deterministic validation.
    ///
    /// Active-validator authorization is deferred until callable dispatch is wired.
    pub fn create_proposal(
        &mut self,
        proposer: Address,
        version: ProtocolVersion,
        activation_height: u64,
        info: &[u8],
        current_height: u64,
    ) -> Result<U256> {
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

        self.write_vote(proposal_id, voter, VoteKind::from_approve(approve), block_number)
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
}
