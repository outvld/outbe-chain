//! Combined on-chain event emission and governance-journal recording.

use alloy_primitives::{keccak256, Address, U256};
use outbe_primitives::error::Result;
use outbe_primitives::governance_journal::{
    record as journal_record, JournalRecord, ProposalRef, VoteTallyRef,
};

use crate::precompile::IVote;
use crate::schema::{ProposalRecord, Vote};
use crate::state::VoteTally;

/// Terminal outcome of a proposal after voting closes.
pub(crate) enum ProposalFinalization {
    Approved,
    Rejected { reason: String },
    Expired,
}

fn proposal_ref(proposal_id: U256, proposer: Address, target_module: Address) -> ProposalRef {
    ProposalRef {
        proposal_id: format!("{proposal_id}"),
        proposer: format!("{proposer:?}"),
        target_module: format!("{target_module:?}"),
    }
}

fn proposal_ref_from_record(proposal: &ProposalRecord) -> ProposalRef {
    proposal_ref(proposal.id, proposal.proposer, proposal.target_module)
}

fn tally_ref(tally: &VoteTally, active_validator_count: u32) -> VoteTallyRef {
    VoteTallyRef {
        yes_votes: tally.yes,
        no_votes: tally.no,
        active_validator_count,
    }
}

fn abi_vote_tally(tally: &VoteTally) -> IVote::VoteTally {
    IVote::VoteTally {
        yes: tally.yes,
        no: tally.no,
    }
}

impl Vote<'_> {
    /// Emits `ProposalCreated` and appends the matching journal record.
    pub(crate) fn notify_proposal_created(
        &mut self,
        block_number: u64,
        proposal_id: U256,
        proposer: Address,
        target_module: Address,
        payload: &str,
        voting_deadline_height: u64,
    ) -> Result<()> {
        self.emit(IVote::ProposalCreated {
            proposalId: proposal_id,
            proposer,
            targetModule: target_module,
            payload: payload.to_string(),
            votingDeadlineHeight: voting_deadline_height,
        })?;
        journal_record(JournalRecord::proposal_created(
            block_number,
            proposal_ref(proposal_id, proposer, target_module),
            voting_deadline_height,
            payload.len(),
            format!("{:?}", keccak256(payload.as_bytes())),
        ));
        Ok(())
    }

    /// Emits `VoteCast` and appends the matching journal record.
    pub(crate) fn notify_vote_cast(
        &mut self,
        block_number: u64,
        proposal_id: U256,
        voter: Address,
        approve: bool,
    ) -> Result<()> {
        self.emit(IVote::VoteCast {
            proposalId: proposal_id,
            validator: voter,
            approve,
        })?;
        journal_record(JournalRecord::vote_cast(
            block_number,
            format!("{proposal_id}"),
            format!("{voter:?}"),
            approve,
        ));
        Ok(())
    }

    /// Emits a terminal proposal event and appends the matching journal record.
    pub(crate) fn notify_proposal_finalized(
        &mut self,
        block_number: u64,
        proposal: &ProposalRecord,
        tally: &VoteTally,
        active_validator_count: u32,
        outcome: ProposalFinalization,
    ) -> Result<()> {
        let proposal_id = proposal.id;
        let proposal_ref = proposal_ref_from_record(proposal);
        let tally_ref = tally_ref(tally, active_validator_count);
        let vote_tally = abi_vote_tally(tally);

        match outcome {
            ProposalFinalization::Approved => {
                self.emit(IVote::ProposalApproved {
                    proposalId: proposal_id,
                    state: vote_tally,
                })?;
                journal_record(JournalRecord::proposal_approved(
                    block_number,
                    proposal_ref,
                    tally_ref,
                ));
            }
            ProposalFinalization::Rejected { reason } => {
                self.emit(IVote::ProposalRejected {
                    proposalId: proposal_id,
                    state: vote_tally,
                    conflictingproposalId: U256::ZERO,
                })?;
                journal_record(JournalRecord::proposal_rejected(
                    block_number,
                    proposal_ref,
                    tally_ref,
                    reason,
                ));
            }
            ProposalFinalization::Expired => {
                self.emit(IVote::ProposalExpired {
                    proposalId: proposal_id,
                    state: vote_tally,
                })?;
                journal_record(JournalRecord::proposal_expired(
                    block_number,
                    proposal_ref,
                    tally_ref,
                ));
            }
        }
        Ok(())
    }
}
