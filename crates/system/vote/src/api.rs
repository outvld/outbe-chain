use alloy_primitives::{Address, U256};
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::schema::Vote;
use crate::state::{ProposalInfo, ProposalStatus};

/// `IVote.getProposal`.
pub fn get_proposal(storage: StorageHandle<'_>, proposal_id: U256) -> Result<Option<ProposalInfo>> {
    Vote::new(storage).get_proposal(proposal_id)
}

/// `IVote.getProposalVoters`.
pub fn get_proposal_voters(
    storage: StorageHandle<'_>,
    proposal_id: U256,
    index: U256,
    count: U256,
) -> Result<Vec<Address>> {
    Vote::new(storage).read_proposal_voters_page(proposal_id, index, count)
}

/// `IVote.listProposals`.
pub fn list_proposals(storage: StorageHandle<'_>, index: U256, count: U256) -> Result<Vec<U256>> {
    Vote::new(storage).list_proposals(index, count)
}

/// `IVote.listProposalsByStatus`.
pub fn list_proposals_by_status(
    storage: StorageHandle<'_>,
    status: ProposalStatus,
    index: U256,
    count: U256,
) -> Result<Vec<U256>> {
    Vote::new(storage).list_proposals_by_status(status, index, count)
}
