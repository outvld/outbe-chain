use alloy_primitives::{Address, U256};
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::schema::Governance;
use crate::state::{ProposalInfo, ProposalStatus};

/// `IGovernance.getProposal`.
pub fn get_proposal(storage: StorageHandle<'_>, proposal_id: U256) -> Result<Option<ProposalInfo>> {
    Governance::new(storage).get_proposal(proposal_id)
}

/// `IGovernance.getProposalVoters`.
pub fn get_proposal_voters(
    storage: StorageHandle<'_>,
    proposal_id: U256,
    index: U256,
    count: U256,
) -> Result<Vec<Address>> {
    Governance::new(storage).read_proposal_voters_page(proposal_id, index, count)
}

/// `IGovernance.listProposals`.
pub fn list_proposals(storage: StorageHandle<'_>, index: U256, count: U256) -> Result<Vec<U256>> {
    Governance::new(storage).list_proposals(index, count)
}

/// `IGovernance.listProposalsByStatus`.
pub fn list_proposals_by_status(
    storage: StorageHandle<'_>,
    status: ProposalStatus,
    index: U256,
    count: U256,
) -> Result<Vec<U256>> {
    Governance::new(storage).list_proposals_by_status(status, index, count)
}
