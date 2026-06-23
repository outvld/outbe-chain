use alloy_primitives::{Address, U256};
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::schema::Governance;
use crate::state::{ProposalInfo, VoteInfo};

pub fn get_proposal(
    storage: StorageHandle<'_>,
    proposal_id: U256,
) -> Result<Option<ProposalInfo>> {
    Governance::new(storage).read_proposal(proposal_id)
}

pub fn list_pending_proposals(storage: StorageHandle<'_>) -> Result<Vec<U256>> {
    Governance::new(storage).list_pending_proposal_ids()
}

pub fn get_vote(
    storage: StorageHandle<'_>,
    proposal_id: U256,
    voter: Address,
) -> Result<Option<VoteInfo>> {
    Governance::new(storage).read_vote(proposal_id, voter)
}
