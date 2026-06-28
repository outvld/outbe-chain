use alloy_primitives::{Address, B256, U256};

use crate::state::VoteTally;

/// Domain payload for `ProposalCreated`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalCreated {
    pub proposal_id: U256,
    pub proposer: Address,
    pub target_module: B256,
    pub action: B256,
    pub payload: Vec<u8>,
    pub voting_deadline_height: u64,
}

/// Domain payload for `VoteCast`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteCast {
    pub proposal_id: U256,
    pub voter: Address,
    pub approve: bool,
}

/// Domain payload for proposal finalization events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalFinalized {
    pub proposal_id: U256,
    pub state: VoteTally,
}
