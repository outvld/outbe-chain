use alloy_primitives::{Address, B256, U256};
use outbe_macros::{contract, storage_record, storage_schema};
use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::storage::types::{Mapping, StorageBytes};

/// Upgrade proposal record keyed by `id`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[storage_record(exists_field = proposer)]
pub struct ProposalRecord {
    #[key]
    pub id: U256,

    #[attribute(order = 0)]
    pub version: String,

    #[attribute(order = 1)]
    pub activation_height: u64,

    #[attribute(order = 2)]
    pub voting_deadline_height: u64,

    #[attribute(order = 3)]
    pub info: Vec<u8>,

    #[attribute(order = 4)]
    pub proposer: Address,

    #[attribute(order = 5)]
    pub proposed_at_height: u64,

    // TODO: Extend storage to support enum fields?
    #[attribute(order = 6)]
    pub status: u8, // ProposalStatus

    #[attribute(order = 7)]
    pub yes_votes: u64,

    #[attribute(order = 8)]
    pub no_votes: u64,
}

/// Vote record keyed by `vote_key = keccak256(proposal_id_be32 || voter_address_20)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[storage_record(exists_field = voter)]
pub struct VoteRecord {
    #[key]
    pub vote_key: B256,

    #[attribute(order = 0)]
    pub voter: Address,

    #[attribute(order = 1)]
    pub vote_kind: u8, // VoteKind

    #[attribute(order = 2)]
    pub block_number: u64,
}

/// EVM storage layout for the Update governance precompile.
///
/// Storage slots:
///   0:  plan_count
///   1:  active_version
///   2:  active_version_height
///   3:  pending_plan_ids
///   4..12: proposals (`ProposalRecord`, 9 slots)
///   13..15: votes (`VoteRecord`, 3 slots)
///   16: version_history
#[storage_schema]
#[contract(addr = UPDATE_ADDRESS)]
pub struct Update {
    #[attribute(order = 0)]
    pub proposal_count: outbe_primitives::storage::dsl::Value<U256>,

    #[attribute(order = 1)]
    pub active_version: StorageBytes,

    #[attribute(order = 2)]
    pub active_version_height: outbe_primitives::storage::dsl::Value<u64>,

    #[attribute(order = 3)]
    pub pending_plan_ids: outbe_primitives::storage::dsl::List<U256>,

    #[attribute(order = 4)]
    pub proposals: outbe_primitives::storage::dsl::Map<U256, ProposalRecord>,

    #[attribute(order = 5)]
    pub votes: outbe_primitives::storage::dsl::Map<B256, VoteRecord>,

    #[attribute(order = 6)]
    pub version_history: Mapping<u64, StorageBytes>,
}
