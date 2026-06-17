use alloy_primitives::{Address, B256, U256};
use outbe_macros::contract;
use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::storage::types::{Mapping, Slot, StorageBytes, StorageVec};

/// EVM storage layout for the Update governance precompile.
///
/// Storage slots:
///   0:  plan_count                 — U256 auto-increment counter
///   1:  active_version             — UTF-8 semver string (StorageBytes)
///   2:  active_version_height      — u64
///   3:  pending_plan_ids           — StorageVec<U256>
///   4:  plan_status                — mapping(uint256 => uint8)
///   5:  plan_activation_height     — mapping(uint256 => uint64)
///   6:  plan_voting_deadline_height — mapping(uint256 => uint64)
///   7:  plan_proposer              — mapping(uint256 => address)
///   8:  plan_proposed_at_height    — mapping(uint256 => uint64)
///   9:  plan_yes_votes             — mapping(uint256 => uint64)
///   10: plan_no_votes              — mapping(uint256 => uint64)
///   11: plan_version               — mapping(uint256 => string/bytes)
///   12: plan_info                  — mapping(uint256 => bytes)
///   13: vote_exists                — mapping(bytes32 => bool)
///   14: vote_plan_id               — mapping(bytes32 => uint256)
///   15: vote_voter                 — mapping(bytes32 => address)
///   16: vote_kind                  — mapping(bytes32 => uint8)
///   17: vote_block_number          — mapping(bytes32 => uint64)
///   18: version_history            — mapping(uint64 => string/bytes)
#[contract(addr = UPDATE_ADDRESS)]
pub struct Update {
    pub plan_count: Slot<U256>,
    pub active_version: StorageBytes,
    pub active_version_height: Slot<u64>,
    pub pending_plan_ids: StorageVec<U256>,

    pub plan_status: Mapping<U256, u8>,
    pub plan_activation_height: Mapping<U256, u64>,
    pub plan_voting_deadline_height: Mapping<U256, u64>,
    pub plan_proposer: Mapping<U256, Address>,
    pub plan_proposed_at_height: Mapping<U256, u64>,
    pub plan_yes_votes: Mapping<U256, u64>,
    pub plan_no_votes: Mapping<U256, u64>,
    pub plan_version: Mapping<U256, StorageBytes>,
    pub plan_info: Mapping<U256, StorageBytes>,

    pub vote_exists: Mapping<B256, bool>,
    pub vote_plan_id: Mapping<B256, U256>,
    pub vote_voter: Mapping<B256, Address>,
    pub vote_kind: Mapping<B256, u8>,
    pub vote_block_number: Mapping<B256, u64>,

    pub version_history: Mapping<u64, StorageBytes>,
}
