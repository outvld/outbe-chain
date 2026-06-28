use crate::errors::VoteError;
use alloy_primitives::{Address, B256, U256};
use outbe_macros::{contract, storage_record, storage_schema};
use outbe_primitives::addresses::VOTE_ADDRESS;
use outbe_primitives::storage::{Storable, StorableType};

/// Lifecycle status of a generic proposal.
///
/// Storage values match the Solidity `ProposalStatus` enum (0-based).
///
/// Flow:
/// 1. `Pending` — created, voting open until `voting_deadline_height`.
/// 2. On deadline (`begin_block`): `Pending` -> `Approved` | `Rejected` | `Expired`.
/// 3. For `Approved`, vote dispatches to the target-module handler; further
///    state (e.g. scheduled update, activation) lives in that module, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProposalStatus {
    Pending = 0,
    Approved = 1,
    Rejected = 2,
    Expired = 3,
}

impl ProposalStatus {
    pub fn from_u8(value: u8) -> std::result::Result<Self, VoteError> {
        match value {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Approved),
            2 => Ok(Self::Rejected),
            3 => Ok(Self::Expired),
            _ => Err(VoteError::InvalidProposalStatus),
        }
    }

    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Returns `true` when the proposal leaves the bounded pending index.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Approved | Self::Rejected | Self::Expired)
    }
}

/// Generic proposal record keyed by `id`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[storage_record(exists_field = proposer)]
pub struct ProposalRecord {
    #[key]
    pub id: U256,

    #[attribute(order = 0)]
    pub proposer: Address,

    #[attribute(order = 1)]
    pub target_module: B256,

    #[attribute(order = 2)]
    pub action: B256,

    #[attribute(order = 3)]
    pub payload: Vec<u8>,

    #[attribute(order = 4)]
    pub created_height: u64,

    #[attribute(order = 5)]
    pub voting_deadline_height: u64,

    // TODO: Extend storage to support enum fields?
    #[attribute(order = 6)]
    pub status: u8, // ProposalStatus
}

impl ProposalRecord {
    /// Reads the typed proposal status from storage.
    pub fn proposal_status(&self) -> std::result::Result<ProposalStatus, VoteError> {
        ProposalStatus::from_u8(self.status)
    }

    /// Writes the typed proposal status to storage.
    pub fn set_proposal_status(&mut self, status: ProposalStatus) {
        self.status = status.to_u8();
    }
}

/// Vote record stored in each proposal's ordered vote list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteRecord {
    pub voter: Address,
    pub vote_kind: u8, // VoteKind
    pub block_number: u64,
}

// TODO: Can we modify `#[storage_record]` macro to generate `Storable`?
impl StorableType for VoteRecord {
    const SLOTS: usize = 1;
}

impl Storable for VoteRecord {
    fn from_word(word: U256) -> Self {
        let bytes = word.to_be_bytes::<32>();
        let mut block_number = [0u8; 8];
        block_number.copy_from_slice(&bytes[21..29]);
        Self {
            voter: Address::from_slice(&bytes[..20]),
            vote_kind: bytes[20],
            block_number: u64::from_be_bytes(block_number),
        }
    }

    fn to_word(&self) -> U256 {
        let mut bytes = [0u8; 32];
        bytes[..20].copy_from_slice(self.voter.as_slice());
        bytes[20] = self.vote_kind;
        bytes[21..29].copy_from_slice(&self.block_number.to_be_bytes());
        U256::from_be_bytes(bytes)
    }
}

/// EVM storage layout for the generic Vote precompile.
///
/// Storage slots:
///   0:  proposal_count
///   1:  pending_proposal_ids
///   2:  proposals: mapping(proposal_id => ProposalRecord) (`ProposalRecord`, 7 slots)
///   3:  votes_map: mapping(voteKey => 1-based proposal_voters index)
///   4:  proposal_voters: mapping(proposalId => VoteRecord[])
#[storage_schema]
#[contract(addr = VOTE_ADDRESS)]
pub struct Vote {
    /// Total number of proposals ever created.
    #[attribute(order = 0)]
    pub proposal_count: outbe_primitives::storage::dsl::Value<U256>,

    /// Bounded list of proposal ids in the voting phase (`Pending` only).
    #[attribute(order = 1)]
    pub pending_proposal_ids: outbe_primitives::storage::dsl::List<U256>,

    #[attribute(order = 2)]
    pub proposals: outbe_primitives::storage::dsl::Map<U256, ProposalRecord>,

    #[attribute(order = 3)]
    /// Maps `keccak256(proposal_id || voter)` to a 1-based position in `proposal_voters`.
    /// Zero means the validator has not voted on the proposal.
    pub votes_map: outbe_primitives::storage::dsl::Map<B256, u32>,

    /// Ordered vote records per proposal.
    #[attribute(order = 4)]
    pub proposal_voters:
        outbe_primitives::storage::dsl::Map<U256, outbe_primitives::storage::dsl::List<VoteRecord>>,
}
