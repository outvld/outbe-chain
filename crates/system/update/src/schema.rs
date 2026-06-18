use alloy_primitives::{Address, B256, U256};
use outbe_macros::{contract, storage_record, storage_schema};
use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::storage::types::Mapping;

use crate::errors::UpdateError;
use crate::ProtocolVersion;

/// Lifecycle status of an upgrade proposal.
///
/// Storage values match the Solidity `ProposalStatus` enum (0-based).
/// Record existence is determined by `proposer`, not by status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProposalStatus {
    Pending = 0,
    /// Approved by quorum, but still waiting for activation height.
    Approved = 1,
    Rejected = 2,
    Expired = 3,
    Activated = 4,
    Cancelled = 5,
}

impl ProposalStatus {
    pub fn from_u8(value: u8) -> std::result::Result<Self, UpdateError> {
        match value {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Approved),
            2 => Ok(Self::Rejected),
            3 => Ok(Self::Expired),
            4 => Ok(Self::Activated),
            5 => Ok(Self::Cancelled),
            _ => Err(UpdateError::InvalidProposalStatus),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Returns `true` when the proposal leaves the tracked lifecycle index.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Rejected | Self::Expired | Self::Activated | Self::Cancelled
        )
    }
}

/// Upgrade proposal record keyed by `id`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[storage_record(exists_field = proposer)]
pub struct ProposalRecord {
    #[key]
    pub id: U256,

    #[attribute(order = 0)]
    pub version: ProtocolVersion,

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

impl ProposalRecord {
    /// Reads the typed proposal status from storage.
    pub fn proposal_status(&self) -> std::result::Result<ProposalStatus, UpdateError> {
        ProposalStatus::from_u8(self.status)
    }

    /// Writes the typed proposal status to storage.
    pub fn set_proposal_status(&mut self, status: ProposalStatus) {
        self.status = status.to_u8();
    }
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
///   0:  proposal_count
///   1:  active_version
///   2:  active_version_height
///   3:  pending_proposal_ids
///   4:  waiting_for_activation_proposal_ids
///   5..13: proposals (`ProposalRecord`, 9 slots)
///   14..16: votes (`VoteRecord`, 3 slots)
///   17: version_history
#[storage_schema]
#[contract(addr = UPDATE_ADDRESS)]
pub struct Update {
    /// Total number of proposals ever created.
    #[attribute(order = 0)]
    pub proposal_count: outbe_primitives::storage::dsl::Value<U256>,

    #[attribute(order = 1)]
    pub active_version: outbe_primitives::storage::dsl::Value<ProtocolVersion>,

    #[attribute(order = 2)]
    pub active_version_height: outbe_primitives::storage::dsl::Value<u64>,

    #[attribute(order = 3)]
    pub pending_proposal_ids: outbe_primitives::storage::dsl::List<U256>,

    #[attribute(order = 4)]
    pub waiting_for_activation_proposal_ids: outbe_primitives::storage::dsl::List<U256>,

    #[attribute(order = 5)]
    pub proposals: outbe_primitives::storage::dsl::Map<U256, ProposalRecord>,

    #[attribute(order = 6)]
    pub votes: outbe_primitives::storage::dsl::Map<B256, VoteRecord>,

    #[attribute(order = 7)]
    pub version_history: Mapping<u64, ProtocolVersion>,
}
