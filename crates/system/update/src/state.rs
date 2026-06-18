use alloy_primitives::{keccak256, Address, B256, U256};

use outbe_primitives::error::Result;

use crate::constants::{MAX_PROTOCOL_VERSION_MINOR, PROTOCOL_VERSION_MINOR_BITS};
use crate::ProtocolVersion;
use crate::errors::UpdateError;
use crate::schema::{ProposalRecord, Update, VoteRecord};

/// Lifecycle status of an upgrade proposal (storage: 1-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProposalStatus {
    Pending = 1,
    Approved = 2,
    Rejected = 3,
    Expired = 4,
    Activated = 5,
    Cancelled = 6,
}

impl ProposalStatus {
    pub fn from_u8(value: u8) -> std::result::Result<Self, UpdateError> {
        match value {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Approved),
            3 => Ok(Self::Rejected),
            4 => Ok(Self::Expired),
            5 => Ok(Self::Activated),
            6 => Ok(Self::Cancelled),
            _ => Err(UpdateError::InvalidProposalStatus),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Maps storage status (1-based) to Solidity `ProposalStatus` enum (0-based).
    pub fn to_abi_u8(self) -> u8 {
        self as u8 - 1
    }

    /// Maps Solidity `ProposalStatus` enum (0-based) to storage status (1-based).
    pub fn from_abi_u8(value: u8) -> std::result::Result<Self, UpdateError> {
        Self::from_u8(value.saturating_add(1))
    }
}

/// Vote choice on a proposal (storage: 0=No, 1=Yes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VoteKind {
    No = 0,
    Yes = 1,
}

impl VoteKind {
    pub fn from_u8(value: u8) -> std::result::Result<Self, UpdateError> {
        match value {
            0 => Ok(Self::No),
            1 => Ok(Self::Yes),
            _ => Err(UpdateError::InvalidVoteKind),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// ABI `castVote(bool approve)` — `true` = Yes, `false` = No.
    pub fn from_approve(approve: bool) -> Self {
        if approve {
            Self::Yes
        } else {
            Self::No
        }
    }

    pub fn to_approve(self) -> bool {
        matches!(self, Self::Yes)
    }
}

/// Yes/no vote counters for a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteTally {
    pub yes: u64,
    pub no: u64,
}

impl From<&ProposalInfo> for VoteTally {
    fn from(proposal: &ProposalInfo) -> Self {
        Self {
            yes: proposal.yes_votes,
            no: proposal.no_votes,
        }
    }
}

/// Materialized upgrade proposal read from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalInfo {
    pub id: U256,
    pub version: ProtocolVersion,
    pub activation_height: u64,
    pub voting_deadline_height: u64,
    pub info: Vec<u8>,
    pub proposer: Address,
    pub proposed_at_height: u64,
    pub status: ProposalStatus,
    pub yes_votes: u64,
    pub no_votes: u64,
}

impl ProposalInfo {
    pub fn tally(&self) -> VoteTally {
        VoteTally::from(self)
    }
}

/// Materialized vote read from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteInfo {
    pub proposal_id: U256,
    pub voter: Address,
    pub vote_kind: VoteKind,
    pub block_number: u64,
}

impl TryFrom<ProposalRecord> for ProposalInfo {
    type Error = UpdateError;

    fn try_from(record: ProposalRecord) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            id: record.id,
            version: record.version,
            activation_height: record.activation_height,
            voting_deadline_height: record.voting_deadline_height,
            info: record.info,
            proposer: record.proposer,
            proposed_at_height: record.proposed_at_height,
            status: ProposalStatus::from_u8(record.status)?,
            yes_votes: record.yes_votes,
            no_votes: record.no_votes,
        })
    }
}

impl VoteRecord {
    pub fn into_vote_info(self, proposal_id: U256) -> std::result::Result<VoteInfo, UpdateError> {
        Ok(VoteInfo {
            proposal_id,
            voter: self.voter,
            vote_kind: VoteKind::from_u8(self.vote_kind)?,
            block_number: self.block_number,
        })
    }
}

/// Composite vote key: `keccak256(proposal_id_be32 || voter_address_20)`.
pub fn vote_key(proposal_id: U256, voter: Address) -> B256 {
    let mut buf = [0u8; 52];
    buf[..32].copy_from_slice(&proposal_id.to_be_bytes::<32>());
    buf[32..52].copy_from_slice(voter.as_slice());
    keccak256(buf)
}

/// Returns the major part of an encoded protocol version.
pub fn protocol_version_major(version: ProtocolVersion) -> u8 {
    (version >> PROTOCOL_VERSION_MINOR_BITS) as u8
}

/// Returns the minor part of an encoded protocol version.
pub fn protocol_version_minor(version: ProtocolVersion) -> u32 {
    version & MAX_PROTOCOL_VERSION_MINOR
}

/// Compares two protocol versions. Returns `true` if `left > right`.
pub fn version_gt(left: ProtocolVersion, right: ProtocolVersion) -> bool {
    left > right
}

/// Compares two protocol versions. Returns `true` if `left >= right`.
pub fn version_gte(left: ProtocolVersion, right: ProtocolVersion) -> bool {
    left >= right
}

impl Update<'_> {
    /// Returns the next proposal id without incrementing the counter.
    pub fn peek_next_proposal_id(&self) -> Result<U256> {
        let current = self.proposal_count.read()?;
        Ok(current + U256::from(1))
    }

    /// Returns `true` when `proposal_id` has been allocated by `write_proposal`.
    pub fn proposal_exists(&self, proposal_id: U256) -> Result<bool> {
        let count = self.proposal_count.read()?;
        Ok(!proposal_id.is_zero() && proposal_id <= count)
    }

    /// Reads a proposal or returns `None` when the id was never allocated.
    pub fn read_proposal(&self, proposal_id: U256) -> Result<Option<ProposalInfo>> {
        if !self.proposal_exists(proposal_id)? {
            return Ok(None);
        }
        Ok(self
            .proposals
            .get(proposal_id)?
            .map(ProposalInfo::try_from)
            .transpose()?)
    }

    /// Reads a vote or returns `None` when absent.
    pub fn read_vote(&self, proposal_id: U256, voter: Address) -> Result<Option<VoteInfo>> {
        let key = vote_key(proposal_id, voter);
        Ok(self
            .votes
            .get(key)?
            .map(|record| record.into_vote_info(proposal_id))
            .transpose()?)
    }

    /// Returns all pending proposal ids currently indexed.
    pub fn list_pending_proposal_ids(&self) -> Result<Vec<U256>> {
        self.pending_proposal_ids.read_all()
    }

    /// Reads the active protocol version.
    pub fn get_active_version(&self) -> Result<Option<ProtocolVersion>> {
        Ok(Some(self.active_version.read()?))
    }

    /// Reads the activation height of the current active version.
    pub fn get_active_version_height(&self) -> Result<u64> {
        self.active_version_height.read()
    }

    /// Reads the version recorded at `height`.
    pub fn version_at_height(&self, height: u64) -> Result<Option<ProtocolVersion>> {
        Ok(Some(self.version_history.read(&height)?))
    }

    /// Writes the active protocol version and records it in `version_history`.
    pub fn set_active_version(&mut self, version: ProtocolVersion, height: u64) -> Result<()> {
        self.active_version.write(version)?;
        self.active_version_height.write(height)?;
        self.version_history.write(&height, version)?;
        Ok(())
    }

    /// Allocates a new proposal id and persists all proposal fields.
    pub fn write_proposal(
        &mut self,
        version: ProtocolVersion,
        activation_height: u64,
        voting_deadline_height: u64,
        info: &[u8],
        proposer: Address,
        proposed_at_height: u64,
        status: ProposalStatus,
    ) -> Result<U256> {
        let proposal_id = self.peek_next_proposal_id()?;
        self.proposal_count.write(proposal_id)?;

        let record = ProposalRecord {
            id: proposal_id,
            proposer,
            proposed_at_height,
            activation_height,
            voting_deadline_height,
            status: status.to_u8(),
            yes_votes: 0,
            no_votes: 0,
            version,
            info: info.to_vec(),
        };
        self.proposals.create(&record)?;

        if status == ProposalStatus::Pending {
            self.pending_proposal_ids.push(proposal_id)?;
        }

        Ok(proposal_id)
    }

    /// Persists a vote and increments the proposal's yes/no counters.
    pub fn write_vote(
        &mut self,
        proposal_id: U256,
        voter: Address,
        kind: VoteKind,
        block_number: u64,
    ) -> Result<()> {
        let key = vote_key(proposal_id, voter);
        self.votes.create(&VoteRecord {
            vote_key: key,
            voter,
            vote_kind: kind.to_u8(),
            block_number,
        })?;

        let mut proposal = self
            .proposals
            .get(proposal_id)?
            .ok_or(UpdateError::ProposalNotFound)?;
        match kind {
            VoteKind::Yes => proposal.yes_votes += 1,
            VoteKind::No => proposal.no_votes += 1,
        }
        self.proposals.update(&proposal)?;
        Ok(())
    }

    /// Updates proposal status and removes it from the pending index when needed.
    pub fn set_proposal_status(&mut self, proposal_id: U256, status: ProposalStatus) -> Result<()> {
        let mut proposal = self
            .proposals
            .get(proposal_id)?
            .ok_or(UpdateError::ProposalNotFound)?;
        proposal.status = status.to_u8();
        self.proposals.update(&proposal)?;
        if status != ProposalStatus::Pending {
            self.remove_pending_proposal_id(proposal_id)?;
        }
        Ok(())
    }

    fn remove_pending_proposal_id(&mut self, proposal_id: U256) -> Result<()> {
        let pending = self.pending_proposal_ids.read_all()?;
        let len = pending.len();
        for (idx, id) in pending.iter().enumerate() {
            if *id == proposal_id {
                let last_idx = (len - 1) as u32;
                if idx as u32 != last_idx {
                    let last = self
                        .pending_proposal_ids
                        .get(last_idx)?
                        .unwrap_or(U256::ZERO);
                    self.pending_proposal_ids.set(idx as u32, last)?;
                }
                let _ = self.pending_proposal_ids.pop()?;
                break;
            }
        }
        Ok(())
    }
}
