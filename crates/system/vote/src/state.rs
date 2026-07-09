use alloy_primitives::{keccak256, Address, B256, U256};
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;
use outbe_validatorset::contract::ValidatorSet;
use tracing::warn;

use crate::constants::MAX_PAGE_SIZE;
use crate::errors::VoteError;
use crate::schema::{ProposalRecord, Vote, VoteRecord};

pub use crate::schema::ProposalStatus;

/// Vote choice on a proposal (storage: 0=No, 1=Yes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VoteKind {
    No = 0,
    Yes = 1,
}

impl VoteKind {
    pub fn from_u8(value: u8) -> std::result::Result<Self, VoteError> {
        match value {
            0 => Ok(Self::No),
            1 => Ok(Self::Yes),
            _ => Err(VoteError::InvalidVoteKind),
        }
    }

    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// ABI `castVote(bool approve)` — `true` = Yes, `false` = No.
    pub const fn from_approve(approve: bool) -> Self {
        if approve {
            Self::Yes
        } else {
            Self::No
        }
    }

    pub const fn to_approve(self) -> bool {
        matches!(self, Self::Yes)
    }
}

/// Yes/no vote counters for a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteTally {
    pub yes: u64,
    pub no: u64,
}

/// `IVote.ProposalInfo` — external view with computed tally, no voter list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalInfo {
    pub id: U256,
    pub proposer: Address,
    pub target_module: Address,
    pub payload: String,
    pub created_height: u64,
    pub voting_deadline_height: u64,
    pub status: ProposalStatus,
    pub state: VoteTally,
    pub voters_count: u64,
}

/// Materialized vote read from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteInfo {
    pub proposal_id: U256,
    pub voter: Address,
    pub vote_kind: VoteKind,
    pub block_number: u64,
}

impl VoteRecord {
    pub fn into_vote_info(self, proposal_id: U256) -> std::result::Result<VoteInfo, VoteError> {
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

/// Returns active validator addresses for tally filtering.
pub fn active_validator_addresses(storage: StorageHandle<'_>) -> Result<Vec<Address>> {
    let vs = ValidatorSet::new(storage);
    Ok(vs
        .get_active_validators()?
        .into_iter()
        .map(|v| v.validator_address)
        .collect())
}

fn is_active_validator(voter: Address, active_validators: &[Address]) -> bool {
    active_validators.iter().any(|active| *active == voter)
}

fn clamp_page(index: U256, count: U256) -> (usize, usize) {
    // Saturating conversion: oversized ABI args must not panic the precompile.
    let index = index.saturating_to::<usize>();
    let count = count.saturating_to::<u64>().min(MAX_PAGE_SIZE) as usize;
    (index, count)
}

/// Recalculates yes/no counts from stored voters filtered by the active validator set.
pub fn calculate_vote_tally(
    governance: &Vote<'_>,
    proposal: &ProposalRecord,
    active_validators: &[Address],
) -> Result<VoteTally> {
    let mut yes = 0u64;
    let mut no = 0u64;
    for vote in governance.proposal_voters.list(&proposal.id).read_all()? {
        if !is_active_validator(vote.voter, active_validators) {
            continue;
        }
        match VoteKind::from_u8(vote.vote_kind)? {
            VoteKind::Yes => yes += 1,
            VoteKind::No => no += 1,
        }
    }
    Ok(VoteTally { yes, no })
}

impl<'storage> Vote<'storage> {
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

    pub fn get_proposal(&self, proposal_id: U256) -> Result<Option<ProposalInfo>> {
        if !self.proposal_exists(proposal_id)? {
            return Ok(None);
        }
        let Some(record) = self.proposals.get(proposal_id)? else {
            return Ok(None);
        };
        let active = active_validator_addresses(self.storage.clone())?;
        let state = calculate_vote_tally(self, &record, &active)?;
        let status = record.proposal_status()?;
        let voters_count = self.proposal_voters.list(&proposal_id).len()? as u64;
        Ok(Some(ProposalInfo {
            id: record.id,
            proposer: record.proposer,
            target_module: record.target_module,
            payload: record.payload,
            created_height: record.created_height,
            voting_deadline_height: record.voting_deadline_height,
            status,
            state,
            voters_count,
        }))
    }

    pub fn read_vote(&self, proposal_id: U256, voter: Address) -> Result<Option<VoteInfo>> {
        let key = vote_key(proposal_id, voter);
        let position = self.votes_map.read(&key)?;
        if position == 0 {
            return Ok(None);
        }
        Ok(self
            .proposal_voters
            .list(&proposal_id)
            .get(position - 1)?
            .map(|record| record.into_vote_info(proposal_id))
            .transpose()?)
    }

    pub fn read_proposal_voters_page(
        &self,
        proposal_id: U256,
        index: U256,
        count: U256,
    ) -> Result<Vec<Address>> {
        self.proposals
            .get(proposal_id)?
            .ok_or(VoteError::ProposalNotFound)?;
        let (index, count) = clamp_page(index, count);
        let voters = self.proposal_voters.list(&proposal_id);
        let len = voters.len()? as usize;
        let mut page = Vec::new();
        for offset in 0..count {
            let pos = index + offset;
            if pos >= len {
                break;
            }
            if let Some(vote) = voters.get(pos as u32)? {
                page.push(vote.voter);
            }
        }
        Ok(page)
    }

    pub fn read_proposal_voters(&self, proposal_id: U256) -> Result<Vec<Address>> {
        self.proposals
            .get(proposal_id)?
            .ok_or(VoteError::ProposalNotFound)?;
        Ok(self
            .proposal_voters
            .list(&proposal_id)
            .read_all()?
            .into_iter()
            .map(|vote| vote.voter)
            .collect())
    }

    pub fn list_proposals(&self, index: U256, count: U256) -> Result<Vec<U256>> {
        let total = self.proposal_count.read()?.saturating_to::<usize>();
        let (index, count) = clamp_page(index, count);
        let mut result = Vec::new();
        for offset in 0..count {
            let pos = index + offset;
            if pos >= total {
                break;
            }
            result.push(U256::from(pos + 1));
        }
        Ok(result)
    }

    pub fn list_proposals_by_status(
        &self,
        status: ProposalStatus,
        index: U256,
        count: U256,
    ) -> Result<Vec<U256>> {
        let total = self.proposal_count.read()?.saturating_to::<usize>();
        let (start_index, page_size) = clamp_page(index, count);
        let mut matched = Vec::new();
        for id_num in 1..=total {
            let proposal_id = U256::from(id_num);
            let Some(record) = self.proposals.get(proposal_id)? else {
                continue;
            };
            if record.proposal_status()? == status {
                matched.push(proposal_id);
            }
        }
        Ok(matched
            .into_iter()
            .skip(start_index)
            .take(page_size)
            .collect())
    }

    pub fn list_pending_proposal_ids(&self) -> Result<Vec<U256>> {
        self.pending_proposal_ids.read_all()
    }

    pub fn pending_proposal_count_by_proposer(&self, proposer: Address) -> Result<u32> {
        let mut count = 0u32;
        for proposal_id in self.list_pending_proposal_ids()? {
            let Some(record) = self.proposals.get(proposal_id)? else {
                continue;
            };
            if record.proposer == proposer {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    pub fn write_proposal(
        &mut self,
        proposer: Address,
        target_module: Address,
        payload: &str,
        created_height: u64,
        voting_deadline_height: u64,
        status: ProposalStatus,
    ) -> Result<U256> {
        let proposal_id = self.peek_next_proposal_id()?;
        self.proposal_count.write(proposal_id)?;

        let record = ProposalRecord {
            id: proposal_id,
            proposer,
            target_module,
            payload: payload.to_string(),
            created_height,
            voting_deadline_height,
            status: status.to_u8(),
        };
        self.proposals.create(&record)?;

        if status == ProposalStatus::Pending {
            self.pending_proposal_ids.push(proposal_id)?;
        }

        Ok(proposal_id)
    }

    pub fn write_vote(
        &mut self,
        proposal_id: U256,
        voter: Address,
        kind: VoteKind,
        block_number: u64,
    ) -> Result<()> {
        let key = vote_key(proposal_id, voter);
        self.proposals
            .get(proposal_id)?
            .ok_or(VoteError::ProposalNotFound)?;
        let votes = self.proposal_voters.list(&proposal_id);
        let index = votes.len()?;
        votes.push(VoteRecord {
            voter,
            vote_kind: kind.to_u8(),
            block_number,
        })?;
        self.votes_map.write(&key, index + 1)?;
        Ok(())
    }

    pub fn set_proposal_status(
        &mut self,
        proposal_id: U256,
        new_status: ProposalStatus,
    ) -> Result<()> {
        let mut proposal = self
            .proposals
            .get(proposal_id)?
            .ok_or(VoteError::ProposalNotFound)?;
        let old_status = proposal.proposal_status()?;

        if old_status == new_status {
            warn!("proposal status is already {old_status:?} for proposal {proposal_id}");
            return Ok(());
        }

        proposal.set_proposal_status(new_status);
        self.proposals.update(&proposal)?;

        if old_status == ProposalStatus::Pending {
            self.remove_pending_proposal_id(proposal_id)?;
        }
        if new_status == ProposalStatus::Pending {
            self.pending_proposal_ids.push(proposal_id)?;
        }

        Ok(())
    }

    fn remove_pending_proposal_id(&mut self, proposal_id: U256) -> Result<()> {
        let ids = self.pending_proposal_ids.read_all()?;
        let Some(removed_idx) = ids.iter().position(|p| *p == proposal_id) else {
            warn!("proposal {proposal_id} not found in pending proposal list");
            return Ok(());
        };

        let len = ids.len();
        if removed_idx != len - 1 {
            let last = self
                .pending_proposal_ids
                .get(len as u32 - 1)?
                .unwrap_or(U256::ZERO);
            self.pending_proposal_ids.set(removed_idx as u32, last)?;
        }
        let _ = self.pending_proposal_ids.pop()?;
        Ok(())
    }
}
