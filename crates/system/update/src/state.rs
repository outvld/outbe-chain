use alloy_primitives::{keccak256, Address, B256, U256};

use outbe_primitives::error::Result;

use crate::errors::UpdateError;
use crate::schema::Update;

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

    /// Maps storage status (1-based) to Solidity `PlanStatus` enum (0-based).
    pub fn to_abi_u8(self) -> u8 {
        self as u8 - 1
    }

    /// Maps Solidity `PlanStatus` enum (0-based) to storage status (1-based).
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

impl From<&PlanInfo> for VoteTally {
    fn from(plan: &PlanInfo) -> Self {
        Self {
            yes: plan.yes_votes,
            no: plan.no_votes,
        }
    }
}

/// Materialized upgrade proposal read from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanInfo {
    pub id: U256,
    pub version: String,
    pub activation_height: u64,
    pub voting_deadline_height: u64,
    pub info: Vec<u8>,
    pub proposer: Address,
    pub proposed_at_height: u64,
    pub status: ProposalStatus,
    pub yes_votes: u64,
    pub no_votes: u64,
}

impl PlanInfo {
    pub fn tally(&self) -> VoteTally {
        VoteTally::from(self)
    }
}

/// Materialized vote read from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteInfo {
    pub plan_id: U256,
    pub voter: Address,
    pub vote_kind: VoteKind,
    pub block_number: u64,
}

/// Composite vote key: `keccak256(plan_id_be32 || voter_address_20)`.
pub fn vote_key(plan_id: U256, voter: Address) -> B256 {
    let mut buf = [0u8; 52];
    buf[..32].copy_from_slice(&plan_id.to_be_bytes::<32>());
    buf[32..52].copy_from_slice(voter.as_slice());
    keccak256(buf)
}

/// Normalizes a semver-like version string to lowercase `vMAJOR.MINOR.PATCH`.
pub fn normalize_version(version: &str) -> std::result::Result<String, UpdateError> {
    let normalized = version.trim().to_lowercase();
    if !is_valid_version(&normalized) {
        return Err(UpdateError::InvalidVersion);
    }
    Ok(normalized)
}

fn is_valid_version(version: &str) -> bool {
    let Some(rest) = version.strip_prefix('v') else {
        return false;
    };
    let mut parts = rest.split('.');
    let Some(major) = parts.next() else {
        return false;
    };
    let Some(minor) = parts.next() else {
        return false;
    };
    let Some(patch) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    [major, minor, patch]
        .into_iter()
        .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

/// Compares two normalized semver strings. Returns `true` if `left > right`.
pub fn version_gt(left: &str, right: &str) -> bool {
    parse_version_triplet(left) > parse_version_triplet(right)
}

/// Compares two normalized semver strings. Returns `true` if `left >= right`.
pub fn version_gte(left: &str, right: &str) -> bool {
    parse_version_triplet(left) >= parse_version_triplet(right)
}

fn parse_version_triplet(version: &str) -> (u64, u64, u64) {
    let rest = version.strip_prefix('v').unwrap_or(version);
    let mut parts = rest.split('.');
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor, patch)
}

impl Update<'_> {
    /// Returns the next plan id without incrementing the counter.
    pub fn peek_next_plan_id(&self) -> Result<U256> {
        let current = self.plan_count.read()?;
        Ok(current + U256::from(1))
    }

    /// Returns `true` when `plan_id` has been allocated by `write_plan`.
    pub fn plan_exists(&self, plan_id: U256) -> Result<bool> {
        let count = self.plan_count.read()?;
        Ok(!plan_id.is_zero() && plan_id <= count)
    }

    /// Reads a proposal or returns `None` when the id was never allocated.
    pub fn read_plan(&self, plan_id: U256) -> Result<Option<PlanInfo>> {
        if !self.plan_exists(plan_id)? {
            return Ok(None);
        }
        let status_raw = self.plan_status.read(&plan_id)?;
        Ok(Some(PlanInfo {
            id: plan_id,
            version: self.plan_version.read_string(&plan_id)?,
            activation_height: self.plan_activation_height.read(&plan_id)?,
            voting_deadline_height: self.plan_voting_deadline_height.read(&plan_id)?,
            info: self.plan_info.get_bytes(&plan_id).read()?,
            proposer: self.plan_proposer.read(&plan_id)?,
            proposed_at_height: self.plan_proposed_at_height.read(&plan_id)?,
            status: ProposalStatus::from_u8(status_raw)?,
            yes_votes: self.plan_yes_votes.read(&plan_id)?,
            no_votes: self.plan_no_votes.read(&plan_id)?,
        }))
    }

    /// Reads a vote or returns `None` when absent.
    pub fn read_vote(&self, plan_id: U256, voter: Address) -> Result<Option<VoteInfo>> {
        let key = vote_key(plan_id, voter);
        if !self.vote_exists.read(&key)? {
            return Ok(None);
        }
        Ok(Some(VoteInfo {
            plan_id: self.vote_plan_id.read(&key)?,
            voter: self.vote_voter.read(&key)?,
            vote_kind: VoteKind::from_u8(self.vote_kind.read(&key)?)?,
            block_number: self.vote_block_number.read(&key)?,
        }))
    }

    /// Returns all pending plan ids currently indexed.
    pub fn list_pending_plan_ids(&self) -> Result<Vec<U256>> {
        self.pending_plan_ids.read_all()
    }

    /// Reads the active protocol version, if any.
    pub fn get_active_version(&self) -> Result<Option<String>> {
        if self.active_version.is_empty()? {
            return Ok(None);
        }
        Ok(Some(self.active_version.read_string()?))
    }

    /// Reads the activation height of the current active version.
    pub fn get_active_version_height(&self) -> Result<u64> {
        self.active_version_height.read()
    }

    /// Reads the version recorded at `height`, if any.
    pub fn version_at_height(&self, height: u64) -> Result<Option<String>> {
        let version = self.version_history.read_string(&height)?;
        if version.is_empty() {
            Ok(None)
        } else {
            Ok(Some(version))
        }
    }

    /// Writes the active protocol version and records it in `version_history`.
    pub fn set_active_version(&mut self, version: &str, height: u64) -> Result<()> {
        let normalized = normalize_version(version)?;
        self.active_version.write_string(&normalized)?;
        self.active_version_height.write(height)?;
        self.version_history.write_string(&height, &normalized)?;
        Ok(())
    }

    /// Allocates a new plan id and persists all plan fields.
    pub fn write_plan(
        &mut self,
        version: &str,
        activation_height: u64,
        voting_deadline_height: u64,
        info: &[u8],
        proposer: Address,
        proposed_at_height: u64,
        status: ProposalStatus,
    ) -> Result<U256> {
        let normalized = normalize_version(version)?;
        let plan_id = self.peek_next_plan_id()?;
        self.plan_count.write(plan_id)?;

        self.plan_status.write(&plan_id, status.to_u8())?;
        self.plan_activation_height
            .write(&plan_id, activation_height)?;
        self.plan_voting_deadline_height
            .write(&plan_id, voting_deadline_height)?;
        self.plan_proposer.write(&plan_id, proposer)?;
        self.plan_proposed_at_height
            .write(&plan_id, proposed_at_height)?;
        self.plan_yes_votes.write(&plan_id, 0)?;
        self.plan_no_votes.write(&plan_id, 0)?;
        self.plan_version.write_string(&plan_id, &normalized)?;
        self.plan_info.get_bytes(&plan_id).write(info)?;

        if status == ProposalStatus::Pending {
            self.pending_plan_ids.push(plan_id)?;
        }

        Ok(plan_id)
    }

    /// Persists a vote and increments the plan's yes/no counters.
    pub fn write_vote(
        &mut self,
        plan_id: U256,
        voter: Address,
        kind: VoteKind,
        block_number: u64,
    ) -> Result<()> {
        let key = vote_key(plan_id, voter);
        self.vote_exists.write(&key, true)?;
        self.vote_plan_id.write(&key, plan_id)?;
        self.vote_voter.write(&key, voter)?;
        self.vote_kind.write(&key, kind.to_u8())?;
        self.vote_block_number.write(&key, block_number)?;

        match kind {
            VoteKind::Yes => {
                let yes = self.plan_yes_votes.read(&plan_id)?;
                self.plan_yes_votes.write(&plan_id, yes + 1)?;
            }
            VoteKind::No => {
                let no = self.plan_no_votes.read(&plan_id)?;
                self.plan_no_votes.write(&plan_id, no + 1)?;
            }
        }
        Ok(())
    }

    /// Updates plan status and removes it from the pending index when needed.
    pub fn set_plan_status(&mut self, plan_id: U256, status: ProposalStatus) -> Result<()> {
        self.plan_status.write(&plan_id, status.to_u8())?;
        if status != ProposalStatus::Pending {
            self.remove_pending_plan_id(plan_id)?;
        }
        Ok(())
    }

    fn remove_pending_plan_id(&mut self, plan_id: U256) -> Result<()> {
        let pending = self.pending_plan_ids.read_all()?;
        let len = pending.len();
        for (idx, id) in pending.iter().enumerate() {
            if *id == plan_id {
                let last_idx = (len - 1) as u32;
                if idx as u32 != last_idx {
                    let last = self.pending_plan_ids.get(last_idx)?.unwrap_or(U256::ZERO);
                    self.pending_plan_ids.set(idx as u32, last)?;
                }
                let _ = self.pending_plan_ids.pop()?;
                break;
            }
        }
        Ok(())
    }
}
