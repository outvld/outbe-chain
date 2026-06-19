//! ABI surface and EVM dispatch for the Update governance precompile.

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolInterface};

use outbe_primitives::dispatch::{
    dispatch_call, metadata, mutate, mutate_void, reject_value, view,
};
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::api::is_version_active_eq;
use crate::constants::VOTING_WINDOW_BLOCKS;
use crate::errors::UpdateError;
use crate::schema::Update;
use crate::state::{ProposalInfo, ProposalStatus, VoteTally};
use crate::ProtocolVersion;

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IUpdate.sol"
);

/// Solidity interface path for the Update precompile ABI.
pub const UPDATE_ABI_PATH: &str = "contracts/precompiles/src/IUpdate.sol";

/// Maps a stored proposal to the `getProposal` ABI return tuple field order.
pub fn get_proposal_return(proposal: &ProposalInfo) -> IUpdate::getProposalReturn {
    let tally = VoteTally::from(proposal);
    IUpdate::getProposalReturn {
        proposalId: proposal.id,
        proposer: proposal.proposer,
        proposedAtHeight: proposal.proposed_at_height,
        activationHeight: proposal.activation_height,
        votingDeadlineHeight: proposal.voting_deadline_height,
        version: proposal.version.into(),
        info: proposal.info.clone().into(),
        status: IUpdate::ProposalStatus::from(proposal.status),
        state: IUpdate::VoteTally {
            yes: tally.yes,
            no: tally.no,
        },
    }
}

/// Dispatches an ABI-encoded call to the Update precompile.
pub fn dispatch(
    storage: StorageHandle<'_>,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    reject_value(&value)?;
    dispatch_call(data, IUpdate::IUpdateCalls::abi_decode, |call| {
        let mut update = Update::new(storage.clone());
        use IUpdate::IUpdateCalls::*;
        match call {
            createProposal(c) => mutate(c, caller, |sender, c| {
                let block_number = storage.block_number()?;
                let proposal_id = update.create_proposal(
                    sender,
                    ProtocolVersion::from(c.version),
                    c.activationHeight,
                    c.info.as_ref(),
                    block_number,
                )?;
                let voting_deadline = block_number.saturating_add(VOTING_WINDOW_BLOCKS);
                update.emit(IUpdate::ProposalCreated {
                    proposalId: proposal_id,
                    proposer: sender,
                    version: c.version,
                    activationHeight: c.activationHeight,
                    votingDeadlineHeight: voting_deadline,
                    info: c.info.clone(),
                })?;
                Ok(proposal_id)
            }),
            castVote(c) => mutate_void(c, caller, |sender, c| {
                let block_number = storage.block_number()?;
                update.cast_vote_approve(c.proposalId, sender, c.approve, block_number)?;
                update.emit(IUpdate::VoteCast {
                    proposalId: c.proposalId,
                    voter: sender,
                    approve: c.approve,
                })
            }),
            cancelProposal(c) => mutate_void(c, caller, |sender, c| {
                let block_number = storage.block_number()?;
                update.cancel_proposal(c.proposalId, sender, block_number)?;
                update.emit(IUpdate::ProposalCancelled {
                    proposalId: c.proposalId,
                    proposer: sender,
                })
            }),
            getProposal(c) => view(c, |c| {
                let proposal = update
                    .read_proposal(c.proposalId)?
                    .ok_or(UpdateError::ProposalNotFound)?;
                Ok(get_proposal_return(&proposal))
            }),
            getActiveVersion(_) => metadata::<IUpdate::getActiveVersionCall>(|| {
                Ok(update.get_active_version()?.unwrap_or_default().into())
            }),
            isVersionActive(c) => view(c, |c| {
                is_version_active_eq(storage.clone(), ProtocolVersion::from(c.version))
            }),
            listPendingProposals(_) => {
                metadata::<IUpdate::listPendingProposalsCall>(|| update.list_pending_proposal_ids())
            }
        }
    })
}

impl From<ProposalStatus> for IUpdate::ProposalStatus {
    fn from(status: ProposalStatus) -> Self {
        match status {
            ProposalStatus::Pending => IUpdate::ProposalStatus::Pending,
            ProposalStatus::Approved => IUpdate::ProposalStatus::Approved,
            ProposalStatus::Rejected => IUpdate::ProposalStatus::Rejected,
            ProposalStatus::Expired => IUpdate::ProposalStatus::Expired,
            ProposalStatus::Activated => IUpdate::ProposalStatus::Activated,
            ProposalStatus::Cancelled => IUpdate::ProposalStatus::Cancelled,
        }
    }
}

impl TryFrom<IUpdate::ProposalStatus> for ProposalStatus {
    type Error = UpdateError;

    fn try_from(status: IUpdate::ProposalStatus) -> std::result::Result<Self, Self::Error> {
        Ok(match status {
            IUpdate::ProposalStatus::Pending => ProposalStatus::Pending,
            IUpdate::ProposalStatus::Approved => ProposalStatus::Approved,
            IUpdate::ProposalStatus::Rejected => ProposalStatus::Rejected,
            IUpdate::ProposalStatus::Expired => ProposalStatus::Expired,
            IUpdate::ProposalStatus::Activated => ProposalStatus::Activated,
            IUpdate::ProposalStatus::Cancelled => ProposalStatus::Cancelled,
            _ => return Err(UpdateError::InvalidProposalStatus),
        })
    }
}
