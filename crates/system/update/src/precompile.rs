//! ABI surface and EVM dispatch for the Update governance precompile.

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolInterface};

use outbe_primitives::dispatch::{dispatch_call, metadata, mutate, mutate_void, reject_value, view};
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::api::is_version_active_eq;
use crate::errors::UpdateError;
use crate::schema::Update;
use crate::state::{ProposalInfo, ProposalStatus, VoteTally};

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
        version: proposal.version,
        info: proposal.info.clone().into(),
        status: IUpdate::ProposalStatus::try_from(proposal.status.to_abi_u8())
            .unwrap_or(IUpdate::ProposalStatus::Pending),
        state: IUpdate::VoteTally {
            yes: tally.yes,
            no: tally.no,
        },
    }
}

/// Maps storage status to the Solidity `ProposalStatus` enum variant.
pub fn proposal_status_to_abi(status: ProposalStatus) -> IUpdate::ProposalStatus {
    IUpdate::ProposalStatus::try_from(status.to_abi_u8())
        .unwrap_or(IUpdate::ProposalStatus::Pending)
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
                update.create_proposal(
                    sender,
                    c.version,
                    c.activationHeight,
                    c.info.as_ref(),
                    block_number,
                )
            }),
            castVote(c) => mutate_void(c, caller, |sender, c| {
                let block_number = storage.block_number()?;
                update.cast_vote_approve(c.proposalId, sender, c.approve, block_number)
            }),
            cancelProposal(c) => mutate_void(c, caller, |sender, c| {
                let block_number = storage.block_number()?;
                update.cancel_proposal(c.proposalId, sender, block_number)
            }),
            getProposal(c) => view(c, |c| {
                let proposal = update
                    .read_proposal(c.proposalId)?
                    .ok_or(UpdateError::ProposalNotFound)?;
                Ok(get_proposal_return(&proposal))
            }),
            getActiveVersion(_) => metadata::<IUpdate::getActiveVersionCall>(|| {
                Ok(update.get_active_version()?.unwrap_or_default())
            }),
            isVersionActive(c) => view(c, |c| is_version_active_eq(storage.clone(), c.version)),
            listPendingProposals(_) => metadata::<IUpdate::listPendingProposalsCall>(|| {
                update.list_pending_proposal_ids()
            }),
        }
    })
}
