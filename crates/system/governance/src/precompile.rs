//! ABI surface and EVM dispatch for the Governance precompile.

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolInterface};

use outbe_primitives::dispatch::{dispatch_call, mutate, mutate_void, reject_value, view};
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::api::{get_proposal, get_proposal_voters, list_proposals, list_proposals_by_status};
use crate::errors::GovernanceError;
use crate::schema::Governance;
use crate::state::{ProposalInfo, ProposalStatus, VoteTally};

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IGovernance.sol"
);

/// Dispatches an ABI-encoded call to the Governance precompile.
pub fn dispatch(
    storage: StorageHandle<'_>,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    reject_value(&value)?;
    dispatch_call(data, IGovernance::IGovernanceCalls::abi_decode, |call| {
        dispatch_governance_call(storage, call, caller)
    })
}

fn dispatch_governance_call(
    storage: StorageHandle<'_>,
    call: IGovernance::IGovernanceCalls,
    caller: Address,
) -> Result<Bytes> {
    let mut governance = Governance::new(storage.clone());
    use IGovernance::IGovernanceCalls::*;
    match call {
        createProposal(c) => mutate(c, caller, |sender, c| {
            let block_number = storage.block_number()?;
            let proposal_id = governance.create_proposal(
                sender,
                c.targetModule,
                c.action,
                c.payload.as_ref(),
                block_number,
            )?;
            let record = governance
                .proposals
                .get(proposal_id)?
                .ok_or(GovernanceError::ProposalNotFound)?;
            governance.emit(IGovernance::ProposalCreated {
                proposalId: proposal_id,
                proposer: sender,
                targetModule: c.targetModule,
                action: c.action,
                payload: c.payload.clone(),
                votingDeadlineHeight: record.voting_deadline_height,
            })?;
            Ok(proposal_id)
        }),
        castVote(c) => mutate_void(c, caller, |sender, c| {
            let block_number = storage.block_number()?;
            governance.cast_vote_approve(c.proposalId, sender, c.approve, block_number)?;
            governance.emit(IGovernance::VoteCast {
                proposalId: c.proposalId,
                validator: sender,
                approve: c.approve,
            })?;
            Ok(())
        }),
        getProposal(c) => view(c, |c| {
            let info = get_proposal(storage.clone(), c.proposalId)?
                .ok_or(GovernanceError::ProposalNotFound)?;
            Ok(proposal_info_return(&info))
        }),
        getProposalVoters(c) => view(c, |c| {
            get_proposal_voters(storage.clone(), c.proposalId, c.index, c.count)
        }),
        listProposals(c) => view(c, |c| list_proposals(storage.clone(), c.index, c.count)),
        listProposalsByStatus(c) => view(c, |c| {
            list_proposals_by_status(
                storage.clone(),
                proposal_status_from_abi(c.status),
                c.index,
                c.count,
            )
        }),
    }
}

fn proposal_info_return(info: &ProposalInfo) -> IGovernance::ProposalInfo {
    IGovernance::ProposalInfo {
        proposalId: info.id,
        proposer: info.proposer,
        targetModule: info.target_module,
        action: info.action,
        payload: info.payload.clone().into(),
        createdHeight: info.created_height,
        votingDeadlineHeight: info.voting_deadline_height,
        status: proposal_status_to_abi(info.status),
        state: vote_tally_return(&info.state),
        votersCount: U256::from(info.voters_count),
    }
}

fn vote_tally_return(tally: &VoteTally) -> IGovernance::VoteTally {
    IGovernance::VoteTally {
        yes: tally.yes,
        no: tally.no,
    }
}

fn proposal_status_to_abi(status: ProposalStatus) -> IGovernance::ProposalStatus {
    match status {
        ProposalStatus::Pending => IGovernance::ProposalStatus::Pending,
        ProposalStatus::Approved => IGovernance::ProposalStatus::Approved,
        ProposalStatus::Rejected => IGovernance::ProposalStatus::Rejected,
        ProposalStatus::Expired => IGovernance::ProposalStatus::Expired,
    }
}

fn proposal_status_from_abi(status: IGovernance::ProposalStatus) -> ProposalStatus {
    match status {
        IGovernance::ProposalStatus::Pending => ProposalStatus::Pending,
        IGovernance::ProposalStatus::Approved => ProposalStatus::Approved,
        IGovernance::ProposalStatus::Rejected => ProposalStatus::Rejected,
        IGovernance::ProposalStatus::Expired => ProposalStatus::Expired,
        _ => ProposalStatus::Pending,
    }
}
