//! ABI surface for the Update governance precompile.
//!
//! Callable EVM dispatch is intentionally not registered in stage 1.
//! Stage 2 will wire manual `sol!` decode/dispatch for dynamic `string`/`bytes`
//! parameters (see the TeeRegistry note on `#[contract_dispatch]` limitations).

use alloy_sol_types::sol;

use crate::state::{PlanInfo, ProposalStatus, VoteTally};

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IUpdate.sol"
);

/// Solidity interface path for the Update precompile ABI.
pub const UPDATE_ABI_PATH: &str = "contracts/precompiles/src/IUpdate.sol";

/// Maps a stored proposal to the `getPlan` ABI return tuple field order.
pub fn get_plan_return(proposal: &PlanInfo) -> IUpdate::getPlanReturn {
    let tally = VoteTally::from(proposal);
    IUpdate::getPlanReturn {
        proposalId: proposal.id,
        proposer: proposal.proposer,
        proposedAtHeight: proposal.proposed_at_height,
        activationHeight: proposal.activation_height,
        votingDeadlineHeight: proposal.voting_deadline_height,
        version: proposal.version.clone(),
        info: proposal.info.clone().into(),
        status: IUpdate::PlanStatus::try_from(proposal.status.to_abi_u8())
            .unwrap_or(IUpdate::PlanStatus::Pending),
        state: IUpdate::VoteTally {
            yes: tally.yes,
            no: tally.no,
        },
    }
}

/// Maps storage status to the Solidity `PlanStatus` enum variant.
pub fn proposal_status_to_abi(status: ProposalStatus) -> IUpdate::PlanStatus {
    IUpdate::PlanStatus::try_from(status.to_abi_u8()).unwrap_or(IUpdate::PlanStatus::Pending)
}
