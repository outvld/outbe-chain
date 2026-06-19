use alloy_primitives::U256;
use alloy_sol_types::SolCall;

use outbe_primitives::error::PrecompileError;

use crate::precompile::{dispatch, IUpdate};
use crate::schema::Update;

use super::{min_activation, with_update, PROPOSER, V1_0, V1_2, V2_0, V3_0, V3_1, VOTER_A};

#[test]
fn precompile_abi_compiles() {
    let _ = IUpdate::createProposalCall::SIGNATURE;
    let _ = IUpdate::castVoteCall::SIGNATURE;
    let _ = IUpdate::getActiveVersionCall::SIGNATURE;
    let _ = IUpdate::getProposalCall::SIGNATURE;
}

#[test]
fn dispatch_create_proposal_and_get_proposal() {
    with_update(|storage| {
        let current = 100u64;
        let create_data = IUpdate::createProposalCall {
            version: V1_2.raw(),
            activationHeight: min_activation(current),
            info: b"notes".to_vec().into(),
        }
        .abi_encode();

        let created = dispatch(storage.clone(), &create_data, PROPOSER, U256::ZERO).unwrap();
        let proposal_id = IUpdate::createProposalCall::abi_decode_returns(&created).unwrap();
        assert_eq!(proposal_id, U256::from(1));

        let get_data = IUpdate::getProposalCall {
            proposalId: proposal_id,
        }
        .abi_encode();
        let ret_bytes = dispatch(storage.clone(), &get_data, PROPOSER, U256::ZERO).unwrap();
        let ret = IUpdate::getProposalCall::abi_decode_returns(&ret_bytes).unwrap();
        assert_eq!(ret.proposalId, proposal_id);
        assert_eq!(ret.version, V1_2.raw());
        assert_eq!(ret.info.as_ref(), b"notes");
        assert_eq!(ret.status, IUpdate::ProposalStatus::Pending);
    });
}

#[test]
fn dispatch_cast_vote_and_reject_duplicate() {
    with_update(|storage| {
        let current = 50u64;
        let create_data = IUpdate::createProposalCall {
            version: V1_0.raw(),
            activationHeight: min_activation(current),
            info: Default::default(),
        }
        .abi_encode();
        let created = dispatch(storage.clone(), &create_data, PROPOSER, U256::ZERO).unwrap();
        let proposal_id = IUpdate::createProposalCall::abi_decode_returns(&created).unwrap();

        let vote_yes = IUpdate::castVoteCall {
            proposalId: proposal_id,
            approve: true,
        }
        .abi_encode();
        dispatch(storage.clone(), &vote_yes, VOTER_A, U256::ZERO).unwrap();

        let vote_again = IUpdate::castVoteCall {
            proposalId: proposal_id,
            approve: false,
        }
        .abi_encode();
        let err = dispatch(storage.clone(), &vote_again, VOTER_A, U256::ZERO).unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("already voted")
        ));
    });
}

#[test]
fn dispatch_cancel_proposal() {
    with_update(|storage| {
        let current = 10u64;
        let create_data = IUpdate::createProposalCall {
            version: V2_0.raw(),
            activationHeight: min_activation(current),
            info: Default::default(),
        }
        .abi_encode();
        let created = dispatch(storage.clone(), &create_data, PROPOSER, U256::ZERO).unwrap();
        let proposal_id = IUpdate::createProposalCall::abi_decode_returns(&created).unwrap();

        let cancel_data = IUpdate::cancelProposalCall {
            proposalId: proposal_id,
        }
        .abi_encode();
        dispatch(storage.clone(), &cancel_data, PROPOSER, U256::ZERO).unwrap();

        let get_data = IUpdate::getProposalCall {
            proposalId: proposal_id,
        }
        .abi_encode();
        let ret_bytes = dispatch(storage, &get_data, PROPOSER, U256::ZERO).unwrap();
        let ret = IUpdate::getProposalCall::abi_decode_returns(&ret_bytes).unwrap();
        assert_eq!(ret.status, IUpdate::ProposalStatus::Cancelled);
    });
}

#[test]
fn dispatch_active_version_and_pending_list() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        update.set_active_version(V3_0, 42).unwrap();

        let active_data = IUpdate::getActiveVersionCall {}.abi_encode();
        let active_bytes = dispatch(storage.clone(), &active_data, PROPOSER, U256::ZERO).unwrap();
        assert_eq!(
            IUpdate::getActiveVersionCall::abi_decode_returns(&active_bytes).unwrap(),
            V3_0.raw()
        );

        let is_active_data = IUpdate::isVersionActiveCall {
            version: V3_0.raw(),
        }
        .abi_encode();
        let is_active_bytes =
            dispatch(storage.clone(), &is_active_data, PROPOSER, U256::ZERO).unwrap();
        assert!(IUpdate::isVersionActiveCall::abi_decode_returns(&is_active_bytes).unwrap());

        let current = 100u64;
        let create_data = IUpdate::createProposalCall {
            version: V3_1.raw(),
            activationHeight: min_activation(current),
            info: Default::default(),
        }
        .abi_encode();
        dispatch(storage.clone(), &create_data, PROPOSER, U256::ZERO).unwrap();

        let list_data = IUpdate::listPendingProposalsCall {}.abi_encode();
        let list_bytes = dispatch(storage, &list_data, PROPOSER, U256::ZERO).unwrap();
        let ids = IUpdate::listPendingProposalsCall::abi_decode_returns(&list_bytes).unwrap();
        assert_eq!(ids, vec![U256::from(1)]);
    });
}

#[test]
fn dispatch_rejects_non_zero_value() {
    with_update(|storage| {
        let data = IUpdate::getActiveVersionCall {}.abi_encode();
        let err = dispatch(storage, &data, PROPOSER, U256::from(1)).unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("non-payable")
        ));
    });
}
