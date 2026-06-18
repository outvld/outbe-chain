use alloy_primitives::{address, Address, U256};
use alloy_sol_types::SolCall;

use outbe_primitives::error::PrecompileError;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;

use crate::api::{
    get_active_version, is_version_active_eq, is_version_active_gte, version_at_height,
};
use crate::constants::{MAX_PROTOCOL_VERSION_MINOR, MIN_ACTIVATION_BUFFER, VOTING_WINDOW_BLOCKS};
use crate::{encode_protocol_version, ProtocolVersion};
use crate::precompile::{dispatch, get_proposal_return, proposal_status_to_abi, IUpdate};
use crate::schema::{ProposalRecord, Update, VoteRecord};
use crate::state::{
    protocol_version_major, protocol_version_minor, vote_key, ProposalStatus, VoteKind, VoteTally,
};

const PROPOSER: Address = address!("0x1111111111111111111111111111111111111111");
const VOTER_A: Address = address!("0x2222222222222222222222222222222222222222");
const VOTER_B: Address = address!("0x3333333333333333333333333333333333333333");
const V1_0: ProtocolVersion = encode_protocol_version(1, 0);
const V1_1: ProtocolVersion = encode_protocol_version(1, 1);
const V1_2: ProtocolVersion = encode_protocol_version(1, 2);
const V1_5: ProtocolVersion = encode_protocol_version(1, 5);
const V1_9: ProtocolVersion = encode_protocol_version(1, 9);
const V2_0: ProtocolVersion = encode_protocol_version(2, 0);
const V3_0: ProtocolVersion = encode_protocol_version(3, 0);
const V3_1: ProtocolVersion = encode_protocol_version(3, 1);
const V9_8: ProtocolVersion = encode_protocol_version(9, 8);

fn with_update<F: FnOnce(StorageHandle)>(f: F) {
    let mut provider = HashMapStorageProvider::new(1);
    let storage = StorageHandle::new(&mut provider);
    f(storage);
}

fn min_activation(current: u64) -> u64 {
    current
        .saturating_add(VOTING_WINDOW_BLOCKS)
        .saturating_add(MIN_ACTIVATION_BUFFER)
}

#[test]
fn create_proposal_writes_fields_and_pending_index() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let proposal_id = update
            .create_proposal(
                PROPOSER,
                V1_2,
                min_activation(current),
                b"release-notes",
                current,
            )
            .unwrap();

        assert_eq!(proposal_id, U256::from(1));
        let proposal = update.read_proposal(proposal_id).unwrap().unwrap();
        assert_eq!(proposal.version, V1_2);
        assert_eq!(proposal.proposer, PROPOSER);
        assert_eq!(proposal.proposed_at_height, current);
        assert_eq!(proposal.status, ProposalStatus::Pending);
        assert_eq!(proposal.info, b"release-notes");
        assert_eq!(proposal.tally(), VoteTally { yes: 0, no: 0 });
        assert_eq!(
            update.list_pending_proposal_ids().unwrap(),
            vec![U256::from(1)]
        );
    });
}

#[test]
fn cast_vote_increments_counters_and_rejects_duplicate() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 50u64;
        let proposal_id = update
            .create_proposal(PROPOSER, V1_1, min_activation(current), b"", current)
            .unwrap();

        update
            .cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
            .unwrap();
        update
            .cast_vote_approve(proposal_id, VOTER_B, false, current + 2)
            .unwrap();

        let proposal = update.read_proposal(proposal_id).unwrap().unwrap();
        assert_eq!(proposal.tally(), VoteTally { yes: 1, no: 1 });

        let err = update
            .cast_vote_approve(proposal_id, VOTER_A, false, current + 3)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("already voted")
        ));
    });
}

#[test]
fn vote_kind_bool_roundtrip() {
    assert_eq!(VoteKind::from_approve(true), VoteKind::Yes);
    assert_eq!(VoteKind::from_approve(false), VoteKind::No);
    assert!(VoteKind::Yes.to_approve());
    assert!(!VoteKind::No.to_approve());
}

#[test]
fn proposal_status_abi_conversion() {
    assert_eq!(ProposalStatus::Pending.to_abi_u8(), 0);
    assert_eq!(ProposalStatus::Cancelled.to_abi_u8(), 5);
    assert_eq!(
        ProposalStatus::from_abi_u8(0).unwrap(),
        ProposalStatus::Pending
    );
    assert_eq!(
        proposal_status_to_abi(ProposalStatus::Approved),
        IUpdate::ProposalStatus::Approved
    );
}

#[test]
fn get_proposal_return_matches_abi_shape() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 10u64;
        let proposal_id = update
            .create_proposal(
                PROPOSER,
                V1_0,
                min_activation(current),
                b"meta",
                current,
            )
            .unwrap();
        let proposal = update.read_proposal(proposal_id).unwrap().unwrap();
        let ret = get_proposal_return(&proposal);
        assert_eq!(ret.proposalId, proposal_id);
        assert_eq!(ret.proposer, PROPOSER);
        assert_eq!(ret.proposedAtHeight, current);
        assert_eq!(ret.version, V1_0);
        assert_eq!(ret.info.as_ref(), b"meta");
        assert_eq!(ret.status, IUpdate::ProposalStatus::Pending);
        assert_eq!(ret.state.yes, 0);
        assert_eq!(ret.state.no, 0);
    });
}

#[test]
fn cancel_proposal_removes_pending_index() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 10u64;
        let proposal_id = update
            .create_proposal(PROPOSER, V2_0, min_activation(current), b"", current)
            .unwrap();

        update
            .cancel_proposal(proposal_id, PROPOSER, current + 1)
            .unwrap();
        let proposal = update.read_proposal(proposal_id).unwrap().unwrap();
        assert_eq!(proposal.status, ProposalStatus::Cancelled);
        assert!(update.list_pending_proposal_ids().unwrap().is_empty());
    });
}

#[test]
fn active_version_helpers_roundtrip() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        update.set_active_version(V1_5, 500).unwrap();

        assert_eq!(
            get_active_version(storage.clone()).unwrap(),
            Some(V1_5)
        );
        assert_eq!(
            version_at_height(storage.clone(), 500).unwrap(),
            Some(V1_5)
        );
        assert!(is_version_active_eq(storage.clone(), V1_5).unwrap());
        assert!(is_version_active_gte(storage.clone(), V1_2).unwrap());
        assert!(!is_version_active_eq(storage.clone(), V1_9).unwrap());
    });
}

#[test]
fn rejects_downgrade_proposal() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        update.set_active_version(V2_0, 1).unwrap();

        let err = update
            .create_proposal(PROPOSER, V1_9, min_activation(10), b"", 10)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("downgrade")
        ));
    });
}

#[test]
fn protocol_version_encoding_roundtrip() {
    let version = encode_protocol_version(7, 42);
    assert_eq!(protocol_version_major(version), 7);
    assert_eq!(protocol_version_minor(version), 42);
    assert_eq!(
        encode_protocol_version(1, MAX_PROTOCOL_VERSION_MINOR),
        (1 << 24) | MAX_PROTOCOL_VERSION_MINOR
    );
    assert_eq!(encode_protocol_version(0, 0), 0);
}

#[test]
fn proposal_record_dynamic_fields_roundtrip() {
    with_update(|storage| {
        let update = Update::new(storage.clone());
        let proposal_id = U256::from(1);
        let record = ProposalRecord {
            id: proposal_id,
            status: ProposalStatus::Pending.to_u8(),
            activation_height: 200,
            voting_deadline_height: 150,
            proposer: PROPOSER,
            proposed_at_height: 100,
            yes_votes: 0,
            no_votes: 0,
            version: V9_8,
            info: b"dynamic-bytes-payload".to_vec(),
        };
        update.proposals.create(&record).unwrap();
        let loaded = update.proposals.get(proposal_id).unwrap().unwrap();
        assert_eq!(loaded.version, V9_8);
        assert_eq!(loaded.info, b"dynamic-bytes-payload");
    });
}

#[test]
fn vote_record_roundtrip() {
    with_update(|storage| {
        let update = Update::new(storage.clone());
        let proposal_id = U256::from(7);
        let key = vote_key(proposal_id, VOTER_A);
        let record = VoteRecord {
            vote_key: key,
            voter: VOTER_A,
            vote_kind: VoteKind::Yes.to_u8(),
            block_number: 42,
        };
        update.votes.create(&record).unwrap();
        let loaded = update.votes.get(key).unwrap().unwrap();
        assert_eq!(loaded.voter, VOTER_A);
        assert_eq!(loaded.vote_kind, VoteKind::Yes.to_u8());
        assert_eq!(loaded.block_number, 42);
        assert_eq!(
            loaded.into_vote_info(proposal_id).unwrap().proposal_id,
            proposal_id
        );
    });
}

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
            version: V1_2,
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
        assert_eq!(ret.version, V1_2);
        assert_eq!(ret.info.as_ref(), b"notes");
        assert_eq!(ret.status, IUpdate::ProposalStatus::Pending);
    });
}

#[test]
fn dispatch_cast_vote_and_reject_duplicate() {
    with_update(|storage| {
        let current = 50u64;
        let create_data = IUpdate::createProposalCall {
            version: V1_0,
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
            version: V2_0,
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
            V3_0
        );

        let is_active_data = IUpdate::isVersionActiveCall {
            version: V3_0,
        }
        .abi_encode();
        let is_active_bytes =
            dispatch(storage.clone(), &is_active_data, PROPOSER, U256::ZERO).unwrap();
        assert!(IUpdate::isVersionActiveCall::abi_decode_returns(&is_active_bytes).unwrap());

        let current = 100u64;
        let create_data = IUpdate::createProposalCall {
            version: V3_1,
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
