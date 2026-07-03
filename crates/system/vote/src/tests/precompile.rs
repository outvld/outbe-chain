use alloy_primitives::{Address, U256};
use alloy_sol_types::{SolCall, SolEvent};

use outbe_primitives::addresses::{UPDATE_ADDRESS, VOTE_ADDRESS};
use outbe_primitives::error::PrecompileError;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;

use crate::precompile::{dispatch_with_handlers, IVote};
use crate::schema::Vote;

use super::{
    create_proposal_test, empty_update_payload, setup_default_validators, test_vote_registry,
    PROPOSER, VOTER_A, VOTER_B,
};

fn dispatch(
    storage: StorageHandle<'_>,
    data: &[u8],
    caller: Address,
    value: U256,
) -> outbe_primitives::error::Result<alloy_primitives::Bytes> {
    dispatch_with_handlers(storage, data, caller, value, test_vote_registry())
}

fn with_vote_provider<F: FnOnce(StorageHandle)>(block_number: u64, f: F) -> HashMapStorageProvider {
    let mut provider = HashMapStorageProvider::new(1);
    provider.set_block_number(block_number);
    let storage = StorageHandle::new(&mut provider);
    setup_default_validators(storage.clone());
    f(storage);
    provider
}

#[test]
fn precompile_abi_compiles() {
    let _ = IVote::createProposalCall::SIGNATURE;
    let _ = IVote::castVoteCall::SIGNATURE;
    let _ = IVote::getProposalCall::SIGNATURE;
}

#[test]
fn dispatch_create_proposal_emits_event() {
    let provider = with_vote_provider(100, |storage| {
        let payload = empty_update_payload(100);
        let data = IVote::createProposalCall {
            targetModule: UPDATE_ADDRESS,
            payload,
        }
        .abi_encode();

        let ret = dispatch(storage.clone(), &data, PROPOSER, U256::ZERO).unwrap();
        let proposal_id = IVote::createProposalCall::abi_decode_returns(&ret).unwrap();
        assert_eq!(proposal_id, U256::from(1));
    });

    assert!(has_event(&provider, IVote::ProposalCreated::SIGNATURE_HASH,));
}

#[test]
fn dispatch_cast_vote_emits_event() {
    let provider = with_vote_provider(100, |storage| {
        let mut governance = Vote::new(storage.clone());
        let proposal_id = create_proposal_test(
            &mut governance,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(100),
            100,
        )
        .unwrap();

        let data = IVote::castVoteCall {
            proposalId: proposal_id,
            approve: true,
        }
        .abi_encode();
        dispatch(storage.clone(), &data, VOTER_A, U256::ZERO).unwrap();
    });

    assert!(has_event(&provider, IVote::VoteCast::SIGNATURE_HASH));
}

#[test]
fn dispatch_rejects_non_zero_value() {
    with_vote_provider(100, |storage| {
        let data = IVote::getProposalCall {
            proposalId: U256::from(1),
        }
        .abi_encode();
        let err = dispatch(storage, &data, PROPOSER, U256::from(1)).unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("non-payable")
        ));
    });
}

#[test]
fn dispatch_views_return_abi_shaped_data() {
    with_vote_provider(200, |storage| {
        let mut governance = Vote::new(storage.clone());
        let payload = update_json_payload_for_test(200);
        let proposal_id = create_proposal_test(
            &mut governance,
            PROPOSER,
            UPDATE_ADDRESS,
            &payload,
            200,
        )
        .unwrap();
        governance
            .cast_vote_approve(proposal_id, VOTER_A, true, 201)
            .unwrap();
        governance
            .cast_vote_approve(proposal_id, VOTER_B, false, 202)
            .unwrap();

        let get_data = IVote::getProposalCall {
            proposalId: proposal_id,
        }
        .abi_encode();
        let ret = dispatch(storage.clone(), &get_data, PROPOSER, U256::ZERO).unwrap();
        let info = IVote::getProposalCall::abi_decode_returns(&ret).unwrap();
        assert_eq!(info.proposalId, proposal_id);
        assert_eq!(info.proposer, PROPOSER);
        assert_eq!(info.targetModule, UPDATE_ADDRESS);
        assert_eq!(info.payload, payload);
        assert_eq!(info.state.yes, 1);
        assert_eq!(info.state.no, 1);
        assert_eq!(info.votersCount, U256::from(2));

        let voters_data = IVote::getProposalVotersCall {
            proposalId: proposal_id,
            index: U256::ZERO,
            count: U256::from(10),
        }
        .abi_encode();
        let voters_ret = dispatch(storage.clone(), &voters_data, PROPOSER, U256::ZERO).unwrap();
        let voters = IVote::getProposalVotersCall::abi_decode_returns(&voters_ret).unwrap();
        assert_eq!(voters, vec![VOTER_A, VOTER_B]);

        let list_data = IVote::listProposalsCall {
            index: U256::ZERO,
            count: U256::from(10),
        }
        .abi_encode();
        let list_ret = dispatch(storage, &list_data, PROPOSER, U256::ZERO).unwrap();
        let ids = IVote::listProposalsCall::abi_decode_returns(&list_ret).unwrap();
        assert_eq!(ids, vec![proposal_id]);
    });
}

#[test]
fn dispatch_create_proposal_rejects_non_zero_value_before_state_change() {
    with_vote_provider(100, |storage| {
        let vote = Vote::new(storage.clone());
        let before = vote.proposal_count.read().unwrap();
        let payload = empty_update_payload(100);
        let data = IVote::createProposalCall {
            targetModule: UPDATE_ADDRESS,
            payload,
        }
        .abi_encode();
        let err = dispatch(storage.clone(), &data, PROPOSER, U256::from(1)).unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("non-payable")
        ));
        assert_eq!(vote.proposal_count.read().unwrap(), before);
    });
}

#[test]
fn dispatch_cast_vote_rejects_non_zero_value_before_state_change() {
    with_vote_provider(100, |storage| {
        let mut vote = Vote::new(storage.clone());
        let proposal_id = create_proposal_test(
            &mut vote,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(100),
            100,
        )
        .unwrap();
        let voters_before = vote.read_proposal_voters(proposal_id).unwrap().len();
        let data = IVote::castVoteCall {
            proposalId: proposal_id,
            approve: true,
        }
        .abi_encode();
        let err = dispatch(storage.clone(), &data, VOTER_A, U256::from(1)).unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("non-payable")
        ));
        assert_eq!(
            vote.read_proposal_voters(proposal_id).unwrap().len(),
            voters_before
        );
    });
}

fn update_json_payload_for_test(current_height: u64) -> String {
    super::update_json_payload(
        outbe_update::encode_protocol_version(1, 2),
        super::min_activation_at(current_height),
        "notes",
    )
}

fn has_event(provider: &HashMapStorageProvider, topic0: alloy_primitives::B256) -> bool {
    provider
        .get_events(VOTE_ADDRESS)
        .iter()
        .any(|log| log.topics().first() == Some(&topic0))
}
