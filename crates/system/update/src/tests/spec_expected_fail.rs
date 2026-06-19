//! Executable specs from `test_task_update.md`.
//!
//! These tests encode the intended final operator/spec flow at a high level:
//! signed precompile calls (`dispatch`), ABI reads (`getProposal`, `getActiveVersion`),
//! and event signatures from `IUpdate.sol`.
//!
//! Tests marked `#[should_panic(expected = "SPEC_EXPECTED_FAIL: ...")]` document
//! gaps versus the original spec. When implementation catches up, remove the
//! attribute and keep the flow/assertions unchanged.

use alloy_primitives::{address, Address, U256};
use alloy_sol_types::{SolCall, SolEvent};

use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::error::PrecompileError;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_validatorset::contract::ValidatorSet;

use crate::api::{get_active_version, version_at_height};
use crate::handlers::{UpgradeHandlerRegistry, UpgradeHandlerSpec};
use crate::precompile::{dispatch, IUpdate};
use crate::schema::Update;
use crate::state::{protocol_version_major, protocol_version_minor, ProposalStatus, VoteKind};
use crate::{encode_protocol_version, ProtocolVersion};

use super::{
    block_ctx, event_count, has_event, min_activation, with_update, UpdateTestExt, PROPOSER, V1_2,
    V1_3, VALIDATOR_OWNER, VOTER_A, VOTER_B,
};

const VOTER_C: Address = address!("0x5555555555555555555555555555555555555555");

fn dummy_pubkey(seed: u8) -> [u8; 48] {
    let mut pk = [0u8; 48];
    pk[0] = seed;
    pk
}

fn register_active_validator(storage: StorageHandle, addr: Address, seed: u8) {
    let mut vs = ValidatorSet::new(storage.clone());
    vs.config_owner.write(VALIDATOR_OWNER).unwrap();
    vs.config_max_validators.write(100).unwrap();
    vs.register_validator(VALIDATOR_OWNER, addr, &dummy_pubkey(seed))
        .unwrap();
    vs.activate_validator(addr).unwrap();
}

fn setup_four_validators(storage: StorageHandle) {
    register_active_validator(storage.clone(), PROPOSER, 1);
    register_active_validator(storage.clone(), VOTER_A, 2);
    register_active_validator(storage.clone(), VOTER_B, 3);
    register_active_validator(storage.clone(), VOTER_C, 4);
}

fn with_four_validators_at<F: FnOnce(StorageHandle, u64)>(
    current: u64,
    f: F,
) -> HashMapStorageProvider {
    let mut provider = HashMapStorageProvider::new(1);
    provider.set_block_number(current);
    let storage = StorageHandle::new(&mut provider);
    setup_four_validators(storage.clone());
    f(storage, current);
    provider
}

fn with_four_validators_provider<F: FnOnce(StorageHandle)>(f: F) -> HashMapStorageProvider {
    with_four_validators_at(100, |storage, _| f(storage))
}

fn spec_version_string(version: ProtocolVersion) -> String {
    format!(
        "v{}.{}.0",
        protocol_version_major(version),
        protocol_version_minor(version)
    )
}

fn dispatch_create_proposal(
    storage: StorageHandle,
    proposer: Address,
    version: ProtocolVersion,
    activation: u64,
    info: &[u8],
) -> U256 {
    let create_data = IUpdate::createProposalCall {
        version,
        activationHeight: activation,
        info: info.to_vec().into(),
    }
    .abi_encode();
    let created = dispatch(storage.clone(), &create_data, proposer, U256::ZERO)
        .expect("createProposal dispatch should succeed for active validator");
    IUpdate::createProposalCall::abi_decode_returns(&created).expect("decode proposal id")
}

fn dispatch_cast_vote(storage: StorageHandle, voter: Address, proposal_id: U256, approve: bool) {
    let vote_data = IUpdate::castVoteCall {
        proposalId: proposal_id,
        approve,
    }
    .abi_encode();
    dispatch(storage, &vote_data, voter, U256::ZERO).expect("castVote dispatch should succeed");
}

fn dispatch_get_proposal(storage: StorageHandle, proposal_id: U256) -> IUpdate::getProposalReturn {
    let get_data = IUpdate::getProposalCall {
        proposalId: proposal_id,
    }
    .abi_encode();
    let ret_bytes = dispatch(storage, &get_data, PROPOSER, U256::ZERO)
        .expect("getProposal dispatch should succeed");
    IUpdate::getProposalCall::abi_decode_returns(&ret_bytes).expect("decode getProposal return")
}

fn dispatch_get_active_version_u32(storage: StorageHandle) -> u32 {
    let active_data = IUpdate::getActiveVersionCall {}.abi_encode();
    let active_bytes = dispatch(storage, &active_data, PROPOSER, U256::ZERO)
        .expect("getActiveVersion dispatch should succeed");
    IUpdate::getActiveVersionCall::abi_decode_returns(&active_bytes).expect("decode active version")
}

fn assert_spec_active_version_string(storage: StorageHandle, expected: &str) {
    assert_eq!(
        dispatch_get_active_version_string(storage),
        expected,
        "active version string helper must match encoded protocol version"
    );
}

fn dispatch_get_active_version_string(storage: StorageHandle) -> String {
    // Draft spec: `getActiveVersion() -> string`. Current ABI returns `uint32`.
    let version = dispatch_get_active_version_u32(storage);
    spec_version_string(version)
}

// ---- state / lifecycle specs ------------------------------------------------

#[test]
fn state_create_proposal_persists_plan_and_pending_index() {
    let provider = with_four_validators_at(100, |storage, current| {
        let activation = min_activation(current);
        let proposal_id = dispatch_create_proposal(
            storage.clone(),
            PROPOSER,
            V1_2,
            activation,
            b"release-notes",
        );

        let ret = dispatch_get_proposal(storage.clone(), proposal_id);
        assert_eq!(ret.proposalId, proposal_id);
        assert_eq!(ret.proposer, PROPOSER);
        assert_eq!(ret.proposedAtHeight, current);
        assert_eq!(ret.activationHeight, activation);
        assert_eq!(ret.version, V1_2);
        assert_eq!(ret.info.as_ref(), b"release-notes");
        assert_eq!(ret.status, IUpdate::ProposalStatus::Pending);

        let list_data = IUpdate::listPendingProposalsCall {}.abi_encode();
        let list_bytes = dispatch(storage, &list_data, PROPOSER, U256::ZERO).unwrap();
        let ids = IUpdate::listPendingProposalsCall::abi_decode_returns(&list_bytes).unwrap();
        assert_eq!(ids, vec![proposal_id]);
    });

    assert!(has_event(
        &provider,
        IUpdate::ProposalCreated::SIGNATURE_HASH
    ));
}

#[test]
fn state_vote_persists_vote_and_tally() {
    with_four_validators_at(50, |storage, current| {
        let proposal_id = dispatch_create_proposal(
            storage.clone(),
            PROPOSER,
            V1_2,
            min_activation(current),
            b"",
        );
        dispatch_cast_vote(storage.clone(), VOTER_A, proposal_id, true);
        dispatch_cast_vote(storage.clone(), VOTER_B, proposal_id, false);

        let update = Update::new(storage.clone());
        let vote_a = update
            .read_vote(proposal_id, VOTER_A)
            .unwrap()
            .expect("vote record for VOTER_A");
        assert_eq!(vote_a.vote_kind, VoteKind::Yes);
        assert_eq!(vote_a.voter, VOTER_A);

        let ret = dispatch_get_proposal(storage, proposal_id);
        assert_eq!(ret.state.yes, 1);
        assert_eq!(ret.state.no, 1);
    });
}

#[test]
fn state_active_version_history_roundtrip() {
    with_four_validators_provider(|storage| {
        let mut update = Update::new(storage.clone());
        let height = 500u64;
        update.set_active_version(V1_2, height).unwrap();

        assert_eq!(get_active_version(storage.clone()).unwrap(), Some(V1_2));
        assert_eq!(
            version_at_height(storage.clone(), height).unwrap(),
            Some(V1_2)
        );
        assert_spec_active_version_string(storage, "v1.2.0");
    });
}

#[test]
fn lifecycle_tally_approves_with_three_of_four_yes() {
    with_four_validators_provider(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id =
            dispatch_create_proposal(storage.clone(), PROPOSER, V1_2, activation, b"");
        dispatch_cast_vote(storage.clone(), VOTER_A, proposal_id, true);
        dispatch_cast_vote(storage.clone(), VOTER_B, proposal_id, true);
        dispatch_cast_vote(storage.clone(), VOTER_C, proposal_id, true);

        let deadline = update
            .read_proposal(proposal_id)
            .unwrap()
            .unwrap()
            .voting_deadline_height;
        update.process_begin_block_test(deadline + 1).unwrap();

        let proposal = update.read_proposal(proposal_id).unwrap().unwrap();
        assert_eq!(proposal.status, ProposalStatus::Approved);
    });
}

#[test]
fn lifecycle_tally_expires_with_two_of_four_yes() {
    with_four_validators_provider(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let proposal_id = dispatch_create_proposal(
            storage.clone(),
            PROPOSER,
            V1_2,
            min_activation(current),
            b"",
        );
        dispatch_cast_vote(storage.clone(), VOTER_A, proposal_id, true);
        dispatch_cast_vote(storage.clone(), VOTER_B, proposal_id, true);

        let deadline = update
            .read_proposal(proposal_id)
            .unwrap()
            .unwrap()
            .voting_deadline_height;
        update.process_begin_block_test(deadline + 1).unwrap();

        let proposal = update.read_proposal(proposal_id).unwrap().unwrap();
        assert_eq!(proposal.status, ProposalStatus::Expired);
        assert_spec_active_version_string(storage, "v0.0.0");
    });
}

#[test]
fn lifecycle_pending_to_approved_to_activated() {
    with_four_validators_provider(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id =
            dispatch_create_proposal(storage.clone(), PROPOSER, V1_2, activation, b"");
        dispatch_cast_vote(storage.clone(), VOTER_A, proposal_id, true);
        dispatch_cast_vote(storage.clone(), VOTER_B, proposal_id, true);
        dispatch_cast_vote(storage.clone(), VOTER_C, proposal_id, true);

        let deadline = update
            .read_proposal(proposal_id)
            .unwrap()
            .unwrap()
            .voting_deadline_height;
        update.process_begin_block_test(deadline + 1).unwrap();
        update.process_begin_block_test(activation).unwrap();

        let proposal = update.read_proposal(proposal_id).unwrap().unwrap();
        assert_eq!(proposal.status, ProposalStatus::Activated);
        assert_eq!(get_active_version(storage.clone()).unwrap(), Some(V1_2));
        assert_spec_active_version_string(storage, "v1.2.0");
    });
}

#[test]
fn lifecycle_activation_is_idempotent_or_replay_safe() {
    let provider = with_four_validators_provider(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id =
            dispatch_create_proposal(storage.clone(), PROPOSER, V1_2, activation, b"");
        dispatch_cast_vote(storage.clone(), VOTER_A, proposal_id, true);
        dispatch_cast_vote(storage.clone(), VOTER_B, proposal_id, true);
        dispatch_cast_vote(storage.clone(), VOTER_C, proposal_id, true);

        let deadline = update
            .read_proposal(proposal_id)
            .unwrap()
            .unwrap()
            .voting_deadline_height;
        update.process_begin_block_test(deadline + 1).unwrap();
        update.process_begin_block_test(activation).unwrap();
        update.process_begin_block_test(activation).unwrap();
    });

    let activated_events = event_count(&provider, IUpdate::UpgradeActivated::SIGNATURE_HASH);
    assert_eq!(
        activated_events, 1,
        "replay activation must not emit duplicate UpgradeActivated events"
    );
}

#[test]
fn lifecycle_conflicting_proposals_same_activation_height() {
    with_four_validators_provider(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let first = dispatch_create_proposal(storage.clone(), PROPOSER, V1_2, activation, b"");
        let second = dispatch_create_proposal(storage.clone(), PROPOSER, V1_3, activation, b"");

        for proposal_id in [first, second] {
            dispatch_cast_vote(storage.clone(), VOTER_A, proposal_id, true);
            dispatch_cast_vote(storage.clone(), VOTER_B, proposal_id, true);
            dispatch_cast_vote(storage.clone(), VOTER_C, proposal_id, true);
        }

        let deadline = update
            .read_proposal(first)
            .unwrap()
            .unwrap()
            .voting_deadline_height;
        update.process_begin_block_test(deadline + 1).unwrap();

        assert_eq!(
            update.read_proposal(first).unwrap().unwrap().status,
            ProposalStatus::Approved
        );
        assert_eq!(
            update.read_proposal(second).unwrap().unwrap().status,
            ProposalStatus::Rejected
        );
    });
}

#[test]
fn lifecycle_handler_error_is_fatal() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id = update
            .create_proposal(PROPOSER, V1_2, activation, b"", current)
            .unwrap();
        update
            .cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
            .unwrap();
        update
            .cast_vote_approve(proposal_id, VOTER_B, true, current + 2)
            .unwrap();

        let deadline = update
            .read_proposal(proposal_id)
            .unwrap()
            .unwrap()
            .voting_deadline_height;
        update.process_begin_block_test(deadline + 1).unwrap();

        let ctx = block_ctx(storage.clone(), activation);
        let registry = UpgradeHandlerRegistry::new(&[UpgradeHandlerSpec {
            version: Some(V1_2),
            label: "failing_handler",
            handler: |_, _| Err(PrecompileError::Fatal("handler failed".into())),
        }]);
        let err = update
            .process_begin_block_with_handlers(&ctx, &registry)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Fatal(message) if message.contains("handler failed")
        ));
        assert_eq!(
            update.read_proposal(proposal_id).unwrap().unwrap().status,
            ProposalStatus::Approved
        );
    });
}

// ---- ABI / event surface specs ----------------------------------------------

#[test]
#[should_panic(
    expected = "SPEC_EXPECTED_FAIL: createProposal(string,uint64,bytes) draft ABI not exposed"
)]
fn abi_create_proposal_accepts_semver_string() {
    assert_eq!(
        IUpdate::createProposalCall::SIGNATURE,
        "createProposal(string,uint64,bytes)",
        "SPEC_EXPECTED_FAIL: createProposal(string,uint64,bytes) draft ABI not exposed"
    );
}

#[test]
#[should_panic(expected = "SPEC_EXPECTED_FAIL: castVote(uint256,uint8) draft ABI not exposed")]
fn abi_cast_vote_accepts_uint8_kind() {
    assert_eq!(
        IUpdate::castVoteCall::SIGNATURE,
        "castVote(uint256,uint8)",
        "SPEC_EXPECTED_FAIL: castVote(uint256,uint8) draft ABI not exposed"
    );
}

#[test]
#[should_panic(
    expected = "SPEC_EXPECTED_FAIL: getActiveVersion must return semver string per draft spec"
)]
fn abi_get_active_version_returns_string() {
    with_four_validators_provider(|storage| {
        assert_eq!(
            dispatch_get_active_version_string(storage),
            "v1.2.0",
            "SPEC_EXPECTED_FAIL: getActiveVersion must return semver string per draft spec"
        );
    });
}

#[test]
#[should_panic(expected = "SPEC_EXPECTED_FAIL: isVersionActive(string) draft ABI not exposed")]
fn abi_is_version_active_accepts_string() {
    assert_eq!(
        IUpdate::isVersionActiveCall::SIGNATURE,
        "isVersionActive(string)",
        "SPEC_EXPECTED_FAIL: isVersionActive(string) draft ABI not exposed"
    );
}

#[test]
fn events_write_calls_emit_receipt_visible_logs() {
    let provider = with_four_validators_provider(|storage| {
        let current = 100u64;
        let proposal_id = dispatch_create_proposal(
            storage.clone(),
            PROPOSER,
            V1_2,
            min_activation(current),
            b"notes",
        );
        dispatch_cast_vote(storage.clone(), VOTER_A, proposal_id, true);

        let cancel_data = IUpdate::cancelProposalCall {
            proposalId: proposal_id,
        }
        .abi_encode();
        dispatch(storage, &cancel_data, PROPOSER, U256::ZERO).unwrap();
    });

    assert!(has_event(
        &provider,
        IUpdate::ProposalCreated::SIGNATURE_HASH
    ));
    assert!(has_event(&provider, IUpdate::VoteCast::SIGNATURE_HASH));
    assert!(has_event(
        &provider,
        IUpdate::ProposalCancelled::SIGNATURE_HASH
    ));
    assert!(
        provider
            .get_events(UPDATE_ADDRESS)
            .iter()
            .all(|log| { log.topics().first().is_some() }),
        "write-call events must carry contract event signatures"
    );
}

#[test]
fn events_lifecycle_emit_receipt_visible_logs() {
    let provider = with_four_validators_provider(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id =
            dispatch_create_proposal(storage.clone(), PROPOSER, V1_2, activation, b"");
        dispatch_cast_vote(storage.clone(), VOTER_A, proposal_id, true);
        dispatch_cast_vote(storage.clone(), VOTER_B, proposal_id, true);
        dispatch_cast_vote(storage.clone(), VOTER_C, proposal_id, true);

        let deadline = update
            .read_proposal(proposal_id)
            .unwrap()
            .unwrap()
            .voting_deadline_height;
        update.process_begin_block_test(deadline + 1).unwrap();
        update.process_begin_block_test(activation).unwrap();
    });

    let approved_event_exists = has_event(&provider, IUpdate::ProposalApproved::SIGNATURE_HASH);
    let activated_event_exists = has_event(&provider, IUpdate::UpgradeActivated::SIGNATURE_HASH);
    assert!(
        approved_event_exists && activated_event_exists,
        "lifecycle processing must emit approval and activation events"
    );
}

#[test]
fn abi_get_plan_returns_spec_plan_shape() {
    with_four_validators_at(100, |storage, current| {
        let activation = min_activation(current);
        let proposal_id =
            dispatch_create_proposal(storage.clone(), PROPOSER, V1_2, activation, b"meta");
        let ret = dispatch_get_proposal(storage.clone(), proposal_id);
        assert_eq!(ret.proposalId, proposal_id);
        assert_eq!(ret.proposer, PROPOSER);
        assert_eq!(ret.proposedAtHeight, current);
        assert_eq!(ret.activationHeight, activation);
        assert_eq!(ret.version, V1_2);
        assert_eq!(ret.info.as_ref(), b"meta");
        assert_eq!(ret.status, IUpdate::ProposalStatus::Pending);
    });
}

#[test]
fn downgrade_attempt_rejected_at_proposal_creation() {
    with_four_validators_at(10, |storage, current| {
        let mut update = Update::new(storage.clone());
        update.set_active_version(V1_3, 1).unwrap();

        let err = dispatch(
            storage.clone(),
            &IUpdate::createProposalCall {
                version: encode_protocol_version(1, 2),
                activationHeight: min_activation(current),
                info: Default::default(),
            }
            .abi_encode(),
            PROPOSER,
            U256::ZERO,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                PrecompileError::Revert(msg) if msg.contains("downgrade")
            ),
            "downgrade proposal must be rejected"
        );
        assert_spec_active_version_string(storage, "v1.3.0");
    });
}
