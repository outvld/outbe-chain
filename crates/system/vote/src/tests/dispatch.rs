use alloy_primitives::address;
use alloy_sol_types::SolEvent;

use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
use outbe_primitives::error::PrecompileError;
use outbe_update::encode_protocol_version;
use outbe_update::handlers::EMPTY_UPGRADE_HANDLER_REGISTRY;
use outbe_update::precompile::IUpdate;
use outbe_update::schema::Update;
use outbe_update::ProtocolVersion;

use crate::constants::VOTING_WINDOW_BLOCKS;
use crate::schema::ProposalStatus;
use crate::schema::Vote;

use super::{
    empty_update_payload, min_activation_at, update_json_payload, with_vote, VoteTestExt, PROPOSER,
    VOTER_A, VOTER_B,
};

const V1_2: ProtocolVersion = encode_protocol_version(1, 2);
const UNKNOWN_TARGET: alloy_primitives::Address =
    address!("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead");

#[test]
fn approved_vote_proposal_schedules_update_and_activates() {
    with_vote(|storage| {
        let mut governance = Vote::new(storage.clone());
        let current = 100u64;
        let deadline = current + VOTING_WINDOW_BLOCKS + 1;
        let activation = min_activation_at(deadline);
        let payload = update_json_payload(V1_2, activation, "notes");
        let proposal_id = governance
            .create_proposal(PROPOSER, UPDATE_ADDRESS, &payload, current)
            .unwrap();

        governance
            .cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
            .unwrap();
        governance
            .cast_vote_approve(proposal_id, VOTER_B, true, current + 2)
            .unwrap();

        let deadline = current + VOTING_WINDOW_BLOCKS + 1;
        governance.process_begin_block_test(deadline).unwrap();

        let record = governance.proposals.get(proposal_id).unwrap().unwrap();
        assert_eq!(record.proposal_status().unwrap(), ProposalStatus::Approved);

        let mut update = Update::new(storage.clone());
        let scheduled = update.read_scheduled_update(proposal_id).unwrap().unwrap();
        assert_eq!(scheduled.version, V1_2);
        assert_eq!(scheduled.activation_height, activation);

        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(activation, 0, 1),
            storage.clone(),
        );
        update
            .process_begin_block_with_handlers(&ctx, &EMPTY_UPGRADE_HANDLER_REGISTRY)
            .unwrap();

        assert_eq!(update.get_active_version().unwrap(), V1_2);
        assert_eq!(update.get_active_version_height().unwrap(), activation);
    });
}

#[test]
fn invalid_json_payload_is_rejected_at_creation() {
    with_vote(|storage| {
        let mut governance = Vote::new(storage.clone());
        let err = governance
            .create_proposal(
                PROPOSER,
                UPDATE_ADDRESS,
                "not-json",
                200,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("invalid proposal payload")
        ));
    });
}

#[test]
fn invalid_update_payload_is_rejected_at_creation() {
    with_vote(|storage| {
        let mut governance = Vote::new(storage.clone());
        let err = governance
            .create_proposal(
                PROPOSER,
                UPDATE_ADDRESS,
                r#"{"version":0,"activationHeight":1000,"info":""}"#,
                200,
            )
            .unwrap_err();
        assert!(matches!(err, PrecompileError::Revert(_)));
    });
}

#[test]
fn handler_conflict_marks_proposal_rejected() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 250u64;
        let deadline = current + VOTING_WINDOW_BLOCKS + 1;
        let activation = min_activation_at(deadline);
        let payload = update_json_payload(V1_2, activation, "");

        let first = vote
            .create_proposal(PROPOSER, UPDATE_ADDRESS, &payload, current)
            .unwrap();
        for (voter, off) in [(VOTER_A, 1), (VOTER_B, 2)] {
            vote.cast_vote_approve(first, voter, true, current + off)
                .unwrap();
        }
        vote.process_begin_block_test(deadline).unwrap();
        assert_eq!(
            vote.proposals
                .get(first)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Approved
        );

        let second = vote
            .create_proposal(VOTER_A, UPDATE_ADDRESS, &payload, current + 1)
            .unwrap();
        for (voter, off) in [(VOTER_A, 3), (VOTER_B, 4)] {
            vote.cast_vote_approve(second, voter, true, current + off)
                .unwrap();
        }
        vote.process_begin_block_test(deadline + 1).unwrap();
        assert_eq!(
            vote.proposals
                .get(second)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Rejected
        );
    });
}

#[test]
fn unknown_target_is_rejected_at_creation() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 260u64;
        let payload = empty_update_payload(current);
        let err = vote
            .create_proposal(PROPOSER, UNKNOWN_TARGET, &payload, current)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("unknown vote target module")
        ));
    });
}

#[test]
fn expired_update_proposal_does_not_emit_upgrade_activated() {
    let mut provider = outbe_primitives::storage::hashmap::HashMapStorageProvider::new(1);
    let storage = outbe_primitives::storage::StorageHandle::new(&mut provider);
    super::setup_default_validators(storage.clone());

    let mut vote = Vote::new(storage.clone());
    let current = 400u64;
    let payload = update_json_payload(
        V1_2,
        min_activation_at(current + VOTING_WINDOW_BLOCKS),
        "",
    );
    let proposal_id = vote
        .create_proposal(PROPOSER, UPDATE_ADDRESS, &payload, current)
        .unwrap();
    vote.cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
        .unwrap();

    let deadline = current + VOTING_WINDOW_BLOCKS + 1;
    vote.process_begin_block_test(deadline).unwrap();
    assert_eq!(
        vote.proposals
            .get(proposal_id)
            .unwrap()
            .unwrap()
            .proposal_status()
            .unwrap(),
        ProposalStatus::Expired
    );

    let update = Update::new(storage);
    assert!(update.read_scheduled_update(proposal_id).unwrap().is_none());
    assert!(!provider
        .get_events(outbe_primitives::addresses::UPDATE_ADDRESS)
        .iter()
        .any(|log| log.topics().first() == Some(&IUpdate::UpgradeActivated::SIGNATURE_HASH)));
}
