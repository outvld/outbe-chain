use alloy_primitives::B256;
use alloy_sol_types::SolEvent;

use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
use outbe_update::constants::MIN_ACTIVATION_BUFFER;
use outbe_update::encode_protocol_version;
use outbe_update::handlers::EMPTY_UPGRADE_HANDLER_REGISTRY;
use outbe_update::payload::encode_scheduled_update_payload;
use outbe_update::precompile::IUpdate;
use outbe_update::schema::Update;
use outbe_update::ProtocolVersion;

use crate::constants::VOTING_WINDOW_BLOCKS;
use crate::schema::ProposalStatus;
use crate::schema::Vote;
use crate::targets::{SCHEDULE_UPDATE_ACTION, UPDATE_TARGET_MODULE};

use super::{with_vote, VoteTestExt, PROPOSER, VOTER_A, VOTER_B};

const V1_2: ProtocolVersion = encode_protocol_version(1, 2);
const UNKNOWN_MODULE: B256 = B256::repeat_byte(0xAB);
const UNKNOWN_ACTION: B256 = B256::repeat_byte(0xCD);

fn min_activation_at(height: u64) -> u64 {
    height.saturating_add(MIN_ACTIVATION_BUFFER)
}

#[test]
fn approved_vote_proposal_schedules_update_and_activates() {
    with_vote(|storage| {
        let mut governance = Vote::new(storage.clone());
        let current = 100u64;
        let deadline = current + VOTING_WINDOW_BLOCKS + 1;
        let activation = min_activation_at(deadline);
        let payload = encode_scheduled_update_payload(V1_2, activation, b"notes");
        let proposal_id = governance
            .create_proposal(
                PROPOSER,
                UPDATE_TARGET_MODULE,
                SCHEDULE_UPDATE_ACTION,
                &payload,
                current,
            )
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

        assert_eq!(update.get_active_version().unwrap(), Some(V1_2));
        assert_eq!(update.get_active_version_height().unwrap(), activation);
    });
}

#[test]
fn invalid_update_payload_marks_proposal_rejected() {
    with_vote(|storage| {
        let mut governance = Vote::new(storage.clone());
        let current = 200u64;
        let proposal_id = governance
            .create_proposal(
                PROPOSER,
                UPDATE_TARGET_MODULE,
                SCHEDULE_UPDATE_ACTION,
                b"too-short",
                current,
            )
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
        assert_eq!(record.proposal_status().unwrap(), ProposalStatus::Rejected);

        let update = Update::new(storage);
        assert!(update.read_scheduled_update(proposal_id).unwrap().is_none());
    });
}

#[test]
fn unknown_target_or_action_is_rejected_without_update_state_change() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 250u64;
        let deadline = current + VOTING_WINDOW_BLOCKS + 1;
        let activation = min_activation_at(deadline);
        let payload = encode_scheduled_update_payload(V1_2, activation, b"");

        let unknown_target = vote
            .create_proposal(
                PROPOSER,
                UNKNOWN_MODULE,
                SCHEDULE_UPDATE_ACTION,
                &payload,
                current,
            )
            .unwrap();
        for (voter, off) in [(VOTER_A, 1), (VOTER_B, 2)] {
            vote.cast_vote_approve(unknown_target, voter, true, current + off)
                .unwrap();
        }

        let unknown_action = vote
            .create_proposal(
                PROPOSER,
                UPDATE_TARGET_MODULE,
                UNKNOWN_ACTION,
                &payload,
                current + 1,
            )
            .unwrap();
        for (voter, off) in [(VOTER_A, 3), (VOTER_B, 4)] {
            vote.cast_vote_approve(unknown_action, voter, true, current + off)
                .unwrap();
        }

        vote.process_begin_block_test(deadline + 1).unwrap();

        assert_eq!(
            vote.proposals
                .get(unknown_target)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Rejected
        );
        assert_eq!(
            vote.proposals
                .get(unknown_action)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Rejected
        );

        let update = Update::new(storage);
        assert!(update
            .read_scheduled_update(unknown_target)
            .unwrap()
            .is_none());
        assert!(update
            .read_scheduled_update(unknown_action)
            .unwrap()
            .is_none());
        assert_eq!(
            update.get_active_version().unwrap(),
            Some(ProtocolVersion::ZERO)
        );
    });
}

#[test]
fn expired_update_proposal_does_not_emit_upgrade_activated() {
    let mut provider = outbe_primitives::storage::hashmap::HashMapStorageProvider::new(1);
    let storage = outbe_primitives::storage::StorageHandle::new(&mut provider);
    super::setup_default_validators(storage.clone());

    let mut vote = Vote::new(storage.clone());
    let current = 400u64;
    let proposal_id = vote
        .create_proposal(
            PROPOSER,
            UPDATE_TARGET_MODULE,
            SCHEDULE_UPDATE_ACTION,
            &encode_scheduled_update_payload(
                V1_2,
                min_activation_at(current + VOTING_WINDOW_BLOCKS),
                b"",
            ),
            current,
        )
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
