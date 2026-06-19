use alloy_primitives::U256;
use alloy_sol_types::{SolCall, SolEvent};

use crate::precompile::{dispatch, IUpdate};
use crate::schema::Update;

use super::{
    event_count, has_event, min_activation, with_update_provider, UpdateTestExt, PROPOSER, V1_2,
    V1_3, VOTER_A, VOTER_B,
};

#[test]
fn dispatch_emits_proposal_created_vote_cast_and_cancelled_events() {
    let provider = with_update_provider(|storage| {
        let current = 100u64;
        let create_data = IUpdate::createProposalCall {
            version: V1_2.raw(),
            activationHeight: min_activation(current),
            info: b"notes".to_vec().into(),
        }
        .abi_encode();
        let created = dispatch(storage.clone(), &create_data, PROPOSER, U256::ZERO).unwrap();
        let proposal_id = IUpdate::createProposalCall::abi_decode_returns(&created).unwrap();

        let vote_data = IUpdate::castVoteCall {
            proposalId: proposal_id,
            approve: true,
        }
        .abi_encode();
        dispatch(storage.clone(), &vote_data, VOTER_A, U256::ZERO).unwrap();

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
}

#[test]
fn lifecycle_emits_approved_and_upgrade_activated_events() {
    let provider = with_update_provider(|storage| {
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
        update.process_begin_block_test(activation).unwrap();
    });

    assert!(has_event(
        &provider,
        IUpdate::ProposalApproved::SIGNATURE_HASH
    ));
    assert!(has_event(
        &provider,
        IUpdate::UpgradeActivated::SIGNATURE_HASH
    ));
}

#[test]
fn lifecycle_emits_expired_event_without_quorum() {
    let provider = with_update_provider(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let proposal_id = update
            .create_proposal(PROPOSER, V1_2, min_activation(current), b"", current)
            .unwrap();
        update
            .cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
            .unwrap();

        let deadline = update
            .read_proposal(proposal_id)
            .unwrap()
            .unwrap()
            .voting_deadline_height;
        update.process_begin_block_test(deadline + 1).unwrap();
    });

    assert!(has_event(
        &provider,
        IUpdate::ProposalExpired::SIGNATURE_HASH
    ));
}

#[test]
fn lifecycle_emits_rejected_event_on_activation_conflict() {
    let provider = with_update_provider(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let first = update
            .create_proposal(PROPOSER, V1_2, activation, b"", current)
            .unwrap();
        let second = update
            .create_proposal(PROPOSER, V1_3, activation, b"", current)
            .unwrap();

        for proposal_id in [first, second] {
            update
                .cast_vote_approve(proposal_id, VOTER_A, true, current + 2)
                .unwrap();
            update
                .cast_vote_approve(proposal_id, VOTER_B, true, current + 3)
                .unwrap();
        }

        let deadline = update
            .read_proposal(first)
            .unwrap()
            .unwrap()
            .voting_deadline_height;
        update.process_begin_block_test(deadline + 1).unwrap();
    });

    assert!(has_event(
        &provider,
        IUpdate::ProposalApproved::SIGNATURE_HASH
    ));
    assert!(has_event(
        &provider,
        IUpdate::ProposalRejected::SIGNATURE_HASH
    ));
    assert_eq!(
        event_count(&provider, IUpdate::ProposalApproved::SIGNATURE_HASH),
        1
    );
    assert_eq!(
        event_count(&provider, IUpdate::ProposalRejected::SIGNATURE_HASH),
        1
    );
}
