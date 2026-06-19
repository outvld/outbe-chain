use crate::api::{get_active_version, version_at_height};
use crate::schema::Update;
use crate::state::ProposalStatus;

use super::{min_activation, with_update, UpdateTestExt, PROPOSER, V1_2, V1_3, VOTER_A, VOTER_B};

#[test]
fn quorum_requires_two_thirds() {
    use crate::runtime::quorum_reached;

    assert!(!quorum_reached(1, 3));
    assert!(quorum_reached(2, 3));
    assert!(!quorum_reached(2, 4));
    assert!(quorum_reached(3, 4));
}

#[test]
fn lifecycle_approves_with_quorum() {
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

        let proposal = update.read_proposal(proposal_id).unwrap().unwrap();
        assert_eq!(proposal.status, ProposalStatus::Approved);
        assert!(update.list_pending_proposal_ids().unwrap().is_empty());
        assert_eq!(
            update.list_waiting_for_activation_proposal_ids().unwrap(),
            vec![proposal_id]
        );
    });
}

#[test]
fn lifecycle_expires_without_quorum() {
    with_update(|storage| {
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

        let proposal = update.read_proposal(proposal_id).unwrap().unwrap();
        assert_eq!(proposal.status, ProposalStatus::Expired);
        assert!(update.list_pending_proposal_ids().unwrap().is_empty());
    });
}

#[test]
fn lifecycle_activates_approved_proposal() {
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
        update.process_begin_block_test(activation).unwrap();

        let proposal = update.read_proposal(proposal_id).unwrap().unwrap();
        assert_eq!(proposal.status, ProposalStatus::Activated);
        assert!(update.list_pending_proposal_ids().unwrap().is_empty());
        assert!(update
            .list_waiting_for_activation_proposal_ids()
            .unwrap()
            .is_empty());
        assert_eq!(get_active_version(storage.clone()).unwrap(), Some(V1_2));
        assert_eq!(version_at_height(storage, activation).unwrap(), Some(V1_2));
    });
}

#[test]
fn approved_proposal_is_excluded_from_pending_index() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let proposal_id = update
            .create_proposal(PROPOSER, V1_2, min_activation(current), b"", current)
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

        assert!(update.list_pending_proposal_ids().unwrap().is_empty());
        assert_eq!(
            update.list_waiting_for_activation_proposal_ids().unwrap(),
            vec![proposal_id]
        );
    });
}

#[test]
fn lifecycle_rejects_conflicting_activation_height() {
    with_update(|storage| {
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

        assert_eq!(
            update.read_proposal(first).unwrap().unwrap().status,
            ProposalStatus::Approved
        );
        assert_eq!(
            update.read_proposal(second).unwrap().unwrap().status,
            ProposalStatus::Rejected
        );
        assert_eq!(
            update.list_waiting_for_activation_proposal_ids().unwrap(),
            vec![first]
        );
        assert!(update.list_pending_proposal_ids().unwrap().is_empty());
    });
}
