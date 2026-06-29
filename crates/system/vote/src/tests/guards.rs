use alloy_primitives::{address, Address};

use outbe_primitives::error::PrecompileError;

use crate::constants::MAX_PENDING_PROPOSALS;
use crate::schema::ProposalStatus;
use crate::schema::Vote;
use crate::targets::{SCHEDULE_UPDATE_ACTION, UPDATE_TARGET_MODULE};

use super::{VoteTestExt, PROPOSER, VOTER_A, VOTER_B, with_vote};

const OUTSIDER: Address = address!("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead");

#[test]
fn create_proposal_rejects_non_validator() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let err = vote
            .create_proposal(
                OUTSIDER,
                UPDATE_TARGET_MODULE,
                SCHEDULE_UPDATE_ACTION,
                b"",
                10,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("not an active validator")
        ));
    });
}

#[test]
fn cast_vote_rejects_non_validator() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let proposal_id = vote
            .create_proposal(
                PROPOSER,
                UPDATE_TARGET_MODULE,
                SCHEDULE_UPDATE_ACTION,
                b"",
                10,
            )
            .unwrap();
        let err = vote
            .cast_vote_approve(proposal_id, OUTSIDER, true, 11)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("not an active validator")
        ));
    });
}

#[test]
fn cast_vote_rejects_after_deadline() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 100u64;
        let proposal_id = vote
            .create_proposal(
                PROPOSER,
                UPDATE_TARGET_MODULE,
                SCHEDULE_UPDATE_ACTION,
                b"",
                current,
            )
            .unwrap();
        let record = vote.proposals.get(proposal_id).unwrap().unwrap();
        let after_deadline = record.voting_deadline_height + 1;
        let err = vote
            .cast_vote_approve(proposal_id, VOTER_A, true, after_deadline)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("voting window is closed")
        ));
    });
}

#[test]
fn cast_vote_rejects_when_not_pending() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 200u64;
        let proposal_id = vote
            .create_proposal(
                PROPOSER,
                UPDATE_TARGET_MODULE,
                SCHEDULE_UPDATE_ACTION,
                b"",
                current,
            )
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
            .unwrap();

        let deadline = current + crate::constants::VOTING_WINDOW_BLOCKS + 1;
        vote.process_begin_block_test(deadline).unwrap();

        let record = vote.proposals.get(proposal_id).unwrap().unwrap();
        assert_ne!(record.proposal_status().unwrap(), ProposalStatus::Pending);

        let err = vote
            .cast_vote_approve(proposal_id, VOTER_B, true, deadline + 1)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("not pending")
        ));
    });
}

#[test]
fn begin_block_does_not_tally_at_exact_deadline() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 300u64;
        let proposal_id = vote
            .create_proposal(
                PROPOSER,
                UPDATE_TARGET_MODULE,
                SCHEDULE_UPDATE_ACTION,
                b"",
                current,
            )
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_B, true, current + 2)
            .unwrap();

        let record = vote.proposals.get(proposal_id).unwrap().unwrap();
        let deadline = record.voting_deadline_height;
        vote.process_begin_block_test(deadline).unwrap();
        assert_eq!(
            vote.proposals.get(proposal_id).unwrap().unwrap().proposal_status().unwrap(),
            ProposalStatus::Pending
        );

        vote.process_begin_block_test(deadline + 1).unwrap();
        assert_ne!(
            vote.proposals.get(proposal_id).unwrap().unwrap().proposal_status().unwrap(),
            ProposalStatus::Pending
        );
    });
}

#[test]
fn max_pending_proposals_is_enforced() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 400u64;
        for i in 0..MAX_PENDING_PROPOSALS {
            vote.create_proposal(
                PROPOSER,
                UPDATE_TARGET_MODULE,
                SCHEDULE_UPDATE_ACTION,
                b"",
                current + i as u64,
            )
            .unwrap();
        }
        let err = vote
            .create_proposal(
                PROPOSER,
                UPDATE_TARGET_MODULE,
                SCHEDULE_UPDATE_ACTION,
                b"",
                current + MAX_PENDING_PROPOSALS as u64,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("too many pending")
        ));
    });
}
