use alloy_primitives::{address, Address, U256};

use outbe_primitives::error::PrecompileError;

use crate::constants::{MAX_PENDING_PROPOSALS, MAX_PENDING_PROPOSALS_PER_VALIDATOR};
use crate::api::get_proposal;
use crate::schema::ProposalStatus;
use crate::schema::Vote;
use crate::state::{active_validator_addresses, calculate_vote_tally, VoteTally};
use outbe_primitives::addresses::UPDATE_ADDRESS;

use super::{
    create_proposal_test, empty_update_payload, register_active_validator, register_pending_validator,
    with_vote, VoteTestExt, PENDING_VOTER, PROPOSER, VOTER_A, VOTER_B,
};

const OUTSIDER: Address = address!("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead");

fn extra_validator_addr(index: u32) -> Address {
    let mut bytes = [0u8; 20];
    bytes[0] = (index >> 8) as u8;
    bytes[1] = (index & 0xff) as u8;
    Address::from(bytes)
}

#[test]
fn create_proposal_rejects_non_validator() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 10u64;
        let err = create_proposal_test(&mut vote, OUTSIDER,
                UPDATE_ADDRESS,
                &empty_update_payload(current),
                current,
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
        let current = 10u64;
        let proposal_id = create_proposal_test(&mut vote, PROPOSER,
                UPDATE_ADDRESS,
                &empty_update_payload(current),
                current,
            )
            .unwrap();
        let err = vote
            .cast_vote_approve(proposal_id, OUTSIDER, true, 11)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("not an eligible validator")
        ));
    });
}

#[test]
fn pending_validator_can_cast_vote() {
    with_vote(|storage| {
        register_pending_validator(storage.clone(), PENDING_VOTER, 4);
        let mut vote = Vote::new(storage.clone());
        let current = 50u64;
        let proposal_id = create_proposal_test(&mut vote, PROPOSER,
                UPDATE_ADDRESS,
                &empty_update_payload(current),
                current,
            )
            .unwrap();

        vote.cast_vote_approve(proposal_id, PENDING_VOTER, true, current + 1)
            .unwrap();

        assert_eq!(
            vote.read_proposal_voters(proposal_id).unwrap(),
            vec![PENDING_VOTER]
        );
    });
}

#[test]
fn pending_validator_cannot_create_proposal() {
    with_vote(|storage| {
        register_pending_validator(storage.clone(), PENDING_VOTER, 4);
        let mut vote = Vote::new(storage.clone());
        let current = 10u64;
        let err = create_proposal_test(&mut vote, PENDING_VOTER,
                UPDATE_ADDRESS,
                &empty_update_payload(current),
                current,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("not an active validator")
        ));
    });
}

#[test]
fn pending_vote_is_stored_but_excluded_from_active_tally() {
    with_vote(|storage| {
        register_pending_validator(storage.clone(), PENDING_VOTER, 4);
        let mut vote = Vote::new(storage.clone());
        let current = 60u64;
        let proposal_id = create_proposal_test(&mut vote, PROPOSER,
                UPDATE_ADDRESS,
                &empty_update_payload(current),
                current,
            )
            .unwrap();

        vote.cast_vote_approve(proposal_id, PENDING_VOTER, true, current + 1)
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_A, true, current + 2)
            .unwrap();

        let record = vote.proposals.get(proposal_id).unwrap().unwrap();
        let active = active_validator_addresses(storage.clone()).unwrap();
        let tally = calculate_vote_tally(&vote, &record, &active).unwrap();
        assert_eq!(tally, VoteTally { yes: 1, no: 0 });

        let info = get_proposal(storage, proposal_id).unwrap().unwrap();
        assert_eq!(info.state, VoteTally { yes: 1, no: 0 });
        assert_eq!(info.voters_count, 2);
    });
}

#[test]
fn cast_vote_rejects_after_deadline() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 100u64;
        let proposal_id = create_proposal_test(&mut vote, PROPOSER,
                UPDATE_ADDRESS,
                &empty_update_payload(current),
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
        let proposal_id = create_proposal_test(&mut vote, PROPOSER,
                UPDATE_ADDRESS,
                &empty_update_payload(current),
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
        let proposal_id = create_proposal_test(&mut vote, PROPOSER,
                UPDATE_ADDRESS,
                &empty_update_payload(current),
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
            vote.proposals
                .get(proposal_id)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Pending
        );

        vote.process_begin_block_test(deadline + 1).unwrap();
        assert_ne!(
            vote.proposals
                .get(proposal_id)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Pending
        );
    });
}

#[test]
fn max_pending_proposals_per_validator_is_enforced() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 350u64;
        create_proposal_test(&mut vote,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(current),
            current,
        )
        .unwrap();

        let err = create_proposal_test(&mut vote, PROPOSER,
                UPDATE_ADDRESS,
                &empty_update_payload(current + 1),
                current + 1,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("validator has too many pending")
        ));
        assert_eq!(
            vote.pending_proposal_count_by_proposer(PROPOSER).unwrap(),
            MAX_PENDING_PROPOSALS_PER_VALIDATOR
        );
    });
}

#[test]
fn other_validator_can_create_while_proposer_has_pending() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 360u64;
        create_proposal_test(&mut vote,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(current),
            current,
        )
        .unwrap();

        create_proposal_test(&mut vote,
            VOTER_A,
            UPDATE_ADDRESS,
            &empty_update_payload(current + 1),
            current + 1,
        )
        .unwrap();
    });
}

#[test]
fn proposer_can_create_after_pending_proposal_is_tallied() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 370u64;
        create_proposal_test(&mut vote,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(current),
            current,
        )
        .unwrap();

        let deadline = current + crate::constants::VOTING_WINDOW_BLOCKS + 1;
        vote.process_begin_block_test(deadline).unwrap();

        let record = vote.proposals.get(U256::from(1)).unwrap().unwrap();
        assert_ne!(record.proposal_status().unwrap(), ProposalStatus::Pending);

        create_proposal_test(&mut vote,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(deadline + 1),
            deadline + 1,
        )
        .unwrap();
    });
}

#[test]
fn max_pending_proposals_is_enforced() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage.clone());
        let current = 400u64;
        for i in 0..MAX_PENDING_PROPOSALS {
            let proposer = match i {
                0 => PROPOSER,
                1 => VOTER_A,
                2 => VOTER_B,
                _ => {
                    let addr = extra_validator_addr(i);
                    register_active_validator(storage.clone(), addr, (i + 16) as u8);
                    addr
                }
            };
            create_proposal_test(&mut vote,
                proposer,
                UPDATE_ADDRESS,
                &empty_update_payload(current + i as u64),
                current + i as u64,
            )
            .unwrap();
        }
        let overflow_proposer = extra_validator_addr(MAX_PENDING_PROPOSALS);
        register_active_validator(
            storage.clone(),
            overflow_proposer,
            (MAX_PENDING_PROPOSALS + 16) as u8,
        );
        let err = create_proposal_test(&mut vote, overflow_proposer,
                UPDATE_ADDRESS,
                &empty_update_payload(current + MAX_PENDING_PROPOSALS as u64),
                current + MAX_PENDING_PROPOSALS as u64,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("too many pending")
        ));
    });
}
