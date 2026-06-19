use alloy_primitives::U256;

use outbe_primitives::error::PrecompileError;

use crate::api::{
    get_active_version, is_version_active_eq, is_version_active_gte, version_at_height,
};
use crate::precompile::{get_proposal_return, IUpdate};
use crate::schema::Update;
use crate::state::{ProposalStatus, VoteTally};

use super::{
    min_activation, with_update, PROPOSER, STRANGER, V1_0, V1_1, V1_2, V1_5, V1_9, V2_0, VOTER_A,
    VOTER_B,
};

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
fn get_proposal_return_matches_abi_shape() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 10u64;
        let proposal_id = update
            .create_proposal(PROPOSER, V1_0, min_activation(current), b"meta", current)
            .unwrap();
        let proposal = update.read_proposal(proposal_id).unwrap().unwrap();
        let ret = get_proposal_return(&proposal);
        assert_eq!(ret.proposalId, proposal_id);
        assert_eq!(ret.proposer, PROPOSER);
        assert_eq!(ret.proposedAtHeight, current);
        assert_eq!(ret.version, V1_0.raw());
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

        assert_eq!(get_active_version(storage.clone()).unwrap(), Some(V1_5));
        assert_eq!(version_at_height(storage.clone(), 500).unwrap(), Some(V1_5));
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
fn non_validator_cannot_create_proposal() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let err = update
            .create_proposal(STRANGER, V1_2, min_activation(100), b"", 100)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("not an active validator")
        ));
    });
}

#[test]
fn non_validator_cannot_vote() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 50u64;
        let proposal_id = update
            .create_proposal(PROPOSER, V1_1, min_activation(current), b"", current)
            .unwrap();
        let err = update
            .cast_vote_approve(proposal_id, STRANGER, true, current + 1)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("not an active validator")
        ));
    });
}
