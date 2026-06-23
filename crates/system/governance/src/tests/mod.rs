use alloy_primitives::{address, U256};

use crate::runtime::quorum_reached;
use crate::schema::ProposalStatus;
use crate::state::{vote_key, VoteKind};

#[test]
fn proposal_status_storage_roundtrip() {
    assert_eq!(ProposalStatus::Pending.to_u8(), 0);
    assert_eq!(ProposalStatus::Expired.to_u8(), 3);
    assert_eq!(
        ProposalStatus::from_u8(ProposalStatus::Approved.to_u8()).unwrap(),
        ProposalStatus::Approved
    );
    assert!(ProposalStatus::Approved.is_terminal());
    assert!(!ProposalStatus::Pending.is_terminal());
    assert!(ProposalStatus::from_u8(4).is_err());
}

#[test]
fn vote_kind_bool_roundtrip() {
    assert_eq!(VoteKind::from_approve(true), VoteKind::Yes);
    assert_eq!(VoteKind::from_approve(false), VoteKind::No);
    assert!(VoteKind::Yes.to_approve());
    assert!(!VoteKind::No.to_approve());
}

#[test]
fn quorum_uses_two_thirds_threshold() {
    assert!(!quorum_reached(0, 0));
    assert!(!quorum_reached(2, 4));
    assert!(quorum_reached(3, 4));
    assert!(quorum_reached(2, 3));
}

#[test]
fn vote_key_depends_on_proposal_and_voter() {
    let voter_a = address!("0x1111111111111111111111111111111111111111");
    let voter_b = address!("0x2222222222222222222222222222222222222222");

    assert_ne!(
        vote_key(U256::from(1), voter_a),
        vote_key(U256::from(2), voter_a)
    );
    assert_ne!(
        vote_key(U256::from(1), voter_a),
        vote_key(U256::from(1), voter_b)
    );
}
