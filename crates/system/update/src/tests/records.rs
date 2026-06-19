use alloy_primitives::U256;

use crate::constants::MAX_PROTOCOL_VERSION_MINOR;
use crate::encode_protocol_version;
use crate::precompile::IUpdate;
use crate::schema::{ProposalRecord, Update, VoteRecord};
use crate::state::{
    protocol_version_major, protocol_version_minor, vote_key, ProposalStatus, VoteKind,
};

use super::{with_update, PROPOSER, V9_8, VOTER_A};

#[test]
fn vote_kind_bool_roundtrip() {
    assert_eq!(VoteKind::from_approve(true), VoteKind::Yes);
    assert_eq!(VoteKind::from_approve(false), VoteKind::No);
    assert!(VoteKind::Yes.to_approve());
    assert!(!VoteKind::No.to_approve());
}

#[test]
fn proposal_status_abi_conversion() {
    assert_eq!(ProposalStatus::Pending.to_u8(), 0);
    assert_eq!(ProposalStatus::Cancelled.to_u8(), 5);
    assert_eq!(ProposalStatus::from_u8(0).unwrap(), ProposalStatus::Pending);
    assert_eq!(
        IUpdate::ProposalStatus::from(ProposalStatus::Approved),
        IUpdate::ProposalStatus::Approved
    );
}

#[test]
fn protocol_version_encoding_roundtrip() {
    let version = encode_protocol_version(7, 42);
    assert_eq!(protocol_version_major(version), 7);
    assert_eq!(protocol_version_minor(version), 42);
    assert_eq!(
        encode_protocol_version(1, MAX_PROTOCOL_VERSION_MINOR).raw(),
        (1 << 24) | MAX_PROTOCOL_VERSION_MINOR
    );
    assert_eq!(encode_protocol_version(0, 0).raw(), 0);
}

#[test]
fn proposal_record_dynamic_fields_roundtrip() {
    with_update(|storage| {
        let update = Update::new(storage.clone());
        let proposal_id = U256::from(1);
        let record = ProposalRecord {
            id: proposal_id,
            status: ProposalStatus::Pending.to_u8(),
            activation_height: 200,
            voting_deadline_height: 150,
            proposer: PROPOSER,
            proposed_at_height: 100,
            yes_votes: 0,
            no_votes: 0,
            version: V9_8,
            info: b"dynamic-bytes-payload".to_vec(),
        };
        update.proposals.create(&record).unwrap();
        let loaded = update.proposals.get(proposal_id).unwrap().unwrap();
        assert_eq!(loaded.version, V9_8);
        assert_eq!(loaded.info, b"dynamic-bytes-payload");
    });
}

#[test]
fn vote_record_roundtrip() {
    with_update(|storage| {
        let update = Update::new(storage.clone());
        let proposal_id = U256::from(7);
        let key = vote_key(proposal_id, VOTER_A);
        let record = VoteRecord {
            vote_key: key,
            voter: VOTER_A,
            vote_kind: VoteKind::Yes.to_u8(),
            block_number: 42,
        };
        update.votes.create(&record).unwrap();
        let loaded = update.votes.get(key).unwrap().unwrap();
        assert_eq!(loaded.voter, VOTER_A);
        assert_eq!(loaded.vote_kind, VoteKind::Yes.to_u8());
        assert_eq!(loaded.block_number, 42);
        assert_eq!(
            loaded.into_vote_info(proposal_id).unwrap().proposal_id,
            proposal_id
        );
    });
}
