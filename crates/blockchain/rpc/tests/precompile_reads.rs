//! Integration tests for reading vote/update state via precompile `eth_call` dispatch.
//!
//! Replaces the removed custom JSON-RPC methods:
//! - `outbe_getUpdateActiveVersion` → `IUpdate.getActiveVersion`
//! - `outbe_getUpdateScheduledUpdate` → `IUpdate.getScheduledUpdate`
//! - `outbe_listUpdateWaitingForActivation` → `IUpdate.listWaitingForActivation`
//! - vote proposal status reads → `IVote.getProposal`

use alloy_primitives::{address, Address, U256};
use alloy_sol_types::SolCall;
use outbe_primitives::addresses::{UPDATE_ADDRESS, VOTE_ADDRESS};
use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
use outbe_update::constants::MIN_ACTIVATION_BUFFER;
use outbe_update::payload::encode_schedule_update_json;
use outbe_update::precompile::{dispatch as dispatch_update, IUpdate};
use outbe_update::schema::Update;
use outbe_update::{encode_protocol_version, ProtocolVersion};
use outbe_vote::precompile::{dispatch as dispatch_vote, IVote};
use outbe_vote::schema::Vote;
use outbe_vote::state::ProposalStatus;
use serde_json::Value;

const PROPOSER: Address = address!("0x1111111111111111111111111111111111111111");
const V1_2: ProtocolVersion = encode_protocol_version(1, 2);
const V1_3: ProtocolVersion = encode_protocol_version(1, 3);

fn min_activation(current: u64) -> u64 {
    current.saturating_add(MIN_ACTIVATION_BUFFER)
}

fn with_storage<F: FnOnce(StorageHandle<'_>)>(f: F) {
    let mut provider = HashMapStorageProvider::new(1);
    let storage = StorageHandle::new(&mut provider);
    f(storage);
}

fn eth_call_update(storage: StorageHandle<'_>, data: &[u8]) -> Vec<u8> {
    dispatch_update(
        storage,
        data,
        Address::ZERO,
        U256::ZERO,
    )
    .expect("update precompile eth_call should succeed")
    .into()
}

fn eth_call_vote(storage: StorageHandle<'_>, data: &[u8]) -> Vec<u8> {
    dispatch_vote(
        storage,
        data,
        Address::ZERO,
        U256::ZERO,
    )
    .expect("vote precompile eth_call should succeed")
    .into()
}

fn schedule_update(
    update: &mut Update<'_>,
    proposal_id: U256,
    version: ProtocolVersion,
    activation_height: u64,
    info: &str,
    current_height: u64,
) {
    let payload: Value = serde_json::from_str(&encode_schedule_update_json(
        version,
        activation_height,
        info,
    ))
    .expect("schedule update JSON should parse");
    update
        .schedule_update_from_propose(proposal_id, &payload, current_height)
        .expect("schedule update should succeed");
}

#[test]
fn precompile_addresses_match_eth_call_targets() {
    assert_eq!(UPDATE_ADDRESS, address!("0x000000000000000000000000000000000000EE0B"));
    assert_eq!(VOTE_ADDRESS, address!("0x000000000000000000000000000000000000EE0C"));
}

#[test]
fn eth_call_get_update_active_version() {
    with_storage(|storage| {
        let mut update = Update::new(storage.clone());
        update.set_active_version(V1_2, 500).unwrap();

        let data = IUpdate::getActiveVersionCall {}.abi_encode();
        let ret = eth_call_update(storage.clone(), &data);
        assert_eq!(
            IUpdate::getActiveVersionCall::abi_decode_returns(&ret).unwrap(),
            V1_2.raw()
        );

        let height_data = IUpdate::getActiveVersionHeightCall {}.abi_encode();
        let height_ret = eth_call_update(storage, &height_data);
        assert_eq!(
            IUpdate::getActiveVersionHeightCall::abi_decode_returns(&height_ret).unwrap(),
            500
        );
    });
}

#[test]
fn eth_call_get_update_scheduled_update() {
    with_storage(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let proposal_id = U256::from(1);
        schedule_update(
            &mut update,
            proposal_id,
            V1_2,
            min_activation(current),
            "release-notes",
            current,
        );

        let data = IUpdate::getScheduledUpdateCall {
            proposalId: proposal_id,
        }
        .abi_encode();
        let ret = eth_call_update(storage, &data);
        let scheduled = IUpdate::getScheduledUpdateCall::abi_decode_returns(&ret).unwrap();

        assert_eq!(scheduled.proposalId, proposal_id);
        assert_eq!(scheduled.version, V1_2.raw());
        assert_eq!(scheduled.activationHeight, min_activation(current));
        assert_eq!(scheduled.info.as_ref(), b"release-notes");
        assert_eq!(
            scheduled.status,
            IUpdate::ScheduledUpdateStatus::Scheduled
        );
    });
}

#[test]
fn eth_call_list_update_waiting_for_activation() {
    with_storage(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        schedule_update(
            &mut update,
            U256::from(1),
            V1_2,
            min_activation(current),
            "",
            current,
        );
        schedule_update(
            &mut update,
            U256::from(2),
            V1_3,
            min_activation(current) + 10,
            "",
            current,
        );

        let data = IUpdate::listWaitingForActivationCall {}.abi_encode();
        let ret = eth_call_update(storage, &data);
        let waiting = IUpdate::listWaitingForActivationCall::abi_decode_returns(&ret).unwrap();
        assert_eq!(waiting, vec![U256::from(1), U256::from(2)]);
    });
}

#[test]
fn eth_call_get_vote_proposal() {
    with_storage(|storage| {
        let payload = encode_schedule_update_json(V1_2, min_activation(100), "notes");
        let mut vote = Vote::new(storage.clone());
        let proposal_id = vote
            .write_proposal(
                PROPOSER,
                UPDATE_ADDRESS,
                &payload,
                100,
                200,
                ProposalStatus::Pending,
            )
            .unwrap();

        let data = IVote::getProposalCall {
            proposalId: proposal_id,
        }
        .abi_encode();
        let ret = eth_call_vote(storage, &data);
        let info = IVote::getProposalCall::abi_decode_returns(&ret).unwrap();

        assert_eq!(info.proposalId, proposal_id);
        assert_eq!(info.proposer, PROPOSER);
        assert_eq!(info.targetModule, UPDATE_ADDRESS);
        assert_eq!(info.payload, payload);
        assert_eq!(info.createdHeight, 100);
        assert_eq!(info.votingDeadlineHeight, 200);
        assert_eq!(info.status, IVote::ProposalStatus::Pending);
    });
}
