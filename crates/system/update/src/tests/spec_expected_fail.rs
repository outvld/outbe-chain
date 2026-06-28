use alloy_primitives::U256;
use alloy_sol_types::{SolCall, SolEvent};

use outbe_primitives::error::PrecompileError;

use crate::payload::encode_scheduled_update_payload;
use crate::precompile::{dispatch, IUpdate};
use crate::schema::ScheduledUpdateStatus;
use crate::schema::Update;

use super::{
    min_activation, schedule_update, with_update, with_update_provider, UpdateTestExt, V1_2, V1_3,
};

#[test]
fn schedule_update_persists_record_and_waiting_index() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let proposal_id = U256::from(1);
        schedule_update(
            &mut update,
            proposal_id,
            V1_2,
            min_activation(current),
            b"notes",
            current,
        )
        .unwrap();

        let scheduled = update.read_scheduled_update(proposal_id).unwrap().unwrap();
        assert_eq!(scheduled.version, V1_2);
        assert_eq!(scheduled.status, ScheduledUpdateStatus::Pending);
        assert_eq!(
            update.list_waiting_for_activation_proposal_ids().unwrap(),
            vec![proposal_id]
        );

        let get_data = IUpdate::getScheduledUpdateCall {
            proposalId: proposal_id,
        }
        .abi_encode();
        let ret_bytes = dispatch(
            storage,
            &get_data,
            alloy_primitives::Address::ZERO,
            U256::ZERO,
        )
        .unwrap();
        let ret = IUpdate::getScheduledUpdateCall::abi_decode_returns(&ret_bytes).unwrap();
        assert_eq!(ret.version, V1_2.raw());
        assert_eq!(ret.status, IUpdate::ScheduledUpdateStatus::Pending);
    });
}

#[test]
fn schedule_emits_scheduled_update_created_event() {
    let provider = with_update_provider(|storage| {
        let mut update = Update::new(storage.clone());
        schedule_update(
            &mut update,
            U256::from(1),
            V1_2,
            min_activation(100),
            b"",
            100,
        )
        .unwrap();
    });

    assert!(provider
        .get_events(outbe_primitives::addresses::UPDATE_ADDRESS)
        .iter()
        .any(|log| log.topics().first() == Some(&IUpdate::ScheduledUpdateCreated::SIGNATURE_HASH)));
}

#[test]
fn activation_sets_active_version() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id = U256::from(1);
        schedule_update(&mut update, proposal_id, V1_2, activation, b"", current).unwrap();
        update.process_begin_block_test(activation).unwrap();

        assert_eq!(update.get_active_version().unwrap(), Some(V1_2));
        assert_eq!(
            update
                .read_scheduled_update(proposal_id)
                .unwrap()
                .unwrap()
                .status,
            ScheduledUpdateStatus::Activated
        );
    });
}

#[test]
fn rejects_activation_height_before_buffer() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let payload = encode_scheduled_update_payload(V1_2, current + 1, b"");
        let err = update
            .schedule_update_from_vote(U256::from(1), &payload, current)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("activation height")
        ));
    });
}

#[test]
fn second_schedule_at_same_activation_height_is_rejected() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        schedule_update(&mut update, U256::from(1), V1_2, activation, b"", current).unwrap();
        let err = schedule_update(&mut update, U256::from(2), V1_3, activation, b"", current)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("activation height")
        ));
    });
}
