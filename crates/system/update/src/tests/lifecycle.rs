use alloy_primitives::U256;

use crate::api::{get_active_version, version_at_height};
use crate::schema::Update;
use crate::schema::ScheduledUpdateStatus;

use super::{min_activation, schedule_update, with_update, UpdateTestExt, V1_2, V1_3};

#[test]
fn lifecycle_activates_scheduled_update() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        let proposal_id = U256::from(1);
        schedule_update(&mut update, proposal_id, V1_2, activation, b"", current).unwrap();

        update.process_begin_block_test(activation).unwrap();

        let scheduled = update.read_scheduled_update(proposal_id).unwrap().unwrap();
        assert_eq!(scheduled.status, ScheduledUpdateStatus::Activated);
        assert!(update
            .list_waiting_for_activation_proposal_ids()
            .unwrap()
            .is_empty());
        assert_eq!(get_active_version(storage.clone()).unwrap(), Some(V1_2));
        assert_eq!(version_at_height(storage, activation).unwrap(), Some(V1_2));
    });
}

#[test]
fn waiting_index_tracks_pending_scheduled_updates() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let proposal_id = U256::from(1);
        schedule_update(
            &mut update,
            proposal_id,
            V1_2,
            min_activation(current),
            b"",
            current,
        )
        .unwrap();

        assert_eq!(
            update.list_waiting_for_activation_proposal_ids().unwrap(),
            vec![proposal_id]
        );
    });
}

#[test]
fn second_schedule_at_same_height_is_rejected() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        schedule_update(&mut update, U256::from(1), V1_2, activation, b"", current).unwrap();
        assert!(schedule_update(
            &mut update,
            U256::from(2),
            V1_3,
            activation,
            b"",
            current
        )
        .is_err());
        assert_eq!(
            update.list_waiting_for_activation_proposal_ids().unwrap(),
            vec![U256::from(1)]
        );
    });
}
