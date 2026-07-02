use alloy_primitives::U256;

use outbe_primitives::error::PrecompileError;

use crate::api::{
    get_active_version, is_version_active_eq, is_version_active_gte, version_at_height,
};
use crate::schema::ScheduledUpdateStatus;
use crate::schema::Update;

use super::{min_activation, schedule_update, with_update, V1_2, V1_3, V1_5, V2_0};

#[test]
fn schedule_update_writes_fields_and_waiting_index() {
    with_update(|storage| {
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
        )
        .unwrap();

        let scheduled = update.read_scheduled_update(proposal_id).unwrap().unwrap();
        assert_eq!(scheduled.proposal_id, proposal_id);
        assert_eq!(scheduled.version, V1_2);
        assert_eq!(scheduled.activation_height, min_activation(current));
        assert_eq!(scheduled.status, ScheduledUpdateStatus::Scheduled);
        assert_eq!(scheduled.info, "release-notes");
        assert_eq!(
            update.list_waiting_for_activation_proposal_ids().unwrap(),
            vec![proposal_id]
        );
    });
}

#[test]
fn active_version_helpers_roundtrip() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        update.set_active_version(V1_5, 500).unwrap();

        assert_eq!(get_active_version(storage.clone()).unwrap(), V1_5);
        assert_eq!(version_at_height(storage.clone(), 500).unwrap(), V1_5);
        assert!(is_version_active_eq(storage.clone(), V1_5).unwrap());
        assert!(is_version_active_gte(storage.clone(), V1_2).unwrap());
        assert!(!is_version_active_eq(storage.clone(), V1_3).unwrap());
    });
}

#[test]
fn rejects_downgrade_schedule() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        update.set_active_version(V2_0, 1).unwrap();

        let err = schedule_update(&mut update, U256::from(1), V1_3, min_activation(10), "", 10)
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("downgrade")
        ));
    });
}

#[test]
fn rejects_duplicate_proposal_id() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let proposal_id = U256::from(1);
        schedule_update(
            &mut update,
            proposal_id,
            V1_2,
            min_activation(current),
            "",
            current,
        )
        .unwrap();

        let err = schedule_update(
            &mut update,
            proposal_id,
            V1_2,
            min_activation(current) + 1,
            "",
            current,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("already exists")
        ));
    });
}

#[test]
fn rejects_conflicting_activation_height() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        schedule_update(&mut update, U256::from(1), V1_2, activation, "", current).unwrap();

        let err =
            schedule_update(&mut update, U256::from(2), V1_2, activation, "", current).unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("activation height")
        ));
    });
}

#[test]
fn max_waiting_for_activation_updates_is_enforced() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let base_activation = min_activation(current);
        for i in 0..crate::constants::MAX_WAITING_FOR_ACTIVATION_UPDATES {
            schedule_update(
                &mut update,
                U256::from(i + 1),
                V1_2,
                base_activation + i as u64,
                "",
                current,
            )
            .unwrap();
        }

        let err = schedule_update(
            &mut update,
            U256::from(65),
            V1_2,
            base_activation + 64,
            "",
            current,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("too many scheduled updates waiting")
        ));
    });
}
