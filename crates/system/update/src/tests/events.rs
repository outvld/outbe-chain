use alloy_primitives::U256;
use alloy_sol_types::SolEvent;

use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::error::PrecompileError;

use crate::precompile::{dispatch, IUpdate};
use crate::schema::Update;

use super::{
    min_activation, schedule_update, with_update, with_update_provider, UpdateTestExt, V1_2,
};

#[test]
fn schedule_emits_scheduled_update_created_event() {
    let provider = with_update_provider(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        schedule_update(
            &mut update,
            U256::from(1),
            V1_2,
            min_activation(current),
            b"notes",
            current,
        )
        .unwrap();
    });

    assert!(has_event(
        &provider,
        IUpdate::ScheduledUpdateCreated::SIGNATURE_HASH
    ));
}

#[test]
fn lifecycle_emits_upgrade_activated_event() {
    let provider = with_update_provider(|storage| {
        let mut update = Update::new(storage.clone());
        let current = 100u64;
        let activation = min_activation(current);
        schedule_update(&mut update, U256::from(1), V1_2, activation, b"", current).unwrap();
        update.process_begin_block_test(activation).unwrap();
    });

    assert!(has_event(
        &provider,
        IUpdate::UpgradeActivated::SIGNATURE_HASH
    ));
}

#[test]
fn dispatch_rejects_unknown_selector() {
    with_update(|storage| {
        // Legacy createProposal selector no longer dispatched at UPDATE_ADDRESS.
        let data = alloy_primitives::hex!("b1a14106");
        let err =
            dispatch(storage, &data, alloy_primitives::Address::ZERO, U256::ZERO).unwrap_err();
        assert!(matches!(err, PrecompileError::Revert(_)));
    });
}

fn has_event(
    provider: &outbe_primitives::storage::hashmap::HashMapStorageProvider,
    topic0: alloy_primitives::B256,
) -> bool {
    provider
        .get_events(UPDATE_ADDRESS)
        .iter()
        .any(|log| log.topics().first() == Some(&topic0))
}
