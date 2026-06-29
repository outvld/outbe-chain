use alloy_primitives::U256;
use alloy_sol_types::SolCall;

use outbe_primitives::error::PrecompileError;

use crate::precompile::{dispatch, IUpdate};
use crate::schema::Update;

use super::{min_activation, schedule_update, with_update, V1_2, V3_0, V3_1};

#[test]
fn precompile_abi_compiles() {
    let _ = IUpdate::getActiveVersionCall::SIGNATURE;
    let _ = IUpdate::getScheduledUpdateCall::SIGNATURE;
    let _ = IUpdate::listWaitingForActivationCall::SIGNATURE;
}

#[test]
fn dispatch_get_scheduled_update() {
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

        let get_data = IUpdate::getScheduledUpdateCall {
            proposalId: proposal_id,
        }
        .abi_encode();
        let ret_bytes = dispatch(
            storage.clone(),
            &get_data,
            alloy_primitives::Address::ZERO,
            U256::ZERO,
        )
        .unwrap();
        let ret = IUpdate::getScheduledUpdateCall::abi_decode_returns(&ret_bytes).unwrap();
        assert_eq!(ret.proposalId, proposal_id);
        assert_eq!(ret.version, V1_2.raw());
        assert_eq!(ret.info.as_ref(), b"notes");
        assert_eq!(ret.status, IUpdate::ScheduledUpdateStatus::Pending);
    });
}

#[test]
fn dispatch_active_version_and_waiting_list() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        update.set_active_version(V3_0, 42).unwrap();

        let active_data = IUpdate::getActiveVersionCall {}.abi_encode();
        let active_bytes = dispatch(
            storage.clone(),
            &active_data,
            alloy_primitives::Address::ZERO,
            U256::ZERO,
        )
        .unwrap();
        assert_eq!(
            IUpdate::getActiveVersionCall::abi_decode_returns(&active_bytes).unwrap(),
            V3_0.raw()
        );

        let is_active_data = IUpdate::isVersionActiveCall {
            version: V3_0.raw(),
        }
        .abi_encode();
        let is_active_bytes = dispatch(
            storage.clone(),
            &is_active_data,
            alloy_primitives::Address::ZERO,
            U256::ZERO,
        )
        .unwrap();
        assert!(IUpdate::isVersionActiveCall::abi_decode_returns(&is_active_bytes).unwrap());

        let current = 100u64;
        schedule_update(
            &mut update,
            U256::from(1),
            V3_1,
            min_activation(current),
            b"",
            current,
        )
        .unwrap();

        let list_data = IUpdate::listWaitingForActivationCall {}.abi_encode();
        let list_bytes = dispatch(
            storage,
            &list_data,
            alloy_primitives::Address::ZERO,
            U256::ZERO,
        )
        .unwrap();
        let ids = IUpdate::listWaitingForActivationCall::abi_decode_returns(&list_bytes).unwrap();
        assert_eq!(ids, vec![U256::from(1)]);
    });
}

#[test]
fn dispatch_rejects_non_zero_value() {
    with_update(|storage| {
        let data = IUpdate::getActiveVersionCall {}.abi_encode();
        let err = dispatch(
            storage,
            &data,
            alloy_primitives::Address::ZERO,
            U256::from(1),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("non-payable")
        ));
    });
}

#[test]
fn dispatch_rejects_unknown_selector() {
    with_update(|storage| {
        let data = [0xde, 0xad, 0xbe, 0xef];
        let err =
            dispatch(storage, &data, alloy_primitives::Address::ZERO, U256::ZERO).unwrap_err();
        assert!(matches!(err, PrecompileError::Revert(_)));
    });
}
