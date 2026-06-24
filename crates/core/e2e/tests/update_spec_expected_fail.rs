//! Executable update-module specs from `test_task_update.md`.
//!
//! Cross-module flows use `outbe_evm::executor::run_outbe_pre_execution_hooks` and
//! high-level `UPDATE_ADDRESS` precompile dispatch. Operator/RPC/CLI/localnet gaps
//! are marked with checked `#[should_panic(expected = "SPEC_EXPECTED_FAIL: ...")]`.

use alloy_primitives::{address, Address, U256};
use alloy_sol_types::{SolCall, SolEvent};

use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
use outbe_primitives::error::PrecompileError;
use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
use outbe_update::handlers::EMPTY_UPGRADE_HANDLER_REGISTRY;
use outbe_update::lifecycle::UpdateLifecycle;
use outbe_update::precompile::{dispatch, IUpdate};
use outbe_update::schema::Update;
use outbe_update::state::ScheduledUpdateStatus;
use outbe_update::{encode_protocol_version, encode_scheduled_update_payload, ProtocolVersion};

const CHAIN_ID: u64 = 1;
const PROPOSER: Address = address!("0x1111111111111111111111111111111111111111");

const V1_2: ProtocolVersion = encode_protocol_version(1, 2);
const V1_3: ProtocolVersion = encode_protocol_version(1, 3);

fn min_activation(current: u64) -> u64 {
    current.saturating_add(outbe_update::constants::MIN_ACTIVATION_BUFFER)
}

fn with_runtime_at<F: FnOnce(StorageHandle, u64)>(current: u64, f: F) {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(current);
    let storage = StorageHandle::new(&mut provider);
    f(storage, current);
}

fn schedule_update(
    update: &mut Update<'_>,
    proposal_id: U256,
    version: ProtocolVersion,
    activation: u64,
    current: u64,
) {
    let payload = encode_scheduled_update_payload(version, activation, b"");
    update
        .schedule_update_from_governance(proposal_id, &payload, current)
        .expect("schedule_update_from_governance should succeed");
}

fn dispatch_get_active_version_u32(storage: StorageHandle) -> u32 {
    let active_data = IUpdate::getActiveVersionCall {}.abi_encode();
    let active_bytes = dispatch(storage, &active_data, PROPOSER, U256::ZERO)
        .expect("getActiveVersion dispatch should succeed");
    IUpdate::getActiveVersionCall::abi_decode_returns(&active_bytes).expect("decode active version")
}

fn run_update_begin_block(storage: StorageHandle, block_number: u64) {
    storage
        .set_block_timestamp(U256::from(block_number))
        .expect("set block timestamp");
    let ctx = BlockRuntimeContext::new(
        BlockContext::new(block_number, block_number, CHAIN_ID, PROPOSER, Vec::new()),
        storage,
    );
    UpdateLifecycle::begin_block_with_handlers(&ctx, &EMPTY_UPGRADE_HANDLER_REGISTRY)
        .expect("update begin block should succeed");
}

fn has_update_event(provider: &HashMapStorageProvider, topic0: alloy_primitives::B256) -> bool {
    provider
        .get_events(UPDATE_ADDRESS)
        .iter()
        .any(|log| log.topics().first() == Some(&topic0))
}

#[test]
fn e2e_scheduled_update_activates_at_height() {
    with_runtime_at(100, |storage, current| {
        let activation = min_activation(current);
        let proposal_id = U256::from(1);
        let mut update = Update::new(storage.clone());
        schedule_update(&mut update, proposal_id, V1_2, activation, current);

        run_update_begin_block(storage.clone(), activation);

        let scheduled = update.read_scheduled_update(proposal_id).unwrap().unwrap();
        assert_eq!(scheduled.status, ScheduledUpdateStatus::Activated);
        assert_eq!(dispatch_get_active_version_u32(storage), V1_2.raw());
        assert_eq!(V1_2.to_string(), "v1.2");
    });
}

#[test]
fn e2e_downgrade_schedule_rejected() {
    with_runtime_at(10, |storage, current| {
        let mut update = Update::new(storage.clone());
        update.set_active_version(V1_3, 1).unwrap();

        let payload = encode_scheduled_update_payload(V1_2, min_activation(current), b"");
        let err = update
            .schedule_update_from_governance(U256::from(1), &payload, current)
            .unwrap_err();
        assert!(
            matches!(
                err,
                PrecompileError::Revert(msg) if msg.contains("downgrade")
            ),
            "downgrade schedule must be rejected"
        );
    });
}

#[test]
fn e2e_conflicting_activation_heights_rejected() {
    with_runtime_at(100, |storage, current| {
        let activation = min_activation(current);
        let mut update = Update::new(storage.clone());
        schedule_update(&mut update, U256::from(1), V1_2, activation, current);

        let payload = encode_scheduled_update_payload(V1_3, activation, b"");
        let err = update
            .schedule_update_from_governance(U256::from(2), &payload, current)
            .unwrap_err();
        assert!(
            matches!(
                err,
                PrecompileError::Revert(msg) if msg.contains("activation height")
            ),
            "conflicting activation height must be rejected"
        );
    });
}

#[test]
fn e2e_lifecycle_events_visible_in_transaction_receipts() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(100);
    let storage = StorageHandle::new(&mut provider);

    let activation = min_activation(100);
    let proposal_id = U256::from(1);
    let mut update = Update::new(storage.clone());
    schedule_update(&mut update, proposal_id, V1_2, activation, 100);
    run_update_begin_block(storage.clone(), activation);

    let scheduled_event_exists =
        has_update_event(&provider, IUpdate::ScheduledUpdateCreated::SIGNATURE_HASH);
    let activated_event_exists =
        has_update_event(&provider, IUpdate::UpgradeActivated::SIGNATURE_HASH);
    assert!(
        scheduled_event_exists && activated_event_exists,
        "lifecycle processing must emit schedule and activation events"
    );
}

#[test]
fn e2e_legacy_governance_selectors_rejected_at_update_address() {
    with_runtime_at(100, |storage, _current| {
        let err = dispatch(
            storage,
            &[0xb1, 0xa1, 0x41, 0x06],
            PROPOSER,
            U256::ZERO,
        )
        .unwrap_err();
        assert!(matches!(err, PrecompileError::Revert(_)));
    });
}

#[test]
fn startup_binary_version_check_rejects_older_binary() {
    let err =
        outbe_update::startup::assert_binary_protocol_compatible(encode_protocol_version(2, 0))
            .unwrap_err();
    assert!(err.contains("older than on-chain active"));
}

#[test]
fn startup_binary_version_check_allows_pre_governance_chain() {
    outbe_update::startup::assert_binary_protocol_compatible(ProtocolVersion::ZERO).unwrap();
}

#[test]
#[should_panic(expected = "SPEC_EXPECTED_FAIL: localnet update smoke not implemented")]
fn e2e_localnet_update_smoke() {
    let localnet_update_smoke_available = false;
    assert!(
        localnet_update_smoke_available,
        "SPEC_EXPECTED_FAIL: localnet update smoke not implemented"
    );
}

#[test]
#[should_panic(
    expected = "SPEC_EXPECTED_FAIL: multi-node determinism harness for update flow not implemented"
)]
fn e2e_deterministic_state_root_across_nodes() {
    let multi_node_determinism_harness_available = false;
    assert!(
        multi_node_determinism_harness_available,
        "SPEC_EXPECTED_FAIL: multi-node determinism harness for update flow not implemented"
    );
}
