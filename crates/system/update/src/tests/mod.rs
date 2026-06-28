use alloy_primitives::U256;

use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;

use crate::constants::MIN_ACTIVATION_BUFFER;
use crate::handlers::EMPTY_UPGRADE_HANDLER_REGISTRY;
use crate::payload::encode_scheduled_update_payload;
use crate::schema::Update;
use crate::{encode_protocol_version, ProtocolVersion};
use outbe_primitives::error::Result;

mod events;
mod handlers;
mod lifecycle;
mod precompile;
mod records;
mod scheduled;
mod spec_expected_fail;

pub(super) const V1_2: ProtocolVersion = encode_protocol_version(1, 2);
pub(super) const V1_3: ProtocolVersion = encode_protocol_version(1, 3);
pub(super) const V1_5: ProtocolVersion = encode_protocol_version(1, 5);
pub(super) const V2_0: ProtocolVersion = encode_protocol_version(2, 0);
pub(super) const V3_0: ProtocolVersion = encode_protocol_version(3, 0);
pub(super) const V3_1: ProtocolVersion = encode_protocol_version(3, 1);
pub(super) const V9_8: ProtocolVersion = encode_protocol_version(9, 8);

pub(super) fn with_update<F: FnOnce(StorageHandle)>(f: F) {
    let mut provider = HashMapStorageProvider::new(1);
    let storage = StorageHandle::new(&mut provider);
    f(storage);
}

pub(super) fn with_update_provider<F: FnOnce(StorageHandle)>(f: F) -> HashMapStorageProvider {
    let mut provider = HashMapStorageProvider::new(1);
    let storage = StorageHandle::new(&mut provider);
    f(storage);
    provider
}

pub(super) fn block_ctx(storage: StorageHandle, block_number: u64) -> BlockRuntimeContext {
    BlockRuntimeContext::new(BlockContext::empty_for_tests(block_number, 0, 1), storage)
}

pub(super) fn min_activation(current: u64) -> u64 {
    current.saturating_add(MIN_ACTIVATION_BUFFER)
}

pub(super) fn schedule_update(
    update: &mut Update<'_>,
    proposal_id: U256,
    version: ProtocolVersion,
    activation_height: u64,
    info: &[u8],
    current_height: u64,
) -> Result<()> {
    let payload = encode_scheduled_update_payload(version, activation_height, info);
    update.schedule_update_from_vote(proposal_id, &payload, current_height)
}

/// Test-only helper: runs begin-block processing with an empty handler registry.
pub(super) trait UpdateTestExt {
    fn process_begin_block_test(&mut self, block_number: u64) -> Result<()>;
}

impl UpdateTestExt for Update<'_> {
    fn process_begin_block_test(&mut self, block_number: u64) -> Result<()> {
        let ctx = block_ctx(self.storage.clone(), block_number);
        self.process_begin_block_with_handlers(&ctx, &EMPTY_UPGRADE_HANDLER_REGISTRY)
    }
}
