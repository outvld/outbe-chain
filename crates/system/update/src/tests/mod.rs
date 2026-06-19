use alloy_primitives::{address, Address};

use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_validatorset::contract::ValidatorSet;

use crate::constants::{MIN_ACTIVATION_BUFFER, VOTING_WINDOW_BLOCKS};
use crate::{encode_protocol_version, ProtocolVersion};

mod events;
mod lifecycle;
mod precompile;
mod proposals;
mod records;
mod spec_expected_fail;

pub(super) const PROPOSER: Address = address!("0x1111111111111111111111111111111111111111");
pub(super) const VOTER_A: Address = address!("0x2222222222222222222222222222222222222222");
pub(super) const VOTER_B: Address = address!("0x3333333333333333333333333333333333333333");
pub(super) const V1_0: ProtocolVersion = encode_protocol_version(1, 0);
pub(super) const V1_1: ProtocolVersion = encode_protocol_version(1, 1);
pub(super) const V1_2: ProtocolVersion = encode_protocol_version(1, 2);
pub(super) const V1_3: ProtocolVersion = encode_protocol_version(1, 3);
pub(super) const V1_5: ProtocolVersion = encode_protocol_version(1, 5);
pub(super) const V1_9: ProtocolVersion = encode_protocol_version(1, 9);
pub(super) const V2_0: ProtocolVersion = encode_protocol_version(2, 0);
pub(super) const V3_0: ProtocolVersion = encode_protocol_version(3, 0);
pub(super) const V3_1: ProtocolVersion = encode_protocol_version(3, 1);
pub(super) const V9_8: ProtocolVersion = encode_protocol_version(9, 8);
pub(super) const VALIDATOR_OWNER: Address = address!("0xffffffffffffffffffffffffffffffffffffffff");
pub(super) const STRANGER: Address = address!("0x4444444444444444444444444444444444444444");

fn dummy_pubkey(seed: u8) -> [u8; 48] {
    let mut pk = [0u8; 48];
    pk[0] = seed;
    pk
}

fn register_active_validator(storage: StorageHandle, addr: Address, seed: u8) {
    let mut vs = ValidatorSet::new(storage.clone());
    vs.config_owner.write(VALIDATOR_OWNER).unwrap();
    vs.config_max_validators.write(100).unwrap();
    vs.register_validator(VALIDATOR_OWNER, addr, &dummy_pubkey(seed))
        .unwrap();
    vs.activate_validator(addr).unwrap();
}

fn setup_default_validators(storage: StorageHandle) {
    register_active_validator(storage.clone(), PROPOSER, 1);
    register_active_validator(storage.clone(), VOTER_A, 2);
    register_active_validator(storage.clone(), VOTER_B, 3);
}

pub(super) fn with_update<F: FnOnce(StorageHandle)>(f: F) {
    let mut provider = HashMapStorageProvider::new(1);
    let storage = StorageHandle::new(&mut provider);
    setup_default_validators(storage.clone());
    f(storage);
}

pub(super) fn with_update_provider<F: FnOnce(StorageHandle)>(f: F) -> HashMapStorageProvider {
    let mut provider = HashMapStorageProvider::new(1);
    let storage = StorageHandle::new(&mut provider);
    setup_default_validators(storage.clone());
    f(storage);
    provider
}

pub(super) fn event_count(
    provider: &HashMapStorageProvider,
    topic0: alloy_primitives::B256,
) -> usize {
    provider
        .get_events(UPDATE_ADDRESS)
        .iter()
        .filter(|log| log.topics().first() == Some(&topic0))
        .count()
}

pub(super) fn has_event(provider: &HashMapStorageProvider, topic0: alloy_primitives::B256) -> bool {
    event_count(provider, topic0) > 0
}

pub(super) fn min_activation(current: u64) -> u64 {
    current
        .saturating_add(VOTING_WINDOW_BLOCKS)
        .saturating_add(MIN_ACTIVATION_BUFFER)
}
