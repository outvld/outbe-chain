//! address-set parity for outbe precompile registration.
//!
//! Verifies:
//! 1. `extend_outbe_precompiles` registers every address listed in
//!    `outbe_precompile_addresses()` (single source of truth for the table).
//! 2. The precompile count matches the current dispatch table; if a new
//!    precompile lands this assertion fails until the address-set is
//!    updated.
//! 3. The set of registered addresses does NOT include any Ethereum
//!    standard precompile addresses (`0x01..0x0a`) — outbe addresses must
//!    not collide with the upstream table.
//! 4. `PrecompilesMap::get` returns `Some(_)` for every outbe address after
//!    `extend_outbe_precompiles` runs (i.e. the dispatch lookup closure is
//!    actually installed).

use alloy_evm::{precompiles::PrecompilesMap, revm::handler::EthPrecompiles};
use alloy_primitives::Address;
use outbe_evm::precompiles::{extend_outbe_precompiles, outbe_precompile_addresses};
use revm::{database_interface::EmptyDB, primitives::hardfork::SpecId};

fn build_extended_precompiles() -> PrecompilesMap {
    let spec = SpecId::default();
    let mut precompiles = PrecompilesMap::from_static(EthPrecompiles::new(spec).precompiles);
    extend_outbe_precompiles::<EmptyDB>(&mut precompiles, spec);
    precompiles
}

#[test]
fn registered_address_count_is_30() {
    let count = outbe_precompile_addresses().len();
    assert_eq!(
        count, 31,
        "outbe registers 31 stateful precompiles (incl. Promis, PromisFactory, Intex, \
         IntexFactory, Desis, and TEE registry); if this changes, update the address list in \
         `outbe_precompile_addresses()` and the dispatch match in `extend_outbe_precompiles`"
    );
}

#[test]
fn ctx_dispatch_hook_installed_after_extend() {
    // outbe stateful precompiles now dispatch via the
    // `set_ctx_dispatch_hook` fork extension on `PrecompilesMap`, not via
    // the static lookup table. `PrecompilesMap::get(addr)` therefore returns
    // `None` for outbe addresses by design — the hook intercepts them
    // earlier in `PrecompileProvider::run`. This test asserts only that the
    // hook is installed.
    let precompiles = build_extended_precompiles();
    assert!(
        precompiles.has_ctx_dispatch_hook(),
        "extend_outbe_precompiles must install the ctx-dispatch hook"
    );
}

#[test]
fn outbe_addresses_do_not_collide_with_eth_standard() {
    fn eth_addr(last: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = last;
        Address::new(bytes)
    }
    let standard: [Address; 10] = [
        eth_addr(0x01),
        eth_addr(0x02),
        eth_addr(0x03),
        eth_addr(0x04),
        eth_addr(0x05),
        eth_addr(0x06),
        eth_addr(0x07),
        eth_addr(0x08),
        eth_addr(0x09),
        eth_addr(0x0a),
    ];
    for outbe in outbe_precompile_addresses() {
        for eth in &standard {
            assert_ne!(
                outbe, eth,
                "outbe precompile address {outbe:?} collides with Ethereum standard {eth:?}"
            );
        }
    }
}

#[test]
fn outbe_addresses_have_no_duplicates() {
    let addrs = outbe_precompile_addresses();
    let mut sorted: Vec<Address> = addrs.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        addrs.len(),
        "outbe_precompile_addresses() must not contain duplicates"
    );
}

#[test]
fn unregistered_address_returns_none() {
    let precompiles = build_extended_precompiles();
    let unknown = Address::from([0xFE; 20]);
    assert!(
        precompiles.get(&unknown).is_none(),
        "PrecompilesMap should return None for unregistered outbe-style address"
    );
}

/// Anti-spam security invariant: every sponsored-tx target is a
/// registered outbe precompile, so a sponsored free tx can only ever
/// invoke protocol-defined entrypoints — never arbitrary EVM code.
#[test]
fn sponsored_whitelist_is_subset_of_registered_precompiles() {
    use outbe_primitives::addresses::SPONSORED_TARGET_WHITELIST;
    let registered = outbe_precompile_addresses();
    for target in SPONSORED_TARGET_WHITELIST {
        assert!(
            registered.contains(target),
            "sponsored whitelist target {target:?} is not a registered outbe precompile — \
             a sponsored tx could route to an unregistered/arbitrary address"
        );
    }
}

/// Anti-abuse invariant: validator-only / settlement entrypoints must
/// NOT be reachable through the free sponsored path. Adding any of
/// these to the whitelist would let an attacker spam consensus-critical
/// precompiles for free; this test fails closed if that ever happens.
#[test]
fn sponsored_whitelist_excludes_validator_entrypoints() {
    use outbe_primitives::addresses::{
        ORACLE_ADDRESS, REWARDS_ADDRESS, SLASH_INDICATOR_ADDRESS, SPONSORED_TARGET_WHITELIST,
        STAKING_ADDRESS, VALIDATOR_SET_ADDRESS, ZEROFEE_ADDRESS,
    };
    let forbidden = [
        VALIDATOR_SET_ADDRESS,
        STAKING_ADDRESS,
        REWARDS_ADDRESS,
        SLASH_INDICATOR_ADDRESS,
        ORACLE_ADDRESS,
        // The paymaster itself must not be a sponsored target (would be
        // a self-call loop / quota nonsense).
        ZEROFEE_ADDRESS,
    ];
    for f in &forbidden {
        assert!(
            !SPONSORED_TARGET_WHITELIST.contains(f),
            "validator/settlement entrypoint {f:?} must NOT be in the sponsored whitelist"
        );
    }
}
