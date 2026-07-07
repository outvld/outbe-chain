//! Steps for `features/s7a_downtime_slash.feature` — port of
//! `scripts/e2e/s7a_downtime_slash.sh`. Kill one committee validator and prove
//! the chain keeps finalizing on the surviving 3-of-4 BFT quorum; also assert the
//! slashing-config read surface is present. (The downtime felony itself is
//! fee-settlement-gated and inactive on the ZeroFee localnet — see the script.)

use cucumber::{given, then, when};

use crate::world::World;

/// `outbe-cli slash config` exposes the felony slash percent (s7a:31-32).
#[given("the slashing config is readable")]
fn slashing_config_readable(world: &mut World) {
    assert!(
        world.rpc.slash_percent().is_some(),
        "slashing config not readable (felony slash percent absent)"
    );
}

/// The named validator is ACTIVE (status 2) before the kill (s7a:33-34).
#[given(expr = "validator {string} starts active")]
fn validator_starts_active(world: &mut World, name: String) {
    let port = world.validators.primary_port();
    let key = world
        .validators
        .by_name(&name)
        .expect("resolve validator")
        .evm_key()
        .expect("read key");
    let addr = world.rpc.address_of(&key).expect("derive address");
    assert_eq!(
        world.rpc.validator_status(port, &addr),
        Some(2),
        "{name} should start ACTIVE (2)"
    );
    world.state.joiner_addr = Some(addr); // reuse the addr slot for the victim
}

/// Kill the named committee validator, recording the head at kill time (s7a:37-38).
#[when(expr = "validator {string} is killed")]
fn validator_is_killed(world: &mut World, name: String) {
    let i = world.validators.by_name(&name).expect("resolve validator").index;
    let port = world.validators.primary_port();
    world.state.marker_height = world.rpc.head(port);
    world.localnet.kill_validator(i).expect("kill validator");
}

/// The surviving committee advances well past the kill height (s7a:41-50).
#[then("the committee keeps finalizing on the remaining 3-of-4 quorum")]
fn committee_keeps_finalizing(world: &mut World) {
    let port = world.validators.primary_port();
    let kill_h = world.state.marker_height.expect("kill height captured");
    let target = kill_h + 15;
    let h = world.rpc.wait_block_gt(port, target, 20).unwrap_or(0);
    assert!(
        h > target,
        "chain did not keep finalizing after losing 1 of 4 (head {h} <= {target})"
    );
}
