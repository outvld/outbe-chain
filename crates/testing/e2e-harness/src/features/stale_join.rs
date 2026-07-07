//! Steps for `features/s7b_stale_join.feature` — port of
//! `scripts/e2e/s7b_stale_join.sh`. A staked-but-unconfirmed joiner must stay
//! PENDING across a full reshare cycle (the stale-join guard keeps it out of the
//! frozen reshare target); only `confirm-ready` lets the next reshare activate it.

use std::thread::sleep;
use std::time::Duration;

use cucumber::{then, when};

use crate::world::World;

/// Provision + launch the joiner, stake it, but deliberately do NOT confirm
/// readiness. Asserts it is PENDING after the stake (s7b:17-22).
#[when("a staked joiner has not confirmed readiness")]
fn staked_joiner_unconfirmed(world: &mut World) {
    let idx = world.validators.joiner_index();
    let joiner_port = world.validators.http_port(idx);
    let primary = world.validators.primary_port();

    world.localnet.provision_joiner(idx).expect("provision joiner");
    world.localnet.launch_joiner(idx, &[]).expect("launch joiner");
    world.rpc.wait_block(joiner_port, 20, 40);

    let key = world.validators.joiner().evm_key().expect("joiner key");
    let addr = world.rpc.address_of(&key).expect("joiner address");
    world.state.joiner_addr = Some(addr.clone());

    world.rpc.stake(&key, 1000).expect("stake joiner");
    sleep(Duration::from_secs(6));
    assert_eq!(
        world.rpc.validator_status(primary, &addr),
        Some(1),
        "joiner should be PENDING (1) after stake"
    );
}

/// The unconfirmed joiner stays PENDING while the committee crosses a full
/// reshare/activation cycle (height > 130 on the dev epoch) (s7b:30-43).
#[then("the unconfirmed joiner stays pending across a full reshare cycle")]
fn stays_pending(world: &mut World) {
    let primary = world.validators.primary_port();
    let addr = world.state.joiner_addr.clone().expect("joiner addr");

    let mut stayed_pending = true;
    let mut crossed = false;
    for _ in 0..40 {
        sleep(Duration::from_secs(10));
        let ch = world.rpc.head(primary).unwrap_or(0);
        if world.rpc.validator_status(primary, &addr) != Some(1) {
            stayed_pending = false;
        }
        if ch > 130 {
            crossed = true;
            break;
        }
    }
    assert!(crossed, "committee did not cross a reshare/activation (height > 130)");
    assert!(
        stayed_pending,
        "unconfirmed joiner did not stay PENDING across the reshare window"
    );

    sleep(Duration::from_secs(10));
    assert_eq!(
        world.rpc.validator_status(primary, &addr),
        Some(1),
        "unconfirmed PENDING joiner must not be activated"
    );
    assert_eq!(world.rpc.active_count(primary), Some(4), "active set must stay 4");
    assert!(
        !world.rpc.is_participant(primary, &addr),
        "unconfirmed joiner must not be a participant"
    );
}

/// Send confirm-ready (s7b:46).
#[when("the joiner confirms readiness")]
fn joiner_confirms(world: &mut World) {
    let key = world.validators.joiner().evm_key().expect("joiner key");
    world.rpc.confirm_ready(&key).expect("confirm ready");
}

/// The confirmed joiner activates on the next reshare: ACTIVE (2), set grows to 5
/// (s7b:47-51).
#[then("the confirmed joiner activates on the next reshare")]
fn confirmed_joiner_activates(world: &mut World) {
    let primary = world.validators.primary_port();
    let addr = world.state.joiner_addr.clone().expect("joiner addr");
    assert!(
        world.rpc.wait_participant(primary, &addr, 40),
        "confirmed joiner never became a participant"
    );
    assert_eq!(
        world.rpc.validator_status(primary, &addr),
        Some(2),
        "joiner should be ACTIVE (2)"
    );
    assert_eq!(world.rpc.active_count(primary), Some(5), "active set should grow to 5");
}
