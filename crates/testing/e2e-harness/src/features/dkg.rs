//! Steps for `features/s5_dkg_failure.feature` — port of
//! `scripts/e2e/s5_dkg_failure.sh`. Freeze a 4->5 reshare target, then take the
//! joiner AND one committee validator offline so the ceremony begins with only
//! 3 online players (< player_threshold) and cannot complete. The OLD committee
//! keeps finalizing on its 3-of-4 quorum (no hard-halt); restoring the downed
//! validator lets a later retry complete and the set reaches 5.

use std::thread::sleep;
use std::time::Duration;

use cucumber::{given, then, when};

use crate::features::common::boot_localnet;
use crate::world::World;

/// Setup with a WIDE DKG activation grace so the VRF window outlasts the failed
/// reshare and RECOVERY can be demonstrated (s5:17-25).
#[given("a fresh localnet with a wide DKG activation grace")]
fn tuned_setup(world: &mut World) {
    boot_localnet(
        world,
        6,
        &[("TESTNET_DKG_ACTIVATION_GRACE_BLOCKS", "600".to_string())],
    );
}

/// Stake + confirm a joiner to freeze a 4->5 reshare target (s5:31-35).
#[when("a staked joiner freezes a 4-to-5 reshare target")]
fn freeze_target(world: &mut World) {
    let idx = world.validators.joiner_index();
    let joiner_port = world.validators.http_port(idx);
    world.localnet.provision_joiner(idx).expect("provision joiner");
    world.localnet.launch_joiner(idx, &[]).expect("launch joiner");
    world.rpc.wait_block(joiner_port, 20, 40);
    let key = world.validators.joiner().evm_key().expect("joiner key");
    world.rpc.stake(&key, 1000).expect("stake");
    sleep(Duration::from_secs(6));
    world.rpc.confirm_ready(&key).expect("confirm ready");
}

/// Take the joiner + validator-3 offline BEFORE the ceremony so it begins with
/// only 3 online players and cannot complete (s5:37-49).
#[when("the reshare loses quorum before it can complete")]
fn lose_quorum(world: &mut World) {
    let primary = world.validators.primary_port();
    let idx = world.validators.joiner_index();
    world.state.marker_height = world.rpc.head(primary);
    world.localnet.stop_joiner(idx).expect("stop joiner");
    world.localnet.kill_validator(3).expect("kill validator-3");
}

/// The old committee keeps finalizing through the stalled reshare and the join
/// does not activate (s5:50-63).
#[then("the old committee keeps finalizing through the stalled reshare")]
fn old_committee_keeps_finalizing(world: &mut World) {
    let primary = world.validators.primary_port();
    let kill_h = world.state.marker_height.expect("kill height");

    let mut retry = 0usize;
    let mut alive_grow = false;
    for _ in 0..30 {
        sleep(Duration::from_secs(10));
        let h = world.rpc.head(primary).unwrap_or(0);
        retry = world
            .localnet
            .log_count(0, "DKG reshare failed, retrying frozen target");
        if h > kill_h + 12 {
            alive_grow = true;
        }
        if retry >= 1 && alive_grow {
            break;
        }
    }
    assert!(retry >= 1, "DKG join-reshare did not retry (flag-based per height)");
    assert!(alive_grow, "old committee did not keep finalizing (3-of-4 quorum)");
    assert_eq!(
        world.localnet.log_count(0, "hard halt"),
        0,
        "unexpected hard-halt (no such model exists)"
    );
    assert_eq!(
        world.rpc.active_count(primary),
        Some(4),
        "join must not activate while its reshare is failing"
    );
}

/// Relaunch the downed validator (`localnet.restart` re-launches dead nodes),
/// leaving the joiner down (s5:65-71).
#[when("the downed validator is restored")]
fn restore_validator(world: &mut World) {
    world.localnet.restart().expect("restart committee");
}

/// With 4 online acking players again, a later retry completes and the set
/// reaches 5 (s5:72-75).
#[then("the reshare completes and the active set reaches 5")]
fn reshare_completes(world: &mut World) {
    let primary = world.validators.primary_port();
    assert!(
        world.rpc.wait_active_count(primary, 5, 40),
        "reshare did not complete after the participant was restored (set != 5)"
    );
}
