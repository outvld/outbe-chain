//! Steps for `features/s4_restart_active.feature` — port of
//! `scripts/e2e/s4_restart_active.sh`. An ACTIVE validator's DKG share lives on
//! disk (keys-dir), not the enclave. Killing and restarting ONLY the node (the
//! enclave container stays up) must resume signing from the persisted share
//! WITHOUT a fresh DKG ceremony.

use std::thread::sleep;
use std::time::Duration;

use cucumber::{then, when};

use crate::world::rpc::Rpc;
use crate::world::World;

/// Lockstep probe (s4:46-48): 5×10s, joiner within 3 of committee and advancing.
fn lockstep_ok(rpc: &Rpc, committee: u16, joiner: u16) -> bool {
    let mut prev = 0u64;
    for _ in 0..5 {
        sleep(Duration::from_secs(10));
        let ch = rpc.head(committee).unwrap_or(0);
        let vh = rpc.head(joiner).unwrap_or(0);
        if ch.saturating_sub(vh) > 3 || vh <= prev {
            return false;
        }
        prev = vh;
    }
    true
}

/// Bring a joiner to ACTIVE with a persisted (keys-dir) share (s4:13-30).
#[when("a joiner reaches active with a persisted share")]
fn joiner_active_persisted_share(world: &mut World) {
    let primary = world.validators.primary_port();
    let idx = world.validators.joiner_index();
    let joiner_port = world.validators.http_port(idx);
    let wwd = world.state.wwd.clone().expect("wwd");

    let v0 = world.validators.get(0).evm_key().expect("v0 key");
    world.rpc.offer_until_supply(&v0, &wwd, primary, "1", 5);

    world.localnet.provision_joiner(idx).expect("provision joiner");
    let keys = world.localnet.keys_dir(idx);
    world
        .localnet
        .launch_joiner(idx, &["--consensus.keys-dir", &keys])
        .expect("launch joiner (keys-dir)");
    world.rpc.wait_block(joiner_port, 20, 40);

    let key = world.validators.joiner().evm_key().expect("joiner key");
    let addr = world.rpc.address_of(&key).expect("joiner addr");
    world.state.joiner_addr = Some(addr.clone());
    world.rpc.stake(&key, 1000).expect("stake");
    sleep(Duration::from_secs(6));
    world.rpc.confirm_ready(&key).expect("confirm ready");

    assert!(
        world.rpc.wait_participant(primary, &addr, 40),
        "joiner did not reach ACTIVE before the restart"
    );
    assert!(
        world.localnet.has_share_file(idx),
        "DKG share was not persisted to the keys dir"
    );
    sleep(Duration::from_secs(20)); // sign a few blocks as ACTIVE
}

/// Kill only the node (enclave container stays up) and restart it with the same
/// keys-dir/datadir (s4:32-37).
#[when("the node is killed and restarted with the same keys")]
fn node_killed_and_restarted(world: &mut World) {
    let primary = world.validators.primary_port();
    let idx = world.validators.joiner_index();
    world.state.marker_count = Some(world.localnet.log_count(idx, "running DKG ceremony"));
    world.state.marker_height = world.rpc.head(primary);
    world.localnet.stop_joiner(idx).expect("stop joiner");
    let keys = world.localnet.keys_dir(idx);
    world
        .localnet
        .launch_joiner(idx, &["--consensus.keys-dir", &keys])
        .expect("relaunch joiner");
}

/// The restarted node catches up and resumes signing WITHOUT a fresh ceremony
/// (s4:38-55).
#[then("it resumes signing from the persisted share without a new ceremony")]
fn resumes_without_new_ceremony(world: &mut World) {
    let primary = world.validators.primary_port();
    let idx = world.validators.joiner_index();
    let joiner_port = world.validators.http_port(idx);
    let addr = world.state.joiner_addr.clone().expect("joiner addr");
    let restart_h = world.state.marker_height.expect("restart height");
    let pre_ceremony = world.state.marker_count.expect("pre ceremony count");

    let h = world.rpc.wait_block(joiner_port, restart_h, 30).unwrap_or(0);
    assert!(h >= restart_h, "restarted node did not catch up (head {h} < {restart_h})");
    assert!(
        world.localnet.log_has(idx, "threshold material ready"),
        "node did not resume from saved DKG state"
    );
    assert_eq!(
        world.localnet.log_count(idx, "running DKG ceremony"),
        pre_ceremony,
        "a fresh DKG ceremony was triggered by the restart"
    );
    assert!(
        world.rpc.is_participant(primary, &addr),
        "node is not an ACTIVE participant after restart"
    );
    assert!(
        lockstep_ok(&world.rpc, primary, joiner_port),
        "restarted validator does not resume signing in lockstep"
    );
    assert_eq!(
        world.localnet.log_count(0, "byzantine evidence observed"),
        0,
        "byzantine/equivocation evidence around the restart"
    );

    // Enclave still works: an offer is executed by the reconnected node.
    let wwd = world.state.wwd.clone().expect("wwd");
    let v1 = world
        .validators
        .by_name("validator-1")
        .expect("v1")
        .evm_key()
        .expect("v1 key");
    world.rpc.offer_until_supply(&v1, &wwd, primary, "2", 5);
    sleep(Duration::from_secs(6));
    assert_eq!(
        world.rpc.supply(primary),
        world.rpc.supply(joiner_port),
        "enclave offer parity post-restart"
    );
}
