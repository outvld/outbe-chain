//! Steps for `features/s1_s2_s6_s3_lifecycle.feature` — port of
//! `scripts/e2e/s1_s2_s6_s3_lifecycle.sh`, one chain through four e2e.md stages:
//!   S1 cold full-node sync + tribute offer (state/supply parity)
//!   S2 promote full-node -> validator via reshare (stake -> confirm -> ACTIVE)
//!   S6 in-flight tribute offer that lands exactly once across the committee change
//!   S3 validator exit -> reshare down -> node demotes to verifier-follower (alive)

use std::thread::sleep;
use std::time::Duration;

use cucumber::{then, when};

use crate::world::rpc::Rpc;
use crate::world::World;

/// Lockstep probe (script's `LOCK` loop): 5×10s, joiner within 3 of committee and
/// strictly advancing each round.
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

/// S1 — submit a tribute offer from the operator; capture the day status first so
/// the invariant (offer is time-driven, not offer-driven) can be checked.
#[when(expr = "operator {string} submits a tribute offer")]
fn submit_offer(world: &mut World, name: String) {
    let primary = world.validators.primary_port();
    let wwd = world.state.wwd.clone().expect("worldwide-day set at setup");
    let key = world
        .validators
        .by_name(&name)
        .expect("resolve operator")
        .evm_key()
        .expect("key");
    world.state.wwd_status_before = world.rpc.wwd_status(primary, &wwd);
    assert!(
        world.rpc.offer_until_supply(&key, &wwd, primary, "1", 5),
        "committee did not process the offer (supply != 1)"
    );
}

/// S1 — supply reached 1 and the worldwide-day status is unchanged by the offer.
#[then("the committee processes the offer without changing the day status")]
fn offer_processed_status_unchanged(world: &mut World) {
    let primary = world.validators.primary_port();
    let wwd = world.state.wwd.clone().expect("wwd");
    assert_eq!(world.rpc.supply(primary).as_deref(), Some("1"), "supply should be 1");
    assert_eq!(
        world.rpc.wwd_status(primary, &wwd),
        world.state.wwd_status_before,
        "day status changed by the offer (should be time-driven)"
    );
}

/// S1 — provision + launch a REGISTERED (not staked) full node and sync it to tip.
#[when("a full node joins and syncs to the committee tip")]
fn full_node_syncs(world: &mut World) {
    let idx = world.validators.joiner_index();
    let joiner_port = world.validators.http_port(idx);
    world.localnet.provision_joiner(idx).expect("provision joiner");
    world.localnet.launch_joiner(idx, &[]).expect("launch joiner");
    let h = world.rpc.wait_block(joiner_port, 20, 40).unwrap_or(0);
    assert!(h >= 20, "full node did not catch up to tip (head {h})");
    let key = world.validators.joiner().evm_key().expect("joiner key");
    world.state.joiner_addr = world.rpc.address_of(&key);
}

/// S1 — the full node has supply + state-root parity and is NOT a participant.
#[then("the full node matches committee supply and state root and is not a participant")]
fn full_node_parity(world: &mut World) {
    let primary = world.validators.primary_port();
    let idx = world.validators.joiner_index();
    let joiner_port = world.validators.http_port(idx);
    let addr = world.state.joiner_addr.clone().expect("joiner addr");

    assert_eq!(world.rpc.supply(joiner_port).as_deref(), Some("1"), "full-node supply parity");
    assert!(
        !world.rpc.is_participant(joiner_port, &addr),
        "a full node must not be a consensus participant"
    );
    assert_eq!(world.rpc.active_count(primary), Some(4), "active set unchanged by a full node");

    let pn = world.rpc.finalized(joiner_port).unwrap_or(20);
    let sr_c = world.rpc.state_root(primary, pn);
    let sr_v = world.rpc.state_root(joiner_port, pn);
    assert_eq!(sr_c, sr_v, "state-root parity committee vs full node @h{pn}");
}

/// S2 — stake the full node, confirm PENDING + not-yet-participant, confirm ready.
#[when("the full node stakes and confirms readiness")]
fn full_node_stakes_confirms(world: &mut World) {
    let primary = world.validators.primary_port();
    let key = world.validators.joiner().evm_key().expect("joiner key");
    let addr = world.state.joiner_addr.clone().expect("joiner addr");

    world.rpc.stake(&key, 1000).expect("stake");
    sleep(Duration::from_secs(6));
    assert_eq!(world.rpc.validator_status(primary, &addr), Some(1), "staked joiner is PENDING");
    assert!(
        !world.rpc.is_participant(primary, &addr),
        "PENDING joiner must not be a participant before confirm-ready"
    );
    world.rpc.confirm_ready(&key).expect("confirm ready");
}

/// S2 + S6 — the joiner activates via reshare while an in-flight offer lands once.
#[then("it is promoted to an active participant and the in-flight offer lands once")]
fn promoted_with_inflight_offer(world: &mut World) {
    let primary = world.validators.primary_port();
    let idx = world.validators.joiner_index();
    let joiner_port = world.validators.http_port(idx);
    let addr = world.state.joiner_addr.clone().expect("joiner addr");
    let wwd = world.state.wwd.clone().expect("wwd");
    let v1 = world
        .validators
        .by_name("validator-1")
        .expect("v1")
        .evm_key()
        .expect("v1 key");

    // In-flight offer submitted during the reshare window; must land exactly once.
    assert!(
        world.rpc.offer_until_supply(&v1, &wwd, primary, "2", 15),
        "in-flight offer did not land (supply != 2)"
    );
    assert!(
        world.rpc.wait_participant(primary, &addr, 70),
        "joiner never became a consensus participant"
    );
    assert_eq!(world.rpc.validator_status(primary, &addr), Some(2), "joiner ACTIVE (2)");
    assert_eq!(world.rpc.active_count(primary), Some(5), "active set grew to 5");
    assert_eq!(world.rpc.supply(primary).as_deref(), Some("2"), "in-flight offer landed once");

    sleep(Duration::from_secs(30)); // settle: engine restarts for the new epoch
    assert!(
        lockstep_ok(&world.rpc, primary, joiner_port),
        "activated joiner does not advance in lockstep (has no working share)"
    );
    assert_eq!(world.rpc.supply(joiner_port).as_deref(), Some("2"), "offer parity on joiner RPC");
}

/// S3 — the promoted validator self-deactivates (ACTIVE -> EXITING, stays a
/// participant with its share until the exclusion reshare).
#[when("the promoted validator deactivates")]
fn promoted_deactivates(world: &mut World) {
    let primary = world.validators.primary_port();
    let key = world.validators.joiner().evm_key().expect("joiner key");
    let addr = world.state.joiner_addr.clone().expect("joiner addr");

    world.rpc.deactivate(&key).expect("deactivate");
    sleep(Duration::from_secs(6));
    assert_eq!(world.rpc.validator_status(primary, &addr), Some(3), "deactivated -> EXITING (3)");
    assert!(
        world.rpc.is_participant(primary, &addr),
        "EXITING stays a participant until the reshare"
    );
    assert_eq!(world.rpc.consensus_count(primary), Some(5), "consensus set still 5");
}

/// S3 — the exclusion reshare shrinks the set to 4, the exited validator becomes
/// UNBONDING, and its node DEMOTES to a verifier-follower that keeps following.
#[then("it exits, the committee reshares down, and the node demotes to a follower")]
fn exits_and_demotes(world: &mut World) {
    let primary = world.validators.primary_port();
    let idx = world.validators.joiner_index();
    let joiner_port = world.validators.http_port(idx);
    let addr = world.state.joiner_addr.clone().expect("joiner addr");

    let mut exit_h = 0u64;
    for _ in 0..45 {
        sleep(Duration::from_secs(10));
        let st = world.rpc.validator_status(primary, &addr);
        let cc = world.rpc.consensus_count(primary);
        if cc == Some(4) && st == Some(4) {
            exit_h = world.rpc.head(primary).unwrap_or(0);
            break;
        }
    }
    assert_eq!(world.rpc.validator_status(primary, &addr), Some(4), "exited -> UNBONDING (4)");
    assert_eq!(world.rpc.consensus_count(primary), Some(4), "consensus set shrank to 4");
    assert!(
        world
            .localnet
            .log_has(idx, "demoting to verifier-follower of the resharded committee"),
        "node did not demote to a verifier-follower"
    );

    sleep(Duration::from_secs(20));
    let vh = world.rpc.head(joiner_port).unwrap_or(0);
    assert!(vh > exit_h, "demoted node stopped following finality (head {vh} <= {exit_h})");

    // A new offer is still executed by the demoted follower (supply parity).
    let wwd = world.state.wwd.clone().expect("wwd");
    let v2 = world
        .validators
        .by_name("validator-2")
        .expect("v2")
        .evm_key()
        .expect("v2 key");
    world.rpc.offer_until_supply(&v2, &wwd, primary, "3", 5);
    sleep(Duration::from_secs(6));
    assert_eq!(
        world.rpc.supply(primary),
        world.rpc.supply(joiner_port),
        "demoted follower supply parity"
    );
}
