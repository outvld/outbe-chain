//! Steps for `features/update_operator.feature` — a step-for-step port of
//! `scripts/e2e/update_operator_flow.sh` (body 194-331). Each step drives the
//! `World` handles only; no `cast`/`cli` strings appear here.

use std::thread::sleep;
use std::time::Duration;

use cucumber::{then, when};

use crate::internal::addresses::UPDATE_ADDR;
use crate::world::World;

/// Blocks past the vote window before an update may activate
/// (`MIN_ACTIVATION_BUFFER`, update_operator_flow.sh:30).
const MIN_ACTIVATION_BUFFER: u64 = 100;

/// Propose a bump to the next protocol version from an operator
/// (update_operator_flow.sh:234-251).
#[when(expr = "operator {string} proposes an update to the next protocol version")]
fn propose_update(world: &mut World, name: String) {
    let operator = world.validators.operator(&name).expect("resolve operator");
    let active = world.rpc.active_version().expect("read active version");
    let version = active + 1;
    let port = world.validators.primary_port();
    let head = world.rpc.head(port).expect("read head");
    let activation = head + world.state.voting_window + MIN_ACTIVATION_BUFFER + 30;

    let payload = serde_json::json!({
        "version": version,
        "activationHeight": activation,
        "info": "e2e update operator smoke",
    })
    .to_string();

    let tx = world
        .rpc
        .send_propose(&operator, &format!("{UPDATE_ADDR:#x}"), &payload)
        .expect("send propose");
    assert!(world.rpc.wait_tx(&tx, 40), "propose tx not mined: {tx}");

    world.state.proposed_version = Some(version);
    world.state.activation_height = Some(activation);
}

/// The proposal is visible, pending, targets the update module, and carries the
/// activation height (update_operator_flow.sh:253-266).
#[then(expr = "proposal {int} is pending, targets the update module, and carries the activation height")]
fn proposal_pending(world: &mut World, id: u64) {
    let mut vs = world.rpc.vote_status(id);
    for _ in 0..10 {
        if vs.visible {
            break;
        }
        sleep(Duration::from_secs(3));
        vs = world.rpc.vote_status(id);
    }
    assert!(vs.visible, "proposal #{id} not visible after propose");
    assert_eq!(vs.status, "pending", "proposal should be pending");
    let update_addr = format!("{UPDATE_ADDR:#x}");
    assert!(
        vs.target.eq_ignore_ascii_case(&update_addr),
        "target {} != update module {update_addr}",
        vs.target
    );
    let activation = world.state.activation_height.expect("activation set by propose");
    assert!(
        vs.payload
            .contains(&format!("\"activationHeight\":{activation}")),
        "payload missing activation height {activation}: {}",
        vs.payload
    );
}

/// Cast yes votes from a comma-separated list of validators
/// (update_operator_flow.sh:268-285).
///
/// The ballots are fired without waiting on each receipt, so the whole set is
/// submitted within a few blocks and the voting window isn't burned by RPC
/// round-trips. A vote may revert (e.g. the proposer already counts as a yes, so
/// its explicit vote is a double-vote); the authoritative check is the yes tally
/// polled by the next step.
#[when(expr = "validators {string} cast yes votes")]
fn cast_yes_votes(world: &mut World, names: String) {
    let id = world.state.proposal_id;
    for name in names.split(',') {
        let validator = world.validators.by_name(name.trim()).expect("resolve validator");
        let _ = world.rpc.cast_vote(&validator, id, true);
    }
}

/// Still pending before the deadline, with the expected yes tally
/// (update_operator_flow.sh:287-294).
#[then(expr = "proposal {int} is still pending with {int} yes votes")]
fn still_pending_with_votes(world: &mut World, id: u64, yes: u64) {
    // The just-fired votes may still be settling; poll until the tally is in,
    // bounded so we stay inside the voting window (bail out the moment the
    // proposal leaves `pending`).
    let mut vs = world.rpc.vote_status(id);
    for _ in 0..8 {
        if vs.yes >= yes || vs.status != "pending" {
            break;
        }
        sleep(Duration::from_secs(2));
        vs = world.rpc.vote_status(id);
    }
    assert_eq!(vs.status, "pending", "proposal should still be pending");
    assert_eq!(vs.yes, yes, "yes tally");
    assert_eq!(vs.no, 0, "no tally");
    world.state.vote_deadline = vs.deadline;
}

/// Advance past the voting deadline (update_operator_flow.sh:296-298).
#[when("the committee passes the vote deadline")]
fn pass_vote_deadline(world: &mut World) {
    let deadline = world.state.vote_deadline.expect("deadline captured");
    let port = world.validators.primary_port();
    let h = world.rpc.wait_block_gt(port, deadline, 80).unwrap_or(0);
    assert!(h > deadline, "did not pass vote deadline {deadline} (got {h})");
}

/// Approved after the deadline tally, with the scheduled update matching the
/// proposal (update_operator_flow.sh:299-311).
#[then(expr = "proposal {int} is approved and the scheduled update matches the proposal")]
fn approved_and_scheduled(world: &mut World, id: u64) {
    assert!(
        world.rpc.wait_vote_status(id, "approved", 60),
        "proposal not approved after deadline"
    );
    let su = world.rpc.scheduled_update(id).expect("scheduled update");
    assert_eq!(
        su.version,
        world.state.proposed_version.expect("version"),
        "scheduled version"
    );
    assert_eq!(
        su.activation,
        world.state.activation_height.expect("activation"),
        "scheduled activation height"
    );
    assert_eq!(su.status, 0, "scheduled update should be waiting for activation");
}

/// Advance past the activation height (update_operator_flow.sh:313-315).
#[when("the committee passes the activation height")]
fn pass_activation_height(world: &mut World) {
    let activation = world.state.activation_height.expect("activation captured");
    let port = world.validators.primary_port();
    let h = world
        .rpc
        .wait_block_gt(port, activation, 180)
        .unwrap_or(0);
    assert!(h > activation, "did not pass activation {activation} (got {h})");
}

/// Active protocol version updated to the proposed version
/// (update_operator_flow.sh:316-317).
#[then("the active protocol version equals the proposed version")]
fn active_version_bumped(world: &mut World) {
    let want = world.state.proposed_version.expect("version");
    let got = world.rpc.wait_active_version(want, 60);
    assert_eq!(got, Some(want), "active protocol version not updated");
}

/// The scheduled update is marked activated (update_operator_flow.sh:318-319).
#[then("the scheduled update is marked activated")]
fn scheduled_marked_activated(world: &mut World) {
    let su = world
        .rpc
        .scheduled_update(world.state.proposal_id)
        .expect("scheduled update");
    assert_eq!(su.status, 1, "scheduled update should be activated");
}
