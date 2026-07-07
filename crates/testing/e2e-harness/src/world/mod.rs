//! The cucumber `World` and the encapsulated handles the steps drive.
//!
//! Steps never shell out directly — they call verb methods on these handles
//! (`world.localnet.start(...)`, `world.rpc.send_propose(...)`,
//! `world.validators.operator(...)`) and thread scratch values through
//! `world.state`. The handles hold a cloned [`Config`] and defer all subprocess
//! work to `crate::internal`.

pub mod localnet;
pub mod rpc;
pub mod state;
pub mod validators;

use crate::env::environment;
use crate::internal::config::Config;
use localnet::Localnet;
use rpc::Rpc;
use state::FixtureState;
use validators::Validators;

// Public result types returned by the `Rpc` handle.
pub use crate::internal::parse::{ScheduledUpdate, VoteStatus};
// The committee's primary RPC port lives with the `Validators` handle.

#[derive(Debug, cucumber::World)]
pub struct World {
    /// The localnet and every owned node: bootstrap/start/stop the committee,
    /// provision/launch the joiner + followers, kill/restart validators.
    pub localnet: Localnet,
    /// Chain reads/sends/waits.
    pub rpc: Rpc,
    /// Validator/operator identities and committee size.
    pub validators: Validators,
    /// Scratch state threaded across the scenario's steps.
    pub state: FixtureState,
}

impl Default for World {
    fn default() -> Self {
        let env = environment();
        let cfg = Config::resolve(&env);
        Self {
            localnet: Localnet::new(cfg.clone()),
            rpc: Rpc::new(cfg.clone()),
            validators: Validators::new(cfg, env.validators),
            state: FixtureState::default(),
        }
    }
}
