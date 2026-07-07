//! Step definitions — the code behind the Gherkin fixtures in `features/`.
//!
//! Steps are registered with cucumber's `#[given]`/`#[when]`/`#[then]` macros
//! (collected via `inventory`), so simply compiling these modules wires them
//! up. Each step drives the `crate::world` handles and nothing else.
//!
//! - [`common`] holds the shared localnet setup + parity steps.
//! - [`update`] backs `features/update_operator.feature`.
//! - [`downtime`] / [`stale_join`] / [`lifecycle`] / [`restart`] / [`dkg`] /
//!   [`follower`] back the S1-S7 + follower validator-lifecycle scenarios.

pub mod common;
pub mod update;

pub mod dkg;
pub mod downtime;
pub mod follower;
pub mod lifecycle;
pub mod restart;
pub mod stale_join;
