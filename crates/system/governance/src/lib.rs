//! `Governance` — reusable on-chain proposal/voting module (`0x…EE0C`).
//!
//! Module-structure layout:
//! - `schema.rs` — storage schema and records.
//! - `state.rs` — proposal/vote CRUD and indexes.
//! - `runtime.rs` — validator-gated proposal/voting logic.
//! - `precompile.rs` — ABI boundary placeholder.
//! - `lifecycle.rs` — begin-block tally entrypoint.
//! - `events.rs` — domain event payloads used by runtime/precompile wiring.

pub mod api;
pub mod constants;
pub mod errors;
pub mod events;
pub mod lifecycle;
pub mod precompile;
pub mod runtime;
pub mod schema;
pub mod state;

pub use precompile::GOVERNANCE_ABI_PATH;
pub use schema::Governance;
pub use state::{ProposalInfo, ProposalStatus, VoteInfo, VoteKind, VoteTally};

#[cfg(test)]
mod tests;
