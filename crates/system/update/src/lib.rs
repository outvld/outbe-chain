//! `Update` — on-chain protocol version scheduling and activation.
//!
//! Vote owns proposal lifecycle; update stores scheduled upgrades and
//! activates them at `activationHeight` via begin-block processing.

pub mod api;
pub mod constants;
pub mod errors;
pub mod handlers;
pub mod vote_target;
pub mod lifecycle;
pub mod payload;
pub mod precompile;
pub mod runtime;
pub mod schema;
pub mod startup;
pub mod state;
pub mod version;

pub use handlers::{UpgradeHandler, UpgradeHandlerRegistry, UpgradeHandlers};
pub use vote_target::UpdateVoteTarget;
pub use payload::{
    decode_schedule_update_json, encode_schedule_update_json, validate_schedule_update_json,
    ScheduleUpdatePayload,
};
pub use schema::Update;
pub use state::ScheduledUpdateInfo;
pub use version::{encode_protocol_version, ProtocolVersion};

#[cfg(test)]
mod tests;
