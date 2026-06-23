//! `Update` — on-chain protocol version scheduling and activation.
//!
//! Governance owns proposal lifecycle; update stores scheduled upgrades and
//! activates them at `activationHeight` via begin-block processing.

pub mod api;
pub mod constants;
pub mod errors;
pub mod handlers;
pub mod lifecycle;
pub mod payload;
pub mod precompile;
pub mod runtime;
pub mod schema;
pub mod startup;
pub mod state;
pub mod version;

pub use handlers::{
    UpgradeHandler, UpgradeHandlerRegistry, UpgradeHandlerSpec, EMPTY_UPGRADE_HANDLER_REGISTRY,
};
pub use payload::{decode_scheduled_update_payload, encode_scheduled_update_payload};
pub use schema::Update;
pub use state::ScheduledUpdateInfo;
pub use version::{encode_protocol_version, ProtocolVersion};

#[cfg(test)]
mod tests;
