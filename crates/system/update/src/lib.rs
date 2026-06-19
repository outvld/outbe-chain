//! `Update` — on-chain upgrade governance storage and contract API.
//!
//! Stage 1: storage layout, state helpers, and ABI surface.
//! Stage 2: callable EVM dispatch.
//! Stage 3: active-validator authorization and begin-block tally/activation.

pub mod api;
pub mod constants;
pub mod errors;
pub mod handlers;
pub mod lifecycle;
pub mod precompile;
pub mod runtime;
pub mod schema;
pub mod startup;
pub mod state;
pub mod version;

pub use handlers::{
    UpgradeHandler, UpgradeHandlerRegistry, UpgradeHandlerSpec, EMPTY_UPGRADE_HANDLER_REGISTRY,
};
pub use schema::Update;
pub use version::{encode_protocol_version, ProtocolVersion};

#[cfg(test)]
mod tests;
