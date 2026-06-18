//! `Update` — on-chain upgrade governance storage and contract API.
//!
//! Stage 1 exposes the storage layout, state helpers, and ABI surface.
//! Stage 2 adds callable EVM dispatch; lifecycle activation is wired later.

pub mod api;
pub mod constants;
pub mod errors;
pub mod precompile;
pub mod runtime;
pub mod schema;
pub mod state;

/// On-chain protocol version: `u8 major + u24 minor` encoded as `u32`.
pub type ProtocolVersion = u32;

/// Encodes the protocol version as `u8 major + u24 minor`.
pub const fn encode_protocol_version(major: u8, minor: u32) -> ProtocolVersion {
    ((major as u32) << crate::constants::PROTOCOL_VERSION_MINOR_BITS) | minor
}

pub use schema::Update;

#[cfg(test)]
mod tests;
