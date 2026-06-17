//! `Update` — on-chain upgrade governance storage and contract API.
//!
//! Stage 1 exposes the storage layout, state helpers, and ABI surface.
//! EVM dispatch registration and lifecycle activation are wired in later stages.

pub mod api;
pub mod constants;
pub mod errors;
pub mod precompile;
pub mod runtime;
pub mod schema;
pub mod state;

pub use schema::Update;

#[cfg(test)]
mod tests;
