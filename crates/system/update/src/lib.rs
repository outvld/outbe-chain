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

pub use schema::Update;

#[cfg(test)]
mod tests;
