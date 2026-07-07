//! Private implementation details behind the `world/` handles: env config,
//! the `xshell` subprocess wrapper, precompile addresses, and output parsers.
//! Nothing here is part of the public handle API.

pub(crate) mod addresses;
pub(crate) mod config;
pub(crate) mod eth;
pub(crate) mod parse;
pub(crate) mod ports;
pub(crate) mod proc;
pub(crate) mod shell;
