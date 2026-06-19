//! Node-level upgrade migration handler registry.
//!
//! Handler implementations live in their owning crates; this module wires them
//! into the Update lifecycle at block activation time.

use outbe_update::handlers::{UpgradeHandlerRegistry, UpgradeHandlerSpec};

/// Active upgrade handlers for this node binary.
///
/// Append entries when a protocol version requires deterministic storage
/// migration at activation height. Versions without a handler activate as
/// version-only switches.
pub static ACTIVE_UPGRADE_HANDLERS: &[UpgradeHandlerSpec] = &[];

static REGISTRY: UpgradeHandlerRegistry = UpgradeHandlerRegistry::new(ACTIVE_UPGRADE_HANDLERS);

/// Returns the compile-time upgrade handler registry for executor wiring.
pub fn registry() -> &'static UpgradeHandlerRegistry {
    &REGISTRY
}
