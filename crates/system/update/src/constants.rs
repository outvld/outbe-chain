//! Protocol constants for upgrade scheduling and activation.
//!
//! All values are `const` and change only via hardfork.

/// Minimum blocks between governance approval and activation height.
pub const MIN_ACTIVATION_BUFFER: u64 = 100;

/// Current binary protocol version.
pub const PROTOCOL_VERSION: crate::ProtocolVersion =
    crate::encode_protocol_version(PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR);

/// Bits reserved for the minor part of an on-chain protocol version.
pub(crate) const PROTOCOL_VERSION_MINOR_BITS: u32 = 24;

/// Maximum minor value in the `u8 major + u24 minor` protocol version encoding.
pub(crate) const MAX_PROTOCOL_VERSION_MINOR: u32 = (1u32 << PROTOCOL_VERSION_MINOR_BITS) - 1;

/// Protocol version embedded into this crate at compile time.
pub(crate) const PROTOCOL_VERSION_MAJOR: u8 =
    crate::version::parse_protocol_version_major_component(env!("CARGO_PKG_VERSION_MAJOR"));
pub(crate) const PROTOCOL_VERSION_MINOR: u32 =
    crate::version::parse_protocol_version_minor_component(env!("CARGO_PKG_VERSION_MINOR"));
