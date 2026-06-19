//! Protocol constants for upgrade governance.
//!
//! All values are `const` and change only via hardfork.

/// Blocks in the voting window (~1 day at 1s block time).
pub const VOTING_WINDOW_BLOCKS: u64 = 86_400;

/// Quorum numerator for 2/3 approval (`yes * DENOM >= active * NUM`).
pub const QUORUM_NUMERATOR: u64 = 2;

/// Quorum denominator for 2/3 approval.
pub const QUORUM_DENOMINATOR: u64 = 3;

/// Minimum blocks between proposal creation and activation after voting closes.
pub const MIN_ACTIVATION_BUFFER: u64 = 100;

/// Cap on simultaneous open proposals in `pending_proposal_ids` (voting phase).
pub const MAX_PENDING_PLANS: u32 = 16;

/// Bits reserved for the minor part of an on-chain protocol version.
pub(crate) const PROTOCOL_VERSION_MINOR_BITS: u32 = 24;

/// Maximum minor value in the `u8 major + u24 minor` protocol version encoding.
pub const MAX_PROTOCOL_VERSION_MINOR: u32 = (1u32 << PROTOCOL_VERSION_MINOR_BITS) - 1;

/// Protocol version embedded into this crate at compile time.
pub(crate) const PROTOCOL_VERSION_MAJOR: u8 =
    crate::version::parse_protocol_version_major_component(env!("CARGO_PKG_VERSION_MAJOR"));
pub(crate) const PROTOCOL_VERSION_MINOR: u32 =
    crate::version::parse_protocol_version_minor_component(env!("CARGO_PKG_VERSION_MINOR"));
pub const PROTOCOL_VERSION: crate::ProtocolVersion =
    crate::encode_protocol_version(PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR);
