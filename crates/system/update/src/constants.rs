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

/// Cap on simultaneous pending proposals indexed in `pending_plan_ids`.
pub const MAX_PENDING_PLANS: u32 = 16;
