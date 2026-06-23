/// Governance voting window in blocks.
///
/// Current placeholder follows the existing update implementation. This is a
/// consensus constant and should only change through a hardfork.
pub const VOTING_WINDOW_BLOCKS: u64 = 86_400;

/// Quorum numerator for `yes_votes / active_validator_count`.
pub const QUORUM_NUMERATOR: u64 = 2;

/// Quorum denominator for `yes_votes / active_validator_count`.
pub const QUORUM_DENOMINATOR: u64 = 3;

/// Maximum number of proposals in the bounded pending index.
pub const MAX_PENDING_PROPOSALS: u32 = 64;
