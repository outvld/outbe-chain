use outbe_primitives::error::PrecompileError;

/// Module-local errors for upgrade governance storage/runtime.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UpdateError {
    #[error("caller is not an active validator")]
    NotValidator,
    #[error("proposal not found")]
    ProposalNotFound,
    #[error("validator already voted on this proposal")]
    AlreadyVoted,
    #[error("voting window closed")]
    VotingClosed,
    #[error("activation height is in the past")]
    HeightInPast,
    #[error("invalid version format; expected vMAJOR.MINOR.PATCH")]
    InvalidVersion,
    #[error("downgrade not allowed: new version must be greater than active version")]
    DowngradeNotAllowed,
    #[error("proposal is not pending")]
    NotPending,
    #[error("only the proposer may cancel this proposal")]
    NotProposer,
    #[error("msg.value must be zero")]
    NonZeroValue,
    #[error("too many pending proposals")]
    TooManyPending,
    #[error("invalid vote kind; expected 0=No or 1=Yes")]
    InvalidVoteKind,
    #[error("invalid proposal status")]
    InvalidProposalStatus,
}

impl From<UpdateError> for PrecompileError {
    fn from(err: UpdateError) -> Self {
        PrecompileError::Revert(err.to_string())
    }
}
