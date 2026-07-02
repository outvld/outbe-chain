use outbe_primitives::error::PrecompileError;

/// Vote module errors.
#[derive(Debug, thiserror::Error)]
pub enum VoteError {
    #[error("caller is not an active validator")]
    NotValidator,
    #[error("caller is not an eligible validator")]
    NotEligibleValidator,
    #[error("proposal not found")]
    ProposalNotFound,
    #[error("proposal is not pending")]
    NotPending,
    #[error("proposal voting window is closed")]
    VotingClosed,
    #[error("validator has already voted on proposal")]
    AlreadyVoted,
    #[error("too many pending proposals")]
    TooManyPending,
    #[error("validator has too many pending proposals")]
    TooManyPendingByValidator,
    #[error("invalid proposal status")]
    InvalidProposalStatus,
    #[error("invalid vote kind")]
    InvalidVoteKind,
    #[error("unknown vote target module")]
    UnknownTargetModule,
    #[error("unknown vote action")]
    UnknownAction,
}

impl From<VoteError> for PrecompileError {
    fn from(err: VoteError) -> Self {
        PrecompileError::Revert(err.to_string())
    }
}
