use outbe_primitives::error::PrecompileError;

/// Governance module errors.
#[derive(Debug, thiserror::Error)]
pub enum GovernanceError {
    #[error("caller is not an active validator")]
    NotValidator,
    #[error("proposal not found")]
    ProposalNotFound,
    #[error("proposal is not pending")]
    NotPending,
    #[error("proposal voting window is closed")]
    VotingClosed,
    #[error("validator has already voted on proposal")]
    AlreadyVoted,
    #[error("too many pending governance proposals")]
    TooManyPending,
    #[error("invalid proposal status")]
    InvalidProposalStatus,
    #[error("invalid vote kind")]
    InvalidVoteKind,
    #[error("unknown governance target module")]
    UnknownTargetModule,
    #[error("unknown governance action")]
    UnknownAction,
}

impl From<GovernanceError> for PrecompileError {
    fn from(err: GovernanceError) -> Self {
        PrecompileError::Revert(err.to_string())
    }
}
