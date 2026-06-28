use outbe_primitives::error::PrecompileError;

/// Module-local errors for upgrade storage/runtime.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UpdateError {
    #[error("scheduled update not found")]
    ScheduledUpdateNotFound,
    #[error("scheduled update already exists for proposal id")]
    ScheduledUpdateAlreadyExists,
    #[error("activation height must be at least current height + MIN_ACTIVATION_BUFFER")]
    HeightInPast,
    #[error("invalid protocol version; expected non-zero u32 encoded as u8 major + u24 minor")]
    InvalidVersion,
    #[error("downgrade not allowed: new version must be greater than active version")]
    DowngradeNotAllowed,
    #[error("invalid vote payload")]
    InvalidPayload,
    #[error("another scheduled update already uses this activation height")]
    ActivationConflict,
    #[error("invalid scheduled update status")]
    InvalidScheduledUpdateStatus,
}

impl From<UpdateError> for PrecompileError {
    fn from(err: UpdateError) -> Self {
        PrecompileError::Revert(err.to_string())
    }
}
