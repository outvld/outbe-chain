pub mod begin_block_precompile;
pub mod builder;
pub mod config;
pub mod debug_subcall;
pub mod executor;
pub mod factory;
pub mod failure_receipt;
pub mod gas;
pub mod precompiles;
pub mod storage;
pub mod upgrade_handlers;
pub mod sub_call;
/// Re-export of the validator EVM signer, which now lives in
/// `outbe-primitives::signer`. Wire/data-only type (no EVM runtime), so it
/// belongs with the other primitives; keeping `outbe_evm::signer` as a path
/// preserves the existing `pub use` re-exports below.
pub use outbe_primitives::signer;
/// Re-export of the system-tx codec, which now physically lives in
/// `outbe-primitives::system_tx`. The codec is wire/data-only (no EVM
/// runtime), so it belongs with the rest of the consensus primitives;
/// keeping the path `outbe_evm::system_tx` working avoids touching ~50
/// call sites in executor / payload builder / tests.
pub use outbe_primitives::system_tx;

pub use config::{
    OutbeBlockAssembler, OutbeBlockExecutionCtx, OutbeEvmConfig, OutbeExecutorBuilder,
    OutbeNextBlockEnvAttributes, RethAccountedParentArtifactProvider,
};
pub use executor::{AccountedParentArtifact, AccountedParentArtifactProvider};
pub use factory::OutbeEvmFactory;
pub use signer::{
    default_validator_evm_key_path, OutbeEvmSigner, SharedOutbeEvmSigner, SignerError,
};
