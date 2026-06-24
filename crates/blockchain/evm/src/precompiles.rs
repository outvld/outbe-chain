//! Outbe precompile registration.
//!
//! Routes outbe stateful precompile addresses through
//! `PrecompilesMap::set_ctx_dispatch_hook` (outbe fork extension on alloy-evm)
//! so the dispatch closure receives a raw pointer to the unbroken
//! `&mut EthEvmContext<DB>`. The closure casts the pointer back to the
//! concrete context type for the current `DB`, builds a [`CtxStorageProvider`]
//! borrowing that context, and dispatches via [`StorageHandle`]. Sub-call
//! invocations from the precompile body hand the same `&mut ctx` to the
//! sub-call driver in [`crate::sub_call`].

use alloy_evm::{eth::EthEvmContext, precompiles::PrecompilesMap};
use alloy_primitives::{Address, Bytes};
use core::fmt::Debug;
use core::marker::PhantomData;
use outbe_primitives::addresses::{
    AGENT_REWARD_ADDRESS, CREDIS_ADDRESS, CREDIS_FACTORY_ADDRESS, DEBUG_SUBCALL_PRECOMPILE_ADDRESS,
    DESIS_ADDRESS, FIDELITY_ADDRESS, GEM_ADDRESS, GEM_FACTORY_ADDRESS, GOVERNANCE_ADDRESS,
    GRATIS_ADDRESS,
    GRATIS_FACTORY_ADDRESS, GRATIS_POOL_ADDRESS, INTEX_ADDRESS, INTEX_FACTORY_ADDRESS,
    METADOSIS_ADDRESS, NOD_ADDRESS, NOD_FACTORY_ADDRESS, ORACLE_ADDRESS, OUTBE_SYSTEM_TX_ADDRESS,
    PROMIS_ADDRESS, PROMIS_FACTORY_ADDRESS, PROMIS_LIMIT_ADDRESS, REWARDS_ADDRESS,
    SLASH_INDICATOR_ADDRESS, STAKING_ADDRESS, TEE_REGISTRY_ADDRESS, TRIBUTE_ADDRESS,
    TRIBUTE_FACTORY_ADDRESS, UPDATE_ADDRESS, VALIDATOR_SET_ADDRESS, VAULT_PROVIDER_ADDRESS,
    ZEROFEE_ADDRESS, ZKPROOF_GROTH16_ADDRESS, ZKPROOF_POSEIDON_ADDRESS,
};
use outbe_primitives::storage::gas::PRECOMPILE_BASE_GAS;
use outbe_primitives::storage::StorageHandle;
use revm::{
    handler::{precompile_output_to_interpreter_result, EthPrecompiles, PrecompileProvider},
    interpreter::{CallInputs, InterpreterResult},
    precompile::{PrecompileHalt, PrecompileOutput, PrecompileResult},
    primitives::hardfork::SpecId,
    Database,
};

use crate::{
    gas::SubcallGasMeter,
    storage::{CtxStorageProvider, ReentrancyStack},
};

type DispatchFn = fn(
    StorageHandle,
    &[u8],
    Address,
    alloy_primitives::U256,
) -> outbe_primitives::error::Result<Bytes>;

/// Per-precompile base gas function. Charged by the registry layer
/// before the dispatch body runs; `outbe_ctx_dispatch` debits
/// `max(PRECOMPILE_BASE_GAS, base_gas_fn(data))` from `inputs.gas_limit`.
///
/// Most precompiles use [`default_base_gas`] (flat `PRECOMPILE_BASE_GAS`);
/// computationally heavy stateless precompiles (Poseidon hash, zk
/// proof verification) declare their own.
type BaseGasFn = fn(&[u8]) -> u64;

/// Default base-gas function — returns the flat `PRECOMPILE_BASE_GAS`.
fn default_base_gas(_input: &[u8]) -> u64 {
    PRECOMPILE_BASE_GAS
}

/// Resolve outbe address to its dispatch entrypoint. Single source of truth
/// for the registered outbe stateful-precompile table.
fn outbe_dispatch_fn(address: &Address) -> Option<(&'static str, DispatchFn, BaseGasFn)> {
    let entry: (&'static str, DispatchFn, BaseGasFn) = match *address {
        a if a == GRATIS_ADDRESS => (
            "gratis",
            outbe_gratis::precompile::dispatch,
            default_base_gas,
        ),
        a if a == GRATIS_FACTORY_ADDRESS => (
            "gratisfactory",
            outbe_gratisfactory::precompile::dispatch,
            default_base_gas,
        ),
        a if a == GRATIS_POOL_ADDRESS => (
            "gratispool",
            outbe_gratispool::precompile::dispatch,
            default_base_gas,
        ),
        a if a == PROMIS_ADDRESS => (
            "promis",
            outbe_promis::precompile::dispatch,
            default_base_gas,
        ),
        a if a == PROMIS_FACTORY_ADDRESS => (
            "promisfactory",
            outbe_promisfactory::precompile::dispatch,
            default_base_gas,
        ),
        a if a == TRIBUTE_ADDRESS => (
            "tribute",
            outbe_tribute::precompile::dispatch,
            default_base_gas,
        ),
        a if a == NOD_ADDRESS => ("nod", outbe_nod::precompile::dispatch, default_base_gas),
        a if a == NOD_FACTORY_ADDRESS => (
            "nodfactory",
            outbe_nodfactory::precompile::dispatch,
            default_base_gas,
        ),
        a if a == GEM_ADDRESS => ("gem", outbe_gem::precompile::dispatch, default_base_gas),
        a if a == GEM_FACTORY_ADDRESS => (
            "gemfactory",
            outbe_gemfactory::precompile::dispatch,
            default_base_gas,
        ),
        a if a == INTEX_ADDRESS => ("intex", outbe_intex::precompile::dispatch, default_base_gas),
        a if a == INTEX_FACTORY_ADDRESS => (
            "intexfactory",
            outbe_intexfactory::precompile::dispatch,
            default_base_gas,
        ),
        a if a == DESIS_ADDRESS => ("desis", outbe_desis::precompile::dispatch, default_base_gas),
        a if a == VAULT_PROVIDER_ADDRESS => (
            "vaultprovider",
            outbe_vaultprovider::precompile::dispatch,
            default_base_gas,
        ),
        a if a == CREDIS_ADDRESS => (
            "credis",
            outbe_credis::precompile::dispatch,
            default_base_gas,
        ),
        a if a == CREDIS_FACTORY_ADDRESS => (
            "credisfactory",
            outbe_credisfactory::precompile::dispatch,
            default_base_gas,
        ),
        a if a == TRIBUTE_FACTORY_ADDRESS => (
            "tributefactory",
            outbe_tributefactory::precompile::dispatch,
            default_base_gas,
        ),
        a if a == VALIDATOR_SET_ADDRESS => (
            "validatorset",
            outbe_validatorset::precompile::dispatch,
            default_base_gas,
        ),
        a if a == SLASH_INDICATOR_ADDRESS => (
            "slashindicator",
            outbe_slashindicator::precompile::dispatch,
            outbe_slashindicator::precompile::base_gas,
        ),
        a if a == STAKING_ADDRESS => (
            "staking",
            outbe_staking::precompile::dispatch,
            default_base_gas,
        ),
        a if a == REWARDS_ADDRESS => (
            "rewards",
            outbe_rewards::precompile::dispatch,
            default_base_gas,
        ),
        a if a == AGENT_REWARD_ADDRESS => (
            "agentreward",
            outbe_agentreward::precompile::dispatch,
            default_base_gas,
        ),
        a if a == METADOSIS_ADDRESS => (
            "metadosis",
            outbe_metadosis::precompile::dispatch,
            default_base_gas,
        ),
        a if a == FIDELITY_ADDRESS => (
            "fidelity",
            outbe_fidelity::precompile::dispatch,
            default_base_gas,
        ),
        a if a == PROMIS_LIMIT_ADDRESS => (
            "promislimit",
            outbe_promislimit::precompile::dispatch,
            default_base_gas,
        ),
        a if a == ORACLE_ADDRESS => (
            "oracle",
            outbe_oracle::precompile::dispatch,
            default_base_gas,
        ),
        a if a == ZEROFEE_ADDRESS => (
            "zerofee",
            outbe_zerofee::precompile::dispatch,
            default_base_gas,
        ),
        a if a == OUTBE_SYSTEM_TX_ADDRESS => (
            "outbe-system-tx",
            crate::begin_block_precompile::dispatch,
            default_base_gas,
        ),
        a if a == DEBUG_SUBCALL_PRECOMPILE_ADDRESS => (
            "debug-subcall",
            crate::debug_subcall::dispatch,
            default_base_gas,
        ),
        a if a == ZKPROOF_POSEIDON_ADDRESS => (
            "zkproof-poseidon",
            outbe_zkproof::dispatch_poseidon,
            outbe_zkproof::poseidon_base_gas,
        ),
        a if a == ZKPROOF_GROTH16_ADDRESS => (
            "zkproof-groth16",
            outbe_zkproof::dispatch_groth16,
            outbe_zkproof::groth16_base_gas,
        ),
        a if a == TEE_REGISTRY_ADDRESS => (
            "teeregistry",
            outbe_teeregistry::precompile::dispatch,
            default_base_gas,
        ),
        a if a == GOVERNANCE_ADDRESS => (
            "governance",
            outbe_governance::precompile::dispatch,
            default_base_gas,
        ),
        a if a == UPDATE_ADDRESS => (
            "update",
            outbe_update::precompile::dispatch,
            default_base_gas,
        ),
        _ => return None,
    };
    Some(entry)
}

/// Translate the outbe-level [`outbe_primitives::error::PrecompileError`] (the
/// flat error type returned from every outbe precompile dispatch function)
/// into a revm [`PrecompileResult`] that the EVM interpreter understands.
///
/// `actual_gas` is the total gas charge attributed to this precompile call
/// (`PRECOMPILE_BASE_GAS` plus any storage-op gas). It is reported on
/// success and `Revert*` paths so the interpreter charges the caller
/// correctly; `Halt(OOG)` reports zero gas because revm treats OOG halts
/// as "consume everything" via `spend_all` in
/// `revm-handler::precompile_output_to_interpreter_result`.
///
/// The mapping is exhaustive over `PrecompileError`'s declared variants;
/// the trailing wildcard arm exists only to satisfy `#[non_exhaustive]`
/// from outbe-primitives and surfaces unknown variants as `Fatal` rather
/// than panicking. refine the `SubCall(_)`
/// arm to per-variant halt mappings once the sub-call body produces those
/// errors at runtime.
#[doc(hidden)]
pub fn map_outbe_precompile_result(
    result: outbe_primitives::error::Result<Bytes>,
    actual_gas: u64,
) -> PrecompileResult {
    match result {
        Ok(bytes) => Ok(PrecompileOutput::new(actual_gas, bytes, 0)),
        Err(outbe_primitives::error::PrecompileError::OutOfGas) => {
            Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, 0))
        }
        Err(outbe_primitives::error::PrecompileError::Revert(msg)) => Ok(PrecompileOutput::revert(
            actual_gas,
            Bytes::from(msg.into_bytes()),
            0,
        )),
        Err(outbe_primitives::error::PrecompileError::RevertBytes(bytes)) => {
            Ok(PrecompileOutput::revert(actual_gas, bytes, 0))
        }
        Err(outbe_primitives::error::PrecompileError::WriteProtection) => Ok(
            PrecompileOutput::halt(PrecompileHalt::other("state change during static call"), 0),
        ),
        Err(outbe_primitives::error::PrecompileError::SubCall(err)) => Err(
            revm::precompile::PrecompileError::Fatal(format!("sub-call error: {err:?}")),
        ),
        Err(outbe_primitives::error::PrecompileError::Unsupported) => Err(
            revm::precompile::PrecompileError::Fatal("precompile reported Unsupported".to_string()),
        ),
        Err(e) => Err(revm::precompile::PrecompileError::Fatal(e.to_string())),
    }
}

/// Returns the list of outbe precompile addresses registered by
/// [`extend_outbe_precompiles`].
///
/// Single source of truth for tests that need to enumerate outbe addresses
/// without re-typing the table. Keep in sync with the match arms in
/// [`extend_outbe_precompiles`]; tests in
/// `crates/blockchain/evm/tests/outbe_precompile_registration.rs` assert
/// the two lists agree.
pub fn outbe_precompile_addresses() -> &'static [Address] {
    &[
        GRATIS_ADDRESS,
        GRATIS_FACTORY_ADDRESS,
        GRATIS_POOL_ADDRESS,
        PROMIS_ADDRESS,
        PROMIS_FACTORY_ADDRESS,
        TRIBUTE_ADDRESS,
        NOD_ADDRESS,
        NOD_FACTORY_ADDRESS,
        GEM_ADDRESS,
        GEM_FACTORY_ADDRESS,
        INTEX_ADDRESS,
        INTEX_FACTORY_ADDRESS,
        DESIS_ADDRESS,
        CREDIS_ADDRESS,
        CREDIS_FACTORY_ADDRESS,
        TRIBUTE_FACTORY_ADDRESS,
        VALIDATOR_SET_ADDRESS,
        SLASH_INDICATOR_ADDRESS,
        STAKING_ADDRESS,
        REWARDS_ADDRESS,
        AGENT_REWARD_ADDRESS,
        METADOSIS_ADDRESS,
        FIDELITY_ADDRESS,
        PROMIS_LIMIT_ADDRESS,
        ORACLE_ADDRESS,
        ZEROFEE_ADDRESS,
        OUTBE_SYSTEM_TX_ADDRESS,
        ZKPROOF_POSEIDON_ADDRESS,
        ZKPROOF_GROTH16_ADDRESS,
        TEE_REGISTRY_ADDRESS,
        GOVERNANCE_ADDRESS,
        UPDATE_ADDRESS,
    ]
}

/// Register outbe stateful precompile dispatch on the given [`PrecompilesMap`]
/// via the `set_ctx_dispatch_hook` fork extension.
///
/// The hook receives a raw pointer to the unbroken `&mut EthEvmContext<DB>`
/// before revm destructures it into `EvmInternals`. The dispatch closure
/// casts the pointer back to `&mut EthEvmContext<DB>` (safe because the
/// `EvmFactory` impl that called us is specialised for the same DB), builds a
/// [`CtxStorageProvider`] borrowing that context, and dispatches the outbe
/// precompile through a [`StorageHandle`]. Sub-call from precompile body
/// reaches `sub_call::run` through the provider's `sub_call` method.
pub fn extend_outbe_precompiles<DB>(precompiles: &mut PrecompilesMap, spec: SpecId)
where
    DB: Database + Debug,
    DB::Error: Debug,
{
    precompiles.set_ctx_dispatch_hook(
        // handles: claim every outbe address.
        |addr: &Address| outbe_dispatch_fn(addr).is_some(),
        // dispatch: ctx_ptr is `*mut EthEvmContext<DB>` (cast in our caller, see
        // `PrecompileProvider::run` in the fork's `precompiles.rs`).
        move |ctx_ptr, inputs| {
            #[allow(unsafe_code)] // sole audited unsafe site; justified below.
            // SAFETY: alloy-evm fork's `PrecompileProvider::run` for
            // PrecompilesMap (specialised at impl site for our `Context<DB>`)
            // casts `&mut Context<...>` to `*mut c_void` and feeds it here.
            // The `DB` generic of this closure is the same `DB` of the
            // `Context<...>` the impl is specialised for (set at
            // `OutbeEvmFactory::create_evm<DB>` call site).
            let ctx: &mut EthEvmContext<DB> = unsafe { &mut *(ctx_ptr as *mut _) };
            outbe_ctx_dispatch::<DB>(ctx, inputs, spec)
        },
    );
}

/// Dispatch one outbe precompile call with full context access.
fn outbe_ctx_dispatch<DB>(
    ctx: &mut EthEvmContext<DB>,
    inputs: &CallInputs,
    spec: SpecId,
) -> Result<Option<InterpreterResult>, String>
where
    DB: Database + Debug,
    DB::Error: Debug,
{
    let address = inputs.bytecode_address;
    let Some((_name, dispatch_fn, base_gas_fn)) = outbe_dispatch_fn(&address) else {
        return Ok(None);
    };

    // Pre-decode call data to evaluate the base-gas function over the
    // exact bytes the dispatch body will see.
    let data: Bytes = match &inputs.input {
        revm::interpreter::CallInput::Bytes(b) => b.clone(),
        revm::interpreter::CallInput::SharedBuffer(_) => Bytes::new(),
    };

    // Per-precompile base gas, floored at PRECOMPILE_BASE_GAS so the
    // existing flat-cost contract still holds for default precompiles.
    let base_gas = base_gas_fn(data.as_ref()).max(PRECOMPILE_BASE_GAS);
    if inputs.gas_limit < base_gas {
        let out = PrecompileOutput::halt(PrecompileHalt::OutOfGas, 0);
        return Ok(Some(precompile_output_to_interpreter_result(
            out,
            inputs.gas_limit,
        )));
    }

    // Reentrancy guard: refuse re-entry into the same outbe address on the
    // active thread's call chain.
    let Some(_reentrancy) = ReentrancyStack::try_enter(address) else {
        let out = PrecompileOutput::revert(
            base_gas,
            Bytes::from_static(b"outbe precompile reentrancy denied"),
            0,
        );
        return Ok(Some(precompile_output_to_interpreter_result(
            out,
            inputs.gas_limit,
        )));
    };

    let is_static = inputs.is_static;
    let caller = inputs.caller;
    let value = match inputs.value {
        revm::interpreter::CallValue::Transfer(v) => v,
        revm::interpreter::CallValue::Apparent(v) => v,
    };
    // revm hands contract -> precompile calls as `CallInput::SharedBuffer`
    // (a range into the caller's shared memory) to skip an alloc. Use the
    // upstream `bytes_local` helper so both variants materialize the actual calldata
    use revm::context_interface::ContextTr;
    let data: Bytes = inputs.input.bytes_local(ctx.local());

    let gas_budget = inputs.gas_limit - base_gas;
    let gas_meter = SubcallGasMeter::new(gas_budget);

    tracing::debug!(
        target: "outbe::precompile::gas",
        ?address,
        gas_limit = inputs.gas_limit,
        base_gas,
        gas_budget,
        "precompile dispatch entry"
    );

    let mut provider =
        CtxStorageProvider::new(ctx, gas_meter, is_static, address, ReentrancyStack, spec);
    let storage = StorageHandle::new(&mut provider);
    let result = dispatch_fn(storage, data.as_ref(), caller, value);

    let storage_gas = gas_budget.saturating_sub(provider.gas.remaining());
    let actual_gas = base_gas + storage_gas;

    tracing::debug!(
        target: "outbe::precompile::gas",
        ?address,
        storage_gas,
        actual_gas,
        gas_remaining = provider.gas.remaining(),
        is_err = result.is_err(),
        "precompile dispatch exit"
    );

    let precompile_result = map_outbe_precompile_result(result, actual_gas);

    let interp_result = match precompile_result {
        Ok(precompile_output) => {
            precompile_output_to_interpreter_result(precompile_output, inputs.gas_limit)
        }
        // Both Fatal(String) and FatalAny(_) propagate as Err(String). At
        // revm 38 these are the only variants; the wildcard is defensive.
        Err(other) => return Err(other.to_string()),
    };

    Ok(Some(interp_result))
}

/// Precompile provider for the borrow-mode sub-call `Evm`
/// (`CTX = &mut EthEvmContext<DB>`), used by [`crate::sub_call`].
///
/// Mirrors the top-level [`PrecompilesMap`] semantics so a sub-call to any
/// outbe precompile behaves exactly like a top-level call: outbe stateful
/// precompiles dispatch through [`outbe_ctx_dispatch`], and everything else
/// (Ethereum precompiles `0x01..0x0a`, ordinary contract calls) falls back to
/// the standard [`EthPrecompiles`].
pub(crate) struct OutbeSubCallPrecompiles<DB> {
    /// Fallback provider for the Ethereum precompiles `0x01..0x0a`.
    eth: EthPrecompiles,
    /// EVM spec id, forwarded to [`outbe_ctx_dispatch`].
    spec: SpecId,
    _db: PhantomData<fn() -> DB>,
}

impl<DB> OutbeSubCallPrecompiles<DB> {
    pub(crate) fn new(spec: SpecId) -> Self {
        Self {
            eth: EthPrecompiles::new(spec),
            spec,
            _db: PhantomData,
        }
    }
}

impl<DB> PrecompileProvider<&mut EthEvmContext<DB>> for OutbeSubCallPrecompiles<DB>
where
    DB: Database + Debug,
    DB::Error: Debug,
{
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: SpecId) -> bool {
        self.spec = spec;
        <EthPrecompiles as PrecompileProvider<&mut EthEvmContext<DB>>>::set_spec(
            &mut self.eth,
            spec,
        )
    }

    fn run(
        &mut self,
        context: &mut &mut EthEvmContext<DB>,
        inputs: &CallInputs,
    ) -> Result<Option<InterpreterResult>, String> {
        // Outbe stateful precompiles first. `outbe_ctx_dispatch` returns
        // `Ok(None)` for any non-outbe address, so this is a cheap no-op for
        // Ethereum precompiles and ordinary contract targets.
        if let Some(result) = outbe_ctx_dispatch::<DB>(&mut **context, inputs, self.spec)? {
            return Ok(Some(result));
        }
        // Standard Ethereum precompiles `0x01..0x0a`; `Ok(None)` here lets the
        // caller push a real interpreter frame for ordinary contract targets.
        <EthPrecompiles as PrecompileProvider<&mut EthEvmContext<DB>>>::run(
            &mut self.eth,
            context,
            inputs,
        )
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        self.eth.warm_addresses()
    }

    fn contains(&self, address: &Address) -> bool {
        self.eth.contains(address)
    }
}
