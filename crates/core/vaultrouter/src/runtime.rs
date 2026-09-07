//! Orchestration logic for the vaultrouter precompile.
//!
//! Faithful port of `contracts/.../VaultRouter.sol`. All cross-contract
//! interaction (ERC-20 token ops, ERC-4626 vault ops, token-bundle top-up) goes
//! through `StorageHandle::call` / `StorageHandle::staticcall`; from the callee's
//! perspective `msg.sender` is `VAULT_ROUTER_ADDRESS` (this precompile).
//!
//! Following the repo convention (see `outbe_credisfactory::runtime`), ERC-20
//! mutating sub-calls propagate failure by reverting; their boolean return is
//! not separately decoded.

use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;

use outbe_primitives::addresses::VAULT_ROUTER_ADDRESS;
use outbe_primitives::error::Result;
use outbe_primitives::stablecoin::validate_currency_code;
use outbe_primitives::storage::StorageHandle;

use crate::api::{IVaultRouter, IVaultRouterCrosschainExtention};
use crate::errors::VaultRouterError;
use crate::schema::{VaultRouterContract, UNKNOWN};
use crate::sol_ext::IReferenceCurrency;
use crate::sol_ext::{ITokenBundle, IVaultV2, IERC20};

/// This precompile's own address (`address(this)` in the Solidity original).
const SELF: Address = VAULT_ROUTER_ADDRESS;

/// Ceiling on a registered asset's `decimals()` accepted by `rebalance`; every scaling
/// below this bound is an exact power-of-ten multiply or a single ceiling divide.
const MAX_ASSET_DECIMALS: u8 = 18;

// ---------------------------------------------------------------------------
// owner gate
// ---------------------------------------------------------------------------

/// Reverts unless `sender` is the configured owner. Replaces `onlyOwner`.
fn ensure_owner(storage: &StorageHandle<'_>, sender: Address) -> Result<()> {
    let contract = VaultRouterContract::new(storage.clone());
    if contract.owner.read()? != sender {
        return Err(VaultRouterError::Unauthorized.into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cross-chain configuration
// ---------------------------------------------------------------------------

/// Configures the Outbe ERC-7786 bridge. A zero address disables the
/// cross-chain vault flow without affecting local liquidity operations.
pub fn set_crosschain_bridge(
    storage: StorageHandle<'_>,
    sender: Address,
    bridge: Address,
) -> Result<()> {
    ensure_owner(&storage, sender)?;
    ensure_no_pending_crosschain_operations(&storage)?;
    let mut contract = VaultRouterContract::new(storage);
    let old_bridge = contract.crosschain_bridge.read()?;
    contract.crosschain_bridge.write(bridge)?;
    contract.emit(IVaultRouterCrosschainExtention::CrosschainBridgeUpdated {
        oldBridge: old_bridge,
        newBridge: bridge,
    })
}

/// Registers the fixed vault adapter for a remote EVM chain. Passing the zero
/// address clears the peer while retaining the chain key's default value.
pub fn set_remote_vault_router(
    storage: StorageHandle<'_>,
    sender: Address,
    chain_id: U256,
    router: Address,
) -> Result<()> {
    ensure_owner(&storage, sender)?;
    ensure_no_pending_crosschain_operations(&storage)?;
    let local_chain_id = U256::from(storage.chain_id()?);
    if chain_id.is_zero() || chain_id == local_chain_id {
        return Err(VaultRouterError::InvalidDestinationChain.into());
    }

    let mut contract = VaultRouterContract::new(storage);
    let old_router = contract.remote_vault_routers.read(&chain_id)?;
    if router.is_zero() {
        contract.remote_vault_routers.clear(&chain_id)?;
    } else {
        contract.remote_vault_routers.write(&chain_id, router)?;
    }
    contract.emit(IVaultRouterCrosschainExtention::RemoteVaultRouterUpdated {
        chainId: chain_id,
        oldRouter: old_router,
        newRouter: router,
    })
}

fn ensure_no_pending_crosschain_operations(storage: &StorageHandle<'_>) -> Result<()> {
    let pending = VaultRouterContract::new(storage.clone())
        .pending_crosschain_operations
        .read()?;
    if !pending.is_zero() {
        return Err(VaultRouterError::CrosschainOperationsPending(pending).into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// vault management (owner-only)
// ---------------------------------------------------------------------------

/// `addVault`: register an ownerless `vault` for its underlying asset and ISO
/// 4217 reference currency, then grant the router an unlimited allowance so
/// the vault can pull on deposit.
pub fn add_vault(storage: StorageHandle<'_>, sender: Address, vault: Address) -> Result<()> {
    ensure_owner(&storage, sender)?;
    if vault.is_zero() {
        return Err(VaultRouterError::ZeroAddress.into());
    }

    let asset = vault_asset(&storage, vault)?;
    if asset.is_zero() {
        return Err(VaultRouterError::ZeroAddress.into());
    }

    let current_owner = vault_owner(&storage, vault)?;
    if !current_owner.is_zero() {
        return Err(VaultRouterError::ReserveVaultOwnerNotRenounced(current_owner).into());
    }

    let iso_code = asset_iso_code(&storage, asset)?;
    validate_currency_code(iso_code)?;

    let mut contract = VaultRouterContract::new(storage.clone());
    if !contract.asset_vault_set(asset).insert(vault)? {
        return Err(VaultRouterError::ReserveVaultAlreadyAdded.into());
    }
    contract.assets.insert(asset)?;
    contract
        .reference_currency_vault_set(iso_code)
        .insert(vault)?;
    contract
        .vault_reference_currencies
        .write(&vault, iso_code)?;

    erc20_approve(&storage, asset, vault, U256::MAX)?;

    contract.emit(IVaultRouter::VaultAdded {
        isoCode: iso_code,
        asset,
        vault,
    })
}

/// Distinct assets whose vaults are registered under `iso_code`.
pub(crate) fn reference_currency_assets(
    storage: &StorageHandle<'_>,
    iso_code: u16,
) -> Result<Vec<Address>> {
    let contract = VaultRouterContract::new(storage.clone());
    let mut assets: Vec<Address> = Vec::new();
    for vault in contract.reference_currency_vault_set(iso_code).read_all()? {
        let asset = vault_asset(storage, vault)?;
        if !assets.contains(&asset) {
            assets.push(asset);
        }
    }
    Ok(assets)
}

/// `removeVault`: deregister `vault` for its asset and revoke the allowance.
pub fn remove_vault(storage: StorageHandle<'_>, sender: Address, vault: Address) -> Result<()> {
    ensure_owner(&storage, sender)?;
    if vault.is_zero() {
        return Err(VaultRouterError::ZeroAddress.into());
    }

    let asset = vault_asset(&storage, vault)?;

    let mut contract = VaultRouterContract::new(storage.clone());
    let mut iso_code = contract.vault_reference_currencies.read(&vault)?;
    if iso_code == 0 {
        // Upgrade compatibility for vaults registered before the ISO index was
        // introduced: resolve their immutable asset metadata on first removal.
        iso_code = asset_iso_code(&storage, asset)?;
    }
    if !contract.asset_vault_set(asset).remove(&vault)? {
        return Err(VaultRouterError::ReserveVaultNotFound.into());
    }
    if contract.asset_vault_set(asset).is_empty()? {
        contract.assets.remove(&asset)?;
    }
    contract
        .reference_currency_vault_set(iso_code)
        .remove(&vault)?;
    contract.vault_reference_currencies.clear(&vault)?;

    erc20_approve(&storage, asset, vault, U256::ZERO)?;

    contract.emit(IVaultRouter::VaultRemoved {
        isoCode: iso_code,
        asset,
        vault,
    })
}

// ---------------------------------------------------------------------------
// liquidity source / target management (owner-only)
// ---------------------------------------------------------------------------

pub fn add_liquidity_source(
    storage: StorageHandle<'_>,
    sender: Address,
    source: Address,
    source_type: u8,
) -> Result<()> {
    ensure_owner(&storage, sender)?;
    if source.is_zero() {
        return Err(VaultRouterError::ZeroAddress.into());
    }
    if source_type == UNKNOWN {
        return Err(VaultRouterError::InvalidLiquiditySource.into());
    }

    let mut contract = VaultRouterContract::new(storage.clone());
    contract.liquidity_sources.insert(source)?;
    contract
        .liquidity_source_types
        .write(&source, source_type)?;

    contract.emit(IVaultRouter::LiquiditySourceAdded {
        sourceAddress: source,
        sourceType: liquidity_source(source_type),
    })
}

pub fn remove_liquidity_source(
    storage: StorageHandle<'_>,
    sender: Address,
    source: Address,
) -> Result<()> {
    ensure_owner(&storage, sender)?;
    let mut contract = VaultRouterContract::new(storage.clone());
    if !contract.liquidity_sources.remove(&source)? {
        return Err(VaultRouterError::LiquiditySourceNotFound.into());
    }
    let source_type = contract.liquidity_source_types.read(&source)?;
    contract.liquidity_source_types.clear(&source)?;

    contract.emit(IVaultRouter::LiquiditySourceRemoved {
        sourceAddress: source,
        sourceType: liquidity_source(source_type),
    })
}

pub fn add_liquidity_target(
    storage: StorageHandle<'_>,
    sender: Address,
    target: Address,
    target_type: u8,
) -> Result<()> {
    ensure_owner(&storage, sender)?;
    if target.is_zero() {
        return Err(VaultRouterError::ZeroAddress.into());
    }
    if target_type == UNKNOWN {
        return Err(VaultRouterError::InvalidLiquidityTarget.into());
    }

    let mut contract = VaultRouterContract::new(storage.clone());
    contract.liquidity_targets.insert(target)?;
    contract
        .liquidity_target_types
        .write(&target, target_type)?;

    contract.emit(IVaultRouter::LiquidityTargetAdded {
        targetAddress: target,
        targetType: liquidity_target(target_type),
    })
}

pub fn remove_liquidity_target(
    storage: StorageHandle<'_>,
    sender: Address,
    target: Address,
) -> Result<()> {
    ensure_owner(&storage, sender)?;
    let mut contract = VaultRouterContract::new(storage.clone());
    if !contract.liquidity_targets.remove(&target)? {
        return Err(VaultRouterError::LiquidityTargetNotFound.into());
    }
    let target_type = contract.liquidity_target_types.read(&target)?;
    contract.liquidity_target_types.clear(&target)?;

    contract.emit(IVaultRouter::LiquidityTargetRemoved {
        targetAddress: target,
        targetType: liquidity_target(target_type),
    })
}

// ---------------------------------------------------------------------------
// liquidity flow
// ---------------------------------------------------------------------------

/// Resolves the `StablesSource` registered for `caller`, returning `Unknown`
/// when `caller` is not a registered source.
pub fn registered_liquidity_source(
    storage: &StorageHandle<'_>,
    caller: Address,
) -> Result<IVaultRouter::StablesSource> {
    let contract = VaultRouterContract::new(storage.clone());
    Ok(liquidity_source(
        contract.liquidity_source_types.read(&caller)?,
    ))
}

/// Resolves the `StablesTarget` registered for `caller`, returning `Unknown`
/// when `caller` is not a registered target.
pub fn registered_liquidity_target(
    storage: &StorageHandle<'_>,
    caller: Address,
) -> Result<IVaultRouter::StablesTarget> {
    let contract = VaultRouterContract::new(storage.clone());
    Ok(liquidity_target(
        contract.liquidity_target_types.read(&caller)?,
    ))
}

/// `deposit`: pulls `amount` of `asset` from the caller and deposits it
/// into the asset's vault, returning the minted shares.
pub(crate) fn deposit(
    storage: StorageHandle<'_>,
    caller: Address,
    asset: Address,
    amount: U256,
    source: IVaultRouter::StablesSource,
) -> Result<U256> {
    if matches!(source, IVaultRouter::StablesSource::Unknown) {
        return Err(VaultRouterError::InvalidLiquiditySource.into());
    }

    let vault = first_vault(&storage, asset)?;

    erc20_transfer_from(&storage, asset, caller, SELF, amount)?;
    let shares = vault_deposit(&storage, vault, amount, SELF)?;

    let mut contract = VaultRouterContract::new(storage.clone());
    contract.emit(IVaultRouter::LiquidityDeposited {
        source: caller,
        vault,
        assetsAmount: amount,
        sharesAmount: shares,
        sourceType: source,
    })?;

    Ok(shares)
}

/// `withdraw`: redeems `amount` of `asset` from the vault and tops it
/// up into `receiver` (a token bundle), returning the burned shares.
pub(crate) fn withdraw(
    storage: StorageHandle<'_>,
    caller: Address,
    asset: Address,
    amount: U256,
    receiver: Address,
    target: IVaultRouter::StablesTarget,
) -> Result<U256> {
    if receiver.is_zero() {
        return Err(VaultRouterError::ZeroAddress.into());
    }
    if matches!(target, IVaultRouter::StablesTarget::Unknown) {
        return Err(VaultRouterError::InvalidLiquidityTarget.into());
    }

    let vault = first_vault(&storage, asset)?;

    let required_shares = vault_preview_withdraw(&storage, vault, amount)?;
    let available_shares = erc20_balance_of(&storage, vault, SELF)?;
    if available_shares < required_shares {
        return Err(VaultRouterError::InsufficientSharesForWithdraw {
            available: available_shares,
            required: required_shares,
        }
        .into());
    }

    let burned_shares = vault_withdraw(&storage, vault, amount, SELF, SELF)?;

    erc20_approve(&storage, asset, receiver, amount)?;
    token_bundle_top_up(&storage, receiver, SELF, asset, amount)?;

    let mut contract = VaultRouterContract::new(storage.clone());
    contract.emit(IVaultRouter::LiquidityWithdrawn {
        target: caller,
        receiver,
        vault,
        assetsAmount: amount,
        burnedShares: burned_shares,
        targetType: target,
    })?;

    Ok(burned_shares)
}

// ---------------------------------------------------------------------------
// rebalance
// ---------------------------------------------------------------------------

/// `rebalance`: moves `amount` of liquidity from `vault_from` to `vault_to`. The caller
/// supplies `asset_to` (the destination vault's underlying asset) at the oracle cross rate
/// and receives `asset_from` in return, so the router never holds a standing allowance and
/// never sources liquidity itself - the caller must have approved this router for at least
/// the required amount beforehand. `max_amount_to` bounds what the router may pull if the
/// rate moved between the caller's quote and this call.
pub(crate) fn rebalance(
    storage: StorageHandle<'_>,
    caller: Address,
    vault_from: Address,
    vault_to: Address,
    amount: U256,
    max_amount_to: U256,
) -> Result<U256> {
    if !outbe_cca::api::is_active(&storage, caller)? {
        return Err(VaultRouterError::CcaNotActive(caller).into());
    }
    if vault_from == vault_to {
        return Err(VaultRouterError::SameVaultRebalance.into());
    }
    if amount.is_zero() {
        return Err(VaultRouterError::InvalidRebalanceAmount.into());
    }

    let (asset_from, asset_to) = registered_rebalance_assets(&storage, vault_from, vault_to)?;
    let amount_to = rebalance_amount_to(&storage, asset_from, asset_to, amount)?;
    if amount_to > max_amount_to {
        return Err(VaultRouterError::RebalanceInputExceedsMax {
            required: amount_to,
            max_amount_to,
        }
        .into());
    }

    let required_shares = vault_preview_withdraw(&storage, vault_from, amount)?;
    let available_shares = erc20_balance_of(&storage, vault_from, SELF)?;
    if available_shares < required_shares {
        return Err(VaultRouterError::InsufficientSharesForWithdraw {
            available: available_shares,
            required: required_shares,
        }
        .into());
    }

    storage.with_checkpoint(|| {
        // Receive before paying: an unapproved or short caller reverts here, before either
        // vault is touched.
        erc20_transfer_from(&storage, asset_to, caller, SELF, amount_to)?;
        let minted = vault_deposit(&storage, vault_to, amount_to, SELF)?;

        let burned = vault_withdraw(&storage, vault_from, amount, SELF, SELF)?;
        erc20_transfer(&storage, asset_from, caller, amount)?;

        let mut contract = VaultRouterContract::new(storage.clone());
        contract.emit(IVaultRouter::LiquidityRebalanced {
            cca: caller,
            vaultFrom: vault_from,
            vaultTo: vault_to,
            assetsWithdrawn: amount,
            burnedShares: burned,
            assetsDeposited: amount_to,
            mintedShares: minted,
        })?;
        Ok(amount_to)
    })
}

/// `previewRebalance`: what a `rebalance` of `amount` from `vault_from` to `vault_to` would
/// require the caller to supply, so it can approve exactly that before calling.
pub(crate) fn preview_rebalance(
    storage: &StorageHandle<'_>,
    vault_from: Address,
    vault_to: Address,
    amount: U256,
) -> Result<(Address, Address, U256)> {
    if vault_from == vault_to {
        return Err(VaultRouterError::SameVaultRebalance.into());
    }
    let (asset_from, asset_to) = registered_rebalance_assets(storage, vault_from, vault_to)?;
    let amount_to = rebalance_amount_to(storage, asset_from, asset_to, amount)?;
    Ok((asset_from, asset_to, amount_to))
}

/// Resolves both vaults' underlying assets and confirms each vault is still registered
/// under its own asset - the enumerable set membership `addVault`/`removeVault` maintain,
/// not `vault_reference_currencies`, which has an upgrade-compatibility hole for vaults
/// registered before the ISO index existed (see `remove_vault` above).
fn registered_rebalance_assets(
    storage: &StorageHandle<'_>,
    vault_from: Address,
    vault_to: Address,
) -> Result<(Address, Address)> {
    let asset_from = vault_asset(storage, vault_from)?;
    let asset_to = vault_asset(storage, vault_to)?;
    let contract = VaultRouterContract::new(storage.clone());
    if !contract.asset_vault_set(asset_from).contains(&vault_from)? {
        return Err(VaultRouterError::RebalanceVaultNotRegistered(vault_from).into());
    }
    if !contract.asset_vault_set(asset_to).contains(&vault_to)? {
        return Err(VaultRouterError::RebalanceVaultNotRegistered(vault_to).into());
    }
    Ok((asset_from, asset_to))
}

/// `amount` of `asset_from` re-expressed in `asset_to`. Identical assets short-circuit at
/// 1:1 with no oracle read and no decimal scaling. Otherwise the two assets' ISO 4217
/// currencies are converted through the oracle's COEN cross rate.
fn rebalance_amount_to(
    storage: &StorageHandle<'_>,
    asset_from: Address,
    asset_to: Address,
    amount: U256,
) -> Result<U256> {
    if asset_from == asset_to {
        return Ok(amount);
    }

    let decimals_from = erc20_decimals(storage, asset_from)?;
    let decimals_to = erc20_decimals(storage, asset_to)?;
    if decimals_from > MAX_ASSET_DECIMALS {
        return Err(VaultRouterError::UnsupportedAssetDecimals(decimals_from).into());
    }
    if decimals_to > MAX_ASSET_DECIMALS {
        return Err(VaultRouterError::UnsupportedAssetDecimals(decimals_to).into());
    }

    let iso_from = asset_iso_code(storage, asset_from)?;
    let iso_to = asset_iso_code(storage, asset_to)?;
    validate_currency_code(iso_from)?;
    validate_currency_code(iso_to)?;
    if decimals_to >= decimals_from {
        let scaled = rescale_decimals(amount, decimals_from, decimals_to)?;
        outbe_oracle::api::fresh_currency_cross_rate(storage.clone(), iso_from, iso_to, scaled)
    } else {
        let converted = outbe_oracle::api::fresh_currency_cross_rate(
            storage.clone(),
            iso_from,
            iso_to,
            amount,
        )?;
        rescale_decimals(converted, decimals_from, decimals_to)
    }
}

/// Rescales `amount` from `from_decimals` to `to_decimals`. Scaling up is an exact
/// power-of-ten multiply; scaling down rounds up.
fn rescale_decimals(amount: U256, from_decimals: u8, to_decimals: u8) -> Result<U256> {
    match to_decimals.cmp(&from_decimals) {
        core::cmp::Ordering::Equal => Ok(amount),
        core::cmp::Ordering::Greater => amount
            .checked_mul(U256::from(10u64).pow(U256::from(to_decimals - from_decimals)))
            .ok_or_else(|| VaultRouterError::InvalidRebalanceAmount.into()),
        core::cmp::Ordering::Less => {
            Ok(amount.div_ceil(U256::from(10u64).pow(U256::from(from_decimals - to_decimals))))
        }
    }
}

// ---------------------------------------------------------------------------
// views
// ---------------------------------------------------------------------------

/// `sharesBalance`: vault shares currently held by this router.
pub fn shares_balance(storage: &StorageHandle<'_>, vault: Address) -> Result<U256> {
    erc20_balance_of(storage, vault, SELF)
}

// ---------------------------------------------------------------------------
// helpers: enum reconstruction
// ---------------------------------------------------------------------------

fn liquidity_source(value: u8) -> IVaultRouter::StablesSource {
    IVaultRouter::StablesSource::try_from(value).unwrap_or(IVaultRouter::StablesSource::Unknown)
}

fn liquidity_target(value: u8) -> IVaultRouter::StablesTarget {
    IVaultRouter::StablesTarget::try_from(value).unwrap_or(IVaultRouter::StablesTarget::Unknown)
}

/// Resolves the first vault for `asset`, reverting if none is configured.
fn first_vault(storage: &StorageHandle<'_>, asset: Address) -> Result<Address> {
    let contract = VaultRouterContract::new(storage.clone());
    contract
        .first_vault(asset)?
        .ok_or_else(|| VaultRouterError::ReserveVaultNotConfigured.into())
}

// ---------------------------------------------------------------------------
// helpers: external sub-calls
// ---------------------------------------------------------------------------

fn erc20_approve(
    storage: &StorageHandle<'_>,
    token: Address,
    spender: Address,
    amount: U256,
) -> Result<()> {
    let calldata = IERC20::approveCall { spender, amount }.abi_encode();
    storage.call(token, U256::ZERO, calldata.into())?;
    Ok(())
}

fn erc20_transfer_from(
    storage: &StorageHandle<'_>,
    token: Address,
    from: Address,
    to: Address,
    amount: U256,
) -> Result<()> {
    let calldata = IERC20::transferFromCall { from, to, amount }.abi_encode();
    storage.call(token, U256::ZERO, calldata.into())?;
    Ok(())
}

fn erc20_balance_of(storage: &StorageHandle<'_>, token: Address, account: Address) -> Result<U256> {
    let ret = storage.staticcall(token, IERC20::balanceOfCall { account }.abi_encode().into())?;
    IERC20::balanceOfCall::abi_decode_returns(&ret)
        .map_err(|_| VaultRouterError::UndecodableReturn("ERC20 balanceOf").into())
}

fn erc20_decimals(storage: &StorageHandle<'_>, token: Address) -> Result<u8> {
    let ret = storage.staticcall(token, IERC20::decimalsCall {}.abi_encode().into())?;
    IERC20::decimalsCall::abi_decode_returns(&ret)
        .map_err(|_| VaultRouterError::UndecodableReturn("ERC20 decimals").into())
}

fn erc20_transfer(
    storage: &StorageHandle<'_>,
    token: Address,
    to: Address,
    amount: U256,
) -> Result<()> {
    let calldata = IERC20::transferCall { to, amount }.abi_encode();
    storage.call(token, U256::ZERO, calldata.into())?;
    Ok(())
}

fn vault_asset(storage: &StorageHandle<'_>, vault: Address) -> Result<Address> {
    let ret = storage.staticcall(vault, IVaultV2::assetCall {}.abi_encode().into())?;
    IVaultV2::assetCall::abi_decode_returns(&ret)
        .map_err(|_| VaultRouterError::UndecodableReturn("IVaultV2 asset").into())
}

fn vault_owner(storage: &StorageHandle<'_>, vault: Address) -> Result<Address> {
    let ret = storage.staticcall(vault, IVaultV2::ownerCall {}.abi_encode().into())?;
    IVaultV2::ownerCall::abi_decode_returns(&ret)
        .map_err(|_| VaultRouterError::UndecodableReturn("IVaultV2 owner").into())
}

fn asset_iso_code(storage: &StorageHandle<'_>, asset: Address) -> Result<u16> {
    let ret = storage.staticcall(
        asset,
        IReferenceCurrency::isoCodeCall {}.abi_encode().into(),
    )?;
    IReferenceCurrency::isoCodeCall::abi_decode_returns(&ret)
        .map_err(|_| VaultRouterError::UndecodableReturn("IReferenceCurrency isoCode").into())
}

fn vault_deposit(
    storage: &StorageHandle<'_>,
    vault: Address,
    assets: U256,
    on_behalf: Address,
) -> Result<U256> {
    let ret = storage.call(
        vault,
        U256::ZERO,
        IVaultV2::depositCall {
            assets,
            onBehalf: on_behalf,
        }
        .abi_encode()
        .into(),
    )?;
    IVaultV2::depositCall::abi_decode_returns(&ret)
        .map_err(|_| VaultRouterError::UndecodableReturn("IVaultV2 deposit").into())
}

fn vault_preview_withdraw(
    storage: &StorageHandle<'_>,
    vault: Address,
    assets: U256,
) -> Result<U256> {
    let ret = storage.staticcall(
        vault,
        IVaultV2::previewWithdrawCall { assets }.abi_encode().into(),
    )?;
    IVaultV2::previewWithdrawCall::abi_decode_returns(&ret)
        .map_err(|_| VaultRouterError::UndecodableReturn("IVaultV2 previewWithdraw").into())
}

fn vault_withdraw(
    storage: &StorageHandle<'_>,
    vault: Address,
    assets: U256,
    receiver: Address,
    on_behalf: Address,
) -> Result<U256> {
    let ret = storage.call(
        vault,
        U256::ZERO,
        IVaultV2::withdrawCall {
            assets,
            receiver,
            onBehalf: on_behalf,
        }
        .abi_encode()
        .into(),
    )?;
    IVaultV2::withdrawCall::abi_decode_returns(&ret)
        .map_err(|_| VaultRouterError::UndecodableReturn("IVaultV2 withdraw").into())
}

fn token_bundle_top_up(
    storage: &StorageHandle<'_>,
    receiver: Address,
    sender: Address,
    token: Address,
    amount: U256,
) -> Result<()> {
    // A CALL to a codeless account succeeds and returns empty in EVM, so topUp's
    // internal guards would be silently skipped if the bundle smart account is not
    // deployed. Reject up front so requestCredis fails instead of half-completing.
    if storage.with_account_info(receiver, |info| Ok(info.is_empty_code_hash()))? {
        return Err(VaultRouterError::ReceiverNotDeployed.into());
    }
    let calldata = ITokenBundle::topUpCall {
        sender,
        token,
        amount,
    }
    .abi_encode();
    storage.call(receiver, U256::ZERO, calldata.into())?;
    Ok(())
}
