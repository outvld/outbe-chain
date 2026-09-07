//! Unit tests for the vaultrouter precompile.
//!
//! Cross-contract interaction is exercised through `HashMapStorageProvider`'s
//! sub-call stubs: `stub_sub_call_at(target, bytes)` pins a target's return
//! payload and `enable_sub_call_stub()` makes every other sub-call succeed with
//! empty returndata (matching the convention in `outbe_credisfactory::tests`).

use alloy_primitives::{address, Address, Bytes, B256, U256};
use alloy_sol_types::{SolCall, SolEvent, SolValue};

use outbe_oracle::api::AddressPair;
use outbe_oracle::schema::OracleContract;
use outbe_primitives::addresses::VAULT_ROUTER_ADDRESS;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::{Bytecode, StorageHandle};

use crate::api::{IVaultRouter, IVaultRouterCrosschainExtention};
use crate::crosschain;
use crate::precompile::{dispatch, dispatch_crosschain};
use crate::runtime;
use crate::schema::VaultRouterContract;
use crate::sol_ext::IReferenceCurrency;
use crate::sol_ext::{IVaultV2, IERC20};

const CHAIN_ID: u64 = 1;
const USD_ISO_CODE: u16 = 840;

fn owner() -> Address {
    address!("0x0000000000000000000000000000000000000a11")
}
fn stranger() -> Address {
    address!("0x0000000000000000000000000000000000000b0b")
}
fn source_account() -> Address {
    address!("0x0000000000000000000000000000000000000111")
}
fn target_account() -> Address {
    address!("0x0000000000000000000000000000000000000222")
}
fn asset() -> Address {
    address!("0x0000000000000000000000000000000000000888")
}
fn vault() -> Address {
    address!("0x0000000000000000000000000000000000000777")
}
fn receiver() -> Address {
    address!("0x0000000000000000000000000000000000000999")
}
fn bridge() -> Address {
    address!("0x000000000000000000000000000000000000b111")
}
fn token_bridge() -> Address {
    address!("0x000000000000000000000000000000000000b222")
}
fn remote_router() -> Address {
    address!("0x000000000000000000000000000000000000b517")
}

fn cca() -> Address {
    address!("0x000000000000000000000000000000000000cca1")
}
fn vault_from() -> Address {
    address!("0x000000000000000000000000000000000000af01")
}
fn vault_to() -> Address {
    address!("0x000000000000000000000000000000000000af02")
}
fn asset_from() -> Address {
    address!("0x000000000000000000000000000000000000a5f1")
}
fn asset_to() -> Address {
    address!("0x000000000000000000000000000000000000a5f2")
}

const EUR_ISO_CODE: u16 = 978;

/// ABI encoding of a single `uint256`/`address` return: the 32-byte big-endian word.
fn word(value: U256) -> Bytes {
    Bytes::from(value.to_be_bytes::<32>().to_vec())
}

/// ABI encoding of a single `address` return.
fn word_addr(value: Address) -> Bytes {
    word(U256::from_be_bytes(value.into_word().0))
}

/// Publishes a `COEN/iso_code` rate directly through the Oracle's own storage
/// schema (a Rust cross-module read, not an EVM sub-call - `OracleContract` is
/// bound to `ORACLE_ADDRESS` in this same provider). `timestamp` must be
/// non-zero and within `FX_RATE_MAX_AGE_SECONDS` of the provider's clock for
/// `fresh_currency_cross_rate` to accept it.
fn write_oracle_rate(
    storage: &StorageHandle<'_>,
    iso_code: u16,
    pair_id: u32,
    rate: U256,
    timestamp: u64,
) {
    let oracle = OracleContract::new(storage.clone());
    let pair = AddressPair::new_coen_to(iso_code);
    oracle.pair_to_index.write(&pair, pair_id).unwrap();
    oracle.exchange_rate.write(&pair_id, rate).unwrap();
    oracle
        .exchange_rate_timestamp
        .write(&pair_id, timestamp)
        .unwrap();
}

fn set_owner(storage: &StorageHandle<'_>, who: Address) {
    VaultRouterContract::new(storage.clone())
        .owner
        .write(who)
        .unwrap();
}

fn configure_crosschain(storage: &StorageHandle<'_>) {
    runtime::set_crosschain_bridge(storage.clone(), owner(), bridge()).unwrap();
    runtime::set_remote_vault_router(storage.clone(), owner(), U256::from(56), remote_router())
        .unwrap();
    crosschain::set_asset(
        storage.clone(),
        owner(),
        asset(),
        token_bridge(),
        U256::from(56),
    )
    .unwrap();
}

// --- ownership ---------------------------------------------------------------

#[test]
fn owner_view_returns_seeded_owner() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());
        let out = dispatch(
            storage.clone(),
            &IVaultRouter::ownerCall {}.abi_encode(),
            stranger(),
            U256::ZERO,
        )
        .unwrap();
        let got = IVaultRouter::ownerCall::abi_decode_returns(&out).unwrap();
        assert_eq!(got, owner());
    });
}

#[test]
fn management_methods_reject_non_owner() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());
        // onlyOwner is checked before any sub-call, so no stubs are needed.
        let err = runtime::add_liquidity_source(storage.clone(), stranger(), source_account(), 1)
            .unwrap_err();
        assert!(err.to_string().contains("unauthorized"), "{err}");

        let err = runtime::add_vault(storage.clone(), stranger(), vault()).unwrap_err();
        assert!(err.to_string().contains("unauthorized"), "{err}");
    });
}

// --- centralized management -------------------------------------------------

#[test]
fn crosschain_abi_is_not_exposed_by_default() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());

        let err = dispatch(
            storage.clone(),
            &IVaultRouterCrosschainExtention::setCrosschainBridgeCall { bridge: bridge() }
                .abi_encode(),
            owner(),
            U256::ZERO,
        )
        .unwrap_err();

        assert!(err.to_string().contains("decode error"), "{err}");
        assert_eq!(
            VaultRouterContract::new(storage)
                .crosschain_bridge
                .read()
                .unwrap(),
            Address::ZERO
        );
    });
}

#[test]
fn owner_configures_bridge_and_remote_router_through_abi() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());
        let bsc_chain_id = U256::from(56);

        dispatch_crosschain(
            storage.clone(),
            &IVaultRouterCrosschainExtention::setCrosschainBridgeCall { bridge: bridge() }
                .abi_encode(),
            owner(),
            U256::ZERO,
        )
        .unwrap();
        dispatch_crosschain(
            storage.clone(),
            &IVaultRouterCrosschainExtention::setRemoteVaultRouterCall {
                chainId: bsc_chain_id,
                router: remote_router(),
            }
            .abi_encode(),
            owner(),
            U256::ZERO,
        )
        .unwrap();

        let bridge_out = dispatch_crosschain(
            storage.clone(),
            &IVaultRouterCrosschainExtention::crosschainBridgeCall {}.abi_encode(),
            stranger(),
            U256::ZERO,
        )
        .unwrap();
        assert_eq!(
            IVaultRouterCrosschainExtention::crosschainBridgeCall::abi_decode_returns(&bridge_out)
                .unwrap(),
            bridge()
        );

        let router_out = dispatch_crosschain(
            storage.clone(),
            &IVaultRouterCrosschainExtention::remoteVaultRouterCall {
                chainId: bsc_chain_id,
            }
            .abi_encode(),
            stranger(),
            U256::ZERO,
        )
        .unwrap();
        assert_eq!(
            IVaultRouterCrosschainExtention::remoteVaultRouterCall::abi_decode_returns(&router_out)
                .unwrap(),
            remote_router()
        );

        let err =
            runtime::set_crosschain_bridge(storage.clone(), stranger(), Address::ZERO).unwrap_err();
        assert!(err.to_string().contains("unauthorized"), "{err}");
    });
}

#[test]
fn crosschain_deposit_stays_pending_until_authenticated_ack() {
    let fee = U256::from(1_000_000);
    let amount = U256::from(100);
    let send_id = B256::from(fee.to_be_bytes::<32>());
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at(token_bridge(), word(fee));
    storage.enable_sub_call_stub();

    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());
        configure_crosschain(&storage);

        let quote = IVaultRouterCrosschainExtention::quoteCrosschainDepositCall {
            assetsAmount: amount,
            destinationGasLimit: U256::from(600_000),
            acknowledgementGasLimit: U256::from(250_000),
        };
        let quote_out = dispatch_crosschain(
            storage.clone(),
            &quote.abi_encode(),
            source_account(),
            U256::ZERO,
        )
        .unwrap();
        let quoted =
            IVaultRouterCrosschainExtention::quoteCrosschainDepositCall::abi_decode_returns(
                &quote_out,
            )
            .unwrap();
        assert_eq!(quoted.nativeFee, fee);

        let call = IVaultRouterCrosschainExtention::crosschainDepositCall {
            assetsAmount: amount,
            destinationGasLimit: quote.destinationGasLimit,
            acknowledgementGasLimit: quote.acknowledgementGasLimit,
        };
        let out = dispatch_crosschain(storage.clone(), &call.abi_encode(), source_account(), fee)
            .unwrap();
        let sent = IVaultRouterCrosschainExtention::crosschainDepositCall::abi_decode_returns(&out)
            .unwrap();
        assert_eq!(sent.operationId, quoted.operationId);
        assert_eq!(sent.sendId, send_id);

        let contract = VaultRouterContract::new(storage.clone());
        assert_eq!(
            contract.crosschain_shares.read(&source_account()).unwrap(),
            U256::ZERO
        );
        assert_eq!(
            contract.operation_statuses.read(&sent.operationId).unwrap(),
            crosschain::STATUS_PENDING
        );
        assert_eq!(
            contract.pending_crosschain_operations.read().unwrap(),
            U256::from(1)
        );

        let err = runtime::set_crosschain_bridge(storage.clone(), owner(), stranger()).unwrap_err();
        assert!(err.to_string().contains("operations pending"), "{err}");

        let payload: Bytes = (
            U256::from(crosschain::DEPOSIT_ACKNOWLEDGEMENT),
            sent.operationId,
            source_account(),
            amount,
        )
            .abi_encode()
            .into();
        let sender: Bytes = crosschain::format_evm_v1(U256::from(56), remote_router()).into();

        let wrong = IVaultRouterCrosschainExtention::receiveMessageCall {
            receiveId: B256::ZERO,
            sender: sender.clone(),
            payload: payload.clone(),
        };
        let err = dispatch_crosschain(storage.clone(), &wrong.abi_encode(), stranger(), U256::ZERO)
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid crosschain sender"),
            "{err}"
        );

        let ack = IVaultRouterCrosschainExtention::receiveMessageCall {
            receiveId: B256::ZERO,
            sender,
            payload,
        };
        dispatch_crosschain(storage.clone(), &ack.abi_encode(), bridge(), U256::ZERO).unwrap();

        let contract = VaultRouterContract::new(storage.clone());
        assert_eq!(
            contract.crosschain_shares.read(&source_account()).unwrap(),
            amount
        );
        assert_eq!(contract.total_crosschain_shares.read().unwrap(), amount);
        assert_eq!(
            contract.operation_statuses.read(&sent.operationId).unwrap(),
            crosschain::STATUS_COMPLETED
        );
        assert_eq!(
            contract.pending_crosschain_operations.read().unwrap(),
            U256::ZERO
        );

        let err = dispatch_crosschain(storage.clone(), &ack.abi_encode(), bridge(), U256::ZERO)
            .unwrap_err();
        assert!(err.to_string().contains("already completed"), "{err}");
    });
}

#[test]
fn crosschain_withdraw_burns_receipt_then_completes_on_token_return() {
    let fee = U256::from(700_000);
    let amount = U256::from(40);
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at(bridge(), word(fee));
    storage.enable_sub_call_stub();

    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());
        configure_crosschain(&storage);
        let contract = VaultRouterContract::new(storage.clone());
        contract
            .crosschain_shares
            .write(&source_account(), U256::from(100))
            .unwrap();
        contract
            .total_crosschain_shares
            .write(U256::from(100))
            .unwrap();

        let quote = IVaultRouterCrosschainExtention::quoteCrosschainWithdrawCall {
            sharesAmount: amount,
            requestGasLimit: U256::from(300_000),
            returnGasLimit: U256::from(450_000),
        };
        let quote_out = dispatch_crosschain(
            storage.clone(),
            &quote.abi_encode(),
            source_account(),
            U256::ZERO,
        )
        .unwrap();
        let quoted =
            IVaultRouterCrosschainExtention::quoteCrosschainWithdrawCall::abi_decode_returns(
                &quote_out,
            )
            .unwrap();
        assert_eq!(quoted.nativeFee, fee);

        let call = IVaultRouterCrosschainExtention::crosschainWithdrawCall {
            sharesAmount: amount,
            requestGasLimit: quote.requestGasLimit,
            returnGasLimit: quote.returnGasLimit,
        };
        let out = dispatch_crosschain(storage.clone(), &call.abi_encode(), source_account(), fee)
            .unwrap();
        let sent =
            IVaultRouterCrosschainExtention::crosschainWithdrawCall::abi_decode_returns(&out)
                .unwrap();
        assert_eq!(sent.operationId, quoted.operationId);

        let contract = VaultRouterContract::new(storage.clone());
        assert_eq!(
            contract.crosschain_shares.read(&source_account()).unwrap(),
            U256::from(60)
        );
        assert_eq!(
            contract.total_crosschain_shares.read().unwrap(),
            U256::from(60)
        );
        assert_eq!(
            contract.operation_statuses.read(&sent.operationId).unwrap(),
            crosschain::STATUS_PENDING
        );

        let extra_data: Bytes = (
            U256::from(crosschain::WITHDRAW_RETURN),
            sent.operationId,
            source_account(),
            amount,
        )
            .abi_encode()
            .into();
        let returned = IVaultRouterCrosschainExtention::onCrosschainTokensReceivedCall {
            sourceDomain: 56,
            from: crosschain::format_evm_v1(U256::from(56), remote_router()).into(),
            amount,
            extraData: extra_data,
        };
        dispatch_crosschain(
            storage.clone(),
            &returned.abi_encode(),
            token_bridge(),
            U256::ZERO,
        )
        .unwrap();

        assert_eq!(
            VaultRouterContract::new(storage.clone())
                .operation_statuses
                .read(&sent.operationId)
                .unwrap(),
            crosschain::STATUS_COMPLETED
        );
    });
}

#[test]
fn failed_crosschain_deposit_does_not_consume_nonce_or_shares() {
    let fee = U256::from(50);
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at(token_bridge(), word(fee));
    storage.enable_sub_call_stub();

    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());
        configure_crosschain(&storage);
        let call = IVaultRouterCrosschainExtention::crosschainDepositCall {
            assetsAmount: U256::from(100),
            destinationGasLimit: U256::from(600_000),
            acknowledgementGasLimit: U256::from(250_000),
        };
        let err = dispatch_crosschain(
            storage.clone(),
            &call.abi_encode(),
            source_account(),
            fee - U256::from(1),
        )
        .unwrap_err();
        assert!(err.to_string().contains("fee mismatch"), "{err}");

        let contract = VaultRouterContract::new(storage.clone());
        assert_eq!(
            contract.crosschain_operation_nonce.read().unwrap(),
            U256::ZERO
        );
        assert_eq!(
            contract.crosschain_shares.read(&source_account()).unwrap(),
            U256::ZERO
        );
        assert_eq!(
            contract.pending_crosschain_operations.read().unwrap(),
            U256::ZERO
        );
    });
}

// --- liquidity sources / targets --------------------------------------------

#[test]
fn add_remove_liquidity_source_enumerates_and_round_trips_type() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());

        // IntexCostAmount == 1.
        runtime::add_liquidity_source(storage.clone(), owner(), source_account(), 1).unwrap();

        let out = dispatch(
            storage.clone(),
            &IVaultRouter::liquiditySourcesCountCall {}.abi_encode(),
            stranger(),
            U256::ZERO,
        )
        .unwrap();
        assert_eq!(
            IVaultRouter::liquiditySourcesCountCall::abi_decode_returns(&out).unwrap(),
            U256::from(1)
        );

        let out = dispatch(
            storage.clone(),
            &IVaultRouter::liquiditySourceAtCall { index: U256::ZERO }.abi_encode(),
            stranger(),
            U256::ZERO,
        )
        .unwrap();
        let got = IVaultRouter::liquiditySourceAtCall::abi_decode_returns(&out).unwrap();
        assert_eq!(got.sourceAddress, source_account());
        assert_eq!(got.sourceType as u8, 1);

        // Removal clears it.
        runtime::remove_liquidity_source(storage.clone(), owner(), source_account()).unwrap();
        assert_eq!(
            VaultRouterContract::new(storage.clone())
                .liquidity_sources
                .len()
                .unwrap(),
            0
        );
    });
}

#[test]
fn add_liquidity_source_rejects_unknown_type_and_remove_rejects_missing() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());

        let err = runtime::add_liquidity_source(storage.clone(), owner(), source_account(), 0)
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid liquidity source"),
            "{err}"
        );

        let err = runtime::remove_liquidity_source(storage.clone(), owner(), source_account())
            .unwrap_err();
        assert!(
            err.to_string().contains("liquidity source not found"),
            "{err}"
        );
    });
}

#[test]
fn add_remove_liquidity_target_enumerates() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());

        // Credis == 1.
        runtime::add_liquidity_target(storage.clone(), owner(), target_account(), 1).unwrap();
        let out = dispatch(
            storage.clone(),
            &IVaultRouter::liquidityTargetAtCall { index: U256::ZERO }.abi_encode(),
            stranger(),
            U256::ZERO,
        )
        .unwrap();
        let got = IVaultRouter::liquidityTargetAtCall::abi_decode_returns(&out).unwrap();
        assert_eq!(got.targetAddress, target_account());
        assert_eq!(got.targetType as u8, 1);

        runtime::remove_liquidity_target(storage.clone(), owner(), target_account()).unwrap();
        assert_eq!(
            VaultRouterContract::new(storage.clone())
                .liquidity_targets
                .len()
                .unwrap(),
            0
        );
    });
}

// --- vault management --------------------------------------------------------

#[test]
fn add_vault_registers_asset_and_vault_then_remove() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault(),
        IVaultV2::assetCall::SELECTOR,
        word(U256::from_be_bytes(asset().into_word().0)),
    );
    storage.stub_sub_call_at_selector(vault(), IVaultV2::ownerCall::SELECTOR, word(U256::ZERO));
    storage.stub_sub_call_at_selector(
        asset(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(U256::from(USD_ISO_CODE)),
    );
    storage.enable_sub_call_stub();
    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());

        runtime::add_vault(storage.clone(), owner(), vault()).unwrap();

        let contract = VaultRouterContract::new(storage.clone());
        assert_eq!(contract.assets.len().unwrap(), 1);
        assert_eq!(contract.assets.at(0).unwrap(), Some(asset()));
        assert_eq!(contract.asset_vault_set(asset()).len().unwrap(), 1);
        assert_eq!(
            contract.asset_vault_set(asset()).at(0).unwrap(),
            Some(vault())
        );
        assert_eq!(
            contract
                .reference_currency_vault_set(USD_ISO_CODE)
                .at(0)
                .unwrap(),
            Some(vault())
        );
        assert_eq!(
            contract.vault_reference_currencies.read(&vault()).unwrap(),
            USD_ISO_CODE
        );

        let count_out = dispatch(
            storage.clone(),
            &IVaultRouter::referenceCurrencyVaultsCountCall {
                isoCode: USD_ISO_CODE,
            }
            .abi_encode(),
            stranger(),
            U256::ZERO,
        )
        .unwrap();
        assert_eq!(
            IVaultRouter::referenceCurrencyVaultsCountCall::abi_decode_returns(&count_out).unwrap(),
            U256::from(1)
        );

        let vault_out = dispatch(
            storage.clone(),
            &IVaultRouter::referenceCurrencyVaultAtCall {
                isoCode: USD_ISO_CODE,
                index: U256::ZERO,
            }
            .abi_encode(),
            stranger(),
            U256::ZERO,
        )
        .unwrap();
        assert_eq!(
            IVaultRouter::referenceCurrencyVaultAtCall::abi_decode_returns(&vault_out).unwrap(),
            vault()
        );

        let iso_out = dispatch(
            storage.clone(),
            &IVaultRouter::vaultReferenceCurrencyCall { vault: vault() }.abi_encode(),
            stranger(),
            U256::ZERO,
        )
        .unwrap();
        assert_eq!(
            IVaultRouter::vaultReferenceCurrencyCall::abi_decode_returns(&iso_out).unwrap(),
            USD_ISO_CODE
        );

        // Duplicate registration reverts.
        let err = runtime::add_vault(storage.clone(), owner(), vault()).unwrap_err();
        assert!(err.to_string().contains("already added"), "{err}");

        // Remove drops both the vault and its (now-empty) asset.
        runtime::remove_vault(storage.clone(), owner(), vault()).unwrap();
        let contract = VaultRouterContract::new(storage.clone());
        assert_eq!(contract.asset_vault_set(asset()).len().unwrap(), 0);
        assert_eq!(contract.assets.len().unwrap(), 0);
        assert_eq!(
            contract
                .reference_currency_vault_set(USD_ISO_CODE)
                .len()
                .unwrap(),
            0
        );
        assert_eq!(
            contract.vault_reference_currencies.read(&vault()).unwrap(),
            0
        );
    });
}

#[test]
fn add_vault_rejects_an_asset_without_a_reference_currency() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault(),
        IVaultV2::assetCall::SELECTOR,
        word(U256::from_be_bytes(asset().into_word().0)),
    );
    storage.stub_sub_call_at_selector(vault(), IVaultV2::ownerCall::SELECTOR, word(U256::ZERO));
    storage.stub_sub_call_at_selector(
        asset(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(U256::ZERO),
    );
    storage.enable_sub_call_stub();

    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());
        let err = runtime::add_vault(storage.clone(), owner(), vault()).unwrap_err();
        assert!(err.to_string().contains("currency code 0"), "{err}");

        let contract = VaultRouterContract::new(storage.clone());
        assert_eq!(contract.assets.len().unwrap(), 0);
        assert_eq!(contract.asset_vault_set(asset()).len().unwrap(), 0);
    });
}

#[test]
fn add_vault_rejects_a_vault_with_an_owner() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault(),
        IVaultV2::assetCall::SELECTOR,
        word(U256::from_be_bytes(asset().into_word().0)),
    );
    storage.stub_sub_call_at_selector(
        vault(),
        IVaultV2::ownerCall::SELECTOR,
        word(U256::from_be_bytes(stranger().into_word().0)),
    );
    storage.enable_sub_call_stub();

    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());
        let err = runtime::add_vault(storage.clone(), owner(), vault()).unwrap_err();
        assert!(err.to_string().contains("owner not renounced"), "{err}");

        let contract = VaultRouterContract::new(storage.clone());
        assert_eq!(contract.assets.len().unwrap(), 0);
        assert_eq!(contract.asset_vault_set(asset()).len().unwrap(), 0);
    });
}

// --- liquidity flow ----------------------------------------------------------

#[test]
fn deposit_happy_path_and_rejects_unknown_source() {
    let shares = U256::from(123u64);
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    // vault.deposit(...) returns `shares`; transferFrom on `asset` succeeds generically.
    storage.stub_sub_call_at(vault(), word(shares));
    storage.enable_sub_call_stub();
    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());

        // An Unknown source discriminant is rejected before any sub-call.
        let err = runtime::deposit(
            storage.clone(),
            source_account(),
            asset(),
            U256::from(10),
            IVaultRouter::StablesSource::Unknown,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("invalid liquidity source"),
            "{err}"
        );

        // Register a vault for the asset (seed the set directly to avoid the
        // vault.asset() stub colliding with vault.deposit()), then deposit
        // declaring a valid source.
        let contract = VaultRouterContract::new(storage.clone());
        contract.asset_vault_set(asset()).insert(vault()).unwrap();
        contract.assets.insert(asset()).unwrap();

        let got = runtime::deposit(
            storage.clone(),
            source_account(),
            asset(),
            U256::from(10),
            IVaultRouter::StablesSource::IntexCostAmount,
        )
        .unwrap();
        assert_eq!(got, shares);
    });
}

#[test]
fn deposit_reverts_when_no_vault_configured() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.enable_sub_call_stub();
    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());
        let err = runtime::deposit(
            storage.clone(),
            source_account(),
            asset(),
            U256::from(10),
            IVaultRouter::StablesSource::IntexCostAmount,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("reserve vault not configured"),
            "{err}"
        );
    });
}

#[test]
fn withdraw_happy_path_and_rejects_unknown_target() {
    let x = U256::from(50u64);
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    // previewWithdraw / balanceOf / withdraw all target `vault` and return `x`:
    // required == available, burned == x.
    storage.stub_sub_call_at(vault(), word(x));
    storage.enable_sub_call_stub();
    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());

        // Zero receiver rejected first.
        let err = runtime::withdraw(
            storage.clone(),
            target_account(),
            asset(),
            U256::from(10),
            Address::ZERO,
            IVaultRouter::StablesTarget::Credis,
        )
        .unwrap_err();
        assert!(err.to_string().contains("zero address"), "{err}");

        // An Unknown target discriminant is rejected before sub-calls.
        let err = runtime::withdraw(
            storage.clone(),
            target_account(),
            asset(),
            U256::from(10),
            receiver(),
            IVaultRouter::StablesTarget::Unknown,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("invalid liquidity target"),
            "{err}"
        );

        // Register a vault, then withdraw declaring a valid target.
        VaultRouterContract::new(storage.clone())
            .asset_vault_set(asset())
            .insert(vault())
            .unwrap();

        // The bundle receiver must be a deployed contract; a CALL to a codeless
        // account would silently no-op the topUp.
        storage
            .set_code(receiver(), Bytecode::new_raw(vec![0x00u8].into()))
            .unwrap();

        let burned = runtime::withdraw(
            storage.clone(),
            target_account(),
            asset(),
            U256::from(10),
            receiver(),
            IVaultRouter::StablesTarget::Credis,
        )
        .unwrap();
        assert_eq!(burned, x);
    });
}

#[test]
fn withdraw_rejects_undeployed_receiver() {
    let x = U256::from(50u64);
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at(vault(), word(x));
    storage.enable_sub_call_stub();
    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());
        VaultRouterContract::new(storage.clone())
            .asset_vault_set(asset())
            .insert(vault())
            .unwrap();

        // receiver() has no code: topUp would be silently skipped, so the whole
        // withdraw (and the requestCredis that drives it) must fail instead.
        let err = runtime::withdraw(
            storage.clone(),
            target_account(),
            asset(),
            U256::from(10),
            receiver(),
            IVaultRouter::StablesTarget::Credis,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not a deployed contract"), "{err}");
    });
}

// --- ABI-path registry gating ------------------------------------------------

#[test]
fn abi_deposit_gates_msg_sender_against_registry() {
    let shares = U256::from(123u64);
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at(vault(), word(shares));
    storage.enable_sub_call_stub();
    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());
        // Register a vault for the asset so the deposit can resolve one.
        let contract = VaultRouterContract::new(storage.clone());
        contract.asset_vault_set(asset()).insert(vault()).unwrap();
        contract.assets.insert(asset()).unwrap();

        let calldata = IVaultRouter::depositCall {
            asset: asset(),
            assetsAmount: U256::from(10),
        }
        .abi_encode();

        // Unregistered caller resolves to Unknown -> rejected.
        let err = dispatch(storage.clone(), &calldata, source_account(), U256::ZERO).unwrap_err();
        assert!(
            err.to_string().contains("invalid liquidity source"),
            "{err}"
        );

        // Register the caller as a source, then the same ABI call succeeds and
        // the precompile resolves the discriminant from the registry.
        runtime::add_liquidity_source(storage.clone(), owner(), source_account(), 1).unwrap();
        let out = dispatch(storage.clone(), &calldata, source_account(), U256::ZERO).unwrap();
        assert_eq!(
            IVaultRouter::depositCall::abi_decode_returns(&out).unwrap(),
            shares
        );
    });
}

#[test]
fn abi_withdraw_gates_msg_sender_against_registry() {
    let x = U256::from(50u64);
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at(vault(), word(x));
    storage.enable_sub_call_stub();
    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());
        VaultRouterContract::new(storage.clone())
            .asset_vault_set(asset())
            .insert(vault())
            .unwrap();
        storage
            .set_code(receiver(), Bytecode::new_raw(vec![0x00u8].into()))
            .unwrap();

        let calldata = IVaultRouter::withdrawCall {
            asset: asset(),
            amount: U256::from(10),
            receiver: receiver(),
        }
        .abi_encode();

        // Unregistered caller resolves to Unknown -> rejected.
        let err = dispatch(storage.clone(), &calldata, target_account(), U256::ZERO).unwrap_err();
        assert!(
            err.to_string().contains("invalid liquidity target"),
            "{err}"
        );

        // Register the caller as a target, then the ABI call succeeds.
        runtime::add_liquidity_target(storage.clone(), owner(), target_account(), 1).unwrap();
        let out = dispatch(storage.clone(), &calldata, target_account(), U256::ZERO).unwrap();
        assert_eq!(
            IVaultRouter::withdrawCall::abi_decode_returns(&out).unwrap(),
            x
        );
    });
}

#[test]
fn reference_currency_assets_deduplicates_vaults_of_one_asset() {
    let second_vault = address!("0x0000000000000000000000000000000000000666");
    let second_asset = address!("0x0000000000000000000000000000000000000555");

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    for (v, a) in [
        (vault(), asset()),
        (second_vault, asset()),
        (
            address!("0x0000000000000000000000000000000000000444"),
            second_asset,
        ),
    ] {
        storage.stub_sub_call_at_selector(
            v,
            IVaultV2::assetCall::SELECTOR,
            word(U256::from_be_bytes(a.into_word().0)),
        );
        storage.stub_sub_call_at_selector(v, IVaultV2::ownerCall::SELECTOR, word(U256::ZERO));
        storage.stub_sub_call_at_selector(
            a,
            IReferenceCurrency::isoCodeCall::SELECTOR,
            word(U256::from(USD_ISO_CODE)),
        );
    }
    storage.enable_sub_call_stub();

    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());
        for v in [
            vault(),
            second_vault,
            address!("0x0000000000000000000000000000000000000444"),
        ] {
            runtime::add_vault(storage.clone(), owner(), v).unwrap();
        }

        let assets = runtime::reference_currency_assets(&storage, USD_ISO_CODE).unwrap();
        assert_eq!(assets.len(), 2);
        assert!(assets.contains(&asset()));
        assert!(assets.contains(&second_asset));
    });
}

#[test]
fn reference_currency_assets_dispatch() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault(),
        IVaultV2::assetCall::SELECTOR,
        word(U256::from_be_bytes(asset().into_word().0)),
    );
    storage.stub_sub_call_at_selector(vault(), IVaultV2::ownerCall::SELECTOR, word(U256::ZERO));
    storage.stub_sub_call_at_selector(
        asset(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(U256::from(USD_ISO_CODE)),
    );
    storage.enable_sub_call_stub();

    StorageHandle::enter(&mut storage, |storage| {
        set_owner(&storage, owner());
        runtime::add_vault(storage.clone(), owner(), vault()).unwrap();

        let assets_out = dispatch(
            storage.clone(),
            &IVaultRouter::referenceCurrencyAssetsCall {
                isoCode: USD_ISO_CODE,
            }
            .abi_encode(),
            stranger(),
            U256::ZERO,
        )
        .unwrap();
        assert_eq!(
            IVaultRouter::referenceCurrencyAssetsCall::abi_decode_returns(&assets_out).unwrap(),
            vec![asset()]
        );
    });
}

// --- rebalance ----------------------------------------------------------------

/// Registers `vault` for `asset` directly through the schema, matching the
/// `deposit`/`withdraw` tests' convention of bypassing `add_vault` (and its own
/// `vault.owner()`/`isoCode()` sub-calls) when the test only cares about the
/// registry membership `rebalance` actually reads.
fn register_vault(storage: &StorageHandle<'_>, asset: Address, vault: Address) {
    VaultRouterContract::new(storage.clone())
        .asset_vault_set(asset)
        .insert(vault)
        .unwrap();
}

#[test]
fn rebalance_rejects_same_vault() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let err = runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_from(),
            U256::from(10),
            U256::MAX,
        )
        .unwrap_err();
        assert!(err.to_string().contains("same vault"), "{err}");
    });
}

#[test]
fn rebalance_rejects_zero_amount() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let err = runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            U256::ZERO,
            U256::MAX,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("invalid rebalance amount"),
            "{err}"
        );
    });
}

#[test]
fn rebalance_rejects_an_unregistered_source_vault() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_to()),
    );
    StorageHandle::enter(&mut storage, |storage| {
        // Only the destination vault is registered.
        register_vault(&storage, asset_to(), vault_to());

        let err = runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            U256::from(10),
            U256::MAX,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not registered"), "{err}");
    });
}

#[test]
fn rebalance_rejects_an_unregistered_destination_vault() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_to()),
    );
    StorageHandle::enter(&mut storage, |storage| {
        // Only the source vault is registered.
        register_vault(&storage, asset_from(), vault_from());

        let err = runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            U256::from(10),
            U256::MAX,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not registered"), "{err}");
    });
}

/// `rebalance` gates registration on `asset_vault_set`, not
/// `vault_reference_currencies` - which `remove_vault` (see `runtime.rs`)
/// documents as unset for vaults registered before the ISO index existed.
/// This pins that the rebalance path does not regress that upgrade path.
#[test]
fn rebalance_accepts_a_vault_whose_reference_currency_index_is_unset() {
    let shares = U256::from(50u64);
    let amount = U256::from(10u64);
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at(vault_from(), word(shares));
    storage.stub_sub_call_at(vault_to(), word(shares));
    storage.enable_sub_call_stub();

    StorageHandle::enter(&mut storage, |storage| {
        register_vault(&storage, asset_from(), vault_from());
        register_vault(&storage, asset_from(), vault_to());

        let contract = VaultRouterContract::new(storage.clone());
        assert_eq!(
            contract
                .vault_reference_currencies
                .read(&vault_from())
                .unwrap(),
            0
        );
        assert_eq!(
            contract
                .vault_reference_currencies
                .read(&vault_to())
                .unwrap(),
            0
        );

        let amount_to = runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            amount,
            U256::MAX,
        )
        .unwrap();
        assert_eq!(amount_to, amount);
    });
}

#[test]
fn rebalance_rejects_insufficient_source_shares() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::previewWithdrawCall::SELECTOR,
        word(U256::from(100u64)),
    );
    storage.stub_sub_call_at_selector(
        vault_from(),
        IERC20::balanceOfCall::SELECTOR,
        word(U256::from(50u64)),
    );

    StorageHandle::enter(&mut storage, |storage| {
        register_vault(&storage, asset_from(), vault_from());
        register_vault(&storage, asset_from(), vault_to());

        let err = runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            U256::from(10),
            U256::MAX,
        )
        .unwrap_err();
        assert!(err.to_string().contains("insufficient shares"), "{err}");
    });
}

#[test]
fn rebalance_rejects_when_the_required_input_exceeds_max() {
    let amount = U256::from(10u64);
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );

    StorageHandle::enter(&mut storage, |storage| {
        register_vault(&storage, asset_from(), vault_from());
        register_vault(&storage, asset_from(), vault_to());

        // Same asset prices 1:1, so `amount_to == amount`; a max one wei below
        // that must be rejected before any vault is touched.
        let err = runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            amount,
            amount - U256::from(1),
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeds max"), "{err}");
    });
}

/// Same asset short-circuits at 1:1 with no oracle read and no decimal
/// scaling - the identity path `rebalance_amount_to` takes before touching
/// `erc20_decimals`/`asset_iso_code` at all.
#[test]
fn rebalance_prices_an_identical_asset_pair_one_to_one() {
    let shares = U256::from(100u64);
    let amount = U256::from(10u64);
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at(vault_from(), word(shares));
    storage.stub_sub_call_at(vault_to(), word(shares));
    storage.enable_sub_call_stub();

    StorageHandle::enter(&mut storage, |storage| {
        register_vault(&storage, asset_from(), vault_from());
        register_vault(&storage, asset_from(), vault_to());

        let amount_to = runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            amount,
            U256::MAX,
        )
        .unwrap();
        assert_eq!(amount_to, amount);
    });
}

/// Two different assets that happen to share a currency: the oracle short
/// circuits internally (`from_iso == to_iso`) so no rate needs to be
/// published - proven here by never seeding the Oracle contract at all.
#[test]
fn rebalance_prices_a_same_currency_pair_one_to_one() {
    let shares = U256::from(100u64);
    let amount = U256::from(10u64);
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_to()),
    );
    storage.stub_sub_call_at_selector(
        asset_from(),
        IERC20::decimalsCall::SELECTOR,
        word(U256::from(6u8)),
    );
    storage.stub_sub_call_at_selector(
        asset_to(),
        IERC20::decimalsCall::SELECTOR,
        word(U256::from(6u8)),
    );
    storage.stub_sub_call_at_selector(
        asset_from(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(U256::from(USD_ISO_CODE)),
    );
    storage.stub_sub_call_at_selector(
        asset_to(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(U256::from(USD_ISO_CODE)),
    );
    storage.stub_sub_call_at(vault_from(), word(shares));
    storage.stub_sub_call_at(vault_to(), word(shares));
    storage.enable_sub_call_stub();

    StorageHandle::enter(&mut storage, |storage| {
        register_vault(&storage, asset_from(), vault_from());
        register_vault(&storage, asset_to(), vault_to());

        // No oracle pair registered for USD anywhere - if the implementation
        // read one despite the equal ISO codes this would revert instead.
        let amount_to = runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            amount,
            U256::MAX,
        )
        .unwrap();
        assert_eq!(amount_to, amount);
    });
}

#[test]
fn rebalance_prices_a_cross_currency_pair_from_the_oracle() {
    const RATE_TIMESTAMP: u64 = 1_700_000_000;
    const USD_PAIR_ID: u32 = 1;
    const EUR_PAIR_ID: u32 = 2;
    let shares = U256::from(1_000u64);
    let amount = U256::from(10u64);

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(RATE_TIMESTAMP));
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_to()),
    );
    storage.stub_sub_call_at_selector(
        asset_from(),
        IERC20::decimalsCall::SELECTOR,
        word(U256::from(6u8)),
    );
    storage.stub_sub_call_at_selector(
        asset_to(),
        IERC20::decimalsCall::SELECTOR,
        word(U256::from(6u8)),
    );
    storage.stub_sub_call_at_selector(
        asset_from(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(U256::from(USD_ISO_CODE)),
    );
    storage.stub_sub_call_at_selector(
        asset_to(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(U256::from(EUR_ISO_CODE)),
    );
    storage.stub_sub_call_at(vault_from(), word(shares));
    storage.stub_sub_call_at(vault_to(), word(shares));
    storage.enable_sub_call_stub();

    StorageHandle::enter(&mut storage, |storage| {
        register_vault(&storage, asset_from(), vault_from());
        register_vault(&storage, asset_to(), vault_to());

        // 1 COEN = 1 USD, 1 COEN = 2 EUR: 10 USD converts to 20 EUR.
        write_oracle_rate(
            &storage,
            USD_ISO_CODE,
            USD_PAIR_ID,
            U256::from(1_000_000u64),
            RATE_TIMESTAMP,
        );
        write_oracle_rate(
            &storage,
            EUR_ISO_CODE,
            EUR_PAIR_ID,
            U256::from(2_000_000u64),
            RATE_TIMESTAMP,
        );

        let amount_to = runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            amount,
            U256::MAX,
        )
        .unwrap();
        assert_eq!(amount_to, U256::from(20u64));
    });
}

#[test]
fn rebalance_scales_across_asset_decimals() {
    let shares = U256::from(1u128 << 60);

    // Scaling up: 6 decimals -> 18 decimals is an exact multiply.
    {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.stub_sub_call_at_selector(
            vault_from(),
            IVaultV2::assetCall::SELECTOR,
            word_addr(asset_from()),
        );
        storage.stub_sub_call_at_selector(
            vault_to(),
            IVaultV2::assetCall::SELECTOR,
            word_addr(asset_to()),
        );
        storage.stub_sub_call_at_selector(
            asset_from(),
            IERC20::decimalsCall::SELECTOR,
            word(U256::from(6u8)),
        );
        storage.stub_sub_call_at_selector(
            asset_to(),
            IERC20::decimalsCall::SELECTOR,
            word(U256::from(18u8)),
        );
        storage.stub_sub_call_at_selector(
            asset_from(),
            IReferenceCurrency::isoCodeCall::SELECTOR,
            word(U256::from(USD_ISO_CODE)),
        );
        storage.stub_sub_call_at_selector(
            asset_to(),
            IReferenceCurrency::isoCodeCall::SELECTOR,
            word(U256::from(USD_ISO_CODE)),
        );
        storage.stub_sub_call_at(vault_from(), word(shares));
        storage.stub_sub_call_at(vault_to(), word(shares));
        storage.enable_sub_call_stub();

        StorageHandle::enter(&mut storage, |storage| {
            register_vault(&storage, asset_from(), vault_from());
            register_vault(&storage, asset_to(), vault_to());

            let amount_to = runtime::rebalance(
                storage.clone(),
                cca(),
                vault_from(),
                vault_to(),
                U256::from(10u64),
                U256::MAX,
            )
            .unwrap();
            assert_eq!(
                amount_to,
                U256::from(10u64) * U256::from(10u64).pow(U256::from(12u64))
            );
        });
    }

    // Scaling down: 18 decimals -> 6 decimals rounds up.
    {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.stub_sub_call_at_selector(
            vault_from(),
            IVaultV2::assetCall::SELECTOR,
            word_addr(asset_from()),
        );
        storage.stub_sub_call_at_selector(
            vault_to(),
            IVaultV2::assetCall::SELECTOR,
            word_addr(asset_to()),
        );
        storage.stub_sub_call_at_selector(
            asset_from(),
            IERC20::decimalsCall::SELECTOR,
            word(U256::from(18u8)),
        );
        storage.stub_sub_call_at_selector(
            asset_to(),
            IERC20::decimalsCall::SELECTOR,
            word(U256::from(6u8)),
        );
        storage.stub_sub_call_at_selector(
            asset_from(),
            IReferenceCurrency::isoCodeCall::SELECTOR,
            word(U256::from(USD_ISO_CODE)),
        );
        storage.stub_sub_call_at_selector(
            asset_to(),
            IReferenceCurrency::isoCodeCall::SELECTOR,
            word(U256::from(USD_ISO_CODE)),
        );
        storage.stub_sub_call_at(vault_from(), word(shares));
        storage.stub_sub_call_at(vault_to(), word(shares));
        storage.enable_sub_call_stub();

        StorageHandle::enter(&mut storage, |storage| {
            register_vault(&storage, asset_from(), vault_from());
            register_vault(&storage, asset_to(), vault_to());

            // 10^13 wei of an 18-decimal asset is 0.00001; ceil-scaled to 6
            // decimals that is 10 minor units, not 9 (10^13 / 10^12 = 10 exactly
            // here, so bump by one wei to force the rounding to bite).
            let amount = U256::from(10u64).pow(U256::from(13u64)) + U256::from(1);
            let amount_to = runtime::rebalance(
                storage.clone(),
                cca(),
                vault_from(),
                vault_to(),
                amount,
                U256::MAX,
            )
            .unwrap();
            assert_eq!(amount_to, U256::from(11u64));
        });
    }
}

#[test]
fn rebalance_rejects_assets_with_more_than_eighteen_decimals() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_to()),
    );
    storage.stub_sub_call_at_selector(
        asset_from(),
        IERC20::decimalsCall::SELECTOR,
        word(U256::from(19u8)),
    );
    // Both decimals are read before either is checked, so the destination's must
    // resolve too even though this test only cares about the source's bound.
    storage.stub_sub_call_at_selector(
        asset_to(),
        IERC20::decimalsCall::SELECTOR,
        word(U256::from(6u8)),
    );

    StorageHandle::enter(&mut storage, |storage| {
        register_vault(&storage, asset_from(), vault_from());
        register_vault(&storage, asset_to(), vault_to());

        let err = runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            U256::from(10),
            U256::MAX,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("unsupported asset decimals"),
            "{err}"
        );
    });
}

/// The pull (receive) is the first external call `rebalance` makes; if the
/// caller has not approved the destination asset, nothing downstream ever
/// runs.
#[test]
fn rebalance_reverts_when_the_caller_has_not_approved_the_destination_asset() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_to()),
    );
    storage.stub_sub_call_at_selector(
        asset_from(),
        IERC20::decimalsCall::SELECTOR,
        word(U256::from(6u8)),
    );
    storage.stub_sub_call_at_selector(
        asset_to(),
        IERC20::decimalsCall::SELECTOR,
        word(U256::from(6u8)),
    );
    storage.stub_sub_call_at_selector(
        asset_from(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(U256::from(USD_ISO_CODE)),
    );
    storage.stub_sub_call_at_selector(
        asset_to(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(U256::from(USD_ISO_CODE)),
    );
    storage.stub_sub_call_at(vault_from(), word(U256::from(100u64)));
    // `asset_to()::transferFromCall` is deliberately left unstubbed, and the
    // global stub is off, so the pull fails closed.

    StorageHandle::enter(&mut storage, |storage| {
        register_vault(&storage, asset_from(), vault_from());
        register_vault(&storage, asset_to(), vault_to());

        runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            U256::from(10),
            U256::MAX,
        )
        .unwrap_err();
    });
    assert!(storage.get_events(VAULT_ROUTER_ADDRESS).is_empty());
}

/// If the destination deposit fails, the source vault's withdraw and the
/// payout transfer - both coded after it - never run.
#[test]
fn rebalance_rolls_back_when_the_destination_deposit_fails() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at(vault_from(), word(U256::from(100u64)));
    storage.stub_sub_call_at(asset_from(), word(U256::from(1u64)));
    // `vault_to()::depositCall` is deliberately left unstubbed.

    StorageHandle::enter(&mut storage, |storage| {
        register_vault(&storage, asset_from(), vault_from());
        register_vault(&storage, asset_from(), vault_to());

        runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            U256::from(10),
            U256::MAX,
        )
        .unwrap_err();
    });
    assert!(storage.get_events(VAULT_ROUTER_ADDRESS).is_empty());
}

/// If the source withdraw fails after the destination deposit already
/// succeeded, the payout transfer - coded after it - never runs, and no
/// event is emitted for the half-completed swap.
#[test]
fn rebalance_rolls_back_when_the_source_withdraw_fails() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::previewWithdrawCall::SELECTOR,
        word(U256::from(10u64)),
    );
    storage.stub_sub_call_at_selector(
        vault_from(),
        IERC20::balanceOfCall::SELECTOR,
        word(U256::from(100u64)),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::depositCall::SELECTOR,
        word(U256::from(10u64)),
    );
    storage.stub_sub_call_at(asset_from(), word(U256::from(1u64)));
    // `vault_from()::withdrawCall` is deliberately left unstubbed.

    StorageHandle::enter(&mut storage, |storage| {
        register_vault(&storage, asset_from(), vault_from());
        register_vault(&storage, asset_from(), vault_to());

        runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            U256::from(10),
            U256::MAX,
        )
        .unwrap_err();
    });
    assert!(storage.get_events(VAULT_ROUTER_ADDRESS).is_empty());
}

/// `outbe_cca::api::is_active` is a stub that answers `Active` for every
/// address (see its own doc comment) - so today `rebalance` rejects no
/// caller on CCA standing alone. This pins that the gate is wired (the seam
/// the real registry drops into), not that it currently restricts anyone.
#[test]
fn rebalance_succeeds_for_a_stranger_because_the_cca_registry_is_a_stub() {
    let shares = U256::from(100u64);
    let amount = U256::from(10u64);
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at(vault_from(), word(shares));
    storage.stub_sub_call_at(vault_to(), word(shares));
    storage.enable_sub_call_stub();

    StorageHandle::enter(&mut storage, |storage| {
        register_vault(&storage, asset_from(), vault_from());
        register_vault(&storage, asset_from(), vault_to());

        let amount_to = runtime::rebalance(
            storage.clone(),
            stranger(),
            vault_from(),
            vault_to(),
            amount,
            U256::MAX,
        )
        .unwrap();
        assert_eq!(amount_to, amount);
    });
}

#[test]
fn preview_rebalance_matches_what_rebalance_pulls() {
    const RATE_TIMESTAMP: u64 = 1_700_000_000;
    const USD_PAIR_ID: u32 = 1;
    const EUR_PAIR_ID: u32 = 2;
    let shares = U256::from(1_000u64);
    let amount = U256::from(10u64);

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(RATE_TIMESTAMP));
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_to()),
    );
    storage.stub_sub_call_at_selector(
        asset_from(),
        IERC20::decimalsCall::SELECTOR,
        word(U256::from(6u8)),
    );
    storage.stub_sub_call_at_selector(
        asset_to(),
        IERC20::decimalsCall::SELECTOR,
        word(U256::from(6u8)),
    );
    storage.stub_sub_call_at_selector(
        asset_from(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(U256::from(USD_ISO_CODE)),
    );
    storage.stub_sub_call_at_selector(
        asset_to(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(U256::from(EUR_ISO_CODE)),
    );
    storage.stub_sub_call_at(vault_from(), word(shares));
    storage.stub_sub_call_at(vault_to(), word(shares));
    storage.enable_sub_call_stub();

    StorageHandle::enter(&mut storage, |storage| {
        register_vault(&storage, asset_from(), vault_from());
        register_vault(&storage, asset_to(), vault_to());
        write_oracle_rate(
            &storage,
            USD_ISO_CODE,
            USD_PAIR_ID,
            U256::from(1_000_000u64),
            RATE_TIMESTAMP,
        );
        write_oracle_rate(
            &storage,
            EUR_ISO_CODE,
            EUR_PAIR_ID,
            U256::from(2_000_000u64),
            RATE_TIMESTAMP,
        );

        let (preview_from, preview_to, preview_amount) =
            runtime::preview_rebalance(&storage, vault_from(), vault_to(), amount).unwrap();
        assert_eq!(preview_from, asset_from());
        assert_eq!(preview_to, asset_to());

        let amount_to = runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            amount,
            U256::MAX,
        )
        .unwrap();
        assert_eq!(preview_amount, amount_to);
    });
}

#[test]
fn rebalance_selectors_reject_native_value() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let call = IVaultRouter::rebalanceCall {
            vaultFrom: vault_from(),
            vaultTo: vault_to(),
            assetsAmount: U256::from(10),
            maxAmountTo: U256::MAX,
        };
        let err = dispatch(storage.clone(), &call.abi_encode(), cca(), U256::from(1)).unwrap_err();
        assert!(err.to_string().contains("non-payable"), "{err}");

        let preview = IVaultRouter::previewRebalanceCall {
            vaultFrom: vault_from(),
            vaultTo: vault_to(),
            assetsAmount: U256::from(10),
        };
        let err =
            dispatch(storage.clone(), &preview.abi_encode(), cca(), U256::from(1)).unwrap_err();
        assert!(err.to_string().contains("non-payable"), "{err}");
    });
}

/// The happy path emits exactly one `LiquidityRebalanced` carrying both legs:
/// what left `vault_from` and what the caller supplied into `vault_to`. The
/// rollback tests below assert the absence of this event, so its presence and
/// contents need pinning too, or "no event" would pass vacuously.
#[test]
fn rebalance_emits_liquidity_rebalanced_with_both_legs() {
    const RATE_TIMESTAMP: u64 = 1_700_000_000;
    const USD_PAIR_ID: u32 = 1;
    const EUR_PAIR_ID: u32 = 2;
    let burned = U256::from(7u64);
    let minted = U256::from(9u64);
    let amount = U256::from(10u64);

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(RATE_TIMESTAMP));
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_to()),
    );
    storage.stub_sub_call_at_selector(
        asset_from(),
        IERC20::decimalsCall::SELECTOR,
        word(U256::from(6u8)),
    );
    storage.stub_sub_call_at_selector(
        asset_to(),
        IERC20::decimalsCall::SELECTOR,
        word(U256::from(6u8)),
    );
    storage.stub_sub_call_at_selector(
        asset_from(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(U256::from(USD_ISO_CODE)),
    );
    storage.stub_sub_call_at_selector(
        asset_to(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(U256::from(EUR_ISO_CODE)),
    );
    // Distinct share counts per vault, so the event cannot pass by echoing one
    // number into both share fields.
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::previewWithdrawCall::SELECTOR,
        word(burned),
    );
    storage.stub_sub_call_at_selector(
        vault_from(),
        IERC20::balanceOfCall::SELECTOR,
        word(U256::from(1_000u64)),
    );
    storage.stub_sub_call_at_selector(vault_from(), IVaultV2::withdrawCall::SELECTOR, word(burned));
    storage.stub_sub_call_at_selector(vault_to(), IVaultV2::depositCall::SELECTOR, word(minted));
    storage.enable_sub_call_stub();

    StorageHandle::enter(&mut storage, |storage| {
        register_vault(&storage, asset_from(), vault_from());
        register_vault(&storage, asset_to(), vault_to());
        // 1 COEN = 1 USD, 1 COEN = 2 EUR: 10 USD is 20 EUR.
        write_oracle_rate(
            &storage,
            USD_ISO_CODE,
            USD_PAIR_ID,
            U256::from(1_000_000u64),
            RATE_TIMESTAMP,
        );
        write_oracle_rate(
            &storage,
            EUR_ISO_CODE,
            EUR_PAIR_ID,
            U256::from(2_000_000u64),
            RATE_TIMESTAMP,
        );

        runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            amount,
            U256::MAX,
        )
        .unwrap();
    });

    let events = storage.get_events(VAULT_ROUTER_ADDRESS);
    assert_eq!(events.len(), 1, "exactly one rebalance event");
    let decoded = IVaultRouter::LiquidityRebalanced::decode_log_data(&events[0]).unwrap();
    assert_eq!(decoded.cca, cca());
    assert_eq!(decoded.vaultFrom, vault_from());
    assert_eq!(decoded.vaultTo, vault_to());
    assert_eq!(decoded.assetsWithdrawn, amount);
    assert_eq!(decoded.burnedShares, burned);
    assert_eq!(decoded.assetsDeposited, U256::from(20u64));
    assert_eq!(decoded.mintedShares, minted);
}

/// An asset whose live `isoCode()` has fallen to zero is not a currency, so it
/// cannot be par to another zero-coded asset. Without the guard the oracle's
/// `from_iso == to_iso` short circuit would price two unrelated assets 1:1.
#[test]
fn rebalance_rejects_an_asset_reporting_no_reference_currency() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at_selector(
        vault_from(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_from()),
    );
    storage.stub_sub_call_at_selector(
        vault_to(),
        IVaultV2::assetCall::SELECTOR,
        word_addr(asset_to()),
    );
    storage.stub_sub_call_at_selector(
        asset_from(),
        IERC20::decimalsCall::SELECTOR,
        word(U256::from(6u8)),
    );
    storage.stub_sub_call_at_selector(
        asset_to(),
        IERC20::decimalsCall::SELECTOR,
        word(U256::from(6u8)),
    );
    // Both assets report "no currency": the pair must be refused, not treated
    // as a matching pair of currencies.
    storage.stub_sub_call_at_selector(
        asset_from(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(U256::ZERO),
    );
    storage.stub_sub_call_at_selector(
        asset_to(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(U256::ZERO),
    );
    storage.enable_sub_call_stub();

    StorageHandle::enter(&mut storage, |storage| {
        register_vault(&storage, asset_from(), vault_from());
        register_vault(&storage, asset_to(), vault_to());

        let err = runtime::rebalance(
            storage.clone(),
            cca(),
            vault_from(),
            vault_to(),
            U256::from(10),
            U256::MAX,
        )
        .unwrap_err();
        assert!(err.to_string().contains("currency code 0"), "{err}");
    });
    assert!(storage.get_events(VAULT_ROUTER_ADDRESS).is_empty());
}
