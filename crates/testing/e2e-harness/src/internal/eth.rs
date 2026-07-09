//! Native JSON-RPC layer — the typed replacement for the harness's `cast`
//! shell-outs.
//!
//! Reads (`eth_call` to the protocol precompiles, block/receipt queries) and
//! local-signer sends go through an alloy [`Provider`] instead of spawning
//! `cast`. Mirrors the canonical provider client in `bin/outbe-feeder`
//! (`ProviderBuilder::new().connect_http(...)`, calldata `abi_encode` + `call` +
//! `abi_decode_returns`, `EthereumWallet` sends).
//!
//! The harness is synchronous (cucumber steps are plain fns), so each call
//! bridges to alloy's async API via [`block_on`], which runs the future on a
//! dedicated background runtime and blocks the caller on a channel. That works
//! regardless of whether the calling step runs on a tokio worker or a plain
//! thread — there is no runtime nesting to panic on.

use std::future::Future;
use std::sync::mpsc::sync_channel;
use std::sync::OnceLock;

use alloy_eips::BlockNumberOrTag;
use alloy_network::EthereumWallet;
use alloy_primitives::{Address, Bytes, TxHash, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolCall};
use eyre::{eyre, Result};
use tokio::runtime::Runtime;

/// Legacy-style gas price used by the old `cast send --gas-price` calls (1 gwei).
const GAS_PRICE_WEI: u128 = 1_000_000_000;

// Precompile ABI surface the harness reads/writes. Signatures mirror the
// `cast call`/`cast send` strings they replace (and `bin/outbe-cli/src/abi.rs`).
sol! {
    #[sol(alloy_sol_types = alloy_sol_types)]
    interface IValidatorSet {
        function validatorByAddress(address v) external view returns (
            address addr, bytes pubkey, uint256 stake, uint8 status,
            uint64 slashCount, uint64 missedBlocks, uint64 missedVotes,
            uint64 blocksProposed, uint64 joined, uint64 deactivated,
            uint64 unbondEnd, bool hasShare);
        function isConsensusParticipant(address v) external view returns (bool);
        function activeValidatorCount() external view returns (uint32);
        function activeConsensusCount() external view returns (uint32);
        function deactivateValidator(address v) external;
        function registerValidator(address v, bytes pubkey, bytes sig) external;
        function setP2pAddress(address v, uint8 kind, bytes addr) external;
    }
    #[sol(alloy_sol_types = alloy_sol_types)]
    interface IUpdate {
        // Returned as a single (dynamic) struct, not flat values — the `bytes`
        // member makes struct-return and multi-return ABI-encode differently.
        struct ScheduledUpdate {
            uint256 proposalId;
            uint32 version;
            uint64 activationHeight;
            bytes info;
            uint8 status;
        }
        function getActiveVersion() external view returns (uint32);
        function getScheduledUpdate(uint256 id) external view returns (ScheduledUpdate memory);
    }
    #[sol(alloy_sol_types = alloy_sol_types)]
    interface IVote {
        function listProposals(uint256 index, uint256 count) external view returns (uint256[] memory);
        function getProposalVoters(uint256 proposalId, uint256 index, uint256 count)
            external
            view
            returns (address[] memory);
    }
    #[sol(alloy_sol_types = alloy_sol_types)]
    interface ITeeRegistry {
        function isBootstrapped() external view returns (bool);
    }
    #[sol(alloy_sol_types = alloy_sol_types)]
    interface ITribute {
        function totalSupply() external view returns (uint256);
    }
    #[sol(alloy_sol_types = alloy_sol_types)]
    interface IStaking {
        function stake(address v, uint256 amount) external payable;
    }
    #[sol(alloy_sol_types = alloy_sol_types)]
    interface IWorldwideDay {
        function getWorldwideDay(uint32 day) external view returns (
            uint8 f0, uint8 f1, uint64 f2, uint64 f3, uint64 f4,
            uint64 f5, uint64 f6, uint256 f7, uint256 f8);
    }
}

/// A dedicated multi-thread runtime that drives every RPC future, independent of
/// whatever thread/runtime the cucumber step is on.
fn eth_runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build eth runtime")
    })
}

/// Run an async future to completion from a synchronous step. The future runs on
/// [`eth_runtime`] and the caller blocks on a channel, so there is no runtime
/// nesting — this is safe whether the caller is a tokio worker or a plain thread.
pub(crate) fn block_on<F>(f: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let (tx, rx) = sync_channel(1);
    eth_runtime().spawn(async move {
        let _ = tx.send(f.await);
    });
    rx.recv().expect("eth runtime dropped the task")
}

/// `eth_call` a view function and decode its return, or `None` on any transport /
/// decode error (the analogue of the old `cast … 2>/dev/null`).
pub(crate) fn read_call<C: SolCall>(url: &str, to: Address, call: &C) -> Option<C::Return>
where
    C::Return: Send + 'static,
{
    let url = url.to_string();
    let data = call.abi_encode();
    block_on(async move {
        let provider = ProviderBuilder::new().connect_http(url.parse().ok()?);
        let tx = TransactionRequest::default()
            .to(to)
            .input(Bytes::from(data).into());
        let out = provider.call(tx).await.ok()?;
        C::abi_decode_returns(&out).ok()
    })
}

/// Head block number (`eth_blockNumber`).
pub(crate) fn block_number(url: &str) -> Option<u64> {
    let url = url.to_string();
    block_on(async move {
        let provider = ProviderBuilder::new().connect_http(url.parse().ok()?);
        provider.get_block_number().await.ok()
    })
}

/// Number of the finalized block.
pub(crate) fn finalized_number(url: &str) -> Option<u64> {
    let url = url.to_string();
    block_on(async move {
        let provider = ProviderBuilder::new().connect_http(url.parse().ok()?);
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Finalized)
            .await
            .ok()??;
        Some(block.header.number)
    })
}

/// `stateRoot` of block `height`, `0x`-hex (parity-comparison friendly).
pub(crate) fn state_root(url: &str, height: u64) -> Option<String> {
    let url = url.to_string();
    block_on(async move {
        let provider = ProviderBuilder::new().connect_http(url.parse().ok()?);
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Number(height))
            .await
            .ok()??;
        Some(format!("{:#x}", block.header.state_root))
    })
}

/// A custom JSON-RPC method returning an arbitrary JSON value (e.g.
/// `outbe_consensusStatus`).
pub(crate) fn raw_json(url: &str, method: &'static str) -> Option<serde_json::Value> {
    let url = url.to_string();
    block_on(async move {
        let provider = ProviderBuilder::new().connect_http(url.parse().ok()?);
        provider
            .raw_request::<_, serde_json::Value>(method.into(), serde_json::json!([]))
            .await
            .ok()
    })
}

/// Receipt success flag for `tx`, or `None` if not yet mined / unreadable.
pub(crate) fn receipt_success(url: &str, tx: &str) -> Option<bool> {
    let url = url.to_string();
    let hash: TxHash = tx.parse().ok()?;
    block_on(async move {
        let provider = ProviderBuilder::new().connect_http(url.parse().ok()?);
        let receipt = provider.get_transaction_receipt(hash).await.ok()??;
        Some(receipt.status())
    })
}

/// Sign and send a contract call from `key`, waiting for its receipt; returns the
/// tx hash. `value` funds a payable call (e.g. `stake`).
pub(crate) fn send_call<C: SolCall>(
    url: &str,
    to: Address,
    key: &str,
    call: &C,
    value: Option<U256>,
) -> Result<String> {
    let signer: PrivateKeySigner = key.parse().map_err(|e| eyre!("invalid private key: {e}"))?;
    let wallet = EthereumWallet::from(signer);
    let url = url.to_string();
    let data = call.abi_encode();
    block_on(async move {
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(url.parse()?);
        let mut tx = TransactionRequest::default()
            .to(to)
            .input(Bytes::from(data).into())
            .max_fee_per_gas(GAS_PRICE_WEI)
            .max_priority_fee_per_gas(0);
        if let Some(v) = value {
            tx = tx.value(v);
        }
        let pending = provider.send_transaction(tx).await?;
        let receipt = pending.get_receipt().await?;
        Ok(format!("{:#x}", receipt.transaction_hash))
    })
}

/// Plain-ether value transfer from `key` to `to` (funds a new joiner account).
pub(crate) fn send_value(url: &str, to: Address, key: &str, value: U256) -> Result<String> {
    let signer: PrivateKeySigner = key.parse().map_err(|e| eyre!("invalid private key: {e}"))?;
    let wallet = EthereumWallet::from(signer);
    let url = url.to_string();
    block_on(async move {
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(url.parse()?);
        let tx = TransactionRequest::default()
            .to(to)
            .value(value)
            .max_fee_per_gas(GAS_PRICE_WEI)
            .max_priority_fee_per_gas(0);
        let pending = provider.send_transaction(tx).await?;
        let receipt = pending.get_receipt().await?;
        Ok(format!("{:#x}", receipt.transaction_hash))
    })
}

/// EOA address (`0x`-hex, checksummed) for a private key — pure, no RPC.
pub(crate) fn address_of(key: &str) -> Option<Address> {
    let signer: PrivateKeySigner = key.parse().ok()?;
    Some(signer.address())
}

/// `amount` whole ether as wei.
pub(crate) fn ether(amount: u64) -> U256 {
    U256::from(amount) * U256::from(1_000_000_000_000_000_000u128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_from_known_key() {
        // Hardhat account #0 — a well-known key→address pair.
        let key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let addr = address_of(key).expect("address");
        assert_eq!(
            format!("{addr:#x}"),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
        assert!(address_of("not-a-key").is_none());
    }

    #[test]
    fn ether_scales() {
        assert_eq!(ether(1), U256::from(1_000_000_000_000_000_000u128));
        assert_eq!(ether(0), U256::ZERO);
    }
}
