//! Test helpers for RPC-facing code.
//!
//! This module is feature-gated behind `test-support` so downstream crates can
//! use shared RPC fakes in tests without pulling them into production builds.

use alloy_primitives::{Address, U256};
use eyre::Result;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// ABI-encode a single U256 return value (32 bytes big-endian).
pub fn abi_u256(val: U256) -> Vec<u8> {
    val.to_be_bytes::<32>().to_vec()
}

/// ABI-encode a single u64 return value (zero-padded to 32 bytes).
pub fn abi_u64(val: u64) -> Vec<u8> {
    abi_u256(U256::from(val))
}

/// Build an eth_call dispatcher from a map of `(contract_address, 4-byte selector)` to response.
pub fn call_map(map: HashMap<(Address, [u8; 4]), Vec<u8>>) -> EthCallMap {
    EthCallMap(map)
}

pub struct EthCallMap(HashMap<(Address, [u8; 4]), Vec<u8>>);

impl EthCallMap {
    pub fn dispatch(&self, to: Address, data: &[u8]) -> Result<Vec<u8>> {
        let selector: [u8; 4] = data
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| eyre::eyre!("eth_call data too short for selector"))?;
        self.0.get(&(to, selector)).cloned().ok_or_else(|| {
            eyre::eyre!(
                "unmocked eth_call to={to:?} selector={}",
                hex::encode(selector)
            )
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum RecordedRpcCall {
    EthCall {
        to: Address,
        data: Vec<u8>,
    },
    EthBlockNumber,
    EthChainId,
    EthGasPrice,
    EthGetTransactionCount {
        address: Address,
    },
    EthEstimateGas {
        from: Address,
        to: Address,
        data: Vec<u8>,
    },
    EthSendRawTransaction {
        raw_tx: Vec<u8>,
    },
    EthGetBalance {
        address: Address,
    },
    NetPeerCount,
    OutbeConsensusStatus,
    OutbeGetEpochInfo,
    EthGetBlockByNumber {
        block: u64,
    },
    EthGetLatestBlock,
    OutbeGetVrfSeed,
    OutbeGetEmissionInfo,
    OutbeGetSlashConfig,
    EthGetLogs {
        address: Address,
        topics: Vec<Option<String>>,
        from_block: String,
        to_block: String,
    },
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum RecordedRpcResponse {
    Bytes(Vec<u8>),
    U64(u64),
    U256(U256),
    Text(String),
    Value(Value),
    Logs(Vec<Value>),
}

impl RecordedRpcResponse {
    pub fn into_bytes(self, method: &str) -> Result<Vec<u8>> {
        match self {
            Self::Bytes(v) => Ok(v),
            other => Err(eyre::eyre!(
                "expected bytes response for {method}, got {other:?}"
            )),
        }
    }

    pub fn into_u64(self, method: &str) -> Result<u64> {
        match self {
            Self::U64(v) => Ok(v),
            other => Err(eyre::eyre!(
                "expected u64 response for {method}, got {other:?}"
            )),
        }
    }

    pub fn into_u256(self, method: &str) -> Result<U256> {
        match self {
            Self::U256(v) => Ok(v),
            other => Err(eyre::eyre!(
                "expected U256 response for {method}, got {other:?}"
            )),
        }
    }

    pub fn into_text(self, method: &str) -> Result<String> {
        match self {
            Self::Text(v) => Ok(v),
            other => Err(eyre::eyre!(
                "expected text response for {method}, got {other:?}"
            )),
        }
    }

    pub fn into_value(self, method: &str) -> Result<Value> {
        match self {
            Self::Value(v) => Ok(v),
            other => Err(eyre::eyre!(
                "expected JSON response for {method}, got {other:?}"
            )),
        }
    }

    pub fn into_logs(self, method: &str) -> Result<Vec<Value>> {
        match self {
            Self::Logs(v) => Ok(v),
            other => Err(eyre::eyre!(
                "expected logs response for {method}, got {other:?}"
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExpectedRpcCall {
    pub call: RecordedRpcCall,
    pub response: Result<RecordedRpcResponse, String>,
}

impl ExpectedRpcCall {
    pub fn ok(call: RecordedRpcCall, response: RecordedRpcResponse) -> Self {
        Self {
            call,
            response: Ok(response),
        }
    }

    #[allow(dead_code)]
    pub fn err(call: RecordedRpcCall, error: impl Into<String>) -> Self {
        Self {
            call,
            response: Err(error.into()),
        }
    }
}

pub struct RecordingRpc {
    expected: Mutex<VecDeque<ExpectedRpcCall>>,
    recorded: Mutex<Vec<RecordedRpcCall>>,
}

impl RecordingRpc {
    pub fn new(expected: impl IntoIterator<Item = ExpectedRpcCall>) -> Self {
        Self {
            expected: Mutex::new(expected.into_iter().collect()),
            recorded: Mutex::new(Vec::new()),
        }
    }

    pub fn recorded_calls(&self) -> Vec<RecordedRpcCall> {
        self.recorded
            .lock()
            .expect("recorded RPC lock poisoned")
            .clone()
    }

    pub fn assert_done(&self) {
        let remaining = self
            .expected
            .lock()
            .expect("expected RPC lock poisoned")
            .clone();
        assert!(
            remaining.is_empty(),
            "unconsumed RPC expectations: {remaining:#?}"
        );
    }

    pub fn next_response(&self, actual: RecordedRpcCall) -> Result<RecordedRpcResponse> {
        self.recorded
            .lock()
            .expect("recorded RPC lock poisoned")
            .push(actual.clone());

        let expected = self
            .expected
            .lock()
            .expect("expected RPC lock poisoned")
            .pop_front()
            .ok_or_else(|| eyre::eyre!("unexpected RPC call with no expectation: {actual:#?}"))?;

        if expected.call != actual {
            eyre::bail!(
                "unexpected RPC call order or args:\nexpected: {:#?}\nactual:   {:#?}",
                expected.call,
                actual
            );
        }

        match expected.response {
            Ok(response) => Ok(response),
            Err(error) => Err(eyre::eyre!("{error}")),
        }
    }
}
