//! Minimal JSON-RPC client for Ethereum-compatible nodes.

use alloy_primitives::{Address, U256};
use eyre::{Result, WrapErr};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Abstraction over JSON-RPC transport for testability.
pub trait Rpc {
    fn eth_call(
        &self,
        to: Address,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
    fn eth_block_number(&self) -> impl std::future::Future<Output = Result<u64>> + Send;
    fn eth_chain_id(&self) -> impl std::future::Future<Output = Result<u64>> + Send;
    fn eth_gas_price(&self) -> impl std::future::Future<Output = Result<U256>> + Send;
    fn eth_get_transaction_count(
        &self,
        address: Address,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;
    fn eth_estimate_gas(
        &self,
        from: Address,
        to: Address,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<u64>> + Send;
    fn eth_send_raw_transaction(
        &self,
        raw_tx: &[u8],
    ) -> impl std::future::Future<Output = Result<String>> + Send;
    fn eth_get_balance(
        &self,
        address: Address,
    ) -> impl std::future::Future<Output = Result<U256>> + Send;
    fn net_peer_count(&self) -> impl std::future::Future<Output = Result<u64>> + Send;
    fn outbe_consensus_status(&self) -> impl std::future::Future<Output = Result<Value>> + Send;
    fn outbe_get_epoch_info(&self) -> impl std::future::Future<Output = Result<Value>> + Send;
    fn eth_get_block_by_number(
        &self,
        block: u64,
    ) -> impl std::future::Future<Output = Result<Value>> + Send;
    fn eth_get_latest_block(&self) -> impl std::future::Future<Output = Result<Value>> + Send;
    fn outbe_get_vrf_seed(&self) -> impl std::future::Future<Output = Result<Value>> + Send;
    fn outbe_get_emission_info(&self) -> impl std::future::Future<Output = Result<Value>> + Send;
    fn outbe_get_slash_config(&self) -> impl std::future::Future<Output = Result<Value>> + Send;
    fn outbe_get_update_active_version(
        &self,
    ) -> impl std::future::Future<Output = Result<Value>> + Send;
    fn outbe_get_update_proposal(
        &self,
        proposal_id: U256,
    ) -> impl std::future::Future<Output = Result<Option<Value>>> + Send;
    fn outbe_list_update_pending_proposals(
        &self,
    ) -> impl std::future::Future<Output = Result<Value>> + Send;
    fn outbe_list_update_waiting_proposals(
        &self,
    ) -> impl std::future::Future<Output = Result<Value>> + Send;
    fn eth_get_logs(
        &self,
        address: Address,
        topics: &[Option<String>],
        from_block: &str,
        to_block: &str,
    ) -> impl std::future::Future<Output = Result<Vec<Value>>> + Send;
}

/// JSON-RPC client backed by reqwest.
pub struct RpcClient {
    url: String,
    client: reqwest::Client,
    id: std::sync::atomic::AtomicU64,
}

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    method: String,
    params: Value,
    id: u64,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    result: Option<Value>,
    error: Option<JsonRpcError>,
    id: Option<Value>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl RpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: reqwest::Client::new(),
            id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    async fn call_rpc(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            method: method.to_string(),
            params,
            id,
        };

        let resp: JsonRpcResponse = self
            .client
            .post(&self.url)
            .json(&req)
            .send()
            .await
            .wrap_err("failed to send RPC request")?
            .error_for_status()
            .wrap_err("RPC HTTP request failed")?
            .json()
            .await
            .wrap_err("failed to parse RPC response")?;

        if resp.id.as_ref() != Some(&Value::from(id)) {
            eyre::bail!(
                "RPC response id mismatch: expected {}, got {:?}",
                id,
                resp.id
            );
        }

        if let Some(err) = resp.error {
            eyre::bail!("RPC error {}: {}", err.code, err.message);
        }

        resp.result.ok_or_else(|| eyre::eyre!("empty RPC result"))
    }

    fn parse_hex_u64(val: &Value) -> Result<u64> {
        let hex_str = val
            .as_str()
            .ok_or_else(|| eyre::eyre!("expected hex string"))?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        u64::from_str_radix(hex_str, 16).wrap_err("failed to parse hex u64")
    }

    fn parse_hex_bytes(val: &Value) -> Result<Vec<u8>> {
        let hex_str = val
            .as_str()
            .ok_or_else(|| eyre::eyre!("expected hex string"))?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        hex::decode(hex_str).wrap_err("failed to decode hex bytes")
    }

    fn parse_hex_u256(val: &Value) -> Result<U256> {
        let hex_str = val
            .as_str()
            .ok_or_else(|| eyre::eyre!("expected hex string"))?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        U256::from_str_radix(hex_str, 16).map_err(|e| eyre::eyre!("failed to parse U256: {e}"))
    }

    /// Call `outbe_getVrfSeed` with a specific block number.
    #[allow(dead_code)]
    pub async fn outbe_get_vrf_seed_at(&self, block_number: u64) -> Result<Value> {
        self.call_rpc("outbe_getVrfSeed", serde_json::json!([block_number]))
            .await
    }
}

impl Rpc for RpcClient {
    async fn eth_call(&self, to: Address, data: &[u8]) -> Result<Vec<u8>> {
        let result = self
            .call_rpc(
                "eth_call",
                serde_json::json!([
                    {
                        "to": format!("{to:?}"),
                        "data": format!("0x{}", hex::encode(data)),
                    },
                    "latest"
                ]),
            )
            .await?;
        Self::parse_hex_bytes(&result)
    }

    async fn eth_block_number(&self) -> Result<u64> {
        let result = self
            .call_rpc("eth_blockNumber", serde_json::json!([]))
            .await?;
        Self::parse_hex_u64(&result)
    }

    async fn eth_chain_id(&self) -> Result<u64> {
        let result = self.call_rpc("eth_chainId", serde_json::json!([])).await?;
        Self::parse_hex_u64(&result)
    }

    async fn eth_gas_price(&self) -> Result<U256> {
        let result = self.call_rpc("eth_gasPrice", serde_json::json!([])).await?;
        Self::parse_hex_u256(&result)
    }

    async fn eth_get_transaction_count(&self, address: Address) -> Result<u64> {
        let result = self
            .call_rpc(
                "eth_getTransactionCount",
                serde_json::json!([format!("{address:?}"), "latest"]),
            )
            .await?;
        Self::parse_hex_u64(&result)
    }

    async fn eth_estimate_gas(&self, from: Address, to: Address, data: &[u8]) -> Result<u64> {
        let result = self
            .call_rpc(
                "eth_estimateGas",
                serde_json::json!([{
                    "from": format!("{from:?}"),
                    "to": format!("{to:?}"),
                    "data": format!("0x{}", hex::encode(data)),
                }]),
            )
            .await?;
        Self::parse_hex_u64(&result)
    }

    async fn eth_send_raw_transaction(&self, raw_tx: &[u8]) -> Result<String> {
        let result = self
            .call_rpc(
                "eth_sendRawTransaction",
                serde_json::json!([format!("0x{}", hex::encode(raw_tx))]),
            )
            .await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| eyre::eyre!("expected tx hash string"))
    }

    async fn eth_get_balance(&self, address: Address) -> Result<U256> {
        let result = self
            .call_rpc(
                "eth_getBalance",
                serde_json::json!([format!("{address:?}"), "latest"]),
            )
            .await?;
        Self::parse_hex_u256(&result)
    }

    async fn net_peer_count(&self) -> Result<u64> {
        let result = self
            .call_rpc("net_peerCount", serde_json::json!([]))
            .await?;
        Self::parse_hex_u64(&result)
    }

    async fn outbe_consensus_status(&self) -> Result<Value> {
        self.call_rpc("outbe_consensusStatus", serde_json::json!([]))
            .await
    }

    async fn outbe_get_epoch_info(&self) -> Result<Value> {
        self.call_rpc("outbe_getEpochInfo", serde_json::json!([]))
            .await
    }

    async fn eth_get_block_by_number(&self, block: u64) -> Result<Value> {
        let hex_block = format!("0x{block:x}");
        self.call_rpc(
            "eth_getBlockByNumber",
            serde_json::json!([hex_block, false]),
        )
        .await
    }

    async fn eth_get_latest_block(&self) -> Result<Value> {
        self.call_rpc("eth_getBlockByNumber", serde_json::json!(["latest", false]))
            .await
    }

    async fn outbe_get_vrf_seed(&self) -> Result<Value> {
        self.call_rpc("outbe_getVrfSeed", serde_json::json!([null]))
            .await
    }

    async fn outbe_get_emission_info(&self) -> Result<Value> {
        self.call_rpc("outbe_getEmissionInfo", serde_json::json!([]))
            .await
    }

    async fn outbe_get_slash_config(&self) -> Result<Value> {
        self.call_rpc("outbe_getSlashConfig", serde_json::json!([]))
            .await
    }

    async fn outbe_get_update_active_version(&self) -> Result<Value> {
        self.call_rpc("outbe_getUpdateActiveVersion", serde_json::json!([]))
            .await
    }

    async fn outbe_get_update_proposal(&self, proposal_id: U256) -> Result<Option<Value>> {
        let result = self
            .call_rpc("outbe_getUpdateProposal", serde_json::json!([proposal_id]))
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    async fn outbe_list_update_pending_proposals(&self) -> Result<Value> {
        self.call_rpc("outbe_listUpdatePendingProposals", serde_json::json!([]))
            .await
    }

    async fn outbe_list_update_waiting_proposals(&self) -> Result<Value> {
        self.call_rpc("outbe_listUpdateWaitingProposals", serde_json::json!([]))
            .await
    }

    async fn eth_get_logs(
        &self,
        address: Address,
        topics: &[Option<String>],
        from_block: &str,
        to_block: &str,
    ) -> Result<Vec<Value>> {
        let topics_json: Vec<Value> = topics
            .iter()
            .map(|t| match t {
                Some(v) => Value::String(v.clone()),
                None => Value::Null,
            })
            .collect();

        let result = self
            .call_rpc(
                "eth_getLogs",
                serde_json::json!([{
                    "address": format!("{address:?}"),
                    "topics": topics_json,
                    "fromBlock": from_block,
                    "toBlock": to_block,
                }]),
            )
            .await?;

        result
            .as_array()
            .cloned()
            .ok_or_else(|| eyre::eyre!("expected array of logs"))
    }
}

/// Test mock for the Rpc trait. Available to all crate test modules.
#[cfg(test)]
pub mod mock {
    use super::*;
    use crate::tx::TxSigner;
    pub use outbe_rpc::test_support::{
        abi_u256, abi_u64, call_map, EthCallMap, ExpectedRpcCall, RecordedRpcCall,
        RecordedRpcResponse, RecordingRpc,
    };

    pub fn recording_send_tx_rpc(
        private_key: &str,
        to: Address,
        data: Vec<u8>,
        value: U256,
    ) -> Result<RecordingRpc> {
        const CHAIN_ID: u64 = 1337;
        const NONCE: u64 = 0;
        const GAS_ESTIMATE: u64 = 21_000;
        const TX_HASH: &str = "0xdeadbeef";

        // `eth_gasPrice` returns `suggested`; `send_tx` signs with the buffered price.
        let suggested = U256::from(1_000_000_000u64);
        let gas_price = crate::tx::buffered_gas_price(suggested);
        let signer = TxSigner::new(private_key)?;
        let gas_limit = GAS_ESTIMATE + GAS_ESTIMATE / 5;
        let raw_tx = signer
            .sign_legacy_tx_for_test(NONCE, gas_price, gas_limit, to, value, &data, CHAIN_ID)?;

        Ok(RecordingRpc::new([
            ExpectedRpcCall::ok(
                RecordedRpcCall::EthChainId,
                RecordedRpcResponse::U64(CHAIN_ID),
            ),
            ExpectedRpcCall::ok(
                RecordedRpcCall::EthGetTransactionCount {
                    address: signer.address(),
                },
                RecordedRpcResponse::U64(NONCE),
            ),
            ExpectedRpcCall::ok(
                RecordedRpcCall::EthGasPrice,
                RecordedRpcResponse::U256(suggested),
            ),
            ExpectedRpcCall::ok(
                RecordedRpcCall::EthEstimateGas {
                    from: signer.address(),
                    to,
                    data: data.clone(),
                },
                RecordedRpcResponse::U64(GAS_ESTIMATE),
            ),
            ExpectedRpcCall::ok(
                RecordedRpcCall::EthSendRawTransaction { raw_tx },
                RecordedRpcResponse::Text(TX_HASH.to_string()),
            ),
        ]))
    }

    /// A configurable mock. `eth_call_fn` dispatches based on (address, selector).
    /// Other fields are simple canned values.
    pub struct MockRpc {
        pub block_number: Result<u64>,
        pub chain_id: Result<u64>,
        pub gas_price: Result<U256>,
        pub balance: Result<U256>,
        pub peer_count: Result<u64>,
        pub tx_count: Result<u64>,
        pub estimate_gas: Result<u64>,
        pub send_raw_tx: Result<String>,
        pub eth_call_map: Option<EthCallMap>,
        pub consensus_status: Result<Value>,
        pub epoch_info: Result<Value>,
        pub latest_block: Result<Value>,
        pub block_by_number: Result<Value>,
        pub vrf_seed: Result<Value>,
        pub emission_info: Result<Value>,
        pub slash_config: Result<Value>,
        pub update_active_version: Result<Value>,
        pub update_proposal: Result<Option<Value>>,
        pub update_pending_proposals: Result<Value>,
        pub update_waiting_proposals: Result<Value>,
        pub logs: Result<Vec<Value>>,
    }

    impl Default for MockRpc {
        fn default() -> Self {
            Self {
                block_number: Err(eyre::eyre!("not mocked")),
                chain_id: Err(eyre::eyre!("not mocked")),
                gas_price: Err(eyre::eyre!("not mocked")),
                balance: Err(eyre::eyre!("not mocked")),
                peer_count: Err(eyre::eyre!("not mocked")),
                tx_count: Err(eyre::eyre!("not mocked")),
                estimate_gas: Err(eyre::eyre!("not mocked")),
                send_raw_tx: Err(eyre::eyre!("not mocked")),
                eth_call_map: None,
                consensus_status: Err(eyre::eyre!("not mocked")),
                epoch_info: Err(eyre::eyre!("not mocked")),
                latest_block: Err(eyre::eyre!("not mocked")),
                block_by_number: Err(eyre::eyre!("not mocked")),
                vrf_seed: Err(eyre::eyre!("not mocked")),
                emission_info: Err(eyre::eyre!("not mocked")),
                slash_config: Err(eyre::eyre!("not mocked")),
                update_active_version: Err(eyre::eyre!("not mocked")),
                update_proposal: Err(eyre::eyre!("not mocked")),
                update_pending_proposals: Err(eyre::eyre!("not mocked")),
                update_waiting_proposals: Err(eyre::eyre!("not mocked")),
                logs: Err(eyre::eyre!("not mocked")),
            }
        }
    }

    fn clone_result<T: Clone>(r: &Result<T>) -> Result<T> {
        match r {
            Ok(v) => Ok(v.clone()),
            Err(e) => Err(eyre::eyre!("{e}")),
        }
    }

    impl Rpc for MockRpc {
        async fn eth_call(&self, to: Address, data: &[u8]) -> Result<Vec<u8>> {
            match &self.eth_call_map {
                Some(map) => map.dispatch(to, data),
                None => Err(eyre::eyre!("eth_call not mocked")),
            }
        }
        async fn eth_block_number(&self) -> Result<u64> {
            clone_result(&self.block_number)
        }
        async fn eth_chain_id(&self) -> Result<u64> {
            clone_result(&self.chain_id)
        }
        async fn eth_gas_price(&self) -> Result<U256> {
            clone_result(&self.gas_price)
        }
        async fn eth_get_transaction_count(&self, _address: Address) -> Result<u64> {
            clone_result(&self.tx_count)
        }
        async fn eth_estimate_gas(
            &self,
            _from: Address,
            _to: Address,
            _data: &[u8],
        ) -> Result<u64> {
            clone_result(&self.estimate_gas)
        }
        async fn eth_send_raw_transaction(&self, _raw_tx: &[u8]) -> Result<String> {
            clone_result(&self.send_raw_tx)
        }
        async fn eth_get_balance(&self, _address: Address) -> Result<U256> {
            clone_result(&self.balance)
        }
        async fn net_peer_count(&self) -> Result<u64> {
            clone_result(&self.peer_count)
        }
        async fn outbe_consensus_status(&self) -> Result<Value> {
            clone_result(&self.consensus_status)
        }
        async fn outbe_get_epoch_info(&self) -> Result<Value> {
            clone_result(&self.epoch_info)
        }
        async fn eth_get_block_by_number(&self, _block: u64) -> Result<Value> {
            clone_result(&self.block_by_number)
        }
        async fn eth_get_latest_block(&self) -> Result<Value> {
            clone_result(&self.latest_block)
        }
        async fn outbe_get_vrf_seed(&self) -> Result<Value> {
            clone_result(&self.vrf_seed)
        }
        async fn outbe_get_emission_info(&self) -> Result<Value> {
            clone_result(&self.emission_info)
        }
        async fn outbe_get_slash_config(&self) -> Result<Value> {
            clone_result(&self.slash_config)
        }
        async fn outbe_get_update_active_version(&self) -> Result<Value> {
            clone_result(&self.update_active_version)
        }
        async fn outbe_get_update_proposal(&self, _proposal_id: U256) -> Result<Option<Value>> {
            clone_result(&self.update_proposal)
        }
        async fn outbe_list_update_pending_proposals(&self) -> Result<Value> {
            clone_result(&self.update_pending_proposals)
        }
        async fn outbe_list_update_waiting_proposals(&self) -> Result<Value> {
            clone_result(&self.update_waiting_proposals)
        }
        async fn eth_get_logs(
            &self,
            _address: Address,
            _topics: &[Option<String>],
            _from_block: &str,
            _to_block: &str,
        ) -> Result<Vec<Value>> {
            clone_result(&self.logs)
        }
    }

    impl Rpc for RecordingRpc {
        async fn eth_call(&self, to: Address, data: &[u8]) -> Result<Vec<u8>> {
            self.next_response(RecordedRpcCall::EthCall {
                to,
                data: data.to_vec(),
            })?
            .into_bytes("eth_call")
        }

        async fn eth_block_number(&self) -> Result<u64> {
            self.next_response(RecordedRpcCall::EthBlockNumber)?
                .into_u64("eth_blockNumber")
        }

        async fn eth_chain_id(&self) -> Result<u64> {
            self.next_response(RecordedRpcCall::EthChainId)?
                .into_u64("eth_chainId")
        }

        async fn eth_gas_price(&self) -> Result<U256> {
            self.next_response(RecordedRpcCall::EthGasPrice)?
                .into_u256("eth_gasPrice")
        }

        async fn eth_get_transaction_count(&self, address: Address) -> Result<u64> {
            self.next_response(RecordedRpcCall::EthGetTransactionCount { address })?
                .into_u64("eth_getTransactionCount")
        }

        async fn eth_estimate_gas(&self, from: Address, to: Address, data: &[u8]) -> Result<u64> {
            self.next_response(RecordedRpcCall::EthEstimateGas {
                from,
                to,
                data: data.to_vec(),
            })?
            .into_u64("eth_estimateGas")
        }

        async fn eth_send_raw_transaction(&self, raw_tx: &[u8]) -> Result<String> {
            self.next_response(RecordedRpcCall::EthSendRawTransaction {
                raw_tx: raw_tx.to_vec(),
            })?
            .into_text("eth_sendRawTransaction")
        }

        async fn eth_get_balance(&self, address: Address) -> Result<U256> {
            self.next_response(RecordedRpcCall::EthGetBalance { address })?
                .into_u256("eth_getBalance")
        }

        async fn net_peer_count(&self) -> Result<u64> {
            self.next_response(RecordedRpcCall::NetPeerCount)?
                .into_u64("net_peerCount")
        }

        async fn outbe_consensus_status(&self) -> Result<Value> {
            self.next_response(RecordedRpcCall::OutbeConsensusStatus)?
                .into_value("outbe_consensusStatus")
        }

        async fn outbe_get_epoch_info(&self) -> Result<Value> {
            self.next_response(RecordedRpcCall::OutbeGetEpochInfo)?
                .into_value("outbe_getEpochInfo")
        }

        async fn eth_get_block_by_number(&self, block: u64) -> Result<Value> {
            self.next_response(RecordedRpcCall::EthGetBlockByNumber { block })?
                .into_value("eth_getBlockByNumber")
        }

        async fn eth_get_latest_block(&self) -> Result<Value> {
            self.next_response(RecordedRpcCall::EthGetLatestBlock)?
                .into_value("eth_getBlockByNumber latest")
        }

        async fn outbe_get_vrf_seed(&self) -> Result<Value> {
            self.next_response(RecordedRpcCall::OutbeGetVrfSeed)?
                .into_value("outbe_getVrfSeed")
        }

        async fn outbe_get_emission_info(&self) -> Result<Value> {
            self.next_response(RecordedRpcCall::OutbeGetEmissionInfo)?
                .into_value("outbe_getEmissionInfo")
        }

        async fn outbe_get_slash_config(&self) -> Result<Value> {
            self.next_response(RecordedRpcCall::OutbeGetSlashConfig)?
                .into_value("outbe_getSlashConfig")
        }

        async fn outbe_get_update_active_version(&self) -> Result<Value> {
            self.next_response(RecordedRpcCall::OutbeGetUpdateActiveVersion)?
                .into_value("outbe_getUpdateActiveVersion")
        }

        async fn outbe_get_update_proposal(&self, proposal_id: U256) -> Result<Option<Value>> {
            let value = self
                .next_response(RecordedRpcCall::OutbeGetUpdateProposal { proposal_id })?
                .into_value("outbe_getUpdateProposal")?;
            if value.is_null() {
                Ok(None)
            } else {
                Ok(Some(value))
            }
        }

        async fn outbe_list_update_pending_proposals(&self) -> Result<Value> {
            self.next_response(RecordedRpcCall::OutbeListUpdatePendingProposals)?
                .into_value("outbe_listUpdatePendingProposals")
        }

        async fn outbe_list_update_waiting_proposals(&self) -> Result<Value> {
            self.next_response(RecordedRpcCall::OutbeListUpdateWaitingProposals)?
                .into_value("outbe_listUpdateWaitingProposals")
        }

        async fn eth_get_logs(
            &self,
            address: Address,
            topics: &[Option<String>],
            from_block: &str,
            to_block: &str,
        ) -> Result<Vec<Value>> {
            self.next_response(RecordedRpcCall::EthGetLogs {
                address,
                topics: topics.to_vec(),
                from_block: from_block.to_string(),
                to_block: to_block.to_string(),
            })?
            .into_logs("eth_getLogs")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};

    async fn serve_rpc_once(
        status: &str,
        response_body: impl Into<String>,
    ) -> (String, oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let status = status.to_string();
        let response_body = response_body.into();
        let (body_tx, body_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];

            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);

                if let Some(header_end) = find_header_end(&request) {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_len = content_length(&headers);
                    if request.len() >= header_end + 4 + content_len {
                        break;
                    }
                }
            }

            let body_start = find_header_end(&request)
                .map(|pos| pos + 4)
                .unwrap_or(request.len());
            let body = String::from_utf8_lossy(&request[body_start..]).to_string();
            let _ = body_tx.send(body);

            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        (format!("http://{addr}"), body_rx)
    }

    async fn serve_rpc_sequence(
        response_bodies: impl IntoIterator<Item = impl Into<String>>,
    ) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let response_bodies: Vec<String> = response_bodies.into_iter().map(Into::into).collect();
        let (body_tx, body_rx) = mpsc::channel(response_bodies.len().max(1));

        tokio::spawn(async move {
            for response_body in response_bodies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_http_request(&mut socket).await;
                let body_start = find_header_end(&request)
                    .map(|pos| pos + 4)
                    .unwrap_or(request.len());
                let body = String::from_utf8_lossy(&request[body_start..]).to_string();
                let _ = body_tx.send(body).await;

                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        (format!("http://{addr}"), body_rx)
    }

    async fn read_http_request(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];

        loop {
            let n = socket.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buf[..n]);

            if let Some(header_end) = find_header_end(&request) {
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_len = content_length(&headers);
                if request.len() >= header_end + 4 + content_len {
                    break;
                }
            }
        }

        request
    }

    fn find_header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn content_length(headers: &str) -> usize {
        headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    // --- transport-level RpcClient tests ---

    #[tokio::test]
    async fn test_rpc_client_eth_call_sends_exact_body_and_decodes_bytes() {
        let (url, body_rx) =
            serve_rpc_once("200 OK", r#"{"jsonrpc":"2.0","result":"0xaabb","id":1}"#).await;
        let client = RpcClient::new(&url);
        let to = address!("0x000000000000000000000000000000000000EE02");

        let result = client.eth_call(to, &[0x12, 0x34]).await.unwrap();

        assert_eq!(result, vec![0xaa, 0xbb]);
        let body: Value = serde_json::from_str(&body_rx.await.unwrap()).unwrap();
        assert_eq!(
            body,
            json!({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [
                    {
                        "to": format!("{to:?}"),
                        "data": "0x1234",
                    },
                    "latest",
                ],
                "id": 1,
            })
        );
    }

    #[tokio::test]
    async fn test_rpc_client_estimate_gas_sends_exact_body() {
        let (url, body_rx) =
            serve_rpc_once("200 OK", r#"{"jsonrpc":"2.0","result":"0x5208","id":1}"#).await;
        let client = RpcClient::new(&url);
        let from = address!("0x1111111111111111111111111111111111111111");
        let to = address!("0x000000000000000000000000000000000000EE02");

        let gas = client
            .eth_estimate_gas(from, to, &[0xde, 0xad])
            .await
            .unwrap();

        assert_eq!(gas, 21_000);
        let body: Value = serde_json::from_str(&body_rx.await.unwrap()).unwrap();
        assert_eq!(
            body,
            json!({
                "jsonrpc": "2.0",
                "method": "eth_estimateGas",
                "params": [{
                    "from": format!("{from:?}"),
                    "to": format!("{to:?}"),
                    "data": "0xdead",
                }],
                "id": 1,
            })
        );
    }

    #[tokio::test]
    async fn test_rpc_client_send_raw_transaction_sends_hex_body() {
        let (url, body_rx) =
            serve_rpc_once("200 OK", r#"{"jsonrpc":"2.0","result":"0xfeed","id":1}"#).await;
        let client = RpcClient::new(&url);

        let tx_hash = client
            .eth_send_raw_transaction(&[0xde, 0xad, 0xbe, 0xef])
            .await
            .unwrap();

        assert_eq!(tx_hash, "0xfeed");
        let body: Value = serde_json::from_str(&body_rx.await.unwrap()).unwrap();
        assert_eq!(
            body,
            json!({
                "jsonrpc": "2.0",
                "method": "eth_sendRawTransaction",
                "params": ["0xdeadbeef"],
                "id": 1,
            })
        );
    }

    #[tokio::test]
    async fn test_rpc_client_send_raw_transaction_non_string_errors() {
        let (url, _body_rx) =
            serve_rpc_once("200 OK", r#"{"jsonrpc":"2.0","result":123,"id":1}"#).await;
        let client = RpcClient::new(&url);

        let err = client
            .eth_send_raw_transaction(&[0xde, 0xad])
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("expected tx hash string"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_rpc_client_get_balance_sends_exact_body_and_decodes_u256() {
        let (url, body_rx) = serve_rpc_once(
            "200 OK",
            r#"{"jsonrpc":"2.0","result":"0xde0b6b3a7640000","id":1}"#,
        )
        .await;
        let client = RpcClient::new(&url);
        let address = address!("0x1111111111111111111111111111111111111111");

        let balance = client.eth_get_balance(address).await.unwrap();

        assert_eq!(balance, U256::from(1_000_000_000_000_000_000u128));
        let body: Value = serde_json::from_str(&body_rx.await.unwrap()).unwrap();
        assert_eq!(
            body,
            json!({
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [format!("{address:?}"), "latest"],
                "id": 1,
            })
        );
    }

    #[tokio::test]
    async fn test_rpc_client_get_block_by_number_sends_hex_block_and_false() {
        let result = json!({"number": "0x2a", "hash": "0xabc"});
        let response = json!({"jsonrpc": "2.0", "result": result, "id": 1}).to_string();
        let (url, body_rx) = serve_rpc_once("200 OK", response).await;
        let client = RpcClient::new(&url);

        let block = client.eth_get_block_by_number(42).await.unwrap();

        assert_eq!(block, json!({"number": "0x2a", "hash": "0xabc"}));
        let body: Value = serde_json::from_str(&body_rx.await.unwrap()).unwrap();
        assert_eq!(
            body,
            json!({
                "jsonrpc": "2.0",
                "method": "eth_getBlockByNumber",
                "params": ["0x2a", false],
                "id": 1,
            })
        );
    }

    #[tokio::test]
    async fn test_rpc_client_get_latest_block_sends_latest_and_false() {
        let result = json!({"number": "0x2b", "hash": "0xdef"});
        let response = json!({"jsonrpc": "2.0", "result": result, "id": 1}).to_string();
        let (url, body_rx) = serve_rpc_once("200 OK", response).await;
        let client = RpcClient::new(&url);

        let block = client.eth_get_latest_block().await.unwrap();

        assert_eq!(block, json!({"number": "0x2b", "hash": "0xdef"}));
        let body: Value = serde_json::from_str(&body_rx.await.unwrap()).unwrap();
        assert_eq!(
            body,
            json!({
                "jsonrpc": "2.0",
                "method": "eth_getBlockByNumber",
                "params": ["latest", false],
                "id": 1,
            })
        );
    }

    #[tokio::test]
    async fn test_rpc_client_get_vrf_seed_sends_null_block_param() {
        let result = json!({"seed": "0x1234"});
        let response = json!({"jsonrpc": "2.0", "result": result, "id": 1}).to_string();
        let (url, body_rx) = serve_rpc_once("200 OK", response).await;
        let client = RpcClient::new(&url);

        let seed = client.outbe_get_vrf_seed().await.unwrap();

        assert_eq!(seed, json!({"seed": "0x1234"}));
        let body: Value = serde_json::from_str(&body_rx.await.unwrap()).unwrap();
        assert_eq!(
            body,
            json!({
                "jsonrpc": "2.0",
                "method": "outbe_getVrfSeed",
                "params": [null],
                "id": 1,
            })
        );
    }

    #[tokio::test]
    async fn test_rpc_client_get_vrf_seed_at_sends_numeric_block_param() {
        let result = json!({"seed": "0xabcd"});
        let response = json!({"jsonrpc": "2.0", "result": result, "id": 1}).to_string();
        let (url, body_rx) = serve_rpc_once("200 OK", response).await;
        let client = RpcClient::new(&url);

        let seed = client.outbe_get_vrf_seed_at(99).await.unwrap();

        assert_eq!(seed, json!({"seed": "0xabcd"}));
        let body: Value = serde_json::from_str(&body_rx.await.unwrap()).unwrap();
        assert_eq!(
            body,
            json!({
                "jsonrpc": "2.0",
                "method": "outbe_getVrfSeed",
                "params": [99],
                "id": 1,
            })
        );
    }

    #[tokio::test]
    async fn test_rpc_client_get_logs_sends_exact_filter_and_decodes_array() {
        let result = json!([
            {
                "address": "0x0000000000000000000000000000000000001006",
                "topics": ["0xaaa"],
                "data": "0x",
            }
        ]);
        let response = json!({"jsonrpc": "2.0", "result": result, "id": 1}).to_string();
        let (url, body_rx) = serve_rpc_once("200 OK", response).await;
        let client = RpcClient::new(&url);
        let address = address!("0x0000000000000000000000000000000000001006");
        let topics = [Some("0xaaa".to_string()), None, Some("0xccc".to_string())];

        let logs = client
            .eth_get_logs(address, &topics, "0x10", "latest")
            .await
            .unwrap();

        assert_eq!(
            logs,
            vec![json!({
                "address": "0x0000000000000000000000000000000000001006",
                "topics": ["0xaaa"],
                "data": "0x",
            })]
        );
        let body: Value = serde_json::from_str(&body_rx.await.unwrap()).unwrap();
        assert_eq!(
            body,
            json!({
                "jsonrpc": "2.0",
                "method": "eth_getLogs",
                "params": [{
                    "address": format!("{address:?}"),
                    "topics": ["0xaaa", null, "0xccc"],
                    "fromBlock": "0x10",
                    "toBlock": "latest",
                }],
                "id": 1,
            })
        );
    }

    #[tokio::test]
    async fn test_rpc_client_get_logs_non_array_errors() {
        let (url, _body_rx) =
            serve_rpc_once("200 OK", r#"{"jsonrpc":"2.0","result":{"log":1},"id":1}"#).await;
        let client = RpcClient::new(&url);
        let address = address!("0x0000000000000000000000000000000000001006");

        let err = client
            .eth_get_logs(address, &[], "earliest", "latest")
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("expected array of logs"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_rpc_client_ids_increment_across_calls() {
        let (url, mut body_rx) = serve_rpc_sequence([
            r#"{"jsonrpc":"2.0","result":"0x1","id":1}"#,
            r#"{"jsonrpc":"2.0","result":"0x2","id":2}"#,
            r#"{"jsonrpc":"2.0","result":"0x3","id":3}"#,
        ])
        .await;
        let client = RpcClient::new(&url);

        assert_eq!(client.eth_block_number().await.unwrap(), 1);
        assert_eq!(client.net_peer_count().await.unwrap(), 2);
        assert_eq!(client.eth_chain_id().await.unwrap(), 3);

        let first: Value = serde_json::from_str(&body_rx.recv().await.unwrap()).unwrap();
        let second: Value = serde_json::from_str(&body_rx.recv().await.unwrap()).unwrap();
        let third: Value = serde_json::from_str(&body_rx.recv().await.unwrap()).unwrap();

        assert_eq!(
            first,
            json!({
                "jsonrpc": "2.0",
                "method": "eth_blockNumber",
                "params": [],
                "id": 1,
            })
        );
        assert_eq!(
            second,
            json!({
                "jsonrpc": "2.0",
                "method": "net_peerCount",
                "params": [],
                "id": 2,
            })
        );
        assert_eq!(
            third,
            json!({
                "jsonrpc": "2.0",
                "method": "eth_chainId",
                "params": [],
                "id": 3,
            })
        );
    }

    #[tokio::test]
    async fn test_rpc_client_quantity_wrappers_send_exact_bodies_and_decode() {
        let (url, mut body_rx) = serve_rpc_sequence([
            r#"{"jsonrpc":"2.0","result":"0x3b9aca00","id":1}"#,
            r#"{"jsonrpc":"2.0","result":"0x7","id":2}"#,
        ])
        .await;
        let client = RpcClient::new(&url);
        let address = address!("0x1111111111111111111111111111111111111111");

        assert_eq!(
            client.eth_gas_price().await.unwrap(),
            U256::from(1_000_000_000u64)
        );
        assert_eq!(client.eth_get_transaction_count(address).await.unwrap(), 7);

        let first: Value = serde_json::from_str(&body_rx.recv().await.unwrap()).unwrap();
        let second: Value = serde_json::from_str(&body_rx.recv().await.unwrap()).unwrap();

        assert_eq!(
            first,
            json!({
                "jsonrpc": "2.0",
                "method": "eth_gasPrice",
                "params": [],
                "id": 1,
            })
        );
        assert_eq!(
            second,
            json!({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionCount",
                "params": [format!("{address:?}"), "latest"],
                "id": 2,
            })
        );
    }

    #[tokio::test]
    async fn test_rpc_client_outbe_no_param_wrappers_send_exact_bodies() {
        let consensus = json!({"mode": "validator"});
        let epoch = json!({"epoch": 3});
        let emission = json!({"rate": "0x1"});
        let slash = json!({"slashAmountPercent": 5});
        let (url, mut body_rx) = serve_rpc_sequence([
            json!({"jsonrpc": "2.0", "result": consensus, "id": 1}).to_string(),
            json!({"jsonrpc": "2.0", "result": epoch, "id": 2}).to_string(),
            json!({"jsonrpc": "2.0", "result": emission, "id": 3}).to_string(),
            json!({"jsonrpc": "2.0", "result": slash, "id": 4}).to_string(),
        ])
        .await;
        let client = RpcClient::new(&url);

        assert_eq!(
            client.outbe_consensus_status().await.unwrap(),
            json!({"mode": "validator"})
        );
        assert_eq!(
            client.outbe_get_epoch_info().await.unwrap(),
            json!({"epoch": 3})
        );
        assert_eq!(
            client.outbe_get_emission_info().await.unwrap(),
            json!({"rate": "0x1"})
        );
        assert_eq!(
            client.outbe_get_slash_config().await.unwrap(),
            json!({"slashAmountPercent": 5})
        );

        let first: Value = serde_json::from_str(&body_rx.recv().await.unwrap()).unwrap();
        let second: Value = serde_json::from_str(&body_rx.recv().await.unwrap()).unwrap();
        let third: Value = serde_json::from_str(&body_rx.recv().await.unwrap()).unwrap();
        let fourth: Value = serde_json::from_str(&body_rx.recv().await.unwrap()).unwrap();

        assert_eq!(
            first,
            json!({
                "jsonrpc": "2.0",
                "method": "outbe_consensusStatus",
                "params": [],
                "id": 1,
            })
        );
        assert_eq!(
            second,
            json!({
                "jsonrpc": "2.0",
                "method": "outbe_getEpochInfo",
                "params": [],
                "id": 2,
            })
        );
        assert_eq!(
            third,
            json!({
                "jsonrpc": "2.0",
                "method": "outbe_getEmissionInfo",
                "params": [],
                "id": 3,
            })
        );
        assert_eq!(
            fourth,
            json!({
                "jsonrpc": "2.0",
                "method": "outbe_getSlashConfig",
                "params": [],
                "id": 4,
            })
        );
    }

    #[tokio::test]
    async fn test_rpc_client_json_rpc_error_returns_error() {
        let (url, _body_rx) = serve_rpc_once(
            "200 OK",
            r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"missing method"},"id":1}"#,
        )
        .await;
        let client = RpcClient::new(&url);

        let err = client.eth_block_number().await.unwrap_err();

        assert!(
            err.to_string().contains("RPC error -32601: missing method"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_rpc_client_missing_result_errors() {
        let (url, _body_rx) = serve_rpc_once("200 OK", r#"{"jsonrpc":"2.0","id":1}"#).await;
        let client = RpcClient::new(&url);

        let err = client.eth_block_number().await.unwrap_err();

        assert!(
            err.to_string().contains("empty RPC result"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_rpc_client_invalid_json_errors() {
        let (url, _body_rx) = serve_rpc_once("200 OK", "not json").await;
        let client = RpcClient::new(&url);

        let err = client.eth_block_number().await.unwrap_err();

        assert!(
            err.to_string().contains("failed to parse RPC response"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_rpc_client_http_status_error() {
        let (url, _body_rx) = serve_rpc_once(
            "500 Internal Server Error",
            r#"{"jsonrpc":"2.0","result":"0x1","id":1}"#,
        )
        .await;
        let client = RpcClient::new(&url);

        let err = client.eth_block_number().await.unwrap_err();

        assert!(
            err.to_string().contains("RPC HTTP request failed"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_rpc_client_response_id_mismatch_errors() {
        let (url, _body_rx) =
            serve_rpc_once("200 OK", r#"{"jsonrpc":"2.0","result":"0x1","id":99}"#).await;
        let client = RpcClient::new(&url);

        let err = client.eth_block_number().await.unwrap_err();

        assert!(
            err.to_string().contains("RPC response id mismatch"),
            "unexpected error: {err}"
        );
    }

    // --- parse_hex_u64 ---

    #[test]
    fn test_parse_hex_u64_with_prefix() {
        assert_eq!(RpcClient::parse_hex_u64(&json!("0x1a")).unwrap(), 26);
    }

    #[test]
    fn test_parse_hex_u64_without_prefix() {
        assert_eq!(RpcClient::parse_hex_u64(&json!("1a")).unwrap(), 26);
    }

    #[test]
    fn test_parse_hex_u64_zero() {
        assert_eq!(RpcClient::parse_hex_u64(&json!("0x0")).unwrap(), 0);
    }

    #[test]
    fn test_parse_hex_u64_max() {
        assert_eq!(
            RpcClient::parse_hex_u64(&json!("0xffffffffffffffff")).unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn test_parse_hex_u64_not_string() {
        assert!(RpcClient::parse_hex_u64(&json!(42)).is_err());
    }

    #[test]
    fn test_parse_hex_u64_invalid_hex() {
        assert!(RpcClient::parse_hex_u64(&json!("0xGG")).is_err());
    }

    #[test]
    fn test_parse_hex_u64_overflow() {
        assert!(RpcClient::parse_hex_u64(&json!("0x10000000000000000")).is_err());
    }

    // --- parse_hex_bytes ---

    #[test]
    fn test_parse_hex_bytes_with_prefix() {
        assert_eq!(
            RpcClient::parse_hex_bytes(&json!("0xdeadbeef")).unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn test_parse_hex_bytes_without_prefix() {
        assert_eq!(
            RpcClient::parse_hex_bytes(&json!("deadbeef")).unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn test_parse_hex_bytes_empty() {
        assert_eq!(
            RpcClient::parse_hex_bytes(&json!("0x")).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn test_parse_hex_bytes_single_byte() {
        assert_eq!(
            RpcClient::parse_hex_bytes(&json!("0xff")).unwrap(),
            vec![0xff]
        );
    }

    #[test]
    fn test_parse_hex_bytes_odd_length() {
        assert!(RpcClient::parse_hex_bytes(&json!("0xabc")).is_err());
    }

    #[test]
    fn test_parse_hex_bytes_not_string() {
        assert!(RpcClient::parse_hex_bytes(&json!(123)).is_err());
    }

    #[test]
    fn test_parse_hex_bytes_invalid_chars() {
        assert!(RpcClient::parse_hex_bytes(&json!("0xZZZZ")).is_err());
    }

    // --- parse_hex_u256 ---

    #[test]
    fn test_parse_hex_u256_with_prefix() {
        assert_eq!(
            RpcClient::parse_hex_u256(&json!("0xde0b6b3a7640000")).unwrap(),
            U256::from(1_000_000_000_000_000_000u128)
        );
    }

    #[test]
    fn test_parse_hex_u256_zero() {
        assert_eq!(
            RpcClient::parse_hex_u256(&json!("0x0")).unwrap(),
            U256::ZERO
        );
    }

    #[test]
    fn test_parse_hex_u256_without_prefix() {
        assert_eq!(
            RpcClient::parse_hex_u256(&json!("ff")).unwrap(),
            U256::from(255u64)
        );
    }

    #[test]
    fn test_parse_hex_u256_max() {
        let hex = format!("0x{}", "f".repeat(64));
        assert_eq!(RpcClient::parse_hex_u256(&json!(hex)).unwrap(), U256::MAX);
    }

    #[test]
    fn test_parse_hex_u256_not_string() {
        assert!(RpcClient::parse_hex_u256(&json!(42)).is_err());
    }

    #[test]
    fn test_parse_hex_u256_invalid_hex() {
        assert!(RpcClient::parse_hex_u256(&json!("0xGHIJ")).is_err());
    }
}
