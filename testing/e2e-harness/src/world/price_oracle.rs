//! Harness-owned mock price source and production `outbe-feeder` lifecycle.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use eyre::{bail, eyre, Result, WrapErr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::internal::config::Config;
use crate::internal::proc::ChildGuard;

const COEN_USD_SYMBOL: &str = "COEN840";
const FEEDER_START_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq)]
struct PricePoint {
    price: String,
    volume: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PriceBook {
    generation: u64,
    entries: BTreeMap<String, PricePoint>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PriceQuote<'a> {
    pub(crate) price: &'a str,
    pub(crate) volume: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FeederSource<'a> {
    pub(crate) base: &'a str,
    pub(crate) quote: &'a str,
    pub(crate) price: &'a str,
    pub(crate) volume: &'a str,
}

#[derive(Clone, Debug)]
pub(crate) struct FeederPair<'a> {
    pub(crate) base: &'a str,
    pub(crate) quote: &'a str,
    pub(crate) sources: Vec<FeederSource<'a>>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FeederLaunch<'a> {
    pub(crate) validator_index: usize,
    pub(crate) rpc_url: &'a str,
    pub(crate) chain_id: u64,
    pub(crate) private_key: &'a str,
    pub(crate) validator_address: &'a str,
    pub(crate) vote_period: u64,
    pub(crate) phase: OracleEvidencePhaseV1,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleEvidencePhaseV1 {
    Initial,
    ClockRestart,
    ControlledUpdate,
    QuorumRecovery,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriceOracleEvidenceV1 {
    pub feeder_binary: String,
    pub feeder_binary_sha256: String,
    pub feeder_processes: Vec<FeederProcessEvidenceV1>,
    pub ticker_requests: u64,
    pub candle_requests: u64,
    pub controlled_sources: Vec<ControlledSourceEvidenceV1>,
    pub canonical_publications: Vec<CanonicalPricePublicationV1>,
    pub quorum_loss_windows: Vec<QuorumLossEvidenceV1>,
    pub penalty_snapshots: Vec<PenaltySnapshotEvidenceV1>,
    pub cohorts: Vec<OracleCohortEvidenceV1>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleCheckpointV1 {
    pub height: u64,
    pub block_hash: alloy_primitives::B256,
    pub state_root: alloy_primitives::B256,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleMemberV1 {
    pub index: usize,
    pub address: alloy_primitives::Address,
    pub port: u16,
    pub node_pid: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleCohortV1 {
    pub checkpoint: OracleCheckpointV1,
    pub members: Vec<OracleMemberV1>,
    pub quorum: usize,
    pub feeder_indices: Vec<usize>,
    /// The fixed A/AB/AB/B negative fixture explicitly controls partial feeders.
    pub overlapping_pairs: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleCohortEvidenceV1 {
    /// First possible launch record for this cohort in append-only process history.
    pub first_process_record: usize,
    pub phase: OracleEvidencePhaseV1,
    pub cohort: OracleCohortV1,
    /// (owned validator index, launch attempt, PID), never signing material.
    pub current_attempts: Vec<(usize, u32, u32)>,
    /// Public observations, including unsuccessful polls before teardown.
    pub observations: Vec<serde_json::Value>,
}

fn validate_live_feeder_indices(cohort: &OracleCohortV1, live: &[usize]) -> Result<()> {
    let distinct = live
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    eyre::ensure!(
        distinct.len() == live.len() && !live.is_empty(),
        "empty or duplicate Oracle feeder owners"
    );
    if cohort.overlapping_pairs {
        eyre::ensure!(
            live.iter()
                .all(|index| cohort.feeder_indices.contains(index)),
            "unexpected overlapping-pair feeder"
        );
    } else {
        eyre::ensure!(
            live == cohort.feeder_indices,
            "Oracle feeder cohort changed; stopped feeders must not be replenished implicitly"
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeederProcessEvidenceV1 {
    pub validator_index: usize,
    pub validator_address: String,
    pub rpc_endpoint: String,
    pub vote_period: u64,
    pub attempt: u32,
    pub pid: u32,
    pub log: String,
    pub started_at_millis: u64,
    pub stopped_at_millis: Option<u64>,
    pub oracle_pairs: Vec<String>,
    pub source_markets: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledSourceEvidenceV1 {
    pub phase: OracleEvidencePhaseV1,
    pub generation: u64,
    pub validator_index: usize,
    pub oracle_pair: String,
    pub source_market: String,
    pub price: String,
    pub volume: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPricePublicationV1 {
    pub phase: OracleEvidencePhaseV1,
    pub validator_count: usize,
    pub base: String,
    pub quote: String,
    pub rate: String,
    pub volume: String,
    pub oracle_block: u64,
    pub oracle_timestamp: u64,
    pub finalized_height: u64,
    pub finalized_timestamp: u64,
    pub age_seconds: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CanonicalPublicationObservation {
    pub(crate) phase: OracleEvidencePhaseV1,
    pub(crate) validator_count: usize,
    pub(crate) base: alloy_primitives::Address,
    pub(crate) quote: alloy_primitives::Address,
    pub(crate) rate: alloy_primitives::U256,
    pub(crate) volume: alloy_primitives::U256,
    pub(crate) oracle_block: u64,
    pub(crate) oracle_timestamp: u64,
    pub(crate) finalized_height: u64,
    pub(crate) finalized_timestamp: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumLossPairEvidenceV1 {
    pub base: String,
    pub quote: String,
    pub last_block_before: u64,
    pub last_block_after: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumLossEvidenceV1 {
    pub stopped_validator_index: usize,
    pub finalized_height_before: u64,
    pub finalized_height_after: u64,
    pub pairs: Vec<QuorumLossPairEvidenceV1>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorPenaltyEvidenceV1 {
    pub validator_index: usize,
    pub validator_address: String,
    pub success: u64,
    pub miss: u64,
    pub abstain: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PenaltySnapshotEvidenceV1 {
    pub phase: OracleEvidencePhaseV1,
    pub validators: Vec<ValidatorPenaltyEvidenceV1>,
}

#[derive(Debug, Serialize)]
struct MockEntry<'a> {
    symbol: &'a str,
    price: &'a str,
    volume: &'a str,
}

#[derive(Debug, Serialize)]
struct MockResponse<'a> {
    data: Vec<MockEntry<'a>>,
}

fn mock_response(path: &str, symbols: &str, book: &PriceBook) -> Result<String> {
    let requested = symbols.split(',').filter(|symbol| !symbol.is_empty());
    let response = match path {
        "/api/tickers" => {
            let mut data = Vec::new();
            for symbol in requested {
                let point = book
                    .entries
                    .get(symbol)
                    .ok_or_else(|| eyre!("unsupported mock price symbol `{symbol}`"))?;
                data.push(MockEntry {
                    symbol,
                    price: &point.price,
                    volume: &point.volume,
                });
            }
            MockResponse { data }
        }
        // An empty candle set deliberately exercises the production provider's
        // documented ticker-VWAP fallback.
        "/api/candles" => {
            for symbol in requested {
                if !book.entries.contains_key(symbol) {
                    bail!("unsupported mock price symbol `{symbol}`");
                }
            }
            MockResponse { data: Vec::new() }
        }
        other => {
            bail!("unsupported mock price path `{other}`");
        }
    };
    serde_json::to_string(&response).map_err(Into::into)
}

#[derive(Debug)]
struct MockServerState {
    book: RwLock<PriceBook>,
    ticker_requests: AtomicU64,
    candle_requests: AtomicU64,
    stop: AtomicBool,
}

struct MockPriceServer {
    addr: SocketAddr,
    state: Arc<MockServerState>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for MockPriceServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MockPriceServer")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl MockPriceServer {
    fn bind(book: PriceBook) -> Result<Self> {
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).wrap_err("bind harness mock price server")?;
        listener
            .set_nonblocking(true)
            .wrap_err("set mock price server nonblocking")?;
        let addr = listener.local_addr()?;
        let state = Arc::new(MockServerState {
            book: RwLock::new(book),
            ticker_requests: AtomicU64::new(0),
            candle_requests: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        });
        let thread_state = Arc::clone(&state);
        let thread = thread::Builder::new()
            .name("e2e-price-source".into())
            .spawn(move || serve_mock_prices(listener, &thread_state))
            .wrap_err("spawn harness mock price server")?;
        Ok(Self {
            addr,
            state,
            thread: Some(thread),
        })
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn book(&self) -> PriceBook {
        self.state
            .book
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn publish(&self, symbol: &str, price: &str, volume: &str) -> Result<u64> {
        if price.is_empty() || volume.is_empty() {
            bail!("controlled price and volume must be non-empty");
        }
        let mut book = self
            .state
            .book
            .write()
            .map_err(|_| eyre!("controlled price book lock is poisoned"))?;
        let generation = book
            .generation
            .checked_add(1)
            .ok_or_else(|| eyre!("controlled price generation overflow"))?;
        let point = book
            .entries
            .get_mut(symbol)
            .ok_or_else(|| eyre!("controlled price symbol `{symbol}` is not configured"))?;
        *point = PricePoint {
            price: price.to_owned(),
            volume: volume.to_owned(),
        };
        book.generation = generation;
        Ok(generation)
    }

    fn request_counts(&self) -> (u64, u64) {
        (
            self.state.ticker_requests.load(Ordering::Relaxed),
            self.state.candle_requests.load(Ordering::Relaxed),
        )
    }

    fn stop(&mut self) {
        self.state.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for MockPriceServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn serve_mock_prices(listener: TcpListener, state: &MockServerState) {
    while !state.stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                let _ = respond_to_price_request(&mut stream, state);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

fn respond_to_price_request(stream: &mut TcpStream, state: &MockServerState) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = [0_u8; 8_192];
    let mut size = 0;
    loop {
        let read = stream.read(&mut request[size..])?;
        if read == 0 {
            break;
        }
        size += read;
        if request[..size]
            .windows(4)
            .any(|window| window == b"\r\n\r\n")
        {
            break;
        }
        eyre::ensure!(
            size < request.len(),
            "mock HTTP request headers are too large"
        );
    }
    eyre::ensure!(
        request[..size]
            .windows(4)
            .any(|window| window == b"\r\n\r\n"),
        "mock HTTP request ended before its headers"
    );
    let request =
        std::str::from_utf8(&request[..size]).wrap_err("mock HTTP request is not UTF-8")?;
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| eyre!("mock HTTP request has no target"))?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let symbols = query
        .split('&')
        .find_map(|field| field.strip_prefix("symbols="))
        .unwrap_or("");
    let book = state
        .book
        .read()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let (status, body) = match mock_response(path, symbols, &book) {
        Ok(body) => {
            match path {
                "/api/tickers" => {
                    state.ticker_requests.fetch_add(1, Ordering::Relaxed);
                }
                "/api/candles" => {
                    state.candle_requests.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
            ("200 OK", body)
        }
        Err(error) => (
            "400 Bad Request",
            serde_json::json!({ "error": error.to_string() }).to_string(),
        ),
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()?;
    Ok(())
}

#[derive(Debug)]
pub struct PriceOracleTopology {
    cfg: Config,
    mocks: BTreeMap<usize, MockPriceServer>,
    feeders: BTreeMap<usize, ChildGuard>,
    evidence: PriceOracleEvidenceV1,
}

impl PriceOracleTopology {
    pub(crate) fn install_cohort(&mut self, phase: OracleEvidencePhaseV1, cohort: OracleCohortV1) {
        self.evidence.cohorts.push(OracleCohortEvidenceV1 {
            first_process_record: self.evidence.feeder_processes.len(),
            phase,
            cohort,
            current_attempts: Vec::new(),
            observations: Vec::new(),
        });
    }

    pub(crate) fn cohort(&self) -> Result<OracleCohortV1> {
        self.evidence
            .cohorts
            .last()
            .map(|entry| entry.cohort.clone())
            .ok_or_else(|| eyre!("Oracle cohort has not been resolved"))
    }

    pub(crate) fn record_cohort_observation(&mut self, observation: serde_json::Value) {
        let process_history_len = self.evidence.feeder_processes.len();
        if let Some(entry) = self.evidence.cohorts.last_mut() {
            entry.observations.push(serde_json::json!({
                "process_history_len": process_history_len,
                "current_attempts": entry.current_attempts,
                "observation": observation,
            }));
        }
    }

    pub(crate) fn ensure_cohort_feeders_alive(&mut self) -> Result<()> {
        let cohort = self.cohort()?;
        validate_live_feeder_indices(&cohort, &self.feeders.keys().copied().collect::<Vec<_>>())?;
        self.ensure_feeder_alive()
    }

    fn refresh_cohort_attempts(&mut self) {
        let attempts = self
            .evidence
            .feeder_processes
            .iter()
            .filter(|process| process.stopped_at_millis.is_none())
            .map(|process| (process.validator_index, process.attempt, process.pid))
            .collect();
        if let Some(entry) = self.evidence.cohorts.last_mut() {
            entry.current_attempts = attempts;
        }
    }

    pub(crate) fn new(cfg: Config) -> Self {
        Self {
            cfg,
            mocks: BTreeMap::new(),
            feeders: BTreeMap::new(),
            evidence: PriceOracleEvidenceV1::default(),
        }
    }

    pub(crate) fn start(&mut self, launch: FeederLaunch<'_>, quote: PriceQuote<'_>) -> Result<()> {
        self.start_with_pairs(
            launch,
            &[FeederPair {
                base: "COEN",
                quote: "840",
                sources: vec![FeederSource {
                    base: "COEN",
                    quote: "840",
                    price: quote.price,
                    volume: quote.volume,
                }],
            }],
        )
    }

    pub(crate) fn start_with_pairs(
        &mut self,
        launch: FeederLaunch<'_>,
        pairs: &[FeederPair<'_>],
    ) -> Result<()> {
        let FeederLaunch {
            validator_index,
            rpc_url,
            chain_id,
            private_key,
            validator_address,
            vote_period,
            phase,
        } = launch;
        if self.feeders.contains_key(&validator_index) {
            bail!("validator-{validator_index} price feeder is already running");
        }
        if pairs.is_empty() || pairs.iter().any(|pair| pair.sources.is_empty()) {
            bail!("a feeder must configure at least one source for one Oracle pair");
        }
        let entries = pairs
            .iter()
            .flat_map(|pair| &pair.sources)
            .map(|source| {
                (
                    format!("{}{}", source.base, source.quote).to_ascii_uppercase(),
                    PricePoint {
                        price: source.price.to_owned(),
                        volume: source.volume.to_owned(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let expected_book = PriceBook {
            generation: 1,
            entries,
        };
        match self.mocks.entry(validator_index) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(MockPriceServer::bind(expected_book.clone())?);
            }
            std::collections::btree_map::Entry::Occupied(entry)
                if entry.get().book().entries != expected_book.entries =>
            {
                bail!("price mock generation changed during one feeder acceptance window");
            }
            std::collections::btree_map::Entry::Occupied(_) => {}
        }

        let directory = self.cfg.dir.join("price-oracle");
        fs::create_dir_all(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        let attempt = u32::try_from(
            self.evidence
                .feeder_processes
                .iter()
                .filter(|process| process.validator_index == validator_index)
                .count()
                + 1,
        )
        .map_err(|_| eyre!("validator-{validator_index} feeder attempt overflow"))?;
        let config_path = directory.join(format!(
            "validator-{validator_index}-feeder-attempt-{attempt}.toml"
        ));
        let log_path = directory.join(format!(
            "validator-{validator_index}-feeder-attempt-{attempt}.log"
        ));
        let mock_url = self
            .mocks
            .get(&validator_index)
            .expect("mock exists before feeder config")
            .base_url();
        write_feeder_config(
            &config_path,
            &FeederConfigInput {
                rpc_url,
                chain_id,
                private_key,
                validator_address,
                mock_url: &mock_url,
                vote_period,
                pairs,
            },
        )?;

        let log_start = fs::metadata(&log_path).map_or(0, |metadata| metadata.len());
        let stdout = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        let stderr = stdout.try_clone()?;
        let mut command = Command::new(&self.cfg.bin_feeder);
        command
            .arg("--config")
            .arg(&config_path)
            .current_dir(&self.cfg.repo)
            .env("RUST_LOG", "outbe_feeder=info")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let mut feeder =
            ChildGuard::spawn(format!("validator-{validator_index} price feeder"), command)?;
        let deadline = Instant::now() + FEEDER_START_TIMEOUT;
        loop {
            if feeder.exited() {
                let _ = fs::remove_file(&config_path);
                bail!(
                    "price feeder exited during startup; see {}",
                    log_path.display()
                );
            }
            let started = log_suffix_contains(&log_path, log_start, "starting outbe-feeder");
            if started {
                break;
            }
            if Instant::now() >= deadline {
                let _ = fs::remove_file(&config_path);
                bail!("price feeder did not start within {FEEDER_START_TIMEOUT:?}");
            }
            thread::sleep(Duration::from_millis(50));
        }
        fs::remove_file(&config_path).wrap_err("remove plaintext feeder config after startup")?;

        self.evidence.feeder_binary = self.cfg.bin_feeder.display().to_string();
        self.evidence.feeder_binary_sha256 = sha256_file(&self.cfg.bin_feeder)?;
        let feeder_pid = feeder.pid();
        let feeder_log = log_path.display().to_string();
        self.evidence
            .feeder_processes
            .push(FeederProcessEvidenceV1 {
                validator_index,
                validator_address: validator_address.to_owned(),
                rpc_endpoint: sanitize_rpc_endpoint(rpc_url),
                vote_period,
                attempt,
                pid: feeder_pid,
                log: feeder_log,
                started_at_millis: unix_millis(),
                stopped_at_millis: None,
                oracle_pairs: pairs
                    .iter()
                    .map(|pair| format!("{}/{}", pair.base, pair.quote))
                    .collect(),
                source_markets: pairs
                    .iter()
                    .flat_map(|pair| &pair.sources)
                    .map(|source| format!("{}:{}/{}", "mock_http", source.base, source.quote))
                    .collect(),
            });
        self.refresh_cohort_attempts();
        let generation = self
            .mocks
            .get(&validator_index)
            .expect("mock exists while recording its sources")
            .book()
            .generation;
        for pair in pairs {
            for source in &pair.sources {
                self.evidence
                    .controlled_sources
                    .push(ControlledSourceEvidenceV1 {
                        phase,
                        generation,
                        validator_index,
                        oracle_pair: format!("{}/{}", pair.base, pair.quote),
                        source_market: format!("mock_http:{}/{}", source.base, source.quote),
                        price: source.price.to_owned(),
                        volume: source.volume.to_owned(),
                    });
            }
        }
        self.feeders.insert(validator_index, feeder);
        Ok(())
    }

    pub fn stop_feeder(&mut self) {
        let stopped_at = unix_millis();
        for validator_index in self.feeders.keys().copied().collect::<Vec<_>>() {
            self.mark_latest_process_stopped(validator_index, stopped_at);
        }
        self.feeders.clear();
        self.refresh_cohort_attempts();
    }

    pub fn stop_validator_feeder(&mut self, validator_index: usize) -> Result<()> {
        self.feeders
            .remove(&validator_index)
            .ok_or_else(|| eyre!("validator-{validator_index} price feeder is not running"))?;
        self.mark_latest_process_stopped(validator_index, unix_millis());
        self.refresh_cohort_attempts();
        Ok(())
    }

    pub fn ensure_feeder_alive(&mut self) -> Result<()> {
        if self.feeders.is_empty() {
            bail!("price feeder is not running");
        }
        for (index, feeder) in &mut self.feeders {
            if feeder.exited() {
                bail!("owned price feeder {index} exited");
            }
        }
        Ok(())
    }

    pub fn is_feeder_running(&mut self) -> bool {
        !self.feeders.is_empty() && self.feeders.values_mut().all(|feeder| !feeder.exited())
    }

    pub fn last_oracle_block(&self) -> Option<u64> {
        self.evidence
            .canonical_publications
            .last()
            .map(|publication| publication.oracle_block)
    }

    pub(crate) fn read_controlled_quote(&self) -> Option<(String, String)> {
        self.mocks.values().find_map(|mock| {
            mock.book()
                .entries
                .get(COEN_USD_SYMBOL)
                .map(|point| (point.price.clone(), point.volume.clone()))
        })
    }

    pub fn publish_quote(
        &mut self,
        phase: OracleEvidencePhaseV1,
        price: &str,
        volume: &str,
    ) -> Result<u64> {
        if self.feeders.is_empty() {
            bail!("price feeder must be running before changing the controlled quote");
        }
        let mut generation = None;
        for (validator_index, mock) in &self.mocks {
            if mock.book().entries.contains_key(COEN_USD_SYMBOL) {
                let next_generation = mock.publish(COEN_USD_SYMBOL, price, volume)?;
                generation = Some(next_generation);
                self.evidence
                    .controlled_sources
                    .push(ControlledSourceEvidenceV1 {
                        phase,
                        generation: next_generation,
                        validator_index: *validator_index,
                        oracle_pair: "COEN/840".to_owned(),
                        source_market: "mock_http:COEN/840".to_owned(),
                        price: price.to_owned(),
                        volume: volume.to_owned(),
                    });
            }
        }
        generation.ok_or_else(|| eyre!("controlled COEN/840 price source is not configured"))
    }

    pub fn evidence_snapshot(&self) -> PriceOracleEvidenceV1 {
        let mut evidence = self.evidence.clone();
        for mock in self.mocks.values() {
            let (ticker_requests, candle_requests) = mock.request_counts();
            evidence.ticker_requests = evidence.ticker_requests.saturating_add(ticker_requests);
            evidence.candle_requests = evidence.candle_requests.saturating_add(candle_requests);
        }
        evidence
    }

    pub(crate) fn record_canonical_publication(
        &mut self,
        observation: CanonicalPublicationObservation,
    ) {
        let CanonicalPublicationObservation {
            phase,
            validator_count,
            base,
            quote,
            rate,
            volume,
            oracle_block,
            oracle_timestamp,
            finalized_height,
            finalized_timestamp,
        } = observation;
        self.evidence
            .canonical_publications
            .push(CanonicalPricePublicationV1 {
                phase,
                validator_count,
                base: format!("{base:#x}"),
                quote: format!("{quote:#x}"),
                rate: rate.to_string(),
                volume: volume.to_string(),
                oracle_block,
                oracle_timestamp,
                finalized_height,
                finalized_timestamp,
                age_seconds: finalized_timestamp.saturating_sub(oracle_timestamp),
            });
    }

    pub fn record_quorum_loss(&mut self, evidence: QuorumLossEvidenceV1) {
        self.evidence.quorum_loss_windows.push(evidence);
    }

    pub fn record_penalty_snapshot(&mut self, evidence: PenaltySnapshotEvidenceV1) {
        self.evidence.penalty_snapshots.push(evidence);
    }

    fn mark_latest_process_stopped(&mut self, validator_index: usize, stopped_at_millis: u64) {
        if let Some(process) = self
            .evidence
            .feeder_processes
            .iter_mut()
            .rev()
            .find(|process| {
                process.validator_index == validator_index && process.stopped_at_millis.is_none()
            })
        {
            process.stopped_at_millis = Some(stopped_at_millis);
        }
    }

    pub fn teardown(&mut self) {
        self.stop_feeder();
        self.mocks.clear();
    }
}

fn unix_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

fn sanitize_rpc_endpoint(endpoint: &str) -> String {
    let without_query = endpoint.split(['?', '#']).next().unwrap_or(endpoint);
    let Some((scheme, remainder)) = without_query.split_once("://") else {
        return "<invalid-rpc-endpoint>".to_owned();
    };
    let authority = remainder.split('/').next().unwrap_or(remainder);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    format!("{scheme}://{authority}")
}

#[cfg(feature = "ocomp-integration")]
pub(crate) fn verify_price_oracle_evidence(
    evidence: &PriceOracleEvidenceV1,
    validator_count: usize,
) -> Result<()> {
    eyre::ensure!(
        validator_count > 0,
        "Oracle validator count must be positive"
    );
    eyre::ensure!(
        Path::new(&evidence.feeder_binary)
            .file_name()
            .and_then(|name| name.to_str())
            == Some("outbe-feeder"),
        "Oracle evidence does not identify outbe-feeder"
    );
    eyre::ensure!(
        evidence.feeder_binary_sha256.len() == 64
            && hex::decode(&evidence.feeder_binary_sha256).is_ok(),
        "Oracle evidence has no exact feeder digest"
    );
    eyre::ensure!(
        evidence.ticker_requests > 0 && evidence.candle_requests > 0,
        "Oracle evidence has no provider request activity"
    );
    eyre::ensure!(
        !evidence.feeder_processes.is_empty(),
        "Oracle evidence has no feeder processes"
    );

    let mut attempts = BTreeMap::<usize, Vec<&FeederProcessEvidenceV1>>::new();
    let mut live_pids = std::collections::BTreeSet::new();
    for process in &evidence.feeder_processes {
        eyre::ensure!(
            process.validator_index < validator_count,
            "Oracle feeder references a validator outside the active set"
        );
        eyre::ensure!(
            process.vote_period > 0
                && process.pid > 0
                && process.started_at_millis > 0
                && process
                    .stopped_at_millis
                    .is_none_or(|stopped| stopped >= process.started_at_millis),
            "Oracle feeder lifecycle is malformed"
        );
        eyre::ensure!(
            process.rpc_endpoint.starts_with("http://")
                || process.rpc_endpoint.starts_with("https://"),
            "Oracle feeder RPC endpoint is malformed"
        );
        eyre::ensure!(
            !process.rpc_endpoint.contains(['@', '?', '#']),
            "Oracle feeder RPC endpoint contains credentials or query data"
        );
        eyre::ensure!(
            process.log.ends_with(&format!(
                "validator-{}-feeder-attempt-{}.log",
                process.validator_index, process.attempt
            )),
            "Oracle feeder log is not attempt-specific"
        );
        eyre::ensure!(
            !process.oracle_pairs.is_empty() && !process.source_markets.is_empty(),
            "Oracle feeder has no configured market"
        );
        if process.stopped_at_millis.is_none() {
            eyre::ensure!(
                live_pids.insert(process.pid),
                "Oracle evidence reuses one PID for multiple live feeders"
            );
        }
        attempts
            .entry(process.validator_index)
            .or_default()
            .push(process);
    }
    for (validator_index, processes) in &mut attempts {
        processes.sort_by_key(|process| process.attempt);
        for (offset, process) in processes.iter().enumerate() {
            eyre::ensure!(
                process.attempt == u32::try_from(offset + 1)?,
                "validator-{validator_index} feeder attempts are not monotonic"
            );
            eyre::ensure!(
                (offset + 1 == processes.len()) == process.stopped_at_millis.is_none(),
                "validator-{validator_index} feeder lifecycle has the wrong live attempt"
            );
        }
    }

    eyre::ensure!(
        !evidence.cohorts.is_empty(),
        "used Oracle evidence has no finalized cohort"
    );
    for (ordinal, entry) in evidence.cohorts.iter().enumerate() {
        let end = evidence
            .cohorts
            .get(ordinal + 1)
            .map_or(evidence.feeder_processes.len(), |next| {
                next.first_process_record
            });
        eyre::ensure!(
            entry.first_process_record <= end && end <= evidence.feeder_processes.len(),
            "Oracle cohort process intervals are invalid"
        );
        let mut previous = entry.first_process_record;
        for observation in &entry.observations {
            let captured: usize =
                serde_json::from_value(observation["process_history_len"].clone())?;
            eyre::ensure!(
                captured >= previous && captured <= end,
                "Oracle observation process history regressed or crossed cohorts"
            );
            previous = captured;
        }
        let cohort = &entry.cohort;
        let members = &cohort.members;
        eyre::ensure!(
            members.len() == validator_count
                && cohort.quorum == validator_count - validator_count / 3
                && cohort.checkpoint.block_hash != alloy_primitives::B256::ZERO
                && cohort.checkpoint.state_root != alloy_primitives::B256::ZERO,
            "Oracle cohort lacks canonical membership/checkpoint"
        );
        let identities = members
            .iter()
            .map(|member| member.address)
            .collect::<std::collections::BTreeSet<_>>();
        let ports = members
            .iter()
            .map(|member| member.port)
            .collect::<std::collections::BTreeSet<_>>();
        let indices = members
            .iter()
            .map(|member| member.index)
            .collect::<std::collections::BTreeSet<_>>();
        eyre::ensure!(
            identities.len() == members.len()
                && ports.len() == members.len()
                && indices.len() == members.len()
                && !identities.contains(&alloy_primitives::Address::ZERO),
            "Oracle cohort duplicates an identity or endpoint"
        );
        eyre::ensure!(
            members
                .iter()
                .all(|member| member.node_pid > 0 && member.port > 0)
                && members.windows(2).all(|pair| pair[0].index < pair[1].index),
            "Oracle cohort owners are invalid or unordered"
        );
        let selected = members
            .iter()
            .take(if cohort.overlapping_pairs {
                members.len()
            } else {
                cohort.quorum
            })
            .map(|member| member.index)
            .collect::<Vec<_>>();
        eyre::ensure!(
            cohort.feeder_indices == selected,
            "Oracle cohort has the wrong planned feeders"
        );
        for &(index, attempt, pid) in &entry.current_attempts {
            let member = members
                .iter()
                .find(|member| member.index == index)
                .ok_or_else(|| eyre!("Oracle feeder is not in its cohort"))?;
            eyre::ensure!(
                cohort.feeder_indices.contains(&index)
                    && evidence
                        .feeder_processes
                        .iter()
                        .any(|process| process.validator_index == index
                            && process.attempt == attempt
                            && process.pid == pid
                            && process
                                .validator_address
                                .parse::<alloy_primitives::Address>()
                                .ok()
                                == Some(member.address)),
                "Oracle cohort attempt has no matching public process identity"
            );
        }
    }

    eyre::ensure!(
        !evidence.controlled_sources.is_empty(),
        "Oracle evidence has no independently recorded controlled sources"
    );
    for source in &evidence.controlled_sources {
        eyre::ensure!(
            source.generation > 0
                && source.validator_index < validator_count
                && canonical_unsigned_decimal(&source.price)
                && canonical_unsigned_decimal(&source.volume)
                && !source.oracle_pair.is_empty()
                && source.source_market.starts_with("mock_http:"),
            "Oracle controlled source record is malformed"
        );
    }

    let mut publication_keys = std::collections::BTreeSet::new();
    for publication in &evidence.canonical_publications {
        eyre::ensure!(
            publication.validator_count == validator_count
                && publication
                    .rate
                    .parse::<alloy_primitives::U256>()
                    .is_ok_and(|rate| !rate.is_zero())
                && publication.volume.parse::<alloy_primitives::U256>().is_ok()
                && publication.oracle_block > 0
                && publication.oracle_block <= publication.finalized_height
                && publication.oracle_timestamp > 0
                && publication.oracle_timestamp <= publication.finalized_timestamp
                && publication.age_seconds
                    == publication
                        .finalized_timestamp
                        .saturating_sub(publication.oracle_timestamp)
                && publication.age_seconds <= 21_600,
            "Oracle publication is stale, malformed, or not finalized"
        );
        eyre::ensure!(
            publication_keys.insert((
                publication.phase,
                publication.base.as_str(),
                publication.quote.as_str(),
                publication.oracle_block,
            )),
            "Oracle evidence contains a duplicate publication"
        );
        verify_publication_cohort(evidence, publication)?;
    }
    eyre::ensure!(
        !evidence.canonical_publications.is_empty(),
        "Oracle evidence has no canonical publications"
    );

    Ok(())
}

#[cfg(any(test, feature = "ocomp-integration"))]
fn verify_publication_cohort(
    evidence: &PriceOracleEvidenceV1,
    publication: &CanonicalPricePublicationV1,
) -> Result<()> {
    let phase = serde_json::to_value(publication.phase)?;
    let mut matched = 0;
    for entry in &evidence.cohorts {
        for wrapper in &entry.observations {
            let observation = &wrapper["observation"];
            if observation["kind"].as_str() != Some("publication_verified")
                || observation["phase"] != phase
                || observation["base"].as_str() != Some(publication.base.as_str())
                || observation["quote"].as_str() != Some(publication.quote.as_str())
                || observation["oracle_block"].as_u64() != Some(publication.oracle_block)
            {
                continue;
            }
            matched += 1;
            let checkpoint: OracleCheckpointV1 =
                serde_json::from_value(observation["checkpoint"].clone())?;
            let after = observation["strictly_after_block"]
                .as_u64()
                .ok_or_else(|| eyre!("Oracle proof has no publication lower bound"))?;
            eyre::ensure!(
                checkpoint.height == publication.finalized_height
                    && checkpoint.height >= entry.cohort.checkpoint.height
                    && after >= entry.cohort.checkpoint.height
                    && checkpoint.block_hash != alloy_primitives::B256::ZERO
                    && checkpoint.state_root != alloy_primitives::B256::ZERO
                    && publication.oracle_block > after,
                "Oracle proof checkpoint/advance mismatch"
            );
            let attempts: Vec<(usize, u32, u32)> =
                serde_json::from_value(wrapper["current_attempts"].clone())?;
            let history_len: usize =
                serde_json::from_value(wrapper["process_history_len"].clone())?;
            eyre::ensure!(
                entry.first_process_record <= history_len
                    && history_len <= evidence.feeder_processes.len(),
                "Oracle proof has invalid process history bounds"
            );
            validate_live_feeder_indices(
                &entry.cohort,
                &attempts.iter().map(|attempt| attempt.0).collect::<Vec<_>>(),
            )?;
            for (index, attempt, pid) in attempts {
                let member = entry
                    .cohort
                    .members
                    .iter()
                    .find(|member| member.index == index)
                    .ok_or_else(|| eyre!("Oracle proof has an unknown feeder owner"))?;
                let (record_index, process) = evidence.feeder_processes[..history_len]
                    .iter()
                    .enumerate()
                    .rev()
                    .find(|(_, process)| process.validator_index == index)
                    .ok_or_else(|| eyre!("Oracle proof feeder has no captured launch record"))?;
                eyre::ensure!(
                    record_index >= entry.first_process_record
                        && process.attempt == attempt
                        && process.pid == pid
                        && process
                            .validator_address
                            .parse::<alloy_primitives::Address>()?
                            == member.address,
                    "Oracle proof feeder is not the captured cohort incarnation"
                );
            }
            let reads = observation["reads"]
                .as_array()
                .ok_or_else(|| eyre!("Oracle proof has no pinned peer reads"))?;
            eyre::ensure!(
                reads.len() == entry.cohort.members.len(),
                "Oracle proof omitted a cohort peer"
            );
            for (read, member) in reads.iter().zip(&entry.cohort.members) {
                let point: OracleCheckpointV1 = serde_json::from_value(read["checkpoint"].clone())?;
                let rate: alloy_primitives::U256 = serde_json::from_value(read["rate"].clone())?;
                let volume: alloy_primitives::U256 =
                    serde_json::from_value(read["volume"].clone())?;
                eyre::ensure!(
                    read["port"].as_u64() == Some(u64::from(member.port))
                        && read["finalized"]
                            .as_u64()
                            .is_some_and(|height| height >= point.height)
                        && point == checkpoint
                        && rate == publication.rate.parse::<alloy_primitives::U256>()?
                        && volume == publication.volume.parse::<alloy_primitives::U256>()?
                        && read["oracle_block"].as_u64() == Some(publication.oracle_block)
                        && read["oracle_timestamp"].as_u64() == Some(publication.oracle_timestamp)
                        && read["finalized_timestamp"].as_u64()
                            == Some(publication.finalized_timestamp),
                    "Oracle proof peer state/finality does not match publication"
                );
            }
        }
    }
    eyre::ensure!(
        matched == 1,
        "Oracle publication requires exactly one complete cohort proof"
    );
    Ok(())
}

#[cfg(feature = "ocomp-integration")]
fn canonical_unsigned_decimal(value: &str) -> bool {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    !whole.is_empty()
        && whole.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
        && value.matches('.').count() <= 1
}

fn log_suffix_contains(path: &Path, start: u64, needle: &str) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    let Ok(start) = usize::try_from(start) else {
        return false;
    };
    bytes
        .get(start..)
        .is_some_and(|suffix| String::from_utf8_lossy(suffix).contains(needle))
}

impl Drop for PriceOracleTopology {
    fn drop(&mut self) {
        self.teardown();
    }
}

struct FeederConfigInput<'a> {
    rpc_url: &'a str,
    chain_id: u64,
    private_key: &'a str,
    validator_address: &'a str,
    mock_url: &'a str,
    vote_period: u64,
    pairs: &'a [FeederPair<'a>],
}

fn write_feeder_config(path: &Path, input: &FeederConfigInput<'_>) -> Result<()> {
    let mut config = format!(
        "[chain]\nrpc_endpoint = \"{}\"\nchain_id = {}\ngasless_oracle_votes = true\n\n[account]\nprivate_key = \"{}\"\nvalidator_address = \"{}\"\n\n[oracle]\nvote_period = {}\npoll_interval_secs = 1\n\n[health]\nenabled = false\n\n[[provider_endpoints]]\nname = \"mock_http\"\nrest = \"{}\"\n",
        input.rpc_url,
        input.chain_id,
        input.private_key,
        input.validator_address,
        input.vote_period,
        input.mock_url,
    );
    for pair in input.pairs {
        config.push_str(&format!(
            "\n[[currency_pairs]]\nbase = \"{}\"\nquote = \"{}\"\n",
            pair.base, pair.quote
        ));
        for source in &pair.sources {
            config.push_str(&format!(
                "\n[[currency_pairs.sources]]\nprovider = \"mock_http\"\nbase = \"{}\"\nquote = \"{}\"\n",
                source.base, source.quote
            ));
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .wrap_err_with(|| format!("create feeder config {}", path.display()))?;
    file.write_all(config.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).wrap_err_with(|| format!("open feeder binary {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1_024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cohort_fixture(overlapping_pairs: bool) -> OracleCohortV1 {
        OracleCohortV1 {
            checkpoint: OracleCheckpointV1 {
                height: 20,
                block_hash: alloy_primitives::B256::repeat_byte(1),
                state_root: alloy_primitives::B256::repeat_byte(2),
            },
            members: (0..4)
                .map(|index| OracleMemberV1 {
                    index,
                    address: alloy_primitives::Address::repeat_byte(
                        u8::try_from(index + 1).unwrap(),
                    ),
                    port: 8000 + u16::try_from(index).unwrap(),
                    node_pid: 100 + u32::try_from(index).unwrap(),
                })
                .collect(),
            quorum: 3,
            feeder_indices: if overlapping_pairs {
                vec![0, 1, 2, 3]
            } else {
                vec![0, 1, 2]
            },
            overlapping_pairs,
        }
    }

    #[test]
    fn stopped_feeder_is_not_replenished_by_publication_checks() {
        let cohort = cohort_fixture(false);
        assert!(validate_live_feeder_indices(&cohort, &[0, 1, 2]).is_ok());
        assert!(validate_live_feeder_indices(&cohort, &[0, 1]).is_err());
        assert!(validate_live_feeder_indices(&cohort, &[0, 1, 1]).is_err());
        assert!(validate_live_feeder_indices(&cohort, &[0, 1, 3]).is_err());
        let overlap = cohort_fixture(true);
        assert!(validate_live_feeder_indices(&overlap, &[0, 1, 3]).is_ok());
        assert!(validate_live_feeder_indices(&overlap, &[0, 1, 2, 3]).is_ok());
        assert!(validate_live_feeder_indices(&overlap, &[0, 1, 4]).is_err());
    }

    #[test]
    fn public_cohort_retains_partial_observations_and_exact_attempts() {
        let evidence = OracleCohortEvidenceV1 {
            first_process_record: 3,
            phase: OracleEvidencePhaseV1::ClockRestart,
            cohort: cohort_fixture(false),
            current_attempts: vec![(0, 2, 101), (1, 2, 102)],
            observations: vec![serde_json::json!({"kind": "publication_error", "port": 8002})],
        };
        let encoded = serde_json::to_value(&evidence).unwrap();
        assert_eq!(
            serde_json::from_value::<OracleCohortEvidenceV1>(encoded).unwrap(),
            evidence
        );
        assert_eq!(evidence.current_attempts.len(), 2); // incomplete launch is retained, not fabricated as quorum
    }

    #[test]
    fn evidence_requires_the_mandatory_cohort_field() {
        let mut encoded = serde_json::to_value(PriceOracleEvidenceV1::default()).unwrap();
        assert_eq!(encoded["cohorts"], serde_json::json!([]));
        encoded.as_object_mut().unwrap().remove("cohorts");
        assert!(serde_json::from_value::<PriceOracleEvidenceV1>(encoded).is_err());
    }

    #[test]
    fn publication_proof_requires_cohort_attempts_and_every_pinned_peer() {
        let cohort = cohort_fixture(false);
        let publication = CanonicalPricePublicationV1 {
            phase: OracleEvidencePhaseV1::Initial,
            validator_count: 4,
            base: format!("{:#x}", alloy_primitives::Address::ZERO),
            quote: format!("{:#x}", alloy_primitives::Address::repeat_byte(9)),
            rate: "1000000".into(),
            volume: "3000000000".into(),
            oracle_block: 21,
            oracle_timestamp: 100,
            finalized_height: 22,
            finalized_timestamp: 102,
            age_seconds: 2,
        };
        let checkpoint = OracleCheckpointV1 {
            height: 22,
            ..cohort.checkpoint.clone()
        };
        let processes = cohort
            .members
            .iter()
            .take(3)
            .map(|member| FeederProcessEvidenceV1 {
                validator_index: member.index,
                validator_address: format!("{:#x}", member.address),
                rpc_endpoint: format!("http://127.0.0.1:{}", member.port),
                vote_period: crate::internal::config::E2E_ORACLE_VOTE_PERIOD_BLOCKS,
                attempt: 1,
                pid: 1000 + u32::try_from(member.index).unwrap(),
                log: format!("validator-{}-feeder-attempt-1.log", member.index),
                started_at_millis: 1,
                stopped_at_millis: None,
                oracle_pairs: vec!["COEN/840".into()],
                source_markets: vec!["mock_http:COEN/840".into()],
            })
            .collect::<Vec<_>>();
        let attempts = processes
            .iter()
            .map(|process| (process.validator_index, process.attempt, process.pid))
            .collect::<Vec<_>>();
        let reads = cohort.members.iter().map(|member| serde_json::json!({
            "port": member.port, "finalized": 22, "checkpoint": checkpoint,
            "rate": alloy_primitives::U256::from(1_000_000), "volume": alloy_primitives::U256::from(3_000_000_000u64),
            "oracle_block": 21, "oracle_timestamp": 100, "finalized_timestamp": 102,
        })).collect::<Vec<_>>();
        let proof = serde_json::json!({
            "process_history_len": 3,
            "current_attempts": attempts,
            "observation": {"kind": "publication_verified", "phase": publication.phase,
                "base": publication.base, "quote": publication.quote, "oracle_block": 21,
                "strictly_after_block": 20, "checkpoint": checkpoint, "reads": reads},
        });
        let evidence = PriceOracleEvidenceV1 {
            feeder_processes: processes,
            cohorts: vec![OracleCohortEvidenceV1 {
                first_process_record: 0,
                phase: OracleEvidencePhaseV1::Initial,
                cohort,
                current_attempts: attempts,
                observations: vec![proof.clone()],
            }],
            ..PriceOracleEvidenceV1::default()
        };
        assert!(verify_publication_cohort(&evidence, &publication).is_ok());
        for field in 0..12 {
            let mut bad = evidence.clone();
            match field {
                0 => bad.cohorts.clear(),
                1 => bad.cohorts[0].observations.clear(),
                2 => bad.cohorts[0].observations.push(proof.clone()),
                3 => {
                    bad.cohorts[0].observations[0]["observation"]["reads"]
                        .as_array_mut()
                        .unwrap()
                        .pop();
                }
                4 => {
                    bad.cohorts[0].observations[0]["observation"]["reads"][3]["finalized"] =
                        serde_json::json!(21)
                }
                5 => bad.cohorts[0].observations[0]["current_attempts"] = serde_json::json!([]),
                6 => {
                    bad.cohorts[0].observations[0]["observation"]["strictly_after_block"] =
                        serde_json::json!(21)
                }
                7 => {
                    bad.cohorts[0].observations[0]["observation"]["reads"][3]["checkpoint"]
                        ["state_root"] = serde_json::json!(alloy_primitives::B256::ZERO)
                }
                8 => {
                    bad.cohorts[0].observations[0]["observation"]["strictly_after_block"] =
                        serde_json::json!(19)
                }
                9 => {
                    bad.cohorts[0].observations[0]
                        .as_object_mut()
                        .unwrap()
                        .remove("process_history_len");
                }
                10 => bad.cohorts[0].observations[0]["process_history_len"] = serde_json::json!(4),
                _ => bad.cohorts[0].first_process_record = 1,
            }
            assert!(
                verify_publication_cohort(&bad, &publication).is_err(),
                "field {field}"
            );
        }
        let mut restarted = evidence.clone();
        let mut next = restarted.feeder_processes[0].clone();
        next.attempt = 2;
        next.pid += 100;
        restarted.feeder_processes[0].stopped_at_millis = Some(2);
        restarted.feeder_processes.push(next);
        // Later teardown/appends cannot invalidate an earlier capture.
        assert!(verify_publication_cohort(&restarted, &publication).is_ok());
        restarted.cohorts[0].observations[0]["process_history_len"] = serde_json::json!(4);
        // A later capture cannot claim that the previous incarnation is current.
        assert!(verify_publication_cohort(&restarted, &publication).is_err());
        restarted.cohorts[0].observations[0]["current_attempts"][0] =
            serde_json::json!([0, 2, 1100]);
        assert!(verify_publication_cohort(&restarted, &publication).is_ok());
        restarted.cohorts[0].observations[0]["process_history_len"] = serde_json::json!(3);
        assert!(verify_publication_cohort(&restarted, &publication).is_err());
    }

    fn coen_book(generation: u64, price: &str, volume: &str) -> PriceBook {
        PriceBook {
            generation,
            entries: BTreeMap::from([(
                COEN_USD_SYMBOL.to_owned(),
                PricePoint {
                    price: price.to_owned(),
                    volume: volume.to_owned(),
                },
            )]),
        }
    }

    #[test]
    fn mock_http_wire_is_exact_and_generation_owned() {
        let mut book = coen_book(7, "1.000000", "1000.000000");
        book.entries.insert(
            "COENUSDC".into(),
            PricePoint {
                price: "1.000001".into(),
                volume: "500.000000".into(),
            },
        );

        assert_eq!(
            mock_response("/api/tickers", COEN_USD_SYMBOL, &book).unwrap(),
            r#"{"data":[{"symbol":"COEN840","price":"1.000000","volume":"1000.000000"}]}"#
        );
        assert_eq!(
            mock_response("/api/candles", COEN_USD_SYMBOL, &book).unwrap(),
            r#"{"data":[]}"#
        );
        assert_eq!(
            mock_response("/api/tickers", "COEN840,COENUSDC", &book).unwrap(),
            r#"{"data":[{"symbol":"COEN840","price":"1.000000","volume":"1000.000000"},{"symbol":"COENUSDC","price":"1.000001","volume":"500.000000"}]}"#
        );
        assert!(mock_response("/api/tickers", "COEN978", &book).is_err());
        assert!(mock_response("/unknown", COEN_USD_SYMBOL, &book).is_err());
        assert_eq!(book.generation, 7);
    }

    #[test]
    fn feeder_config_is_private_and_contains_only_the_frozen_interface() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("feeder.toml");
        let pairs = [FeederPair {
            base: "COEN",
            quote: "840",
            sources: vec![
                FeederSource {
                    base: "COEN",
                    quote: "USDT",
                    price: "1",
                    volume: "2",
                },
                FeederSource {
                    base: "COEN",
                    quote: "USDC",
                    price: "1",
                    volume: "3",
                },
            ],
        }];
        write_feeder_config(
            &path,
            &FeederConfigInput {
                rpc_url: "http://127.0.0.1:18545",
                chain_id: 54_322_345,
                private_key: "0xsecret",
                validator_address: "0x0000000000000000000000000000000000000001",
                mock_url: "http://127.0.0.1:31415",
                vote_period: 8,
                pairs: &pairs,
            },
        )
        .unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("vote_period = 8"));
        assert!(contents.contains("poll_interval_secs = 1"));
        assert!(contents.contains("gasless_oracle_votes = true"));
        assert!(contents.contains("enabled = false"));
        assert!(contents.contains("[[currency_pairs.sources]]"));
        assert!(contents.contains("quote = \"USDT\""));
        assert!(contents.contains("quote = \"USDC\""));
        assert!(!contents.contains("providers ="));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn feeder_restart_does_not_accept_the_previous_log_episodes_start_marker() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("feeder.log");
        fs::write(&path, "starting outbe-feeder\nold episode stopped\n").unwrap();
        let next_episode = fs::metadata(&path).unwrap().len();

        assert!(!log_suffix_contains(
            &path,
            next_episode,
            "starting outbe-feeder"
        ));
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"starting outbe-feeder\n")
            .unwrap();
        assert!(log_suffix_contains(
            &path,
            next_episode,
            "starting outbe-feeder"
        ));
    }

    #[test]
    fn retained_rpc_endpoint_omits_credentials_path_query_and_fragment() {
        assert_eq!(
            sanitize_rpc_endpoint("https://user:pass@rpc.example/v3/secret?key=hidden#fragment"),
            "https://rpc.example"
        );
    }

    #[test]
    fn bound_mock_server_serves_ticker_and_empty_candle_fallback() {
        let mut server = match MockPriceServer::bind(coen_book(3, "1.250000", "4.000000")) {
            Ok(server) => server,
            Err(error) if bind_permission_denied(&error) => return,
            Err(error) => panic!("bind mock server: {error:#}"),
        };
        let ticker = raw_get(server.addr, "/api/tickers?symbols=COEN840");
        assert!(ticker.contains("200 OK"));
        assert!(ticker
            .contains(r#"{"data":[{"symbol":"COEN840","price":"1.250000","volume":"4.000000"}]}"#));
        let candles = raw_get(server.addr, "/api/candles?symbols=COEN840");
        assert!(candles.contains(r#"{"data":[]}"#));
        assert_eq!(server.request_counts(), (1, 1));
        server.stop();
    }

    #[test]
    fn bound_mock_server_publishes_one_atomic_new_price_generation() {
        let mut server = match MockPriceServer::bind(coen_book(3, "1.000000", "4.000000")) {
            Ok(server) => server,
            Err(error) if bind_permission_denied(&error) => return,
            Err(error) => panic!("bind mock server: {error:#}"),
        };

        let generation = server
            .publish(COEN_USD_SYMBOL, "1.080001", "4.000000")
            .expect("publish controlled qualification quote");
        assert_eq!(generation, 4);
        assert_eq!(server.book(), coen_book(4, "1.080001", "4.000000"));
        let ticker = raw_get(server.addr, "/api/tickers?symbols=COEN840");
        assert!(
            ticker.contains(
                r#"{"data":[{"symbol":"COEN840","price":"1.080001","volume":"4.000000"}]}"#
            ),
            "unexpected ticker response: {ticker:?}"
        );
        server.stop();
    }

    fn bind_permission_denied(error: &eyre::Report) -> bool {
        error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
        })
    }

    fn raw_get(addr: SocketAddr, target: &str) -> String {
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(
            stream,
            "GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = Vec::new();
        let mut buffer = [0_u8; 4_096];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => response.extend_from_slice(&buffer[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("read mock response: {error}"),
            }
        }
        String::from_utf8(response).unwrap()
    }
}
