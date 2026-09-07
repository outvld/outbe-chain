//! Per-node port allocation for the localnet.
//!
//! Every node owns one **contiguous legacy block** of chain/OCOMP ports plus a
//! separate two-port Radicle block. Keeping the allocators separate prevents a
//! new sidecar from renumbering consensus ports embedded in existing fixtures.
//!
//! ```text
//! OCOMP reserves six consecutive TCP slots at the end of each node block:
//! Supervisor registration, Supervisor ZeroMQ, and four Worker observability ports.
//! ```
//!
//! Blocks are handed out from a cursor that only ever moves forward, so they are
//! disjoint by construction and no two services can collide. A node index the
//! harness has never seen - the joiner at `i = committee size`, the followers at
//! their high slots - simply takes the next block on first use, so the committee
//! size need not be known up front.
//!
//! A block is *scanned* for by default: the cursor walks forward until it finds
//! [`BLOCK`] consecutive ports the OS reports free. The window slides as a unit,
//! so a block stays contiguous. `--no-resolve-ports` skips the scan and takes the
//! cursor's block verbatim.
//!
//! A block's ports follow from *allocation order*, not from the node index - so a
//! node whose first candidate port is busy shifts only itself, never the nodes
//! allocated after it.
//!
//! [`Ports::start_scenario`] forgets the node->block map but leaves the cursor
//! alone, so each scenario's nodes land above the previous scenario's. A port is
//! never reused within a process, which keeps a torn-down node's lingering socket
//! (or a peer still dialing it) from bleeding into the next scenario.
//!
//! The committee's consensus/p2p ports are baked into `validators.json`/genesis at
//! bootstrap, so blocks `0..n` are allocated at the scenario's start and reused
//! unchanged at launch. The cursor never rewinds, so a later block can't alias a
//! genesis-baked one.

use std::collections::HashMap;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex, MutexGuard};

use eyre::{bail, Result, WrapErr};

/// First port the allocator considers.
pub(crate) const NODE_BASE: u16 = 18545;

/// Which transport(s) a service needs free for the probe to consider a port open.
#[derive(Clone, Copy)]
enum Proto {
    Tcp,
    Udp,
    /// reth `--port` binds RLPx (TCP) and discv4 (UDP) on the same number.
    TcpUdp,
}

/// A service occupying one slot of a node's port block.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Service {
    Http,
    Tee,
    P2p,
    Discv5,
    Authrpc,
    Metrics,
    Consensus,
    Radicle,
    RadicleStatus,
    OcompSupervisor,
    OcompMessage,
    OcompWorker0,
    OcompWorker1,
    OcompWorker2,
    OcompWorker3,
    OcompSuccessorSupervisor,
    OcompSuccessorMessage,
    OcompSuccessorWorker0,
    OcompSuccessorWorker1,
    OcompSuccessorWorker2,
    OcompSuccessorWorker3,
    OcompSnapshotExporter,
}

impl Service {
    /// Every service known to collision and preflight checks.
    #[cfg(test)]
    const ALL: [Service; 22] = [
        Self::Http,
        Self::Tee,
        Self::P2p,
        Self::Discv5,
        Self::Authrpc,
        Self::Metrics,
        Self::Consensus,
        Self::OcompSupervisor,
        Self::OcompMessage,
        Self::OcompWorker0,
        Self::OcompWorker1,
        Self::OcompWorker2,
        Self::OcompWorker3,
        Self::OcompSuccessorSupervisor,
        Self::OcompSuccessorMessage,
        Self::OcompSuccessorWorker0,
        Self::OcompSuccessorWorker1,
        Self::OcompSuccessorWorker2,
        Self::OcompSuccessorWorker3,
        Self::OcompSnapshotExporter,
        Self::Radicle,
        Self::RadicleStatus,
    ];

    /// Complete chain/OCOMP runtime block. Derived OCOMP listeners must have an
    /// explicit slot here so allocation and preflight cannot miss them.
    const CORE: [Service; 20] = [
        Self::Http,
        Self::Tee,
        Self::P2p,
        Self::Discv5,
        Self::Authrpc,
        Self::Metrics,
        Self::Consensus,
        Self::OcompSupervisor,
        Self::OcompMessage,
        Self::OcompWorker0,
        Self::OcompWorker1,
        Self::OcompWorker2,
        Self::OcompWorker3,
        Self::OcompSuccessorSupervisor,
        Self::OcompSuccessorMessage,
        Self::OcompSuccessorWorker0,
        Self::OcompSuccessorWorker1,
        Self::OcompSuccessorWorker2,
        Self::OcompSuccessorWorker3,
        Self::OcompSnapshotExporter,
    ];

    const RADICLE: [Service; 2] = [Self::Radicle, Self::RadicleStatus];

    fn is_radicle(self) -> bool {
        matches!(self, Self::Radicle | Self::RadicleStatus)
    }

    /// This service's slot within a node's block.
    fn offset(self) -> u16 {
        match self {
            Self::Http => 0,
            Self::Tee => 1,
            Self::P2p => 2,
            Self::Discv5 => 3,
            Self::Authrpc => 4,
            Self::Metrics => 5,
            Self::Consensus => 6,
            Self::OcompSupervisor => 7,
            Self::OcompMessage => 8,
            Self::OcompWorker0 => 9,
            Self::OcompWorker1 => 10,
            Self::OcompWorker2 => 11,
            Self::OcompWorker3 => 12,
            Self::OcompSuccessorSupervisor => 13,
            Self::OcompSuccessorMessage => 14,
            Self::OcompSuccessorWorker0 => 15,
            Self::OcompSuccessorWorker1 => 16,
            Self::OcompSuccessorWorker2 => 17,
            Self::OcompSuccessorWorker3 => 18,
            Self::OcompSnapshotExporter => 19,
            Self::Radicle => 0,
            Self::RadicleStatus => 1,
        }
    }

    fn proto(self) -> Proto {
        match self {
            Self::P2p => Proto::TcpUdp,
            Self::Discv5 => Proto::Udp,
            _ => Proto::Tcp,
        }
    }
}

/// Ports per node block.
// Keep the established 21-port stride so removing an obsolete listener does
// not renumber the consensus ports baked into canonical fixtures.
const BLOCK: u16 = 21;
const RADICLE_BLOCK: u16 = Service::RADICLE.len() as u16;
// macOS reserves 49152..=65535 for ephemeral sockets, leaving no space above
// it; start Radicle below that interval. Linux starts at 50000 and skips its
// kernel-reported ephemeral interval to 61000 on the default configuration.
#[cfg(target_os = "macos")]
const RADICLE_BASE: u16 = 40_000;
#[cfg(not(target_os = "macos"))]
const RADICLE_BASE: u16 = 50_000;

/// Port allocator shared by every [`Config`](crate::internal::config::Config)
/// clone of a run.
///
/// The clones are not independent: `World::default()` hands one `Config` to each
/// of `Localnet`, `Rpc`, and `Validators`, and a block allocated through one must
/// look the same through the others. Hence the shared, interior-mutable resolver.
#[derive(Clone, Debug)]
pub(crate) struct Ports {
    inner: Arc<Mutex<Resolver>>,
}

#[derive(Debug)]
struct Resolver {
    /// Node index -> first port of its block.
    blocks: HashMap<usize, u16>,
    /// Node index -> first port of its separate Radicle block.
    radicle_blocks: HashMap<usize, u16>,
    /// Lowest port not yet handed out. Only ever moves forward.
    cursor: u64,
    /// Lowest Radicle port not yet handed out.
    radicle_cursor: u64,
    /// All issued spans, including earlier scenarios whose sockets may linger.
    issued: Vec<(u16, u16)>,
    /// Probe the OS for a free window, rather than taking the cursor verbatim.
    scan: bool,
}

impl Ports {
    /// An allocator with nothing handed out yet, its cursor at [`NODE_BASE`].
    ///
    /// `scan` probes the OS for each free window (the default); `--no-resolve-ports`
    /// turns it off, yielding the static `NODE_BASE + i * BLOCK` layout.
    pub fn new(scan: bool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Resolver {
                blocks: HashMap::new(),
                radicle_blocks: HashMap::new(),
                cursor: u64::from(NODE_BASE),
                radicle_cursor: u64::from(RADICLE_BASE),
                issued: Vec::new(),
                scan,
            })),
        }
    }

    /// Reconstruct a previously resolved validator->service layout.
    ///
    /// The order is validator order. Each entry is the first port of that
    /// validator's complete [`BLOCK`]-wide service block.
    pub(crate) fn from_block_starts(starts: &[u16]) -> Result<Self> {
        for (index, &start) in starts.iter().enumerate() {
            fits(u64::from(start))?;
            let end = start + (BLOCK - 1);
            for (previous_index, &previous) in starts[..index].iter().enumerate() {
                let previous_end = previous + (BLOCK - 1);
                if start <= previous_end && previous <= end {
                    bail!(
                        "persisted validator-{index} port block {start}..={end} overlaps validator-{previous_index} block {previous}..={previous_end}"
                    );
                }
            }
        }
        let cursor = starts
            .iter()
            .copied()
            .max()
            .map_or(u64::from(NODE_BASE), |start| {
                u64::from(start) + u64::from(BLOCK)
            });
        Ok(Self {
            inner: Arc::new(Mutex::new(Resolver {
                blocks: starts.iter().copied().enumerate().collect(),
                radicle_blocks: HashMap::new(),
                cursor,
                radicle_cursor: u64::from(RADICLE_BASE),
                issued: starts
                    .iter()
                    .map(|&start| (start, start + (BLOCK - 1)))
                    .collect(),
                // Only CORE spans were persisted. Fresh sidecar/joiner ports
                // still need the normal OS collision and ephemeral checks.
                scan: true,
            })),
        })
    }

    /// Begin a scenario: forget the previous one's node->block map, then allocate
    /// the committee's blocks (`0..n`) so their consensus/p2p ports are fixed
    /// before bootstrap bakes them into genesis.
    ///
    /// The cursor is untouched, so this scenario's blocks sit above the last one's
    /// and no port is reused within the process.
    pub fn start_scenario(&self, n: usize) -> Result<()> {
        let mut r = lock(&self.inner);
        r.blocks.clear();
        r.radicle_blocks.clear();
        (0..n).try_for_each(|i| r.block_start(i).map(drop))
    }

    /// Return the complete ordered block layout for durable handoff to another
    /// harness process, allocating any missing committee blocks first.
    pub(crate) fn block_starts(&self, nodes: usize) -> Result<Vec<u16>> {
        let mut resolver = lock(&self.inner);
        (0..nodes)
            .map(|index| resolver.block_start(index))
            .collect()
    }

    /// The port node `i` uses for `svc`, allocating its block on first use.
    ///
    /// Panics only when the port space above the cursor is exhausted - an
    /// unrecoverable property of the machine, not of the caller.
    pub(crate) fn port(&self, svc: Service, i: usize) -> u16 {
        let mut resolver = lock(&self.inner);
        let start = if svc.is_radicle() {
            resolver.radicle_block_start(i)
        } else {
            resolver.block_start(i)
        }
        .unwrap_or_else(|e| panic!("e2e ports: {e}"));
        start + svc.offset()
    }

    /// Prove that every configured service port for `0..nodes` is still free.
    ///
    /// Persistent LocalNet restores bootstrap's resolved layout so genesis and
    /// the later owner process use identical ports. This preflight prevents an
    /// old or unrelated process from being mistaken for a newly owned node.
    #[cfg_attr(not(feature = "ocomp-integration"), allow(dead_code))]
    pub(crate) fn ensure_available(&self, nodes: usize) -> Result<()> {
        let mut resolver = lock(&self.inner);
        for index in 0..nodes {
            let start = resolver.block_start(index)?;
            for service in Service::CORE {
                let port = start + service.offset();
                if !is_free(port, service.proto()) {
                    bail!(
                        "LocalNet port preflight failed: validator-{index} {service:?} port {port} is already in use"
                    );
                }
            }
            let start = resolver.radicle_block_start(index)?;
            for service in Service::RADICLE {
                let port = start + service.offset();
                if !is_free(port, service.proto()) {
                    bail!(
                        "LocalNet port preflight failed: validator-{index} {service:?} port {port} is already in use"
                    );
                }
            }
        }
        Ok(())
    }
}

/// Lock the resolver, recovering from a poisoned mutex.
///
/// The resolver outlives any one scenario, so a panic in one (cucumber catches
/// them and moves on) must not brick every later scenario's port lookups.
fn lock(inner: &Mutex<Resolver>) -> MutexGuard<'_, Resolver> {
    inner.lock().unwrap_or_else(|e| e.into_inner())
}

impl Resolver {
    /// First port of node `i`'s block - the one already allocated, or the next.
    fn block_start(&mut self, i: usize) -> Result<u16> {
        if let Some(&start) = self.blocks.get(&i) {
            return Ok(start);
        }
        let start = self.alloc()?;
        self.blocks.insert(i, start);
        Ok(start)
    }

    fn radicle_block_start(&mut self, i: usize) -> Result<u16> {
        if let Some(&start) = self.radicle_blocks.get(&i) {
            return Ok(start);
        }
        let start = self.alloc_radicle()?;
        self.radicle_blocks.insert(i, start);
        Ok(start)
    }

    /// Take the next block at or above the cursor, and advance the cursor past it.
    fn alloc(&mut self) -> Result<u16> {
        let mut candidate = self.cursor;
        loop {
            let start = fits(candidate)?;
            if !self.overlaps_issued(start, BLOCK) && (!self.scan || window_free(start)) {
                self.cursor = u64::from(start) + u64::from(BLOCK);
                self.issued.push((start, start + (BLOCK - 1)));
                return Ok(start);
            }
            candidate = u64::from(start) + 1;
        }
    }

    fn alloc_radicle(&mut self) -> Result<u16> {
        let ephemeral = if self.scan {
            Some(ephemeral_port_range()?)
        } else {
            None
        };
        self.alloc_radicle_avoiding(ephemeral)
    }

    fn alloc_radicle_avoiding(&mut self, ephemeral: Option<(u16, u16)>) -> Result<u16> {
        let mut candidate = self.radicle_cursor;
        loop {
            let start = fits_width(candidate, RADICLE_BLOCK)?;
            if let Some((low, high)) = ephemeral {
                if ranges_overlap((start, start + (RADICLE_BLOCK - 1)), (low, high)) {
                    candidate = u64::from(high) + 1;
                    continue;
                }
            }
            if !self.overlaps_issued(start, RADICLE_BLOCK)
                && (!self.scan || radicle_window_free(start))
            {
                self.radicle_cursor = u64::from(start) + u64::from(RADICLE_BLOCK);
                self.issued.push((start, start + (RADICLE_BLOCK - 1)));
                return Ok(start);
            }
            candidate = u64::from(start) + 1;
        }
    }

    fn overlaps_issued(&self, start: u16, width: u16) -> bool {
        self.issued
            .iter()
            .any(|&span| ranges_overlap((start, start + (width - 1)), span))
    }
}

fn ranges_overlap(left: (u16, u16), right: (u16, u16)) -> bool {
    left.0 <= right.1 && right.0 <= left.1
}

#[cfg(target_os = "linux")]
fn ephemeral_port_range() -> Result<(u16, u16)> {
    let path = "/proc/sys/net/ipv4/ip_local_port_range";
    let value = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("read {path} for Radicle port allocation"))?;
    parse_ephemeral_port_range(&value).wrap_err_with(|| format!("parse {path}"))
}

#[cfg(target_os = "macos")]
fn ephemeral_port_range() -> Result<(u16, u16)> {
    let output = std::process::Command::new("sysctl")
        .args([
            "-n",
            "net.inet.ip.portrange.first",
            "net.inet.ip.portrange.last",
        ])
        .output()
        .wrap_err("read macOS ephemeral port range for Radicle port allocation")?;
    if !output.status.success() {
        bail!(
            "read macOS ephemeral port range for Radicle port allocation: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let value =
        std::str::from_utf8(&output.stdout).wrap_err("macOS ephemeral port range is not UTF-8")?;
    parse_ephemeral_port_range(value).wrap_err("parse macOS ephemeral port range")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn ephemeral_port_range() -> Result<(u16, u16)> {
    bail!("ephemeral port range discovery is unsupported on this operating system")
}

fn parse_ephemeral_port_range(value: &str) -> Result<(u16, u16)> {
    let ports = value
        .split_whitespace()
        .map(str::parse::<u16>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let [low, high] = ports.as_slice() else {
        bail!("ephemeral port range must contain exactly two ports");
    };
    if *low == 0 || low > high {
        bail!("invalid ephemeral port range {low}..={high}");
    }
    Ok((*low, *high))
}

/// `start` as a `u16`, once we know a whole block fits at or above it.
fn fits(start: u64) -> Result<u16> {
    fits_width(start, BLOCK)
}

fn fits_width(start: u64, width: u16) -> Result<u16> {
    if start + u64::from(width) - 1 > u64::from(u16::MAX) {
        bail!("no free {width}-port block at or above {start}");
    }
    Ok(start as u16)
}

/// Whether every port of the block starting at `start` is bindable.
fn window_free(start: u16) -> bool {
    Service::CORE
        .iter()
        .all(|svc| is_free(start + svc.offset(), svc.proto()))
}

fn radicle_window_free(start: u16) -> bool {
    Service::RADICLE
        .iter()
        .all(|svc| is_free(start + svc.offset(), svc.proto()))
}

/// Whether `port` is bindable on loopback for the required transport(s).
///
/// A bind probe alone is not enough for TCP: nodes bind their service ports on
/// the wildcard address, and BSD `SO_REUSEADDR` semantics let a later
/// loopback-specific bind succeed over a live `0.0.0.0` listener. Ask for a
/// connection first - an answer proves somebody owns the port whatever address
/// they bound - and only then try to bind, so the probe's own listener can
/// never answer its own connect.
fn is_free(port: u16, proto: Proto) -> bool {
    let tcp = || {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return false;
        }
        TcpListener::bind(("127.0.0.1", port)).is_ok()
    };
    let udp = || UdpSocket::bind(("127.0.0.1", port)).is_ok();
    match proto {
        Proto::Tcp => tcp(),
        Proto::Udp => udp(),
        Proto::TcpUdp => tcp() && udp(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::Path;

    use super::Service::*;
    use super::*;

    /// One scenario's worth of the static layout: no probing, block `i` at
    /// `NODE_BASE + i * BLOCK`.
    fn static_ports(n: usize) -> Ports {
        let p = Ports::new(false);
        p.start_scenario(n)
            .expect("static layout cannot exhaust the port space");
        p
    }

    #[test]
    fn unscanned_layout_is_block_per_node() {
        let p = static_ports(3);
        assert_eq!(p.port(Http, 0), 18545);
        assert_eq!(p.port(Tee, 0), 18546);
        assert_eq!(p.port(Consensus, 0), 18551);
        assert_eq!(p.port(OcompSupervisor, 0), 18552);
        assert_eq!(p.port(OcompSnapshotExporter, 0), 18564);
        assert_eq!(p.port(Radicle, 0), RADICLE_BASE);
        assert_eq!(p.port(RadicleStatus, 0), RADICLE_BASE + 1);
        assert_eq!(p.port(Http, 1), NODE_BASE + BLOCK);
        assert_eq!(p.port(Tee, 1), NODE_BASE + BLOCK + 1);
        assert_eq!(p.port(Radicle, 1), RADICLE_BASE + RADICLE_BLOCK);
    }

    #[test]
    fn ocomp_derived_listeners_are_inside_each_disjoint_node_block() {
        let p = static_ports(4);
        for index in 0..4 {
            let supervisor = p.port(OcompSupervisor, index);
            assert_eq!(p.port(OcompMessage, index), supervisor + 1);
            assert_eq!(p.port(OcompWorker0, index), supervisor + 2);
            assert_eq!(p.port(OcompWorker3, index), supervisor + 5);
            assert_eq!(p.port(OcompSuccessorSupervisor, index), supervisor + 6);
            assert_eq!(p.port(OcompSuccessorMessage, index), supervisor + 7);
            assert_eq!(p.port(OcompSuccessorWorker0, index), supervisor + 8);
            assert_eq!(p.port(OcompSuccessorWorker3, index), supervisor + 11);
            assert_eq!(p.port(OcompSnapshotExporter, index), supervisor + 12);
        }
    }

    #[test]
    fn canonical_ocomp_fixture_uses_the_current_static_consensus_ports() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/ocomp-final-v1/base/validators.json");
        let validators: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture).expect("canonical validators fixture"))
                .expect("canonical validators JSON");
        let validators = validators.as_array().expect("validators array");
        let ports = static_ports(validators.len());

        for (index, validator) in validators.iter().enumerate() {
            let address = validator["p2p_address"]
                .as_str()
                .expect("validator p2p_address");
            let fixture_port = address
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse::<u16>().ok())
                .expect("validator p2p port");
            assert_eq!(
                fixture_port,
                ports.port(Consensus, index),
                "canonical validator-{index} consensus port drifted from the harness layout"
            );
        }
    }

    /// The reported bug: a node index past the committee used to panic. Blocks
    /// follow allocation order, so the joiner and followers take the next ones.
    #[test]
    fn grown_index_does_not_panic() {
        let p = static_ports(4);
        assert_eq!(p.port(Http, 4), NODE_BASE + 4 * BLOCK, "joiner");
        assert_eq!(p.port(Http, 14), NODE_BASE + 5 * BLOCK, "follower1");
        assert_eq!(p.port(Tee, 15), NODE_BASE + 6 * BLOCK + 1, "follower2");
    }

    /// A scenario never lands on a port the previous one used, however many nodes
    /// that one grew.
    #[test]
    fn scenarios_never_reuse_ports() {
        let p = static_ports(2);
        let first: HashSet<u16> = [0, 1, 2, 14]
            .iter()
            .flat_map(|&i| Service::ALL.map(|svc| p.port(svc, i)))
            .collect();

        p.start_scenario(2).expect("second scenario");
        for i in [0, 1, 2, 14] {
            for svc in Service::ALL {
                assert!(
                    !first.contains(&p.port(svc, i)),
                    "{svc:?} of node {i} reuses a port from the previous scenario"
                );
            }
        }
    }

    /// Guards the old layout's http[6] == authrpc[0] == 8551 collision.
    #[test]
    fn blocks_are_disjoint() {
        let p = static_ports(4);
        let nodes = [0, 1, 2, 3, 4, 14, 15];
        let mut seen = HashSet::new();
        for i in nodes {
            for svc in Service::ALL {
                assert!(seen.insert(p.port(svc, i)), "{svc:?} of node {i} collides");
            }
        }
        assert_eq!(seen.len(), nodes.len() * Service::ALL.len());
    }

    /// Every `Config` clone must see the same lazily-allocated block.
    #[test]
    fn clones_share_growth() {
        let a = static_ports(1);
        let b = a.clone();
        assert_eq!(a.port(Http, 20), b.port(Http, 20));
        // A block first allocated through `b` is visible through `a`.
        let via_b = b.port(Http, 21);
        assert_eq!(lock(&a.inner).blocks.get(&21).copied(), Some(via_b));
    }

    #[test]
    fn port_is_memoized() {
        // Memoization is independent of OS socket probing. Keep this unit test
        // deterministic in restricted sandboxes where loopback bind is denied;
        // `scan_shifts_whole_block_past_a_held_port` owns scan behavior.
        let p = Ports::new(false);
        p.start_scenario(1).expect("static allocation");
        assert_eq!(p.port(Http, 9), p.port(Http, 9));
    }

    #[test]
    fn static_layout_preflight_rejects_an_occupied_service_port() {
        let Ok(_held) = TcpListener::bind(("127.0.0.1", NODE_BASE)) else {
            // Some restricted test sandboxes deny loopback bind entirely. The
            // production command still performs the same OS-level preflight.
            return;
        };
        let p = static_ports(1);
        let error = p
            .ensure_available(1)
            .expect_err("occupied validator-0 HTTP port must fail preflight");
        let message = error.to_string();
        assert!(message.contains("validator-0"));
        assert!(message.contains("Http"));
        assert!(message.contains(&NODE_BASE.to_string()));
    }

    /// Nodes bind their service ports on the wildcard address, not on loopback.
    /// BSD `SO_REUSEADDR` semantics let a later `127.0.0.1` bind succeed over a
    /// live `0.0.0.0` listener, so a bind-only probe waves a stale node through.
    ///
    /// Takes an ephemeral port rather than the static layout: the sibling
    /// preflight test holds [`NODE_BASE`], and nextest runs both at once.
    #[test]
    fn preflight_rejects_a_wildcard_held_service_port() {
        let Ok(held) = TcpListener::bind(("0.0.0.0", 0)) else {
            // Some restricted test sandboxes deny bind entirely.
            return;
        };
        let occupied = held.local_addr().expect("bound address").port();
        if fits(u64::from(occupied)).is_err() {
            return; // no room for a whole block at this ephemeral port
        }
        // Slot 0 of the block is Http, so the block starts on the held port.
        let p = Ports::from_block_starts(&[occupied]).expect("single block layout");
        let error = p
            .ensure_available(1)
            .expect_err("wildcard-held validator-0 Http port must fail preflight");
        let message = error.to_string();
        assert!(message.contains("validator-0"), "{message}");
        assert!(message.contains("Http"), "{message}");
        assert!(message.contains(&occupied.to_string()), "{message}");
    }

    #[test]
    fn persisted_block_layout_round_trips_every_core_service_port() {
        let original = static_ports(3);
        let starts = original.block_starts(3).unwrap();
        let restored = Ports::from_block_starts(&starts).unwrap();

        for index in 0..3 {
            for service in Service::CORE {
                assert_eq!(
                    restored.port(service, index),
                    original.port(service, index),
                    "validator-{index} {service:?}"
                );
            }
        }
    }

    #[test]
    fn persisted_block_layout_rejects_overlapping_blocks() {
        let error = Ports::from_block_starts(&[NODE_BASE, NODE_BASE + BLOCK - 1])
            .expect_err("overlapping blocks must be rejected");
        assert!(error.to_string().contains("overlap"));
    }

    #[test]
    fn restored_layout_protects_fresh_radicle_ports_without_renumbering_core() {
        let restored = Ports::from_block_starts(&[NODE_BASE, NODE_BASE + BLOCK]).unwrap();
        let ephemeral = ephemeral_port_range().unwrap();
        let mut seen = HashSet::new();
        for index in 0..2 {
            assert_eq!(restored.port(Http, index), NODE_BASE + index as u16 * BLOCK);
            for service in Service::ALL {
                let port = restored.port(service, index);
                assert!(seen.insert(port), "reconstructed services overlap");
                if service.is_radicle() {
                    assert!(!ranges_overlap((port, port), ephemeral));
                }
            }
        }
    }

    /// A busy port shifts only the block that hits it; later blocks follow the
    /// cursor, so they never skew relative to each other.
    #[test]
    fn scan_shifts_whole_block_past_a_held_port() {
        let held = TcpListener::bind(("127.0.0.1", NODE_BASE));
        if held.is_ok() {
            let p = Ports::new(true);
            p.start_scenario(2).expect("scan");
            let first = p.port(Http, 0);
            assert_ne!(first, NODE_BASE, "should skip the held port");
            for service in Service::CORE {
                assert_eq!(
                    p.port(service, 0),
                    first + service.offset(),
                    "block must stay contiguous at {service:?}"
                );
            }
            assert!(
                p.port(Http, 1) - first >= BLOCK,
                "the next block follows the cursor"
            );
            assert_eq!(
                p.port(RadicleStatus, 0),
                p.port(Radicle, 0) + 1,
                "the separate Radicle block stays contiguous"
            );
        }
    }

    #[test]
    fn radicle_skips_the_entire_kernel_ephemeral_interval() {
        for cursor in [49_999, 50_000, 60_999] {
            let ports = Ports::new(false);
            let mut resolver = lock(&ports.inner);
            resolver.radicle_cursor = cursor;
            assert_eq!(
                resolver
                    .alloc_radicle_avoiding(Some((50_000, 60_999)))
                    .unwrap(),
                61_000
            );
        }
        let ports = Ports::new(false);
        let mut resolver = lock(&ports.inner);
        resolver.radicle_cursor = 49_998;
        assert_eq!(
            resolver
                .alloc_radicle_avoiding(Some((50_000, 60_999)))
                .unwrap(),
            49_998
        );
        assert_eq!(
            resolver
                .alloc_radicle_avoiding(Some((50_000, 60_999)))
                .unwrap(),
            61_000
        );
    }

    #[test]
    fn malformed_kernel_range_is_not_silently_ignored() {
        assert_eq!(
            parse_ephemeral_port_range("32768\t60999\n").unwrap(),
            (32768, 60999)
        );
        for value in [
            "",
            "32768",
            "1 2 3",
            "0 123",
            "60000 50000",
            "1 65536",
            "no ports",
        ] {
            assert!(parse_ephemeral_port_range(value).is_err(), "{value}");
        }
    }

    #[test]
    fn core_and_radicle_never_reissue_each_others_spans() {
        let ports = Ports::new(false);
        let mut resolver = lock(&ports.inner);
        resolver.cursor = 50_000;
        resolver.radicle_cursor = 50_000;
        assert_eq!(resolver.block_start(0).unwrap(), 50_000);
        assert_eq!(resolver.radicle_block_start(0).unwrap(), 50_021);
        assert_eq!(resolver.block_start(1).unwrap(), 50_023);
        drop(resolver);
        ports.start_scenario(0).unwrap();
        let mut resolver = lock(&ports.inner);
        assert_eq!(resolver.radicle_block_start(0).unwrap(), 50_044);
    }

    #[test]
    fn final_port_block_is_not_reissued_after_exhaustion() {
        let ports = Ports::new(false);
        let mut resolver = lock(&ports.inner);
        resolver.radicle_cursor = 65_534;
        assert_eq!(resolver.alloc_radicle_avoiding(None).unwrap(), 65_534);
        assert!(resolver.alloc_radicle_avoiding(None).is_err());
        resolver.cursor = 65_515;
        assert!(
            resolver.alloc().is_err(),
            "last core span overlaps issued Radicle ports"
        );
    }

    #[test]
    fn last_core_window_ends_at_maximum_port_and_is_not_reissued() {
        let ports = Ports::new(false);
        let mut resolver = lock(&ports.inner);
        let start = u16::MAX - (BLOCK - 1);
        resolver.cursor = u64::from(start);
        assert_eq!(resolver.alloc().unwrap(), start);
        assert_eq!(resolver.issued, vec![(start, u16::MAX)]);
        assert_eq!(resolver.cursor, u64::from(u16::MAX) + 1);
        assert!(resolver.alloc().is_err());
    }

    #[test]
    fn persisted_final_core_window_round_trips_in_either_order() {
        let last = u16::MAX - (BLOCK - 1);
        for starts in [[NODE_BASE, last], [last, NODE_BASE]] {
            let ports = Ports::from_block_starts(&starts).unwrap();
            assert_eq!(ports.block_starts(2).unwrap(), starts);
            let mut resolver = lock(&ports.inner);
            assert_eq!(resolver.cursor, u64::from(u16::MAX) + 1);
            assert!(resolver.alloc().is_err());
        }
        assert!(Ports::from_block_starts(&[last, last]).is_err());
    }

    #[test]
    fn scanned_radicle_pair_skips_an_occupied_status_port() {
        let held = TcpListener::bind(("127.0.0.1", 0)).expect("bind occupied status fixture");
        let occupied = held.local_addr().unwrap().port();
        let ports = Ports::new(true);
        let mut resolver = lock(&ports.inner);
        resolver.radicle_cursor = u64::from(occupied - 1);
        let start = resolver.alloc_radicle_avoiding(None).unwrap();
        assert!(
            start > occupied,
            "neither peer nor status may use the held port"
        );
    }
}
