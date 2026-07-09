//! Per-node port allocation for the localnet.
//!
//! Every node owns one **contiguous block** of ports, one per service:
//!
//! ```text
//! offset:    0      1      2       3        4        5         6
//!          http    tee    p2p   discv5  authrpc  metrics  consensus
//! node 0: 18545  18546  18547   18548    18549    18550     18551
//! node 1: 18552  18553  18554   18555    18556    18557     18558
//! ```
//!
//! Blocks are handed out from a cursor that only ever moves forward, so they are
//! disjoint by construction and no two services can collide. A node index the
//! harness has never seen — the joiner at `i = committee size`, the followers at
//! their high slots — simply takes the next block on first use, so the committee
//! size need not be known up front.
//!
//! A block is *scanned* for by default: the cursor walks forward until it finds
//! [`BLOCK`] consecutive ports the OS reports free. The window slides as a unit,
//! so a block stays contiguous. `--no-resolve-ports` skips the scan and takes the
//! cursor's block verbatim.
//!
//! A block's ports follow from *allocation order*, not from the node index — so a
//! node whose first candidate port is busy shifts only itself, never the nodes
//! allocated after it.
//!
//! [`Ports::start_scenario`] forgets the node→block map but leaves the cursor
//! alone, so each scenario's nodes land above the previous scenario's. A port is
//! never reused within a process, which keeps a torn-down node's lingering socket
//! (or a peer still dialing it) from bleeding into the next scenario.
//!
//! The committee's consensus/p2p ports are baked into `validators.json`/genesis at
//! bootstrap, so blocks `0..n` are allocated at the scenario's start and reused
//! unchanged at launch. The cursor never rewinds, so a later block can't alias a
//! genesis-baked one.

use std::collections::HashMap;
use std::net::{TcpListener, UdpSocket};
use std::sync::{Arc, Mutex, MutexGuard};

use eyre::{bail, Result};

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
}

impl Service {
    /// Block order. Adding a service widens [`BLOCK`] and renumbers every node.
    const ALL: [Service; 7] = [
        Self::Http,
        Self::Tee,
        Self::P2p,
        Self::Discv5,
        Self::Authrpc,
        Self::Metrics,
        Self::Consensus,
    ];

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
const BLOCK: u16 = Service::ALL.len() as u16;

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
    /// Node index → first port of its block.
    blocks: HashMap<usize, u16>,
    /// Lowest port not yet handed out. Only ever moves forward.
    cursor: u16,
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
                cursor: NODE_BASE,
                scan,
            })),
        }
    }

    /// Begin a scenario: forget the previous one's node→block map, then allocate
    /// the committee's blocks (`0..n`) so their consensus/p2p ports are fixed
    /// before bootstrap bakes them into genesis.
    ///
    /// The cursor is untouched, so this scenario's blocks sit above the last one's
    /// and no port is reused within the process.
    pub fn start_scenario(&self, n: usize) -> Result<()> {
        let mut r = lock(&self.inner);
        r.blocks.clear();
        (0..n).try_for_each(|i| r.block_start(i).map(drop))
    }

    /// The port node `i` uses for `svc`, allocating its block on first use.
    ///
    /// Panics only when the port space above the cursor is exhausted — an
    /// unrecoverable property of the machine, not of the caller.
    pub(crate) fn port(&self, svc: Service, i: usize) -> u16 {
        let start = lock(&self.inner)
            .block_start(i)
            .unwrap_or_else(|e| panic!("e2e ports: {e}"));
        start + svc.offset()
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
    /// First port of node `i`'s block — the one already allocated, or the next.
    fn block_start(&mut self, i: usize) -> Result<u16> {
        if let Some(&start) = self.blocks.get(&i) {
            return Ok(start);
        }
        let start = self.alloc()?;
        self.blocks.insert(i, start);
        Ok(start)
    }

    /// Take the next block at or above the cursor, and advance the cursor past it.
    fn alloc(&mut self) -> Result<u16> {
        let mut candidate = u64::from(self.cursor);
        loop {
            let start = fits(candidate)?;
            if !self.scan || window_free(start) {
                // Saturating: a block ending exactly at `u16::MAX` leaves no room
                // for another, and the next `fits` will say so.
                self.cursor = start.saturating_add(BLOCK);
                return Ok(start);
            }
            candidate = u64::from(start) + 1;
        }
    }
}

/// `start` as a `u16`, once we know a whole block fits at or above it.
fn fits(start: u64) -> Result<u16> {
    if start + u64::from(BLOCK) - 1 > u64::from(u16::MAX) {
        bail!("no free {BLOCK}-port block at or above {start}");
    }
    Ok(start as u16)
}

/// Whether every port of the block starting at `start` is bindable.
fn window_free(start: u16) -> bool {
    Service::ALL
        .iter()
        .all(|svc| is_free(start + svc.offset(), svc.proto()))
}

/// Whether `port` is bindable on loopback for the required transport(s).
fn is_free(port: u16, proto: Proto) -> bool {
    let tcp = || TcpListener::bind(("127.0.0.1", port)).is_ok();
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
        assert_eq!(p.port(Http, 1), 18552);
        assert_eq!(p.port(Tee, 1), 18553);
    }

    /// The reported bug: a node index past the committee used to panic. Blocks
    /// follow allocation order, so the joiner and followers take the next ones.
    #[test]
    fn grown_index_does_not_panic() {
        let p = static_ports(4);
        assert_eq!(p.port(Http, 4), 18573, "joiner");
        assert_eq!(p.port(Http, 14), 18580, "follower1");
        assert_eq!(p.port(Tee, 15), 18588, "follower2");
    }

    /// A scenario never lands on a port the previous one used, however many nodes
    /// that one grew.
    #[test]
    fn scenarios_never_reuse_ports() {
        let p = static_ports(2);
        let first: Vec<u16> = [0, 1, 2, 14]
            .iter()
            .flat_map(|&i| Service::ALL.map(|svc| p.port(svc, i)))
            .collect();
        let high = *first.iter().max().expect("ports");

        p.start_scenario(2).expect("second scenario");
        assert_ne!(p.port(Http, 0), first[0], "validator-0 must move");
        for i in [0, 1, 2, 14] {
            for svc in Service::ALL {
                assert!(
                    p.port(svc, i) > high,
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
        let p = Ports::new(true);
        p.start_scenario(1).expect("scan");
        assert_eq!(p.port(Http, 9), p.port(Http, 9));
    }

    /// A busy port shifts only the block that hits it; later blocks follow the
    /// cursor, so they never skew relative to each other.
    #[test]
    fn scan_shifts_whole_block_past_a_held_port() {
        let held = TcpListener::bind(("127.0.0.1", NODE_BASE));
        if held.is_ok() {
            let p = Ports::new(true);
            p.start_scenario(2).expect("scan");
            assert_ne!(p.port(Http, 0), NODE_BASE, "should skip the held port");
            assert_eq!(
                p.port(Consensus, 0) - p.port(Http, 0),
                BLOCK - 1,
                "block must stay contiguous"
            );
            assert_eq!(
                p.port(Http, 1) - p.port(Http, 0),
                BLOCK,
                "the next block follows the cursor"
            );
        }
    }
}
