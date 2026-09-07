//! Production ownership and finalization boundary for the compressed-entity tree.
//!
//! The manager deliberately keeps speculative candidates in memory while the
//! sole finalized tree lives in the CE-owned MDBX environment. Opening a
//! parent view takes one immutable MDBX read transaction; finalization applies
//! one exact candidate atomically before advancing retention and removing
//! cache entries.

use std::{
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use outbe_primitives::error::PrecompileError;
use thiserror::Error;

use crate::{
    api::{AuthenticatedParentTree, AuthenticatedParentTreeFactory},
    persistence::{
        ApplyOutcome, CeMdbx, CeRetentionCursor, ExactParentIdentity, FinalizedMarker,
        PersistenceError,
    },
    staging::{
        AuthenticatedCatalogView, CandidateCache, CandidateCacheLimits, ProvisionalTreeBatch,
        PublicationOutcome, StagedTreeBatch, StagingError,
    },
    MdbxAuthenticatedTree,
};

/// PoC default for the small gate before the next finalized CE apply.
///
/// Production wiring may set a stricter value, but may not leave the gate
/// unbounded.
pub const DEFAULT_EXPORT_LEASE_OPEN_TIMEOUT: Duration = Duration::from_secs(2);
const EXPORT_LEASE_OFFER_DOMAIN: [u8; 4] = *b"OCEO";
const EXPORT_LEASE_OPEN_ACK_DOMAIN: [u8; 4] = *b"OCEA";
const EXPORT_LEASE_WIRE_LEN: usize = 4 + 8 + 32 + 4 + 8 + 32 + 32;

/// Observable state of one opaque CE export lease generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportLeaseStatus {
    Pending,
    Opened,
    TimedOut,
}

/// Fixed-size offer sent to the exporter. Its fields are private so only the
/// tree owner can mint a generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportLeaseOffer {
    generation: u64,
    challenge: B256,
    identity: ExactParentIdentity,
}

impl ExportLeaseOffer {
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn identity(self) -> ExactParentIdentity {
        self.identity
    }

    #[must_use]
    pub fn encode_fixed(self) -> [u8; EXPORT_LEASE_WIRE_LEN] {
        encode_export_lease(
            EXPORT_LEASE_OFFER_DOMAIN,
            self.generation,
            self.challenge,
            self.identity,
        )
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, TreeServiceError> {
        let (generation, challenge, identity) =
            decode_export_lease(bytes, EXPORT_LEASE_OFFER_DOMAIN)?;
        Ok(Self {
            generation,
            challenge,
            identity,
        })
    }

    /// Constructs an acknowledgement only from a view that actually opened the
    /// exact offered marker/root.
    pub fn confirm_open(
        self,
        view: &AuthenticatedCatalogView,
    ) -> Result<ExportLeaseOpenAck, TreeServiceError> {
        let actual = view.identity();
        if actual != self.identity {
            return Err(TreeServiceError::ExportLeaseIdentityMismatch {
                expected: self.identity,
                actual,
            });
        }
        Ok(ExportLeaseOpenAck {
            generation: self.generation,
            challenge: self.challenge,
            identity: self.identity,
        })
    }
}

/// Opaque acknowledgement minted only after an exact read-only view opens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportLeaseOpenAck {
    generation: u64,
    challenge: B256,
    identity: ExactParentIdentity,
}

impl ExportLeaseOpenAck {
    #[must_use]
    pub fn encode_fixed(self) -> [u8; EXPORT_LEASE_WIRE_LEN] {
        encode_export_lease(
            EXPORT_LEASE_OPEN_ACK_DOMAIN,
            self.generation,
            self.challenge,
            self.identity,
        )
    }

    fn decode_fixed(bytes: &[u8]) -> Result<Self, TreeServiceError> {
        let (generation, challenge, identity) =
            decode_export_lease(bytes, EXPORT_LEASE_OPEN_ACK_DOMAIN)?;
        Ok(Self {
            generation,
            challenge,
            identity,
        })
    }
}

fn encode_export_lease(
    domain: [u8; 4],
    generation: u64,
    challenge: B256,
    identity: ExactParentIdentity,
) -> [u8; EXPORT_LEASE_WIRE_LEN] {
    let mut bytes = [0_u8; EXPORT_LEASE_WIRE_LEN];
    bytes[..4].copy_from_slice(&domain);
    bytes[4..12].copy_from_slice(&generation.to_be_bytes());
    bytes[12..44].copy_from_slice(challenge.as_slice());
    bytes[44..48].copy_from_slice(&identity.commitment_scheme_version.to_be_bytes());
    bytes[48..56].copy_from_slice(&identity.block_number.to_be_bytes());
    bytes[56..88].copy_from_slice(identity.block_hash.as_slice());
    bytes[88..120].copy_from_slice(identity.root.as_slice());
    bytes
}

fn decode_export_lease(
    bytes: &[u8],
    expected_domain: [u8; 4],
) -> Result<(u64, B256, ExactParentIdentity), TreeServiceError> {
    if bytes.len() != EXPORT_LEASE_WIRE_LEN || bytes[..4] != expected_domain {
        return Err(TreeServiceError::MalformedExportLease);
    }
    let generation = u64::from_be_bytes(
        bytes[4..12]
            .try_into()
            .map_err(|_| TreeServiceError::MalformedExportLease)?,
    );
    if generation == 0 {
        return Err(TreeServiceError::MalformedExportLease);
    }
    let challenge = B256::from_slice(&bytes[12..44]);
    if challenge.is_zero() {
        return Err(TreeServiceError::MalformedExportLease);
    }
    let commitment_scheme_version = u32::from_be_bytes(
        bytes[44..48]
            .try_into()
            .map_err(|_| TreeServiceError::MalformedExportLease)?,
    );
    let block_number = u64::from_be_bytes(
        bytes[48..56]
            .try_into()
            .map_err(|_| TreeServiceError::MalformedExportLease)?,
    );
    Ok((
        generation,
        challenge,
        ExactParentIdentity {
            commitment_scheme_version,
            block_number,
            block_hash: B256::from_slice(&bytes[56..88]),
            root: B256::from_slice(&bytes[88..120]),
        },
    ))
}

#[derive(Clone, Copy, Debug)]
struct ActiveExportLease {
    offer: ExportLeaseOffer,
    deadline: Instant,
}

#[derive(Debug)]
struct ExportLeaseState {
    next_generation: u64,
    active: Option<ActiveExportLease>,
    last: Option<(ExportLeaseOffer, ExportLeaseStatus)>,
}

#[derive(Debug)]
struct ExportLeaseGate {
    timeout: Duration,
    state: Mutex<ExportLeaseState>,
    changed: Condvar,
}

impl ExportLeaseGate {
    fn new(timeout: Duration) -> Result<Self, TreeServiceError> {
        if timeout.is_zero() || timeout > DEFAULT_EXPORT_LEASE_OPEN_TIMEOUT {
            return Err(TreeServiceError::InvalidExportLeaseTimeout);
        }
        Ok(Self {
            timeout,
            state: Mutex::new(ExportLeaseState {
                next_generation: 1,
                active: None,
                last: None,
            }),
            changed: Condvar::new(),
        })
    }

    fn arm(
        &self,
        identity: ExactParentIdentity,
        challenge: B256,
    ) -> Result<ExportLeaseOffer, TreeServiceError> {
        if challenge.is_zero() {
            return Err(TreeServiceError::ZeroExportLeaseChallenge);
        }
        let mut state = self.lock()?;
        expire_if_due(&mut state, Instant::now());
        if let Some(active) = state.active {
            if active.offer.identity == identity && active.offer.challenge == challenge {
                return Ok(active.offer);
            }
            return Err(TreeServiceError::ConflictingExportLease {
                active: active.offer.identity,
                requested: identity,
            });
        }
        let generation = state.next_generation;
        state.next_generation = generation
            .checked_add(1)
            .ok_or(TreeServiceError::ExportLeaseGenerationOverflow)?;
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(TreeServiceError::InvalidExportLeaseTimeout)?;
        let offer = ExportLeaseOffer {
            generation,
            challenge,
            identity,
        };
        state.active = Some(ActiveExportLease { offer, deadline });
        state.last = Some((offer, ExportLeaseStatus::Pending));
        Ok(offer)
    }

    fn acknowledge(&self, ack: ExportLeaseOpenAck) -> Result<(), TreeServiceError> {
        let mut state = self.lock()?;
        expire_if_due(&mut state, Instant::now());
        let Some(active) = state.active else {
            if let Some((last, ExportLeaseStatus::Opened)) = state.last {
                if last.generation == ack.generation
                    && last.challenge == ack.challenge
                    && last.identity == ack.identity
                {
                    return Ok(());
                }
            }
            return Err(stale_export_lease(&state, ack.generation));
        };
        if active.offer.generation != ack.generation {
            return Err(stale_export_lease(&state, ack.generation));
        }
        if active.offer.identity != ack.identity {
            return Err(TreeServiceError::ExportLeaseIdentityMismatch {
                expected: active.offer.identity,
                actual: ack.identity,
            });
        }
        if active.offer.challenge != ack.challenge {
            return Err(TreeServiceError::ExportLeaseChallengeMismatch);
        }
        state.active = None;
        state.last = Some((active.offer, ExportLeaseStatus::Opened));
        self.changed.notify_all();
        Ok(())
    }

    fn status(&self, generation: u64) -> Result<ExportLeaseStatus, TreeServiceError> {
        let mut state = self.lock()?;
        expire_if_due(&mut state, Instant::now());
        if state
            .active
            .is_some_and(|active| active.offer.generation == generation)
        {
            return Ok(ExportLeaseStatus::Pending);
        }
        match state.last {
            Some((actual, status)) if actual.generation == generation => Ok(status),
            _ => Err(stale_export_lease(&state, generation)),
        }
    }

    fn wait_before_next_apply(&self, current: FinalizedMarker) -> Result<(), TreeServiceError> {
        let expected = exact_identity(current);
        let mut state = self.lock()?;
        loop {
            expire_if_due(&mut state, Instant::now());
            let Some(active) = state.active else {
                return Ok(());
            };
            if active.offer.identity != expected {
                return Err(TreeServiceError::ConflictingExportLease {
                    active: active.offer.identity,
                    requested: expected,
                });
            }
            let remaining = active.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                expire_if_due(&mut state, Instant::now());
                return Ok(());
            }
            let (next, _) = self
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| TreeServiceError::LockPoisoned("export lease gate"))?;
            state = next;
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ExportLeaseState>, TreeServiceError> {
        self.state
            .lock()
            .map_err(|_| TreeServiceError::LockPoisoned("export lease gate"))
    }
}

fn expire_if_due(state: &mut ExportLeaseState, now: Instant) {
    if let Some(active) = state.active {
        if now >= active.deadline {
            state.active = None;
            state.last = Some((active.offer, ExportLeaseStatus::TimedOut));
        }
    }
}

fn stale_export_lease(state: &ExportLeaseState, requested: u64) -> TreeServiceError {
    let actual = state
        .active
        .map(|active| active.offer.generation)
        .or_else(|| state.last.map(|(offer, _)| offer.generation));
    TreeServiceError::StaleExportLease { requested, actual }
}

fn exact_identity(marker: FinalizedMarker) -> ExactParentIdentity {
    ExactParentIdentity {
        commitment_scheme_version: marker.commitment_scheme_version,
        block_number: marker.height,
        block_hash: marker.block_hash,
        root: marker.new_root,
    }
}

/// Result of applying an exact finalized block to the CE materialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalizedCandidateOutcome {
    Applied(FinalizedMarker),
    AlreadyApplied(FinalizedMarker),
}

impl FinalizedCandidateOutcome {
    #[must_use]
    pub const fn marker(self) -> FinalizedMarker {
        match self {
            Self::Applied(marker) | Self::AlreadyApplied(marker) => marker,
        }
    }
}

/// Explicitly-owned production tree service. There are no process globals and
/// no implicit cache limits: callers must supply benchmark-derived bounds.
#[derive(Debug)]
pub struct CompressedTreeService {
    db: Arc<CeMdbx>,
    candidates: Mutex<CandidateCache>,
    retention: CeRetentionCursor,
    finalization: Mutex<()>,
    export_lease: ExportLeaseGate,
}

impl CompressedTreeService {
    pub(crate) fn open_finalized_snapshot(
        &self,
    ) -> Result<Box<dyn crate::staging::FinalizedTreeSnapshot>, TreeServiceError> {
        self.db.open_snapshot().map_err(Into::into)
    }

    /// Takes ownership of the CE MDBX environment and seeds retention from its
    /// already-verified finalized marker.
    pub fn new(db: CeMdbx, limits: CandidateCacheLimits) -> Result<Self, TreeServiceError> {
        Self::new_with_export_lease_timeout(db, limits, DEFAULT_EXPORT_LEASE_OPEN_TIMEOUT)
    }

    pub fn new_with_export_lease_timeout(
        db: CeMdbx,
        limits: CandidateCacheLimits,
        export_lease_timeout: Duration,
    ) -> Result<Self, TreeServiceError> {
        let marker = db.marker()?;
        Ok(Self {
            db: Arc::new(db),
            candidates: Mutex::new(CandidateCache::new(limits)),
            retention: CeRetentionCursor::from_verified_marker(marker),
            finalization: Mutex::new(()),
            export_lease: ExportLeaseGate::new(export_lease_timeout)?,
        })
    }

    /// Arms one exact marker while holding the same serialization boundary as
    /// finalized apply. A missed marker is a local availability failure.
    pub fn arm_finalized_export(
        &self,
        required: FinalizedMarker,
        challenge: B256,
    ) -> Result<ExportLeaseOffer, TreeServiceError> {
        let _guard = self
            .finalization
            .lock()
            .map_err(|_| TreeServiceError::LockPoisoned("finalization boundary"))?;
        let current = self.db.marker()?;
        if current != required {
            return Err(TreeServiceError::ExportLeaseMarkerAdvanced {
                requested: required,
                current,
            });
        }
        self.export_lease.arm(exact_identity(required), challenge)
    }

    /// Returns the fixed identity of the CE environment owned by this service.
    ///
    /// Snapshot handoff exposes only the schema number from this identity; it
    /// never exposes the database path or a writer-capable handle.
    #[must_use]
    pub fn environment_identity(&self) -> &crate::persistence::EnvironmentIdentity {
        self.db.identity()
    }

    pub(crate) fn acknowledge_export_open(
        &self,
        ack: ExportLeaseOpenAck,
    ) -> Result<(), TreeServiceError> {
        self.export_lease.acknowledge(ack)
    }

    /// Accepts only the acknowledgement wire domain emitted after an exporter
    /// opened and verified the exact read-only snapshot.
    pub fn acknowledge_export_open_bytes(&self, bytes: &[u8]) -> Result<(), TreeServiceError> {
        self.acknowledge_export_open(ExportLeaseOpenAck::decode_fixed(bytes)?)
    }

    pub fn export_lease_status(
        &self,
        generation: u64,
    ) -> Result<ExportLeaseStatus, TreeServiceError> {
        self.export_lease.status(generation)
    }

    /// Opens one exact-parent tree session over one immutable MDBX snapshot.
    /// Every marker field is checked against `identity` before the session is
    /// returned.
    pub fn open_parent(
        &self,
        identity: ExactParentIdentity,
    ) -> Result<Arc<dyn AuthenticatedParentTree>, TreeServiceError> {
        let tree = MdbxAuthenticatedTree::open(Arc::clone(&self.db), identity)
            .map_err(TreeServiceError::ParentView)?;
        Ok(Arc::new(tree))
    }

    /// Freezes and publishes a provisional batch under the executor-assigned
    /// block hash. Repeating the identical publication is a successful no-op.
    pub fn publish_candidate(
        &self,
        block_hash: B256,
        provisional: ProvisionalTreeBatch,
    ) -> Result<PublicationOutcome, TreeServiceError> {
        let _guard = self
            .finalization
            .lock()
            .map_err(|_| TreeServiceError::LockPoisoned("finalization boundary"))?;
        let current = self.db.marker()?;
        let batch = provisional.freeze(block_hash);
        if current.height == batch.block_number
            && current.block_hash == batch.block_hash
            && current.parent_block_hash == batch.parent_block_hash
            && current.parent_root == batch.parent_root()
            && current.new_root == batch.new_root()
        {
            return Ok(PublicationOutcome::AlreadyPublished);
        }
        if batch.block_number != current.height.saturating_add(1)
            || batch.parent_block_hash != current.block_hash
            || batch.parent_root() != current.new_root
        {
            return Err(TreeServiceError::NonContiguousPublication {
                current_marker: current,
                candidate_height: batch.block_number,
                block_hash,
                parent_block_hash: batch.parent_block_hash,
                parent_root: batch.parent_root(),
            });
        }
        self.candidates
            .lock()
            .map_err(|_| TreeServiceError::LockPoisoned("candidate cache"))?
            .publish(batch)
            .map_err(Into::into)
    }

    /// Fetches an immutable exact candidate. A matching hash at another height
    /// is rejected instead of being silently reinterpreted.
    pub fn candidate(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> Result<Option<Arc<StagedTreeBatch>>, TreeServiceError> {
        let candidate = self
            .candidates
            .lock()
            .map_err(|_| TreeServiceError::LockPoisoned("candidate cache"))?
            .get(block_hash);
        match candidate {
            Some(candidate) if candidate.block_number != block_number => {
                Err(TreeServiceError::CandidateIdentityMismatch {
                    requested_height: block_number,
                    block_hash,
                    candidate_height: candidate.block_number,
                })
            }
            candidate => Ok(candidate),
        }
    }

    /// Drops one proposer candidate after a later payload guard rejects the
    /// assembled block. Finalization and removal share one serialization lock.
    pub fn discard_candidate(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> Result<bool, TreeServiceError> {
        let _guard = self
            .finalization
            .lock()
            .map_err(|_| TreeServiceError::LockPoisoned("finalization boundary"))?;
        let mut candidates = self
            .candidates
            .lock()
            .map_err(|_| TreeServiceError::LockPoisoned("candidate cache"))?;
        if let Some(candidate) = candidates.get(block_hash) {
            if candidate.block_number != block_number {
                return Err(TreeServiceError::CandidateIdentityMismatch {
                    requested_height: block_number,
                    block_hash,
                    candidate_height: candidate.block_number,
                });
            }
        }
        Ok(candidates.remove(block_hash).is_some())
    }

    /// Applies the exact candidate and only then advances retention and removes
    /// the winning/losing candidates at or below its height. Repeating a known
    /// completed finalization is idempotent even after cache removal.
    pub fn apply_finalized(
        &self,
        block_number: u64,
        block_hash: B256,
        authoritative_root: B256,
    ) -> Result<FinalizedCandidateOutcome, TreeServiceError> {
        let _guard = self
            .finalization
            .lock()
            .map_err(|_| TreeServiceError::LockPoisoned("finalization boundary"))?;
        let marker_before = self.db.marker()?;
        if block_number > marker_before.height {
            self.export_lease.wait_before_next_apply(marker_before)?;
        }

        let Some(candidate) = self.candidate(block_number, block_hash)? else {
            let marker = marker_before;
            if marker.height == block_number
                && marker.block_hash == block_hash
                && marker.new_root == authoritative_root
            {
                self.retention
                    .advance_or_confirm_after_known_commit(marker)?;
                self.remove_finalized_candidates(block_number)?;
                return Ok(FinalizedCandidateOutcome::AlreadyApplied(marker));
            }
            return Err(TreeServiceError::CandidateMissing {
                block_number,
                block_hash,
                current_marker: marker,
            });
        };

        if candidate.new_root() != authoritative_root {
            return Err(TreeServiceError::AuthoritativeRootMismatch {
                block_number,
                block_hash,
                candidate_root: candidate.new_root(),
                authoritative_root,
            });
        }

        let outcome = self.db.apply_finalized(&candidate)?;
        let finalized = match outcome {
            ApplyOutcome::Applied(marker) => FinalizedCandidateOutcome::Applied(marker),
            ApplyOutcome::AlreadyApplied(marker) => {
                FinalizedCandidateOutcome::AlreadyApplied(marker)
            }
        };

        // The cursor cannot move until MDBX has returned a known-successful
        // outcome. Cache removal is deliberately last.
        self.retention
            .advance_or_confirm_after_known_commit(finalized.marker())?;
        self.remove_finalized_candidates(block_number)?;
        Ok(finalized)
    }

    /// Explicit, idempotent cache cleanup policy used after a successful
    /// finalized apply.
    pub fn remove_finalized_candidates(&self, height: u64) -> Result<(), TreeServiceError> {
        self.candidates
            .lock()
            .map_err(|_| TreeServiceError::LockPoisoned("candidate cache"))?
            .remove_finalized(height);
        Ok(())
    }

    /// Restart never attempts to resurrect speculative state.
    pub fn discard_speculative_candidates(&self) -> Result<(), TreeServiceError> {
        self.candidates
            .lock()
            .map_err(|_| TreeServiceError::LockPoisoned("candidate cache"))?
            .discard_all_on_restart();
        Ok(())
    }

    pub fn finalized_marker(&self) -> Result<FinalizedMarker, TreeServiceError> {
        self.db.marker().map_err(Into::into)
    }

    #[must_use]
    pub fn retention_height(&self) -> u64 {
        self.retention.height()
    }
}

impl AuthenticatedParentTreeFactory for CompressedTreeService {
    fn open_parent(
        &self,
        identity: ExactParentIdentity,
    ) -> outbe_primitives::error::Result<Arc<dyn AuthenticatedParentTree>> {
        CompressedTreeService::open_parent(self, identity).map_err(|error| match error {
            TreeServiceError::ParentView(error) => error,
            other => PrecompileError::Fatal(other.to_string()),
        })
    }
}

#[derive(Debug, Error)]
pub enum TreeServiceError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    Staging(#[from] StagingError),
    #[error("candidate shard count mismatch: expected {expected}, got {actual}")]
    ShardCountMismatch { expected: u32, actual: u32 },
    #[error("unable to open exact compressed-tree parent: {0}")]
    ParentView(PrecompileError),
    #[error("compressed-tree {0} lock is poisoned")]
    LockPoisoned(&'static str),
    #[error("CE export lease timeout must be non-zero and no greater than the PoC bound")]
    InvalidExportLeaseTimeout,
    #[error("CE export lease generation overflow")]
    ExportLeaseGenerationOverflow,
    #[error("CE export lease challenge cannot be zero")]
    ZeroExportLeaseChallenge,
    #[error("CE export lease acknowledgement challenge does not match the active offer")]
    ExportLeaseChallengeMismatch,
    #[error("CE export lease fixed-size encoding is malformed")]
    MalformedExportLease,
    #[error(
        "CE export marker was missed: requested {requested:?}, current finalized marker {current:?}"
    )]
    ExportLeaseMarkerAdvanced {
        requested: FinalizedMarker,
        current: FinalizedMarker,
    },
    #[error("conflicting CE export lease: active {active:?}, requested {requested:?}")]
    ConflictingExportLease {
        active: ExactParentIdentity,
        requested: ExactParentIdentity,
    },
    #[error("stale CE export lease generation {requested}; current generation is {actual:?}")]
    StaleExportLease { requested: u64, actual: Option<u64> },
    #[error("CE export lease identity mismatch: expected {expected:?}, got {actual:?}")]
    ExportLeaseIdentityMismatch {
        expected: ExactParentIdentity,
        actual: ExactParentIdentity,
    },
    #[error(
        "candidate {block_hash} requested at height {requested_height}, stored at {candidate_height}"
    )]
    CandidateIdentityMismatch {
        requested_height: u64,
        block_hash: B256,
        candidate_height: u64,
    },
    #[error(
        "candidate for finalized block {block_number}/{block_hash} is missing; current marker is {current_marker:?}"
    )]
    CandidateMissing {
        block_number: u64,
        block_hash: B256,
        current_marker: FinalizedMarker,
    },
    #[error(
        "candidate {candidate_height}/{block_hash} does not extend current marker {current_marker:?}: parent {parent_block_hash}/{parent_root}"
    )]
    NonContiguousPublication {
        current_marker: FinalizedMarker,
        candidate_height: u64,
        block_hash: B256,
        parent_block_hash: B256,
        parent_root: B256,
    },
    #[error(
        "candidate {block_number}/{block_hash} root {candidate_root} differs from authoritative EVM root {authoritative_root}"
    )]
    AuthoritativeRootMismatch {
        block_number: u64,
        block_hash: B256,
        candidate_root: B256,
        authoritative_root: B256,
    },
}

// ADR-009's flat-namespace fixtures are replaced by ADR-010 catalog fixtures below.
#[cfg(test)]
mod tests {
    use super::*;
    use outbe_primitives::time::WorldwideDay;

    use crate::{
        persistence::{EnvironmentIdentity, LOCAL_STORAGE_SCHEMA_VERSION},
        sealed_root, CeTopologyV1, Commitment, EntityRef, FinalLeafMutation, WwdEntityId,
        ACTIVE_COMMITMENT_SCHEME, K_PROVISIONAL,
    };

    fn b256(last: u8) -> B256 {
        let mut bytes = [0_u8; 32];
        bytes[31] = last;
        B256::from(bytes)
    }

    fn environment() -> EnvironmentIdentity {
        EnvironmentIdentity {
            local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
            chain_id: 8080,
            genesis_hash: b256(1),
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            topology: CeTopologyV1.encode(),
            tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".to_owned(),
            vendor_revision: "ad555350c866b2265d87d2d7fbd146fbc918bfe5".to_owned(),
        }
    }

    fn genesis() -> FinalizedMarker {
        FinalizedMarker {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            height: 0,
            block_hash: environment().genesis_hash,
            parent_block_hash: B256::ZERO,
            parent_root: B256::ZERO,
            new_root: sealed_root(B256::ZERO).unwrap(),
        }
    }

    fn service_with_lease_timeout(
        directory: &std::path::Path,
        lease_timeout: std::time::Duration,
    ) -> CompressedTreeService {
        let db = CeMdbx::open(directory, environment(), genesis()).unwrap();
        // These are test fixture bounds, not production defaults.
        CompressedTreeService::new_with_export_lease_timeout(
            db,
            CandidateCacheLimits {
                max_candidates: 4,
                max_encoded_bytes: 1_000_000,
            },
            lease_timeout,
        )
        .unwrap()
    }

    fn service(directory: &std::path::Path) -> CompressedTreeService {
        service_with_lease_timeout(directory, std::time::Duration::from_secs(1))
    }

    #[test]
    fn ocomp_lease_configuration_rejects_a_timeout_above_the_poc_bound() {
        let directory = tempfile::tempdir().unwrap();
        let db = CeMdbx::open(directory.path(), environment(), genesis()).unwrap();
        assert!(matches!(
            CompressedTreeService::new_with_export_lease_timeout(
                db,
                CandidateCacheLimits {
                    max_candidates: 4,
                    max_encoded_bytes: 1_000_000,
                },
                DEFAULT_EXPORT_LEASE_OPEN_TIMEOUT + std::time::Duration::from_nanos(1),
            ),
            Err(TreeServiceError::InvalidExportLeaseTimeout)
        ));
    }

    fn genesis_identity() -> ExactParentIdentity {
        ExactParentIdentity {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            block_number: 0,
            block_hash: genesis().block_hash,
            root: genesis().new_root,
        }
    }

    const CHILD_ROOT: &str = "OUTBE_CE_TEST_ROOT";
    const CHILD_OFFER: &str = "OUTBE_CE_TEST_OFFER";
    const CHILD_ACK: &str = "OUTBE_CE_TEST_ACK";
    const CHILD_RELEASE: &str = "OUTBE_CE_TEST_RELEASE";

    struct ReadOnlyExporterChild {
        child: std::process::Child,
        acknowledgement_path: std::path::PathBuf,
        release_path: std::path::PathBuf,
    }

    impl ReadOnlyExporterChild {
        fn wait_for_ack(&mut self) -> ExportLeaseOpenAck {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if let Ok(bytes) = std::fs::read(&self.acknowledgement_path) {
                    if let Ok(acknowledgement) = ExportLeaseOpenAck::decode_fixed(&bytes) {
                        return acknowledgement;
                    }
                }
                if let Some(status) = self.child.try_wait().unwrap() {
                    panic!("read-only exporter exited before acknowledgement: {status}");
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "read-only exporter acknowledgement timed out"
                );
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }

        fn release_and_wait(mut self) {
            std::fs::write(&self.release_path, []).unwrap();
            let status = self.child.wait().unwrap();
            assert!(status.success(), "read-only exporter failed: {status}");
        }
    }

    fn spawn_read_only_exporter(
        directory: &std::path::Path,
        offer: ExportLeaseOffer,
    ) -> ReadOnlyExporterChild {
        let control = directory.join(format!(
            "lease-{}-{:#x}",
            offer.generation(),
            offer.challenge
        ));
        std::fs::create_dir_all(&control).unwrap();
        let offer_path = control.join("offer");
        let acknowledgement_path = control.join("ack");
        let release_path = control.join("release");
        std::fs::write(&offer_path, offer.encode_fixed()).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tree_manager::tests::ce_read_only_exporter_child",
                "--nocapture",
            ])
            .env(CHILD_ROOT, directory)
            .env(CHILD_OFFER, &offer_path)
            .env(CHILD_ACK, &acknowledgement_path)
            .env(CHILD_RELEASE, &release_path)
            .spawn()
            .unwrap();
        ReadOnlyExporterChild {
            child,
            acknowledgement_path,
            release_path,
        }
    }

    #[test]
    fn ce_read_only_exporter_child() {
        let Some(root) = std::env::var_os(CHILD_ROOT) else {
            return;
        };
        let offer_path = std::env::var_os(CHILD_OFFER).unwrap();
        let acknowledgement_path = std::env::var_os(CHILD_ACK).unwrap();
        let release_path = std::env::var_os(CHILD_RELEASE).unwrap();
        let offer = ExportLeaseOffer::decode_fixed(&std::fs::read(offer_path).unwrap()).unwrap();
        let read_only =
            crate::CeMdbxReadOnly::open(std::path::Path::new(&root), environment()).unwrap();
        let view = read_only.open_exact(offer.identity()).unwrap();
        let catalog_root = view.catalog_root();
        let acknowledgement = offer.confirm_open(&view).unwrap();
        std::fs::write(acknowledgement_path, acknowledgement.encode_fixed()).unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !std::path::Path::new(&release_path).exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "parent did not release read-only exporter"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_eq!(view.catalog_root(), catalog_root);
    }

    #[test]
    fn exact_parent_identity_is_checked_before_any_tree_read() {
        let directory = tempfile::tempdir().unwrap();
        let service = service(directory.path());
        assert!(service.open_parent(genesis_identity()).is_ok());

        for wrong in [
            ExactParentIdentity {
                block_hash: b256(99),
                ..genesis_identity()
            },
            ExactParentIdentity {
                root: b256(99),
                ..genesis_identity()
            },
            ExactParentIdentity {
                block_number: 9,
                ..genesis_identity()
            },
        ] {
            assert!(matches!(
                service.open_parent(wrong),
                Err(TreeServiceError::ParentView(_))
            ));
        }
    }

    #[test]
    fn exact_parent_identity_and_read_root_mismatches_are_corruption_not_readiness() {
        let directory = tempfile::tempdir().unwrap();
        let service = service(directory.path());
        let wrong = ExactParentIdentity {
            block_hash: b256(99),
            ..genesis_identity()
        };

        let factory: &dyn AuthenticatedParentTreeFactory = &service;
        assert!(matches!(
            factory.open_parent(wrong),
            Err(PrecompileError::Fatal(_))
        ));

        let parent = factory.open_parent(genesis_identity()).unwrap();
        let entity = EntityRef::Tribute(WwdEntityId::from_day_and_digest(
            WorldwideDay::new(7),
            [3_u8; 32],
        ));
        assert!(matches!(
            parent.read_leaf_verified(entity, b256(88)),
            Err(PrecompileError::Fatal(_))
        ));
    }

    #[test]
    fn parent_proof_candidate_and_finalized_reopen_form_one_authenticated_flow() {
        let directory = tempfile::tempdir().unwrap();
        let service = service(directory.path());
        let parent = service.open_parent(genesis_identity()).unwrap();
        let entity = EntityRef::Tribute(WwdEntityId::from_day_and_digest(
            WorldwideDay::new(7),
            [3_u8; 32],
        ));
        let commitment = Commitment::try_from(b256(17).0).unwrap();

        assert_eq!(
            parent
                .read_leaf_verified(entity, genesis_identity().root)
                .unwrap(),
            None
        );
        let provisional = parent
            .prepare_seal(
                1,
                &[FinalLeafMutation {
                    entity,
                    final_leaf: Some(commitment),
                }],
                &[],
            )
            .unwrap();
        let block_hash = b256(2);
        assert_eq!(
            service
                .publish_candidate(block_hash, provisional.clone())
                .unwrap(),
            PublicationOutcome::Published
        );
        assert_eq!(
            service.publish_candidate(block_hash, provisional).unwrap(),
            PublicationOutcome::AlreadyPublished
        );

        let staged = service.candidate(1, block_hash).unwrap().unwrap();
        assert_eq!(staged.parent_root(), genesis().new_root);
        let new_root = staged.new_root();
        assert_eq!(
            service.apply_finalized(1, block_hash, new_root).unwrap(),
            FinalizedCandidateOutcome::Applied(staged.marker(ACTIVE_COMMITMENT_SCHEME))
        );
        assert_eq!(service.retention_height(), 1);
        assert!(service.candidate(1, block_hash).unwrap().is_none());

        let reopened = service
            .open_parent(ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 1,
                block_hash,
                root: new_root,
            })
            .unwrap();
        assert_eq!(
            reopened.read_leaf_verified(entity, new_root).unwrap(),
            Some(commitment)
        );
    }

    #[test]
    fn one_candidate_atomically_seals_and_reopens_changes_from_multiple_shards() {
        let directory = tempfile::tempdir().unwrap();
        let service = service(directory.path());
        let identity = WwdEntityId::try_from(
            hex::decode("000000010405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let tribute = EntityRef::Tribute(identity);
        let bucket = EntityRef::NodBucket(identity);
        let tribute_leaf = Commitment::try_from(b256(11).0).unwrap();
        let bucket_leaf = Commitment::try_from(b256(12).0).unwrap();

        let parent = service.open_parent(genesis_identity()).unwrap();
        let provisional = parent
            .prepare_seal(
                1,
                &[
                    FinalLeafMutation {
                        entity: tribute,
                        final_leaf: Some(tribute_leaf),
                    },
                    FinalLeafMutation {
                        entity: bucket,
                        final_leaf: Some(bucket_leaf),
                    },
                ],
                &[],
            )
            .unwrap();
        assert_eq!(provisional.changed_shard_count(), 2);
        assert_eq!(provisional.changed_collections.len(), 2);
        assert!(provisional.changed_collections.values().all(|collection| {
            let collection = collection.mutation().expect("mutation operation");
            collection.shard_set.parent_shard_roots.len() == K_PROVISIONAL as usize
                && collection.shard_set.new_shard_roots.len() == K_PROVISIONAL as usize
        }));

        let block_hash = b256(91);
        let new_root = provisional.new_root();
        service.publish_candidate(block_hash, provisional).unwrap();
        service.apply_finalized(1, block_hash, new_root).unwrap();

        let reopened = service
            .open_parent(ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 1,
                block_hash,
                root: new_root,
            })
            .unwrap();
        assert_eq!(
            reopened.read_leaf_verified(tribute, new_root).unwrap(),
            Some(tribute_leaf)
        );
        assert_eq!(
            reopened.read_leaf_verified(bucket, new_root).unwrap(),
            Some(bucket_leaf)
        );
    }

    #[test]
    fn completed_finalization_is_idempotent_after_candidate_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let service = service(directory.path());
        let parent = service.open_parent(genesis_identity()).unwrap();
        let provisional = parent.prepare_seal(1, &[], &[]).unwrap();
        let block_hash = b256(2);
        service.publish_candidate(block_hash, provisional).unwrap();

        let root = service
            .candidate(1, block_hash)
            .unwrap()
            .unwrap()
            .new_root();

        assert!(matches!(
            service.apply_finalized(1, block_hash, root).unwrap(),
            FinalizedCandidateOutcome::Applied(_)
        ));
        assert!(matches!(
            service.apply_finalized(1, block_hash, root).unwrap(),
            FinalizedCandidateOutcome::AlreadyApplied(_)
        ));
        assert_eq!(service.retention_height(), 1);
        assert!(matches!(
            service.apply_finalized(2, b256(3), b256(4)),
            Err(TreeServiceError::CandidateMissing { .. })
        ));
    }

    #[test]
    fn authoritative_root_mismatch_cannot_mutate_mdbx_or_drop_candidate() {
        let directory = tempfile::tempdir().unwrap();
        let service = service(directory.path());
        let parent = service.open_parent(genesis_identity()).unwrap();
        let provisional = parent.prepare_seal(1, &[], &[]).unwrap();
        let block_hash = b256(2);
        service.publish_candidate(block_hash, provisional).unwrap();

        assert!(matches!(
            service.apply_finalized(1, block_hash, b256(77)),
            Err(TreeServiceError::AuthoritativeRootMismatch { .. })
        ));
        assert_eq!(service.finalized_marker().unwrap(), genesis());
        assert_eq!(service.retention_height(), 0);
        assert!(service.candidate(1, block_hash).unwrap().is_some());
    }

    #[test]
    fn late_payload_rejection_discards_only_the_exact_candidate() {
        let directory = tempfile::tempdir().unwrap();
        let service = service(directory.path());
        let first_hash = b256(2);
        let competing_hash = b256(3);
        for hash in [first_hash, competing_hash] {
            let provisional = service
                .open_parent(genesis_identity())
                .unwrap()
                .prepare_seal(1, &[], &[])
                .unwrap();
            service.publish_candidate(hash, provisional).unwrap();
        }

        assert!(service.discard_candidate(1, first_hash).unwrap());
        assert!(service.candidate(1, first_hash).unwrap().is_none());
        assert!(service.candidate(1, competing_hash).unwrap().is_some());
        assert_eq!(service.finalized_marker().unwrap(), genesis());
    }

    #[test]
    fn stale_or_wrong_parent_candidate_is_rejected_before_cache_publication() {
        let directory = tempfile::tempdir().unwrap();
        let service = service(directory.path());
        let mut wrong_parent = service
            .open_parent(genesis_identity())
            .unwrap()
            .prepare_seal(1, &[], &[])
            .unwrap();
        wrong_parent.parent_block_hash = b256(44);
        assert!(matches!(
            service.publish_candidate(b256(2), wrong_parent),
            Err(TreeServiceError::NonContiguousPublication { .. })
        ));
        assert!(service.candidate(1, b256(2)).unwrap().is_none());
    }

    #[test]
    fn ocm_exporter_opens_one_exact_read_only_snapshot_before_the_writer_advances() {
        let directory = tempfile::tempdir().unwrap();
        let service = service(directory.path());
        let offer = service.arm_finalized_export(genesis(), b256(70)).unwrap();
        let mut exporter = spawn_read_only_exporter(directory.path(), offer);
        let opened = exporter.wait_for_ack();
        service.acknowledge_export_open(opened).unwrap();

        let entity = EntityRef::Tribute(WwdEntityId::from_day_and_digest(
            WorldwideDay::new(7),
            [0x44_u8; 32],
        ));
        let commitment = Commitment::try_from(b256(17).0).unwrap();
        let provisional = service
            .open_parent(genesis_identity())
            .unwrap()
            .prepare_seal(
                1,
                &[FinalLeafMutation {
                    entity,
                    final_leaf: Some(commitment),
                }],
                &[],
            )
            .unwrap();
        let block_hash = b256(2);
        let new_root = provisional.new_root();
        service.publish_candidate(block_hash, provisional).unwrap();
        service.apply_finalized(1, block_hash, new_root).unwrap();

        assert_ne!(
            service.finalized_marker().unwrap().new_root,
            genesis().new_root
        );
        exporter.release_and_wait();
    }

    #[test]
    fn ocm_export_offer_bytes_cannot_acknowledge_an_unopened_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let service = service(directory.path());
        let offer = service.arm_finalized_export(genesis(), b256(71)).unwrap();

        assert!(matches!(
            service.acknowledge_export_open_bytes(&offer.encode_fixed()),
            Err(TreeServiceError::MalformedExportLease)
        ));
        assert_eq!(
            service.export_lease_status(offer.generation()).unwrap(),
            ExportLeaseStatus::Pending
        );

        let mut exporter = spawn_read_only_exporter(directory.path(), offer);
        let opened = exporter.wait_for_ack();
        service
            .acknowledge_export_open_bytes(&opened.encode_fixed())
            .unwrap();
        service
            .acknowledge_export_open_bytes(&opened.encode_fixed())
            .expect("lost acknowledgement response must replay exactly");
        assert_eq!(
            service.export_lease_status(offer.generation()).unwrap(),
            ExportLeaseStatus::Opened
        );
        exporter.release_and_wait();
    }

    #[test]
    fn ocm_lease_restart_challenge_rejects_an_old_ack_at_a_reused_generation() {
        let directory = tempfile::tempdir().unwrap();
        let (old_offer, old_ack) = {
            let service = service(directory.path());
            let offer = service.arm_finalized_export(genesis(), b256(80)).unwrap();
            let mut exporter = spawn_read_only_exporter(directory.path(), offer);
            let ack = exporter.wait_for_ack();
            service.acknowledge_export_open(ack).unwrap();
            exporter.release_and_wait();
            (offer, ack)
        };

        let restarted = service(directory.path());
        let fresh = restarted.arm_finalized_export(genesis(), b256(81)).unwrap();
        assert_eq!(fresh.generation(), old_offer.generation());
        assert_ne!(fresh.encode_fixed(), old_offer.encode_fixed());
        assert!(matches!(
            restarted.acknowledge_export_open(old_ack),
            Err(TreeServiceError::ExportLeaseChallengeMismatch)
        ));
        assert_eq!(
            restarted.export_lease_status(fresh.generation()).unwrap(),
            ExportLeaseStatus::Pending
        );

        let mut exporter = spawn_read_only_exporter(directory.path(), fresh);
        let fresh_ack = exporter.wait_for_ack();
        restarted.acknowledge_export_open(fresh_ack).unwrap();
        exporter.release_and_wait();
    }

    #[test]
    fn ocm_lease_generation_rejects_stale_ack_and_marker_races() {
        let directory = tempfile::tempdir().unwrap();
        let service = service(directory.path());

        let first = service.arm_finalized_export(genesis(), b256(72)).unwrap();
        let mut first_exporter = spawn_read_only_exporter(directory.path(), first);
        let first_ack = first_exporter.wait_for_ack();
        service.acknowledge_export_open(first_ack).unwrap();
        first_exporter.release_and_wait();

        let provisional = service
            .open_parent(genesis_identity())
            .unwrap()
            .prepare_seal(1, &[], &[])
            .unwrap();
        let block_hash = b256(2);
        let root = provisional.new_root();
        service.publish_candidate(block_hash, provisional).unwrap();
        let marker = service
            .apply_finalized(1, block_hash, root)
            .unwrap()
            .marker();

        assert!(matches!(
            service.arm_finalized_export(genesis(), b256(73)),
            Err(TreeServiceError::ExportLeaseMarkerAdvanced { .. })
        ));

        let second = service.arm_finalized_export(marker, b256(74)).unwrap();
        assert!(second.generation() > first.generation());
        assert!(matches!(
            service.acknowledge_export_open(first_ack),
            Err(TreeServiceError::StaleExportLease { .. })
        ));
        let mut second_exporter = spawn_read_only_exporter(directory.path(), second);
        let second_ack = second_exporter.wait_for_ack();
        service.acknowledge_export_open(second_ack).unwrap();
        second_exporter.release_and_wait();
        assert_eq!(
            service.export_lease_status(second.generation()).unwrap(),
            ExportLeaseStatus::Opened
        );
    }

    #[test]
    fn ocm_lease_timeout_is_bounded_and_the_next_finalized_apply_continues() {
        let directory = tempfile::tempdir().unwrap();
        let timeout = std::time::Duration::from_millis(25);
        let service = service_with_lease_timeout(directory.path(), timeout);

        let provisional = service
            .open_parent(genesis_identity())
            .unwrap()
            .prepare_seal(1, &[], &[])
            .unwrap();
        let block_hash = b256(2);
        let root = provisional.new_root();
        service.publish_candidate(block_hash, provisional).unwrap();
        let offer = service.arm_finalized_export(genesis(), b256(75)).unwrap();

        let started = std::time::Instant::now();
        service.apply_finalized(1, block_hash, root).unwrap();
        let elapsed = started.elapsed();

        assert!(elapsed >= timeout);
        assert!(elapsed < std::time::Duration::from_secs(1));
        assert_eq!(
            service.export_lease_status(offer.generation()).unwrap(),
            ExportLeaseStatus::TimedOut
        );
        assert_eq!(service.finalized_marker().unwrap().height, 1);
    }
}
