//! Deterministic begin-block system-transaction primitives.
//!
//! represents runtime system transactions as ordinary signed Ethereum
//! legacy transaction artifacts so standard `eth_*` RPC methods can expose their
//! receipts and logs. The artifacts are consensus inputs only: execution uses
//! `transact_system_call` with `SYSTEM_ADDRESS` as the EVM caller, while the
//! signed transaction authenticates the proposer and fixes receipt/tx ordering.
//!
//! Current scope is begin-zone-only. All active system txs run before user
//! transactions in this order:
//!
//! 1. [`SystemTxKind::CertifiedParentAccounting`] for block `>= 2`.
//! 2. [`SystemTxKind::LateFinalizeCredits`] for block `>= 2` (mandatory
//!    inclusion-window phase: records late finalize credits and settles the
//!    matured `N+K` fee escrow).
//! 3. [`SystemTxKind::CycleTick`] for block `>= 1`.
//! 4. [`SystemTxKind::BoundaryOutcome`] iff the header carries a BoundaryOutcome
//!    (mandatory at block `1` under V2 for the genesis bootstrap).
//! 5. [`SystemTxKind::OracleSlashWindow`] for block `>= 1`.
//! 6. [`SystemTxKind::HookEvents`] for block `>= 1` (receipt container for
//!    whitelisted pre-exec hook logs; no lifecycle re-execution).
//!
//! ## V2 codec
//!
//! This module ships the V2 wire codec exclusively. V1 system-tx input bytes
//! (selectors `OSF1`/`OSC1`/`OSB1`/`OSO1` with version byte `1`) are rejected
//! at every height. Selectors are `OSA3`/`OSC2`/`OSB2`/`OSO2` and the version
//! byte is `2`. Greenfield rollout.
//!
//! The split helper below is structural-only: it rejects reserved-address
//! transactions outside the contiguous system zones and rejects wrong-zone or
//! out-of-order system tx kinds. [`validate_active_system_tx_set`] performs the
//! separate membership check for a concrete block number and BoundaryOutcome
//! presence.

use alloy_consensus::{SignableTransaction, Transaction as AlloyTransaction, TxLegacy};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Bytes, TxKind, B256, U256};
use reth_ethereum::TransactionSigned;
use reth_primitives_traits::SignedTransaction;

use crate::{
    consensus::DkgBoundaryArtifact,
    consensus_metadata::CertifiedParentAccountingMetadata,
    error::PrecompileError,
    reshare_artifact::{
        decode_boundary_artifact, decode_late_finalize_credits_artifact, encode_boundary_artifact,
        encode_late_finalize_credits_artifact, LateFinalizeCreditsArtifact,
    },
    tee_bootstrap::TeeBootstrapPayload,
};

pub use crate::addresses::OUTBE_SYSTEM_TX_ADDRESS;

/// Version byte immediately after the 4-byte kind selector in system-tx input.
///
/// Bumped to `2` for V2 Certified-Parent Accounting. Decoder
/// rejects any other value, so V1 bodies with `1` are rejected at every height.
pub const SYSTEM_TX_INPUT_VERSION: u8 = 2;

/// Selector for [`SystemTxKind::CertifiedParentAccounting`] (V2 OSA3).
pub const CERTIFIED_PARENT_ACCOUNTING_SELECTOR: [u8; 4] = [b'O', b'S', b'A', b'3'];
/// Selector for [`SystemTxKind::CycleTick`] (V2 OSC2).
pub const CYCLE_TICK_SELECTOR: [u8; 4] = [b'O', b'S', b'C', b'2'];
/// Selector for [`SystemTxKind::BoundaryOutcome`] (V2 OSB2).
pub const BOUNDARY_OUTCOME_SELECTOR: [u8; 4] = [b'O', b'S', b'B', b'2'];
/// Selector for [`SystemTxKind::OracleSlashWindow`] (V2 OSO2).
pub const ORACLE_SLASH_WINDOW_SELECTOR: [u8; 4] = [b'O', b'S', b'O', b'2'];
/// Selector for [`SystemTxKind::TeeBootstrap`] (V2 OST2, Phase 3b).
pub const TEE_BOOTSTRAP_SELECTOR: [u8; 4] = [b'O', b'S', b'T', b'2'];
/// Selector for [`SystemTxKind::LateFinalizeCredits`].
pub const LATE_FINALIZE_CREDITS_SELECTOR: [u8; 4] = [b'O', b'S', b'L', b'2'];
/// Selector for [`SystemTxKind::HookEvents`] (V2 OSH2).
pub const HOOK_EVENTS_SELECTOR: [u8; 4] = [b'O', b'S', b'H', b'2'];

/// Hard cap on system transactions emitted in a block.
pub const MAX_SYSTEM_TXS_PER_BLOCK: u8 = 16;

/// Highest block number that bootstraps the chain without Phase 1
/// (`CertifiedParentAccounting`). Block `n` runs Phase 1 in pre-execution iff
/// `n >= GENESIS_BOOTSTRAP_BLOCK_NUMBER + 1`. sets this to `1` so
/// Phase 1 begins at block `2` while block `1` still carries the genesis
/// `BoundaryOutcome` as its first begin-zone system transaction.
pub const GENESIS_BOOTSTRAP_BLOCK_NUMBER: u64 = 1;

/// Internal execution gas limit used by the Outbe-aware system-call path.
/// This value is never used as the visible `gas_limit` of the signed
/// transaction envelope; visible envelopes use their Ethereum intrinsic gas so
/// generic block replay/import tools do not reject them as exceeding the
/// block gas limit.
pub const SYSTEM_TX_ARTIFACT_GAS_LIMIT: u64 = 10_000_000_000;

/// Minimum visible gas charged by a system transaction envelope.
pub const SYSTEM_TX_VISIBLE_GAS_FLOOR: u64 = 21_000;

const SYSTEM_TX_ZERO_BYTE_GAS: u64 = 4;
const SYSTEM_TX_NON_ZERO_BYTE_GAS: u64 = 16;

/// Body-zone position of a system tx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyZone {
    BeginBlock,
    EndBlock,
}

/// begin_block system transaction kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SystemTxKind {
    CertifiedParentAccounting,
    /// mandatory begin-zone phase (blocks `>= 2`) that records verified
    /// late-finalize credits within the `K`-block inclusion window and settles
    /// matured per-block fee escrows. Ordered immediately after Phase 1 (CPA).
    LateFinalizeCredits,
    CycleTick,
    BoundaryOutcome,
    /// Phase 3b: one-time TEE registry bootstrap (present only in the bootstrap
    /// block; reads the same-block `CommitteeSnapshotStore` written by Phase 3a).
    TeeBootstrap,
    OracleSlashWindow,
    /// Receipt container for whitelisted pre-exec hook events (`Vote`, `Update`, …).
    HookEvents,
}

impl SystemTxKind {
    pub const fn selector(self) -> [u8; 4] {
        match self {
            Self::CertifiedParentAccounting => CERTIFIED_PARENT_ACCOUNTING_SELECTOR,
            Self::LateFinalizeCredits => LATE_FINALIZE_CREDITS_SELECTOR,
            Self::CycleTick => CYCLE_TICK_SELECTOR,
            Self::BoundaryOutcome => BOUNDARY_OUTCOME_SELECTOR,
            Self::TeeBootstrap => TEE_BOOTSTRAP_SELECTOR,
            Self::OracleSlashWindow => ORACLE_SLASH_WINDOW_SELECTOR,
            Self::HookEvents => HOOK_EVENTS_SELECTOR,
        }
    }

    pub const fn body_zone(self) -> BodyZone {
        // Current scope is begin-zone-only.
        BodyZone::BeginBlock
    }

    /// Whether a non-success EVM result (`Revert` / `Halt`) executing this
    /// begin-zone phase must fail the whole block instead of being recorded as a
    /// soft `status = 0` receipt and skipped.
    ///
    /// Consensus- and economic-critical phases are one-shot: their work cannot
    /// be retried by a later block, so a swallowed revert permanently loses it —
    /// stranded validator-fee escrow (`LateFinalizeCredits`), a dropped day of
    /// emission / terminal Metadosis (`CycleTick`), a skipped reshare / validator
    /// set activation (`BoundaryOutcome`), or unrecorded finalized-parent
    /// accounting (`CertifiedParentAccounting`). For these, a revert is a hard
    /// `BlockExecutionError`: the block is rejected on every validator
    /// deterministically (the revert is a function of committed chain state, the
    /// same for all proposers), honoring the "never silent stall / terminal
    /// failure is fatal" invariant rather than silently forfeiting real money or
    /// a protocol-state transition.
    ///
    /// `OracleSlashWindow` and `TeeBootstrap` stay soft: a revert there skips an
    /// oracle penalty or a one-time TEE registry bootstrap — an integrity/feature
    /// gap, not a money loss or a finality break — and halting the chain over it
    /// would be the worse failure mode.
    pub const fn revert_fails_block(self) -> bool {
        match self {
            Self::CertifiedParentAccounting
            | Self::LateFinalizeCredits
            | Self::CycleTick
            | Self::BoundaryOutcome => true,
            Self::TeeBootstrap | Self::OracleSlashWindow | Self::HookEvents => false,
        }
    }

    pub const fn begin_order(self) -> Option<u8> {
        match self {
            Self::CertifiedParentAccounting => Some(0),
            Self::LateFinalizeCredits => Some(1),
            Self::CycleTick => Some(2),
            Self::BoundaryOutcome => Some(3),
            Self::TeeBootstrap => Some(4),
            Self::OracleSlashWindow => Some(5),
            Self::HookEvents => Some(6),
        }
    }

    pub const fn end_order(self) -> Option<u8> {
        None
    }

    fn order_in(self, zone: BodyZone) -> Option<u8> {
        match zone {
            BodyZone::BeginBlock => self.begin_order(),
            BodyZone::EndBlock => self.end_order(),
        }
    }
}

/// Versioned calldata body system transactions.
///
/// completed the wire-format swap: Phase 1 system-tx input now
/// carries the V2 slim
/// [`crate::consensus_metadata::CertifiedParentAccountingMetadata`]
/// instead of the V1 `ConsensusMetadataEnvelope`. The V2 payload omits the
/// dead `encoded_finalize_votes` field (V2 signer bitmap is authoritative)
/// and carries the V2 `committee_set_hash`, `vrf_material_version`,
/// `vrf_group_public_key_hash`, and `proof_kind` fields the verifier needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemTxInputV2 {
    CertifiedParentAccounting {
        metadata: CertifiedParentAccountingMetadata,
    },
    LateFinalizeCredits {
        artifact: LateFinalizeCreditsArtifact,
    },
    CycleTick,
    BoundaryOutcome {
        artifact: DkgBoundaryArtifact,
    },
    TeeBootstrap {
        payload: TeeBootstrapPayload,
    },
    OracleSlashWindow,
    HookEvents,
}

impl SystemTxInputV2 {
    pub const fn kind(&self) -> SystemTxKind {
        match self {
            Self::CertifiedParentAccounting { .. } => SystemTxKind::CertifiedParentAccounting,
            Self::LateFinalizeCredits { .. } => SystemTxKind::LateFinalizeCredits,
            Self::CycleTick => SystemTxKind::CycleTick,
            Self::BoundaryOutcome { .. } => SystemTxKind::BoundaryOutcome,
            Self::TeeBootstrap { .. } => SystemTxKind::TeeBootstrap,
            Self::OracleSlashWindow => SystemTxKind::OracleSlashWindow,
            Self::HookEvents => SystemTxKind::HookEvents,
        }
    }

    /// Encode as `selector(4) || version(1) || canonical_body`.
    pub fn encode(&self) -> Result<Bytes, SystemTxError> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.kind().selector());
        out.push(SYSTEM_TX_INPUT_VERSION);
        match self {
            Self::CertifiedParentAccounting { metadata } => {
                out.extend_from_slice(
                    metadata
                        .encode()
                        .map_err(SystemTxError::from_precompile)?
                        .as_ref(),
                );
            }
            Self::CycleTick | Self::OracleSlashWindow | Self::HookEvents => {}
            Self::LateFinalizeCredits { artifact } => {
                // Empty batches encode to empty bytes — the mandatory tx then
                // carries an empty body and still drives the window-close settle.
                out.extend_from_slice(
                    encode_late_finalize_credits_artifact(artifact)
                        .map_err(SystemTxError::from_precompile)?
                        .as_ref(),
                );
            }
            Self::BoundaryOutcome { artifact } => {
                out.extend_from_slice(
                    encode_boundary_artifact(artifact)
                        .map_err(SystemTxError::from_precompile)?
                        .as_ref(),
                );
            }
            Self::TeeBootstrap { payload } => {
                out.extend_from_slice(
                    payload
                        .encode()
                        .map_err(SystemTxError::from_precompile)?
                        .as_ref(),
                );
            }
        }
        Ok(Bytes::from(out))
    }

    pub fn decode(data: &[u8]) -> Result<Self, SystemTxError> {
        if data.len() < 5 {
            return Err(SystemTxError::InputTooShort { len: data.len() });
        }
        let selector = selector_from_input(data)?;
        let kind = system_tx_kind_from_selector(selector)?;
        let version = data[4];
        if version != SYSTEM_TX_INPUT_VERSION {
            return Err(SystemTxError::UnsupportedVersion(version));
        }
        let body = &data[5..];
        match kind {
            SystemTxKind::CertifiedParentAccounting => Ok(Self::CertifiedParentAccounting {
                metadata: CertifiedParentAccountingMetadata::decode(body)
                    .map_err(SystemTxError::from_precompile)?,
            }),
            SystemTxKind::LateFinalizeCredits => Ok(Self::LateFinalizeCredits {
                // Empty body ⇒ empty (no-op) artifact; the matured-window close
                // still runs on execution.
                artifact: decode_late_finalize_credits_artifact(body)
                    .map_err(SystemTxError::from_precompile)?
                    .unwrap_or_default(),
            }),
            SystemTxKind::CycleTick => {
                if !body.is_empty() {
                    return Err(SystemTxError::UnexpectedBody {
                        kind,
                        len: body.len(),
                    });
                }
                Ok(Self::CycleTick)
            }
            SystemTxKind::OracleSlashWindow => {
                if !body.is_empty() {
                    return Err(SystemTxError::UnexpectedBody {
                        kind,
                        len: body.len(),
                    });
                }
                Ok(Self::OracleSlashWindow)
            }
            SystemTxKind::HookEvents => {
                if !body.is_empty() {
                    return Err(SystemTxError::UnexpectedBody {
                        kind,
                        len: body.len(),
                    });
                }
                Ok(Self::HookEvents)
            }
            SystemTxKind::BoundaryOutcome => {
                let Some(artifact) =
                    decode_boundary_artifact(body).map_err(SystemTxError::from_precompile)?
                else {
                    return Err(SystemTxError::MissingBoundaryOutcomeBody);
                };
                Ok(Self::BoundaryOutcome { artifact })
            }
            SystemTxKind::TeeBootstrap => Ok(Self::TeeBootstrap {
                payload: TeeBootstrapPayload::decode(body)
                    .map_err(SystemTxError::from_precompile)?,
            }),
        }
    }
}

/// Executor cursor that names the next system-tx phase the block executor
/// expects to consume. introduces this enum so phase routing no
/// longer derives from `self.inner.receipts.len()` once Phase 1 is committed
/// in `apply_pre_execution_changes` (pre-execution) rather than the main tx
/// loop.
///
/// Invariants:
/// - On block `1` (genesis bootstrap), cursor starts at `CycleTick { body_index: 0 }`.
/// - On block `n >= GENESIS_BOOTSTRAP_BLOCK_NUMBER + 1`, cursor starts at
///   `Phase1Preexecuted { body_index: 0, tx_hash, receipt_index: 0 }` after
///   the executor has pre-built and committed the Phase 1 system tx.
/// - The cursor advances exactly once per consumed begin-zone system tx; on
///   reaching the first non-system tx (or block end) it is `UserTxs`.
/// - Encoded purely in-memory: never serialised, hashed, or part of any
///   wire format or `header.extra_data`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemTxPhase {
    /// Phase 1 (`CertifiedParentAccounting`) has been built, verified, and
    /// committed in pre-execution. The proposer-supplied body[`body_index`]
    /// must match `tx_hash` byte-for-byte and is validated without
    /// re-execution.
    Phase1Preexecuted {
        body_index: u8,
        tx_hash: B256,
        receipt_index: u8,
    },
    /// Next expected begin-zone tx is the mandatory (blocks `>= 2`)
    /// `LateFinalizeCredits` phase, ordered immediately after Phase 1.
    LateFinalizeCredits { body_index: u8 },
    /// Next expected begin-zone tx is Phase 2 (`CycleTick`).
    CycleTick { body_index: u8 },
    /// Next expected begin-zone tx is the optional Phase 3
    /// (`BoundaryOutcome`); only emitted when the header carries a boundary
    /// outcome artifact.
    BoundaryOutcomeOptional { body_index: u8 },
    /// Next expected begin-zone tx is the optional Phase 3b
    /// (`TeeBootstrap`); present only in the one-time bootstrap block.
    TeeBootstrapOptional { body_index: u8 },
    /// Next expected begin-zone tx is Phase 4 (`OracleSlashWindow`).
    OracleSlashWindow { body_index: u8 },
    /// Next expected begin-zone tx is the mandatory `HookEvents` receipt carrier.
    HookEvents { body_index: u8 },
    /// All begin-zone system txs consumed; only user transactions remain.
    UserTxs,
}

impl SystemTxPhase {
    /// Initial cursor for `block_number` given the configured genesis
    /// bootstrap threshold. Block `1` has no Phase 1 (genesis bootstrap),
    /// so its cursor starts at `CycleTick { body_index: 0 }`. Block `n` with
    /// `n >= genesis_bootstrap_block_number + 1` starts at
    /// `Phase1Preexecuted { body_index: 0, .. }` with a zero placeholder
    /// `tx_hash`; the executor overwrites the placeholder after the Phase 1
    /// preflight commits.
    pub const fn initial_for_block(block_number: u64, genesis_bootstrap_block_number: u64) -> Self {
        if block_number > genesis_bootstrap_block_number
            && block_number > GENESIS_BOOTSTRAP_BLOCK_NUMBER
        {
            Self::Phase1Preexecuted {
                body_index: 0,
                tx_hash: B256::ZERO,
                receipt_index: 0,
            }
        } else {
            Self::CycleTick { body_index: 0 }
        }
    }

    /// The begin-zone system-tx kind the cursor expects to consume next, or
    /// `None` if the cursor is `UserTxs`.
    pub const fn expected_kind(&self) -> Option<SystemTxKind> {
        match self {
            Self::Phase1Preexecuted { .. } => Some(SystemTxKind::CertifiedParentAccounting),
            Self::LateFinalizeCredits { .. } => Some(SystemTxKind::LateFinalizeCredits),
            Self::CycleTick { .. } => Some(SystemTxKind::CycleTick),
            Self::BoundaryOutcomeOptional { .. } => Some(SystemTxKind::BoundaryOutcome),
            Self::TeeBootstrapOptional { .. } => Some(SystemTxKind::TeeBootstrap),
            Self::OracleSlashWindow { .. } => Some(SystemTxKind::OracleSlashWindow),
            Self::HookEvents { .. } => Some(SystemTxKind::HookEvents),
            Self::UserTxs => None,
        }
    }

    /// Body index of the next expected begin-zone system tx, or `None` if
    /// the cursor is `UserTxs`.
    pub const fn body_index(&self) -> Option<u8> {
        match self {
            Self::Phase1Preexecuted { body_index, .. }
            | Self::LateFinalizeCredits { body_index }
            | Self::CycleTick { body_index }
            | Self::BoundaryOutcomeOptional { body_index }
            | Self::TeeBootstrapOptional { body_index }
            | Self::OracleSlashWindow { body_index }
            | Self::HookEvents { body_index } => Some(*body_index),
            Self::UserTxs => None,
        }
    }

    /// Advance the cursor after a successful begin-zone system-tx commit.
    /// Given the cursor's current variant and whether the current block
    /// carries a boundary-outcome artifact, returns the next cursor
    /// position. Once Oracle slash-window is consumed (or directly after
    /// CycleTick / BoundaryOutcome on block 1's degenerate path), the
    /// cursor transitions to `UserTxs`.
    ///
    /// `has_boundary_outcome` controls whether Phase 3
    /// (`BoundaryOutcomeOptional`) is interleaved between `CycleTick` and
    /// `OracleSlashWindow`. The flag mirrors the block-1 invariant:
    /// at block 1, V2 always carries a boundary outcome (genesis bootstrap),
    /// so `has_boundary_outcome = true` is the canonical path there.
    ///
    /// `has_tee_bootstrap` interleaves the optional Phase 3b
    /// (`TeeBootstrapOptional`) after `BoundaryOutcome` (or after
    /// `CycleTick` if no boundary outcome) and before `OracleSlashWindow`. It is
    /// true only in the one-time bootstrap block.
    pub const fn advance_after_commit(
        self,
        has_boundary_outcome: bool,
        has_tee_bootstrap: bool,
    ) -> Self {
        match self {
            Self::Phase1Preexecuted { body_index, .. } => Self::LateFinalizeCredits {
                body_index: body_index + 1,
            },
            Self::LateFinalizeCredits { body_index } => Self::CycleTick {
                body_index: body_index + 1,
            },
            Self::CycleTick { body_index } => {
                if has_boundary_outcome {
                    Self::BoundaryOutcomeOptional {
                        body_index: body_index + 1,
                    }
                } else if has_tee_bootstrap {
                    Self::TeeBootstrapOptional {
                        body_index: body_index + 1,
                    }
                } else {
                    Self::OracleSlashWindow {
                        body_index: body_index + 1,
                    }
                }
            }
            Self::BoundaryOutcomeOptional { body_index } => {
                if has_tee_bootstrap {
                    Self::TeeBootstrapOptional {
                        body_index: body_index + 1,
                    }
                } else {
                    Self::OracleSlashWindow {
                        body_index: body_index + 1,
                    }
                }
            }
            Self::TeeBootstrapOptional { body_index } => Self::OracleSlashWindow {
                body_index: body_index + 1,
            },
            Self::OracleSlashWindow { body_index } => Self::HookEvents {
                body_index: body_index + 1,
            },
            Self::HookEvents { .. } | Self::UserTxs => Self::UserTxs,
        }
    }
}

/// Structural split of block transactions into system begin-prefix, user middle,
/// and system end-suffix.
#[derive(Debug, Clone)]
pub struct SystemTxLayout<'a> {
    pub begin: Vec<&'a TransactionSigned>,
    pub user: Vec<&'a TransactionSigned>,
    pub end: Vec<&'a TransactionSigned>,
}

impl<'a> SystemTxLayout<'a> {
    pub fn is_empty(&self) -> bool {
        self.begin.is_empty() && self.user.is_empty() && self.end.is_empty()
    }

    pub fn system_tx_count(&self) -> usize {
        self.begin.len() + self.end.len()
    }

    pub fn begin_block_kinds(&self) -> Result<Vec<SystemTxKind>, SystemTxError> {
        self.begin
            .iter()
            .map(|tx| decode_system_tx_kind(tx))
            .collect()
    }

    pub fn end_block_kinds(&self) -> Result<Vec<SystemTxKind>, SystemTxError> {
        self.end
            .iter()
            .map(|tx| decode_system_tx_kind(tx))
            .collect()
    }

    /// True if the begin zone contains a system tx of `kind`. Used to derive the
    /// layout-signaled optional-phase flags (e.g. the one-time
    /// [`SystemTxKind::TeeBootstrap`]). A decode failure — which a
    /// successful [`split_system_layout`] precludes — is treated as absent.
    pub fn has_begin_kind(&self, kind: SystemTxKind) -> bool {
        self.begin_block_kinds()
            .map(|kinds| kinds.contains(&kind))
            .unwrap_or(false)
    }
}

/// Errors returned by deterministic system-tx helpers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SystemTxError {
    #[error("system tx input too short: {len} bytes")]
    InputTooShort { len: usize },
    #[error("unknown system tx selector: 0x{0:02x?}")]
    UnknownSelector([u8; 4]),
    #[error("unsupported system tx input version: {0}")]
    UnsupportedVersion(u8),
    #[error("unexpected body for {kind:?}: {len} bytes")]
    UnexpectedBody { kind: SystemTxKind, len: usize },
    #[error("missing boundary outcome body")]
    MissingBoundaryOutcomeBody,
    #[error("system tx codec error: {0}")]
    Codec(String),
    #[error("calldata kind mismatch: expected {expected:?}, actual {actual:?}")]
    CalldataKindMismatch {
        expected: SystemTxKind,
        actual: SystemTxKind,
    },
    #[error("system tx ordinal {ordinal} exceeds max {max}")]
    OrdinalTooLarge { ordinal: u8, max: u8 },
    #[error("system tx nonce overflow for block {block_number}, ordinal {ordinal}")]
    NonceOverflow { block_number: u64, ordinal: u8 },
    #[error("system tx visible gas overflow for calldata length {len}")]
    VisibleGasOverflow { len: usize },
    #[error("system tx kind {kind:?} is in {actual:?} zone, expected {expected:?}")]
    SystemTxInWrongZone {
        kind: SystemTxKind,
        expected: BodyZone,
        actual: BodyZone,
    },
    #[error(
        "system tx kind order violation in {zone:?}: previous {previous:?}, current {current:?}"
    )]
    OutOfOrder {
        zone: BodyZone,
        previous: SystemTxKind,
        current: SystemTxKind,
    },
    #[error("reserved system tx found in user zone at transaction index {index}")]
    MidBlockSystemTx { index: usize },
    #[error("too many system txs in block: {actual} > {max}")]
    TooManySystemTxs { actual: usize, max: u8 },
    #[error(
        "active system tx set mismatch: expected {expected:?}, actual begin {actual_begin:?}, actual end {actual_end:?}"
    )]
    ActiveSystemTxSetMismatch {
        expected: Vec<SystemTxKind>,
        actual_begin: Vec<SystemTxKind>,
        actual_end: Vec<SystemTxKind>,
    },
    #[error(
        "V2 genesis bootstrap: block 1 must carry a BoundaryOutcome system tx (got has_boundary_outcome = false)"
    )]
    V2Block1MissingBoundaryOutcome,
    #[error("phase1 tx decode failed: {0}")]
    Phase1TxDecode(String),
    #[error("phase1 tx signature recovery failed: {0}")]
    Phase1SignatureRecovery(String),
    #[error("phase1 tx must call OUTBE_SYSTEM_TX_ADDRESS")]
    Phase1WrongRecipient,
    #[error("phase1 tx must not transfer native value")]
    Phase1NonZeroValue,
    #[error("phase1 tx chain_id mismatch: expected {expected}, actual {actual:?}")]
    Phase1ChainIdMismatch { expected: u64, actual: Option<u64> },
    #[error("phase1 tx nonce mismatch: expected {expected}, actual {actual}")]
    Phase1NonceMismatch { expected: u64, actual: u64 },
    #[error("phase1 tx gas_limit mismatch: expected {expected}, actual {actual}")]
    Phase1GasLimitMismatch { expected: u64, actual: u64 },
    #[error("phase1 tx calldata mismatch")]
    Phase1CalldataMismatch,
    #[error("phase1 tx signature_hash mismatch")]
    Phase1SignatureHashMismatch,
    #[error("phase1 tx signer mismatch: expected {expected}, actual {actual}")]
    Phase1SignerMismatch {
        expected: alloy_primitives::Address,
        actual: alloy_primitives::Address,
    },
}

impl SystemTxError {
    fn from_precompile(error: PrecompileError) -> Self {
        Self::Codec(error.to_string())
    }
}

pub fn system_tx_kind_from_selector(selector: [u8; 4]) -> Result<SystemTxKind, SystemTxError> {
    match selector {
        CERTIFIED_PARENT_ACCOUNTING_SELECTOR => Ok(SystemTxKind::CertifiedParentAccounting),
        LATE_FINALIZE_CREDITS_SELECTOR => Ok(SystemTxKind::LateFinalizeCredits),
        CYCLE_TICK_SELECTOR => Ok(SystemTxKind::CycleTick),
        BOUNDARY_OUTCOME_SELECTOR => Ok(SystemTxKind::BoundaryOutcome),
        TEE_BOOTSTRAP_SELECTOR => Ok(SystemTxKind::TeeBootstrap),
        ORACLE_SLASH_WINDOW_SELECTOR => Ok(SystemTxKind::OracleSlashWindow),
        HOOK_EVENTS_SELECTOR => Ok(SystemTxKind::HookEvents),
        other => Err(SystemTxError::UnknownSelector(other)),
    }
}

pub fn selector_from_input(input: &[u8]) -> Result<[u8; 4], SystemTxError> {
    let Some(bytes) = input.get(..4) else {
        return Err(SystemTxError::InputTooShort { len: input.len() });
    };
    bytes
        .try_into()
        .map_err(|_| SystemTxError::InputTooShort { len: input.len() })
}

pub fn is_reserved_system_tx<T>(tx: &T) -> bool
where
    T: AlloyTransaction + ?Sized,
{
    tx.to() == Some(OUTBE_SYSTEM_TX_ADDRESS)
}

pub fn decode_system_tx_kind(tx: &TransactionSigned) -> Result<SystemTxKind, SystemTxError> {
    let input = SystemTxInputV2::decode(tx.input().as_ref())?;
    Ok(input.kind())
}

pub fn system_tx_nonce(block_number: u64, ordinal: u8) -> Result<u64, SystemTxError> {
    if ordinal >= MAX_SYSTEM_TXS_PER_BLOCK {
        return Err(SystemTxError::OrdinalTooLarge {
            ordinal,
            max: MAX_SYSTEM_TXS_PER_BLOCK,
        });
    }
    block_number
        .checked_mul(u64::from(MAX_SYSTEM_TXS_PER_BLOCK))
        .and_then(|base| base.checked_add(u64::from(ordinal)))
        .ok_or(SystemTxError::NonceOverflow {
            block_number,
            ordinal,
        })
}

/// Ethereum-compatible visible gas limit for a system tx envelope.
///
/// Outbe executes the system precompile with
/// [`SYSTEM_TX_ARTIFACT_GAS_LIMIT`] internally, but the signed transaction
/// stored in the block body only needs to be valid as an Ethereum legacy
/// envelope. Charging intrinsic calldata gas keeps system txs visible to
/// generic replay/import tooling without exposing the 100M internal lane.
pub fn system_tx_visible_gas_limit(calldata: &[u8]) -> Result<u64, SystemTxError> {
    calldata
        .iter()
        .try_fold(SYSTEM_TX_VISIBLE_GAS_FLOOR, |gas, byte| {
            let byte_gas = if *byte == 0 {
                SYSTEM_TX_ZERO_BYTE_GAS
            } else {
                SYSTEM_TX_NON_ZERO_BYTE_GAS
            };
            gas.checked_add(byte_gas)
        })
        .ok_or(SystemTxError::VisibleGasOverflow {
            len: calldata.len(),
        })
}

pub fn build_unsigned_system_tx(
    kind: SystemTxKind,
    ordinal: u8,
    block_number: u64,
    chain_id: u64,
    calldata: Bytes,
) -> Result<TxLegacy, SystemTxError> {
    let actual = SystemTxInputV2::decode(calldata.as_ref())?.kind();
    if actual != kind {
        return Err(SystemTxError::CalldataKindMismatch {
            expected: kind,
            actual,
        });
    }

    Ok(TxLegacy {
        chain_id: Some(chain_id),
        nonce: system_tx_nonce(block_number, ordinal)?,
        gas_price: 0,
        gas_limit: system_tx_visible_gas_limit(calldata.as_ref())?,
        to: TxKind::Call(OUTBE_SYSTEM_TX_ADDRESS),
        value: U256::ZERO,
        input: calldata,
    })
}

/// Validate that a signed Phase 1 system transaction is the canonical
/// `CertifiedParentAccounting` witness for `expected_calldata`.
pub fn validate_phase1_witness_against(
    tx: &TransactionSigned,
    expected_calldata: &[u8],
    expected_proposer: alloy_primitives::Address,
    chain_id: u64,
    block_number: u64,
) -> Result<B256, SystemTxError> {
    let tx_hash = validate_phase1_envelope_shape(tx, expected_calldata, chain_id, block_number)?;
    let signer = tx
        .try_recover()
        .map_err(|error| SystemTxError::Phase1SignatureRecovery(error.to_string()))?;
    if signer != expected_proposer {
        return Err(SystemTxError::Phase1SignerMismatch {
            expected: expected_proposer,
            actual: signer,
        });
    }
    Ok(tx_hash)
}

/// Decode and validate a signed Phase 1 transaction from evidence bytes,
/// returning the recovered proposer and canonical calldata.
pub fn recover_phase1_proposer(
    tx_bytes: &[u8],
    chain_id: u64,
    block_number: u64,
) -> Result<(alloy_primitives::Address, Bytes), SystemTxError> {
    let mut tx_slice = tx_bytes;
    let tx = TransactionSigned::decode_2718(&mut tx_slice)
        .map_err(|error| SystemTxError::Phase1TxDecode(error.to_string()))?;
    if !tx_slice.is_empty() {
        return Err(SystemTxError::Phase1TxDecode(format!(
            "phase1 tx has {} trailing bytes after EIP-2718 envelope",
            tx_slice.len()
        )));
    }
    let calldata = tx.input().clone();
    validate_phase1_envelope_shape(&tx, calldata.as_ref(), chain_id, block_number)?;
    let proposer = tx
        .try_recover()
        .map_err(|error| SystemTxError::Phase1SignatureRecovery(error.to_string()))?;
    Ok((proposer, calldata))
}

fn validate_phase1_envelope_shape(
    tx: &TransactionSigned,
    calldata: &[u8],
    chain_id: u64,
    block_number: u64,
) -> Result<B256, SystemTxError> {
    if tx.to() != Some(OUTBE_SYSTEM_TX_ADDRESS) {
        return Err(SystemTxError::Phase1WrongRecipient);
    }
    if tx.value() != U256::ZERO {
        return Err(SystemTxError::Phase1NonZeroValue);
    }
    if tx.chain_id() != Some(chain_id) {
        return Err(SystemTxError::Phase1ChainIdMismatch {
            expected: chain_id,
            actual: tx.chain_id(),
        });
    }
    let expected_nonce = system_tx_nonce(block_number, 0)?;
    if tx.nonce() != expected_nonce {
        return Err(SystemTxError::Phase1NonceMismatch {
            expected: expected_nonce,
            actual: tx.nonce(),
        });
    }
    let expected_gas_limit = system_tx_visible_gas_limit(calldata)?;
    if tx.gas_limit() != expected_gas_limit {
        return Err(SystemTxError::Phase1GasLimitMismatch {
            expected: expected_gas_limit,
            actual: tx.gas_limit(),
        });
    }
    if tx.input().as_ref() != calldata {
        return Err(SystemTxError::Phase1CalldataMismatch);
    }
    let actual = SystemTxInputV2::decode(calldata)?.kind();
    if actual != SystemTxKind::CertifiedParentAccounting {
        return Err(SystemTxError::CalldataKindMismatch {
            expected: SystemTxKind::CertifiedParentAccounting,
            actual,
        });
    }
    let expected_unsigned = build_unsigned_system_tx(
        SystemTxKind::CertifiedParentAccounting,
        0,
        block_number,
        chain_id,
        Bytes::copy_from_slice(calldata),
    )?;
    if tx.signature_hash() != expected_unsigned.signature_hash() {
        return Err(SystemTxError::Phase1SignatureHashMismatch);
    }
    Ok(tx.signature_hash())
}

pub fn split_system_layout<'a>(
    txs: &'a [TransactionSigned],
) -> Result<SystemTxLayout<'a>, SystemTxError> {
    let mut begin = Vec::new();
    let mut prefix_end = 0usize;
    let mut previous_begin = None;

    while prefix_end < txs.len() && is_reserved_system_tx(&txs[prefix_end]) {
        let kind = decode_system_tx_kind(&txs[prefix_end])?;
        ensure_system_tx_in_zone(kind, BodyZone::BeginBlock)?;
        ensure_monotonic(BodyZone::BeginBlock, previous_begin, kind)?;
        previous_begin = Some(kind);
        begin.push(&txs[prefix_end]);
        prefix_end += 1;
    }

    let mut suffix_entries: Vec<(usize, SystemTxKind)> = Vec::new();
    let mut suffix_start = txs.len();
    while suffix_start > prefix_end && is_reserved_system_tx(&txs[suffix_start - 1]) {
        suffix_start -= 1;
        let kind = decode_system_tx_kind(&txs[suffix_start])?;
        ensure_system_tx_in_zone(kind, BodyZone::EndBlock)?;
        suffix_entries.push((suffix_start, kind));
    }
    suffix_entries.reverse();

    let mut previous_end = None;
    let mut end = Vec::with_capacity(suffix_entries.len());
    for (index, kind) in suffix_entries {
        ensure_monotonic(BodyZone::EndBlock, previous_end, kind)?;
        previous_end = Some(kind);
        end.push(&txs[index]);
    }

    for (offset, tx) in txs[prefix_end..suffix_start].iter().enumerate() {
        if is_reserved_system_tx(tx) {
            return Err(SystemTxError::MidBlockSystemTx {
                index: prefix_end + offset,
            });
        }
    }

    Ok(SystemTxLayout {
        begin,
        user: txs[prefix_end..suffix_start].iter().collect(),
        end,
    })
}

pub fn expected_begin_block_kinds(
    block_number: u64,
    has_boundary_outcome: bool,
    has_tee_bootstrap: bool,
) -> Vec<SystemTxKind> {
    let mut expected = match block_number {
        0 => Vec::new(),
        1 => vec![SystemTxKind::CycleTick],
        _ => vec![
            SystemTxKind::CertifiedParentAccounting,
            // mandatory inclusion-window phase, ordered after Phase 1
            // and before CycleTick for every block >= 2 (empty when nothing to
            // credit; its body still drives the matured-window settlement).
            SystemTxKind::LateFinalizeCredits,
            SystemTxKind::CycleTick,
        ],
    };
    if block_number > 0 && has_boundary_outcome {
        expected.push(SystemTxKind::BoundaryOutcome);
    }
    if block_number > 0 && has_tee_bootstrap {
        expected.push(SystemTxKind::TeeBootstrap);
    }
    if block_number > 0 {
        expected.push(SystemTxKind::OracleSlashWindow);
        expected.push(SystemTxKind::HookEvents);
    }
    expected
}

pub fn validate_active_system_tx_set(
    layout: &SystemTxLayout<'_>,
    block_number: u64,
    has_boundary_outcome: bool,
    has_tee_bootstrap: bool,
) -> Result<(), SystemTxError> {
    let actual = layout.system_tx_count();
    if actual > usize::from(MAX_SYSTEM_TXS_PER_BLOCK) {
        return Err(SystemTxError::TooManySystemTxs {
            actual,
            max: MAX_SYSTEM_TXS_PER_BLOCK,
        });
    }

    // / V2: block 1 mandatorily carries the genesis bootstrap
    // BoundaryOutcome. Reject the layout if the proposer omitted it; the
    // expected-kinds list rejection below is structural, this rejection is
    // protocol-level for V2 greenfield.
    if block_number == 1 && !has_boundary_outcome {
        return Err(SystemTxError::V2Block1MissingBoundaryOutcome);
    }

    let expected =
        expected_begin_block_kinds(block_number, has_boundary_outcome, has_tee_bootstrap);
    let actual_begin = layout.begin_block_kinds()?;
    let actual_end = layout.end_block_kinds()?;
    if actual_begin != expected || !actual_end.is_empty() {
        return Err(SystemTxError::ActiveSystemTxSetMismatch {
            expected,
            actual_begin,
            actual_end,
        });
    }
    Ok(())
}

fn ensure_system_tx_in_zone(kind: SystemTxKind, actual: BodyZone) -> Result<(), SystemTxError> {
    let expected = kind.body_zone();
    if expected != actual {
        return Err(SystemTxError::SystemTxInWrongZone {
            kind,
            expected,
            actual,
        });
    }
    Ok(())
}

fn ensure_monotonic(
    zone: BodyZone,
    previous: Option<SystemTxKind>,
    current: SystemTxKind,
) -> Result<(), SystemTxError> {
    let Some(previous) = previous else {
        return Ok(());
    };
    let previous_order = previous
        .order_in(zone)
        .ok_or(SystemTxError::SystemTxInWrongZone {
            kind: previous,
            expected: previous.body_zone(),
            actual: zone,
        })?;
    let current_order = current
        .order_in(zone)
        .ok_or(SystemTxError::SystemTxInWrongZone {
            kind: current,
            expected: current.body_zone(),
            actual: zone,
        })?;
    if current_order <= previous_order {
        return Err(SystemTxError::OutOfOrder {
            zone,
            previous,
            current,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ReshareResult;
    use crate::signer::OutbeEvmSigner;
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{address, Signature, B256};

    const CHAIN_ID: u64 = 2026;

    fn sample_metadata() -> CertifiedParentAccountingMetadata {
        CertifiedParentAccountingMetadata {
            finalized_block_number: 41,
            finalized_block_hash: B256::repeat_byte(0x41),
            finalized_epoch: 7,
            finalized_view: 42,
            parent_view: 41,
            ordered_committee: vec![address!("0x1111111111111111111111111111111111111111")],
            signer_bitmap: vec![1],
            proof: Bytes::from_static(b"cert"),
            committee_set_hash: B256::repeat_byte(0x77),
            vrf_material_version: 3,
            vrf_group_public_key_hash: B256::repeat_byte(0x88),
            proof_kind: crate::consensus_metadata::ParentParticipationProof::Finalization,
            // V2 contract requires `missed_proposers` to be empty;
            // this test fixture keeps it empty to stay consistent with the
            // verifier rule.
            missed_proposers: Vec::new(),
        }
    }

    fn sample_boundary() -> DkgBoundaryArtifact {
        DkgBoundaryArtifact {
            epoch: 8,
            dkg_cycle: 2,
            freeze_height: 40,
            planned_activation_height: 42,
            target_set_hash: B256::repeat_byte(0x33),
            vrf_material_version: 3,
            vrf_group_public_key: B256::repeat_byte(0x44),
            vrf_group_public_key_bytes: Bytes::from_static(&[0x44u8; 96]),
            committee_set_hash: B256::repeat_byte(0x66),
            is_validator_set_change: true,
            outcome: Bytes::from_static(b"boundary"),
            is_full_dkg: false,
            tee_recipient_pubkeys: Vec::new(),
            tee_reshare_registrations: Vec::new(),
            endorsement_signature: alloy_primitives::Bytes::new(),
            reshare: ReshareResult {
                new_active_set: vec![address!("0x3333333333333333333333333333333333333333")],
                active_set_hash: B256::repeat_byte(0x55),
            },
        }
    }

    fn sample_tee_bootstrap() -> crate::tee_bootstrap::TeeBootstrapPayload {
        use crate::tee_bootstrap::{
            TeeBootstrapPayload, TeeRegistrationBundle, TeeValidatorSignature,
        };
        let validator = address!("0x2222222222222222222222222222222222222222");
        TeeBootstrapPayload {
            policy_hash: B256::repeat_byte(0xB1),
            committee_snapshot_hash: B256::repeat_byte(0xB2),
            committee_snapshot_block: 1,
            key_epoch: 0,
            tribute_offer_epoch: 0,
            dkg_transcript_hash: B256::repeat_byte(0xB3),
            tribute_offer_public_key: B256::repeat_byte(0xB4),
            tribute_offer_group_public_key: alloy_primitives::Bytes::from(vec![0xB5; 96]),
            registrations: vec![TeeRegistrationBundle {
                validator,
                recipient_x25519: B256::repeat_byte(0x21),
                attestation_pub: B256::repeat_byte(0x22),
                noise_static_pub: B256::repeat_byte(0x23),
                mrenclave: B256::repeat_byte(0x24),
                mrsigner: B256::repeat_byte(0x25),
                isv_svn: 3,
                keys_hash: B256::repeat_byte(0x26),
            }],
            policy: crate::tee_bootstrap::TeePolicy::default(),
            validator_signatures: vec![TeeValidatorSignature {
                validator,
                signature: [0x41; 65],
            }],
        }
    }

    fn input_for(kind: SystemTxKind) -> SystemTxInputV2 {
        match kind {
            SystemTxKind::CertifiedParentAccounting => SystemTxInputV2::CertifiedParentAccounting {
                metadata: sample_metadata(),
            },
            SystemTxKind::LateFinalizeCredits => SystemTxInputV2::LateFinalizeCredits {
                artifact: LateFinalizeCreditsArtifact::default(),
            },
            SystemTxKind::CycleTick => SystemTxInputV2::CycleTick,
            SystemTxKind::BoundaryOutcome => SystemTxInputV2::BoundaryOutcome {
                artifact: sample_boundary(),
            },
            SystemTxKind::TeeBootstrap => SystemTxInputV2::TeeBootstrap {
                payload: sample_tee_bootstrap(),
            },
            SystemTxKind::OracleSlashWindow => SystemTxInputV2::OracleSlashWindow,
            SystemTxKind::HookEvents => SystemTxInputV2::HookEvents,
        }
    }

    fn system_tx(kind: SystemTxKind, ordinal: u8, block_number: u64) -> TransactionSigned {
        let input = input_for(kind).encode().expect("system input encodes");
        build_unsigned_system_tx(kind, ordinal, block_number, CHAIN_ID, input)
            .expect("system tx builds")
            .into_signed(Signature::test_signature())
            .into()
    }

    fn user_tx() -> TransactionSigned {
        TxLegacy {
            chain_id: Some(CHAIN_ID),
            nonce: 0,
            gas_price: 0,
            gas_limit: 21_000,
            to: TxKind::Call(address!("0x4444444444444444444444444444444444444444")),
            value: U256::ZERO,
            input: Bytes::new(),
        }
        .into_signed(Signature::test_signature())
        .into()
    }

    fn test_signer(seed: u8) -> OutbeEvmSigner {
        OutbeEvmSigner::from_secret_bytes([seed; 32]).expect("valid test signer")
    }

    fn phase1_calldata() -> Bytes {
        input_for(SystemTxKind::CertifiedParentAccounting)
            .encode()
            .expect("phase1 input encodes")
    }

    fn signed_phase1(
        signer: &OutbeEvmSigner,
        block_number: u64,
        chain_id: u64,
        calldata: Bytes,
    ) -> TransactionSigned {
        let unsigned = build_unsigned_system_tx(
            SystemTxKind::CertifiedParentAccounting,
            0,
            block_number,
            chain_id,
            calldata,
        )
        .expect("phase1 tx builds");
        signer.sign_unsigned(unsigned).expect("phase1 signs")
    }

    #[test]
    fn input_roundtrips_every_system_tx_kind() {
        for kind in [
            SystemTxKind::CertifiedParentAccounting,
            SystemTxKind::LateFinalizeCredits,
            SystemTxKind::CycleTick,
            SystemTxKind::BoundaryOutcome,
            SystemTxKind::TeeBootstrap,
            SystemTxKind::OracleSlashWindow,
            SystemTxKind::HookEvents,
        ] {
            let input = input_for(kind);
            let encoded = input.encode().expect("input encodes");
            let decoded = SystemTxInputV2::decode(&encoded).expect("input decodes");
            assert_eq!(decoded, input);
            assert_eq!(decoded.kind(), kind);
        }
    }

    #[test]
    fn build_unsigned_system_tx_sets_deterministic_fields() {
        let input = input_for(SystemTxKind::CycleTick)
            .encode()
            .expect("input encodes");
        let tx = build_unsigned_system_tx(SystemTxKind::CycleTick, 0, 1, CHAIN_ID, input.clone())
            .expect("tx builds");
        assert_eq!(tx.chain_id, Some(CHAIN_ID));
        assert_eq!(tx.nonce, u64::from(MAX_SYSTEM_TXS_PER_BLOCK));
        assert_eq!(tx.gas_price, 0);
        assert_eq!(
            tx.gas_limit,
            system_tx_visible_gas_limit(input.as_ref()).expect("visible gas computes")
        );
        assert!(tx.gas_limit >= SYSTEM_TX_VISIBLE_GAS_FLOOR);
        assert!(tx.gas_limit < SYSTEM_TX_ARTIFACT_GAS_LIMIT);
        assert_eq!(tx.to, TxKind::Call(OUTBE_SYSTEM_TX_ADDRESS));
        assert_eq!(tx.value, U256::ZERO);
        assert_eq!(tx.input, input);
    }

    #[test]
    fn signature_hash_is_deterministic_for_identical_inputs() {
        let input = input_for(SystemTxKind::CycleTick)
            .encode()
            .expect("input encodes");
        let a = build_unsigned_system_tx(SystemTxKind::CycleTick, 0, 42, CHAIN_ID, input.clone())
            .expect("tx builds");
        let b = build_unsigned_system_tx(SystemTxKind::CycleTick, 0, 42, CHAIN_ID, input)
            .expect("tx builds");
        assert_eq!(a.signature_hash(), b.signature_hash());

        let different_block = build_unsigned_system_tx(
            SystemTxKind::CycleTick,
            0,
            43,
            CHAIN_ID,
            input_for(SystemTxKind::CycleTick)
                .encode()
                .expect("input encodes"),
        )
        .expect("tx builds");
        assert_ne!(a.signature_hash(), different_block.signature_hash());
    }

    #[test]
    fn phase1_witness_validation_accepts_canonical_signed_tx() {
        let signer = test_signer(1);
        let calldata = phase1_calldata();
        let signed = signed_phase1(&signer, 42, CHAIN_ID, calldata.clone());

        let validated = validate_phase1_witness_against(
            &signed,
            calldata.as_ref(),
            signer.address(),
            CHAIN_ID,
            42,
        )
        .expect("canonical phase1 witness validates");

        assert_eq!(validated, signed.signature_hash());
    }

    #[test]
    fn phase1_witness_validation_rejects_wrong_signer() {
        let signer = test_signer(1);
        let other = test_signer(2);
        let calldata = phase1_calldata();
        let signed = signed_phase1(&signer, 42, CHAIN_ID, calldata.clone());

        let err = validate_phase1_witness_against(
            &signed,
            calldata.as_ref(),
            other.address(),
            CHAIN_ID,
            42,
        )
        .expect_err("wrong proposer must be rejected");

        assert!(matches!(
            err,
            SystemTxError::Phase1SignerMismatch { expected, actual }
                if expected == other.address() && actual == signer.address()
        ));
    }

    #[test]
    fn phase1_witness_validation_rejects_wrong_chain_id_and_nonce() {
        let signer = test_signer(1);
        let calldata = phase1_calldata();
        let signed = signed_phase1(&signer, 42, CHAIN_ID, calldata.clone());

        let wrong_chain = validate_phase1_witness_against(
            &signed,
            calldata.as_ref(),
            signer.address(),
            CHAIN_ID + 1,
            42,
        )
        .expect_err("wrong chain id must be rejected");
        assert!(matches!(
            wrong_chain,
            SystemTxError::Phase1ChainIdMismatch { expected, actual }
                if expected == CHAIN_ID + 1 && actual == Some(CHAIN_ID)
        ));

        let wrong_nonce = validate_phase1_witness_against(
            &signed,
            calldata.as_ref(),
            signer.address(),
            CHAIN_ID,
            43,
        )
        .expect_err("wrong block-number nonce must be rejected");
        assert!(matches!(
            wrong_nonce,
            SystemTxError::Phase1NonceMismatch { .. }
        ));
    }

    #[test]
    fn phase1_witness_validation_rejects_noncanonical_envelope_shape() {
        let signer = test_signer(1);
        let calldata = phase1_calldata();
        let base = build_unsigned_system_tx(
            SystemTxKind::CertifiedParentAccounting,
            0,
            42,
            CHAIN_ID,
            calldata.clone(),
        )
        .expect("phase1 tx builds");

        let mut wrong_gas = base.clone();
        wrong_gas.gas_limit = wrong_gas.gas_limit.saturating_add(1);
        let signed_wrong_gas = signer.sign_unsigned(wrong_gas).expect("signs");
        assert!(matches!(
            validate_phase1_witness_against(
                &signed_wrong_gas,
                calldata.as_ref(),
                signer.address(),
                CHAIN_ID,
                42
            ),
            Err(SystemTxError::Phase1GasLimitMismatch { .. })
        ));

        let mut wrong_value = base.clone();
        wrong_value.value = U256::from(1);
        let signed_wrong_value = signer.sign_unsigned(wrong_value).expect("signs");
        assert!(matches!(
            validate_phase1_witness_against(
                &signed_wrong_value,
                calldata.as_ref(),
                signer.address(),
                CHAIN_ID,
                42
            ),
            Err(SystemTxError::Phase1NonZeroValue)
        ));

        let mut wrong_recipient = base;
        wrong_recipient.to = TxKind::Call(address!("0x5555555555555555555555555555555555555555"));
        let signed_wrong_recipient = signer.sign_unsigned(wrong_recipient).expect("signs");
        assert!(matches!(
            validate_phase1_witness_against(
                &signed_wrong_recipient,
                calldata.as_ref(),
                signer.address(),
                CHAIN_ID,
                42
            ),
            Err(SystemTxError::Phase1WrongRecipient)
        ));
    }

    #[test]
    fn phase1_witness_validation_rejects_wrong_calldata_or_kind() {
        let signer = test_signer(1);
        let calldata = phase1_calldata();
        let signed = signed_phase1(&signer, 42, CHAIN_ID, calldata.clone());

        let mut altered = sample_metadata();
        altered.finalized_block_hash = B256::repeat_byte(0x99);
        let altered_calldata = SystemTxInputV2::CertifiedParentAccounting { metadata: altered }
            .encode()
            .expect("altered phase1 input encodes");
        assert!(matches!(
            validate_phase1_witness_against(
                &signed,
                altered_calldata.as_ref(),
                signer.address(),
                CHAIN_ID,
                42
            ),
            Err(SystemTxError::Phase1CalldataMismatch)
        ));

        let cycle_calldata = input_for(SystemTxKind::CycleTick)
            .encode()
            .expect("cycle input encodes");
        let cycle_unsigned = build_unsigned_system_tx(
            SystemTxKind::CycleTick,
            0,
            42,
            CHAIN_ID,
            cycle_calldata.clone(),
        )
        .expect("cycle tx builds");
        let signed_cycle = signer.sign_unsigned(cycle_unsigned).expect("cycle signs");
        assert!(matches!(
            validate_phase1_witness_against(
                &signed_cycle,
                cycle_calldata.as_ref(),
                signer.address(),
                CHAIN_ID,
                42
            ),
            Err(SystemTxError::CalldataKindMismatch {
                expected: SystemTxKind::CertifiedParentAccounting,
                actual: SystemTxKind::CycleTick,
            })
        ));
    }

    #[test]
    fn canonical_phase1_calldata_changes_signature_hash() {
        let mut left_meta = sample_metadata();
        left_meta.finalized_block_hash = B256::repeat_byte(0x11);
        let left = SystemTxInputV2::CertifiedParentAccounting {
            metadata: left_meta,
        }
        .encode()
        .expect("left input encodes");

        let mut right_meta = sample_metadata();
        right_meta.finalized_block_hash = B256::repeat_byte(0x22);
        let right = SystemTxInputV2::CertifiedParentAccounting {
            metadata: right_meta,
        }
        .encode()
        .expect("right input encodes");

        let left_tx = build_unsigned_system_tx(
            SystemTxKind::CertifiedParentAccounting,
            0,
            42,
            CHAIN_ID,
            left,
        )
        .expect("left tx builds");
        let right_tx = build_unsigned_system_tx(
            SystemTxKind::CertifiedParentAccounting,
            0,
            42,
            CHAIN_ID,
            right,
        )
        .expect("right tx builds");

        assert_ne!(left_tx.signature_hash(), right_tx.signature_hash());
    }

    #[test]
    fn recover_phase1_proposer_rejects_trailing_eip2718_bytes() {
        let signer = test_signer(1);
        let calldata = phase1_calldata();
        let signed = signed_phase1(&signer, 42, CHAIN_ID, calldata);
        let mut encoded = Vec::new();
        signed.encode_2718(&mut encoded);
        encoded.push(0);

        let err =
            recover_phase1_proposer(&encoded, CHAIN_ID, 42).expect_err("trailing bytes rejected");

        assert!(
            matches!(err, SystemTxError::Phase1TxDecode(message) if message.contains("trailing bytes"))
        );
    }

    #[test]
    fn nonce_is_block_number_times_max_plus_ordinal() {
        assert_eq!(system_tx_nonce(1, 0).expect("nonce"), 16);
        assert_eq!(system_tx_nonce(200_600, 2).expect("nonce"), 3_209_602);
        assert!(matches!(
            system_tx_nonce(u64::MAX, 15),
            Err(SystemTxError::NonceOverflow { .. })
        ));
    }

    #[test]
    fn split_accepts_empty_and_user_only_layouts() {
        let empty = split_system_layout(&[]).expect("empty splits");
        assert!(empty.is_empty());

        let txs = vec![user_tx(), user_tx()];
        let layout = split_system_layout(&txs).expect("user-only splits");
        assert_eq!(layout.begin.len(), 0);
        assert_eq!(layout.user.len(), 2);
        assert_eq!(layout.end.len(), 0);
    }

    #[test]
    fn split_accepts_block1_cycle_tick_prefix() {
        let txs = vec![system_tx(SystemTxKind::CycleTick, 0, 1), user_tx()];
        let layout = split_system_layout(&txs).expect("layout splits");
        assert_eq!(
            layout.begin_block_kinds().expect("kinds"),
            vec![SystemTxKind::CycleTick]
        );
        assert_eq!(layout.user.len(), 1);
        assert!(layout.end.is_empty());
    }

    #[test]
    fn split_accepts_block_with_optional_boundary_prefix() {
        let txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 42),
            system_tx(SystemTxKind::CycleTick, 1, 42),
            system_tx(SystemTxKind::BoundaryOutcome, 2, 42),
            user_tx(),
        ];
        let layout = split_system_layout(&txs).expect("layout splits");
        assert_eq!(
            layout.begin_block_kinds().expect("kinds"),
            vec![
                SystemTxKind::CertifiedParentAccounting,
                SystemTxKind::CycleTick,
                SystemTxKind::BoundaryOutcome,
            ]
        );
        assert_eq!(layout.user.len(), 1);
    }

    #[test]
    fn split_rejects_out_of_order_prefix() {
        let txs = vec![
            system_tx(SystemTxKind::CycleTick, 0, 42),
            system_tx(SystemTxKind::CertifiedParentAccounting, 1, 42),
        ];
        assert!(matches!(
            split_system_layout(&txs),
            Err(SystemTxError::OutOfOrder { .. })
        ));
    }

    #[test]
    fn split_rejects_reserved_tx_in_wrong_suffix_zone() {
        let txs = vec![user_tx(), system_tx(SystemTxKind::CycleTick, 0, 42)];
        assert!(matches!(
            split_system_layout(&txs),
            Err(SystemTxError::SystemTxInWrongZone {
                actual: BodyZone::EndBlock,
                ..
            })
        ));
    }

    #[test]
    fn split_rejects_reserved_tx_in_middle_zone() {
        let txs = vec![
            system_tx(SystemTxKind::CycleTick, 0, 1),
            user_tx(),
            system_tx(SystemTxKind::BoundaryOutcome, 1, 1),
            user_tx(),
        ];
        assert!(matches!(
            split_system_layout(&txs),
            Err(SystemTxError::MidBlockSystemTx { index: 2 })
        ));
    }

    #[test]
    fn validate_active_system_tx_set_accepts_expected_membership() {
        let block0 = split_system_layout(&[]).expect("layout");
        validate_active_system_tx_set(&block0, 0, false, false).expect("genesis ok");

        // / V2: block 1 mandatorily carries a BoundaryOutcome for
        // the genesis bootstrap.
        let block1_txs = vec![
            system_tx(SystemTxKind::CycleTick, 0, 1),
            system_tx(SystemTxKind::BoundaryOutcome, 1, 1),
            system_tx(SystemTxKind::OracleSlashWindow, 2, 1),
            system_tx(SystemTxKind::HookEvents, 3, 1),
        ];
        let block1 = split_system_layout(&block1_txs).expect("layout");
        validate_active_system_tx_set(&block1, 1, true, false).expect("block 1 V2 ok");

        let block2_txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::LateFinalizeCredits, 1, 2),
            system_tx(SystemTxKind::CycleTick, 2, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 3, 2),
            system_tx(SystemTxKind::HookEvents, 4, 2),
        ];
        let block2 = split_system_layout(&block2_txs).expect("layout");
        validate_active_system_tx_set(&block2, 2, false, false).expect("block 2 ok");

        let block2_with_boundary_txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::LateFinalizeCredits, 1, 2),
            system_tx(SystemTxKind::CycleTick, 2, 2),
            system_tx(SystemTxKind::BoundaryOutcome, 3, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 4, 2),
            system_tx(SystemTxKind::HookEvents, 5, 2),
        ];
        let block2_with_boundary = split_system_layout(&block2_with_boundary_txs).expect("layout");
        validate_active_system_tx_set(&block2_with_boundary, 2, true, false)
            .expect("block 2 boundary ok");
    }

    #[test]
    fn validate_active_system_tx_set_requires_mandatory_and_conditional_kinds() {
        let missing_finalization_txs = vec![
            system_tx(SystemTxKind::CycleTick, 0, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 1, 2),
        ];
        let missing_finalization = split_system_layout(&missing_finalization_txs).expect("layout");
        assert!(matches!(
            validate_active_system_tx_set(&missing_finalization, 2, false, false),
            Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
        ));

        let missing_cycle_tick_txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 1, 2),
        ];
        let missing_cycle_tick = split_system_layout(&missing_cycle_tick_txs).expect("layout");
        assert!(matches!(
            validate_active_system_tx_set(&missing_cycle_tick, 2, false, false),
            Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
        ));

        // / V2: block 1 must include CycleTick AND BoundaryOutcome.
        // Missing CycleTick (with the mandatory BoundaryOutcome present)
        // still yields ActiveSystemTxSetMismatch.
        let block1_missing_cycle_tick_txs = vec![
            system_tx(SystemTxKind::BoundaryOutcome, 0, 1),
            system_tx(SystemTxKind::OracleSlashWindow, 1, 1),
            system_tx(SystemTxKind::HookEvents, 2, 1),
        ];
        let block1_missing_cycle_tick =
            split_system_layout(&block1_missing_cycle_tick_txs).expect("layout");
        assert!(matches!(
            validate_active_system_tx_set(&block1_missing_cycle_tick, 1, true, false),
            Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
        ));

        // / V2: block 1 without BoundaryOutcome is rejected with
        // the V2-specific genesis bootstrap error before structural checks.
        let block1_no_boundary_txs = vec![
            system_tx(SystemTxKind::CycleTick, 0, 1),
            system_tx(SystemTxKind::OracleSlashWindow, 1, 1),
            system_tx(SystemTxKind::HookEvents, 2, 1),
        ];
        let block1_no_boundary = split_system_layout(&block1_no_boundary_txs).expect("layout");
        assert!(matches!(
            validate_active_system_tx_set(&block1_no_boundary, 1, false, false),
            Err(SystemTxError::V2Block1MissingBoundaryOutcome)
        ));

        let missing_oracle_slash_window_txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::CycleTick, 1, 2),
            system_tx(SystemTxKind::HookEvents, 2, 2),
        ];
        let missing_oracle_slash_window =
            split_system_layout(&missing_oracle_slash_window_txs).expect("layout");
        assert!(matches!(
            validate_active_system_tx_set(&missing_oracle_slash_window, 2, false, false),
            Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
        ));

        let missing_boundary_txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::CycleTick, 1, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 2, 2),
            system_tx(SystemTxKind::HookEvents, 3, 2),
        ];
        let missing_boundary = split_system_layout(&missing_boundary_txs).expect("layout");
        assert!(matches!(
            validate_active_system_tx_set(&missing_boundary, 2, true, false),
            Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
        ));

        let unexpected_boundary_txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::CycleTick, 1, 2),
            system_tx(SystemTxKind::BoundaryOutcome, 2, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 3, 2),
            system_tx(SystemTxKind::HookEvents, 4, 2),
        ];
        let unexpected_boundary = split_system_layout(&unexpected_boundary_txs).expect("layout");
        assert!(matches!(
            validate_active_system_tx_set(&unexpected_boundary, 2, false, false),
            Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
        ));
    }

    #[test]
    fn revert_fails_block_classifies_critical_begin_zone_phases() {
        // consensus- and economic-critical phases fail the block on
        // a revert/halt; non-critical phases keep the soft-receipt skip. Pin the
        // full classification so a new phase is forced to make this choice.
        for kind in [
            SystemTxKind::CertifiedParentAccounting,
            SystemTxKind::LateFinalizeCredits,
            SystemTxKind::CycleTick,
            SystemTxKind::BoundaryOutcome,
        ] {
            assert!(
                kind.revert_fails_block(),
                "{kind:?} must fail the block on revert"
            );
        }
        for kind in [
            SystemTxKind::TeeBootstrap,
            SystemTxKind::OracleSlashWindow,
            SystemTxKind::HookEvents,
        ] {
            assert!(
                !kind.revert_fails_block(),
                "{kind:?} must keep the soft-receipt skip"
            );
        }
    }

    #[test]
    fn validate_active_system_tx_set_handles_optional_phase3b_bootstrap() {
        // Block carrying the one-time Phase 3b bootstrap (after BoundaryOutcome,
        // before OracleSlashWindow) validates iff has_tee_bootstrap.
        let txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::LateFinalizeCredits, 1, 2),
            system_tx(SystemTxKind::CycleTick, 2, 2),
            system_tx(SystemTxKind::BoundaryOutcome, 3, 2),
            system_tx(SystemTxKind::TeeBootstrap, 4, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 5, 2),
            system_tx(SystemTxKind::HookEvents, 6, 2),
        ];
        let layout = split_system_layout(&txs).expect("layout");
        validate_active_system_tx_set(&layout, 2, true, true).expect("bootstrap block ok");

        // Same bytes, but the flag says no bootstrap expected -> mismatch.
        assert!(matches!(
            validate_active_system_tx_set(&layout, 2, true, false),
            Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
        ));

        // Bootstrap without a boundary outcome (degenerate but well-defined).
        let txs_no_bo = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::LateFinalizeCredits, 1, 2),
            system_tx(SystemTxKind::CycleTick, 2, 2),
            system_tx(SystemTxKind::TeeBootstrap, 3, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 4, 2),
            system_tx(SystemTxKind::HookEvents, 5, 2),
        ];
        let layout_no_bo = split_system_layout(&txs_no_bo).expect("layout");
        validate_active_system_tx_set(&layout_no_bo, 2, false, true).expect("bootstrap w/o bo ok");
    }

    #[test]
    fn advance_after_commit_interleaves_optional_phase3b() {
        // CycleTick -> BoundaryOutcome -> TeeBootstrap -> OracleSlashWindow.
        let cycle = SystemTxPhase::CycleTick { body_index: 1 };
        let bo = cycle.advance_after_commit(true, true);
        assert_eq!(bo, SystemTxPhase::BoundaryOutcomeOptional { body_index: 2 });
        let tee = bo.advance_after_commit(true, true);
        assert_eq!(tee, SystemTxPhase::TeeBootstrapOptional { body_index: 3 });
        let oracle = tee.advance_after_commit(true, true);
        assert_eq!(oracle, SystemTxPhase::OracleSlashWindow { body_index: 4 });
        let hook_events = oracle.advance_after_commit(true, true);
        assert_eq!(hook_events, SystemTxPhase::HookEvents { body_index: 5 });
        assert_eq!(
            hook_events.advance_after_commit(true, true),
            SystemTxPhase::UserTxs
        );

        // No boundary, bootstrap present: CycleTick -> TeeBootstrap.
        assert_eq!(
            SystemTxPhase::CycleTick { body_index: 1 }.advance_after_commit(false, true),
            SystemTxPhase::TeeBootstrapOptional { body_index: 2 }
        );

        // Neither: CycleTick -> OracleSlashWindow (unchanged common path).
        assert_eq!(
            SystemTxPhase::CycleTick { body_index: 1 }.advance_after_commit(false, false),
            SystemTxPhase::OracleSlashWindow { body_index: 2 }
        );
        assert_eq!(
            SystemTxPhase::OracleSlashWindow { body_index: 2 }.advance_after_commit(false, false),
            SystemTxPhase::HookEvents { body_index: 3 }
        );
    }

    #[test]
    fn reserved_address_does_not_collide_with_system_precompiles() {
        let addr_bytes = OUTBE_SYSTEM_TX_ADDRESS.0;
        assert_eq!(addr_bytes[0], 0xff);
        assert_ne!(addr_bytes[19], 0x00);
    }

    // ---------- : SystemTxPhase cursor tests ----------

    #[test]
    fn initial_for_block_block_1_is_cycletick() {
        // block 1 (genesis bootstrap) skips Phase 1 and starts at CycleTick.
        let cursor = SystemTxPhase::initial_for_block(1, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
        assert_eq!(cursor, SystemTxPhase::CycleTick { body_index: 0 });
        assert_eq!(cursor.expected_kind(), Some(SystemTxKind::CycleTick));
        assert_eq!(cursor.body_index(), Some(0));
    }

    #[test]
    fn initial_for_block_block_2_is_phase1_preexecuted() {
        // Block 2 (first post-bootstrap block) starts at Phase1Preexecuted with
        // a zero placeholder tx_hash that the executor overwrites after the
        // Phase 1 preflight commits.
        let cursor = SystemTxPhase::initial_for_block(2, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
        assert!(matches!(
            cursor,
            SystemTxPhase::Phase1Preexecuted {
                body_index: 0,
                receipt_index: 0,
                ..
            }
        ));
        if let SystemTxPhase::Phase1Preexecuted { tx_hash, .. } = cursor {
            assert_eq!(tx_hash, B256::ZERO);
        }
        assert_eq!(
            cursor.expected_kind(),
            Some(SystemTxKind::CertifiedParentAccounting)
        );
    }

    #[test]
    fn initial_for_block_block_0_is_cycletick_placeholder() {
        // Block 0 is genesis; it has no begin-zone txs at all, but the cursor
        // initialisation must not panic and must not pick the Phase 1 branch.
        let cursor = SystemTxPhase::initial_for_block(0, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
        assert_eq!(cursor, SystemTxPhase::CycleTick { body_index: 0 });
    }

    #[test]
    fn expected_kind_returns_phase_for_each_variant() {
        let cases = [
            (
                SystemTxPhase::Phase1Preexecuted {
                    body_index: 0,
                    tx_hash: B256::ZERO,
                    receipt_index: 0,
                },
                Some(SystemTxKind::CertifiedParentAccounting),
            ),
            (
                SystemTxPhase::CycleTick { body_index: 1 },
                Some(SystemTxKind::CycleTick),
            ),
            (
                SystemTxPhase::BoundaryOutcomeOptional { body_index: 2 },
                Some(SystemTxKind::BoundaryOutcome),
            ),
            (
                SystemTxPhase::TeeBootstrapOptional { body_index: 3 },
                Some(SystemTxKind::TeeBootstrap),
            ),
            (
                SystemTxPhase::OracleSlashWindow { body_index: 4 },
                Some(SystemTxKind::OracleSlashWindow),
            ),
            (
                SystemTxPhase::HookEvents { body_index: 5 },
                Some(SystemTxKind::HookEvents),
            ),
            (SystemTxPhase::UserTxs, None),
        ];
        for (phase, expected) in cases {
            assert_eq!(phase.expected_kind(), expected, "phase={phase:?}");
        }
    }

    #[test]
    fn body_index_matches_for_every_begin_zone_variant() {
        for (phase, expected) in [
            (
                SystemTxPhase::Phase1Preexecuted {
                    body_index: 0,
                    tx_hash: B256::ZERO,
                    receipt_index: 0,
                },
                Some(0),
            ),
            (SystemTxPhase::CycleTick { body_index: 1 }, Some(1)),
            (
                SystemTxPhase::BoundaryOutcomeOptional { body_index: 2 },
                Some(2),
            ),
            (
                SystemTxPhase::TeeBootstrapOptional { body_index: 3 },
                Some(3),
            ),
            (SystemTxPhase::OracleSlashWindow { body_index: 4 }, Some(4)),
            (SystemTxPhase::HookEvents { body_index: 5 }, Some(5)),
            (SystemTxPhase::UserTxs, None),
        ] {
            assert_eq!(phase.body_index(), expected, "phase={phase:?}");
        }
    }
}
