//! Append-only JSONL journal for Vote / governance critical events.
//!
//! The journal is a process-local sidecar to the standard reth log. It is
//! written one JSON record per critical state-transition event under a
//! single file path (`<datadir>/governance-journal.jsonl`) and is **never
//! rotated** by the application. Operators may snapshot or trim the file
//! manually; the runtime never truncates it.
//!
//! ## Best-effort semantics
//!
//! The journal is **best-effort** observability — writes that fail (disk
//! full, permission error, file unwritable) emit a `tracing::warn!` and
//! are dropped. They never block the consensus / state-transition path
//! that produced them. Determinism is unaffected: the journal is a side
//! effect identical on every node, and absence of the journal does not
//! change the on-chain state.
//!
//! ## Initialization
//!
//! [`init`] is called once at node startup with the data directory. If
//! [`init`] is not called (e.g. tests), [`record`] silently no-ops.

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Filename of the journal inside the configured data directory.
pub const JOURNAL_FILENAME: &str = "governance-journal.jsonl";

/// Common block context shared by every journal record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventContext {
    pub wall_clock: String,
    pub block_number: u64,
}

impl EventContext {
    /// Builds context for the current wall-clock time at `block_number`.
    pub fn at(block_number: u64) -> Self {
        Self {
            wall_clock: iso8601_now(),
            block_number,
        }
    }
}

/// Proposal identity fields reused across finalization records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalRef {
    pub proposal_id: String,
    pub proposer: String,
    pub target_module: String,
    pub action: String,
}

/// Yes/no vote counters at a tally point.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VoteTallyRef {
    pub yes_votes: u64,
    pub no_votes: u64,
    pub active_validator_count: u32,
}

/// One record in the governance journal.
///
/// `tag = "event"` lets `serde_json` emit a flat object with the variant
/// name in the `event` field, which is convenient for ad-hoc grep / `jq`.
/// Nested structs are flattened into the top-level JSON object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[non_exhaustive]
pub enum JournalRecord {
    /// A new proposal was created and entered the voting phase.
    ProposalCreated {
        #[serde(flatten)]
        ctx: EventContext,
        #[serde(flatten)]
        proposal: ProposalRef,
        voting_deadline_height: u64,
        payload_len: usize,
        payload_hash: String,
    },

    /// An active validator cast a vote on a pending proposal.
    VoteCast {
        #[serde(flatten)]
        ctx: EventContext,
        proposal_id: String,
        voter: String,
        approve: bool,
    },

    /// Quorum reached and the target-module handler accepted the proposal.
    ProposalApproved {
        #[serde(flatten)]
        ctx: EventContext,
        #[serde(flatten)]
        proposal: ProposalRef,
        #[serde(flatten)]
        tally: VoteTallyRef,
    },

    /// Quorum reached but the target-module handler reverted the proposal.
    ProposalRejected {
        #[serde(flatten)]
        ctx: EventContext,
        #[serde(flatten)]
        proposal: ProposalRef,
        #[serde(flatten)]
        tally: VoteTallyRef,
        reject_reason: String,
    },

    /// Voting deadline passed without reaching quorum.
    ProposalExpired {
        #[serde(flatten)]
        ctx: EventContext,
        #[serde(flatten)]
        proposal: ProposalRef,
        #[serde(flatten)]
        tally: VoteTallyRef,
    },
}

impl JournalRecord {
    /// Journal entry for a newly created proposal.
    pub fn proposal_created(
        block_number: u64,
        proposal: ProposalRef,
        voting_deadline_height: u64,
        payload_len: usize,
        payload_hash: String,
    ) -> Self {
        Self::ProposalCreated {
            ctx: EventContext::at(block_number),
            proposal,
            voting_deadline_height,
            payload_len,
            payload_hash,
        }
    }

    /// Journal entry for a cast vote.
    pub fn vote_cast(block_number: u64, proposal_id: String, voter: String, approve: bool) -> Self {
        Self::VoteCast {
            ctx: EventContext::at(block_number),
            proposal_id,
            voter,
            approve,
        }
    }

    /// Journal entry for an approved proposal.
    pub fn proposal_approved(
        block_number: u64,
        proposal: ProposalRef,
        tally: VoteTallyRef,
    ) -> Self {
        Self::ProposalApproved {
            ctx: EventContext::at(block_number),
            proposal,
            tally,
        }
    }

    /// Journal entry for a rejected proposal.
    pub fn proposal_rejected(
        block_number: u64,
        proposal: ProposalRef,
        tally: VoteTallyRef,
        reject_reason: String,
    ) -> Self {
        Self::ProposalRejected {
            ctx: EventContext::at(block_number),
            proposal,
            tally,
            reject_reason,
        }
    }

    /// Journal entry for an expired proposal.
    pub fn proposal_expired(block_number: u64, proposal: ProposalRef, tally: VoteTallyRef) -> Self {
        Self::ProposalExpired {
            ctx: EventContext::at(block_number),
            proposal,
            tally,
        }
    }
}

struct Journal {
    writer: Mutex<BufWriter<File>>,
}

static JOURNAL: OnceLock<Journal> = OnceLock::new();

/// Initialize the journal. Must be called once at node startup before any
/// state-transition path runs. Subsequent calls are no-ops.
///
/// `datadir` is created if missing; the journal file is opened in append
/// mode so existing content is preserved across node restarts.
pub fn init(datadir: &Path) -> std::io::Result<()> {
    if JOURNAL.get().is_some() {
        return Ok(());
    }

    let path = journal_path(datadir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    let writer = BufWriter::new(file);

    let _ = JOURNAL.set(Journal {
        writer: Mutex::new(writer),
    });
    tracing::info!(
        target: "outbe::governance::journal",
        path = %path.display(),
        "governance journal initialized",
    );
    Ok(())
}

/// Returns the journal path under `datadir`.
pub fn journal_path(datadir: &Path) -> PathBuf {
    datadir.join(JOURNAL_FILENAME)
}

/// Append `record` to the journal. If [`init`] has not been called, this
/// is a no-op (test-friendly). Write errors are logged at WARN and
/// swallowed — never blocks the caller's state-transition path.
pub fn record(record: JournalRecord) {
    let Some(journal) = JOURNAL.get() else {
        return;
    };

    let line = match serde_json::to_string(&record) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                target: "outbe::governance::journal",
                error = %e,
                "failed to serialize journal record",
            );
            return;
        }
    };

    let mut guard = match journal.writer.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    if let Err(e) = writeln!(guard, "{line}") {
        tracing::warn!(
            target: "outbe::governance::journal",
            error = %e,
            "failed to append journal record",
        );
        return;
    }
    if let Err(e) = guard.flush() {
        tracing::warn!(
            target: "outbe::governance::journal",
            error = %e,
            "failed to flush journal record",
        );
    }
}

/// Returns an ISO-8601 UTC timestamp string for `wall_clock` fields.
///
/// Uses raw `std::time::SystemTime` rather than `chrono` to avoid pulling
/// a new dependency. Format: `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn iso8601_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = now.as_secs() as i64;
    let millis = now.subsec_millis();
    let (year, month, day, hour, minute, second) = unix_to_civil(total_secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Decompose Unix seconds into (Y, M, D, h, m, s) UTC. Pure integer arithmetic.
fn unix_to_civil(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = (rem / 3600) as u32;
    let minute = ((rem % 3600) / 60) as u32;
    let second = (rem % 60) as u32;
    let (year, month, day) = days_to_civil(days);
    (year, month, day, hour, minute, second)
}

/// Howard Hinnant's days-from-epoch -> civil-date algorithm.
fn days_to_civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn sample_proposal() -> ProposalRef {
        ProposalRef {
            proposal_id: "1".into(),
            proposer: "0x2cf6fbd0".into(),
            target_module: "0x4082".into(),
            action: "0xfcd8".into(),
        }
    }

    fn sample_tally() -> VoteTallyRef {
        VoteTallyRef {
            yes_votes: 3,
            no_votes: 1,
            active_validator_count: 4,
        }
    }

    #[test]
    fn record_when_uninit_is_noop() {
        record(JournalRecord::vote_cast(0, "1".into(), "0xabc".into(), true));
    }

    #[test]
    fn journal_path_uses_governance_filename() {
        let dir = std::path::Path::new("/tmp/outbe-test");
        assert_eq!(journal_path(dir), dir.join("governance-journal.jsonl"));
    }

    #[test]
    fn record_serializes_to_jsonl_with_event_tag() {
        let rec = JournalRecord::proposal_approved(12_345, sample_proposal(), sample_tally());
        let json = serde_json::to_string(&rec).expect("serializable");
        assert!(json.contains("\"event\":\"proposal_approved\""));
        assert!(json.contains("\"yes_votes\":3"));
        assert!(json.contains("\"proposal_id\":\"1\""));
        assert!(json.contains("\"block_number\":12345"));
    }

    #[test]
    fn finalization_variants_share_flat_proposal_and_tally_fields() {
        let proposal = sample_proposal();
        let tally = sample_tally();
        for rec in [
            JournalRecord::proposal_approved(100, proposal.clone(), tally),
            JournalRecord::proposal_rejected(100, proposal.clone(), tally, "bad payload".into()),
            JournalRecord::proposal_expired(100, proposal, tally),
        ] {
            let json = serde_json::to_string(&rec).unwrap();
            assert!(json.contains("\"proposer\":\"0x2cf6fbd0\""));
            assert!(json.contains("\"yes_votes\":3"));
            assert!(json.contains("\"active_validator_count\":4"));
        }
    }

    #[test]
    fn iso8601_format_shape() {
        let s = iso8601_now();
        assert_eq!(s.len(), 24);
        assert!(s.ends_with('Z'));
        assert!(s.chars().nth(4) == Some('-'));
        assert!(s.chars().nth(10) == Some('T'));
    }

    #[test]
    fn init_then_record_writes_lines_and_survives_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = journal_path(dir.path());
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let mut writer = std::io::BufWriter::new(file);
        let rec = JournalRecord::proposal_expired(19_200, sample_proposal(), sample_tally());
        writeln!(writer, "{}", serde_json::to_string(&rec).unwrap()).unwrap();
        writer.flush().unwrap();
        drop(writer);

        let mut content = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert!(content.contains("\"event\":\"proposal_expired\""));
        assert!(content.contains("\"block_number\":19200"));
    }
}
