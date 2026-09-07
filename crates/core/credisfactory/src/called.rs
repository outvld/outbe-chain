//! Daily price-path scan: calls and voids positions off the Oracle's
//! finalized per-UTC-day VWAPs. Driven by the Cycle daily trigger.
//!
//! One pass over the dense active-position index applies up to two transitions
//! per position, in lifecycle order:
//!
//! - `Open -> Called` when the COEN price in the position's REFERENCE currency sat
//!   at or above the call price on [`CALL_BREACH_DAYS`] of the trailing
//!   [`CALL_LOOKBACK_DAYS`] days. The issuance currency the position is denominated
//!   in never enters the threshold.
//! - `Called -> Void` when the settlement window has lapsed with principal still
//!   outstanding.
//!
//! The breach rule needs no per-position streak state: the daily series is
//! global per currency, so one trailing window per reference currency decides
//! every position anchored to it, and the count is recomputed from oracle
//! history on every run rather than carried. Mirrors `outbe_gem::hooks::scan_and_call`,
//! which evaluates the same `CALL_WINDOW`/`CALL_THRESHOLD` shape.

use alloy_primitives::U256;

use outbe_credis::constants::{CALL_BREACH_DAYS, CALL_LOOKBACK_DAYS};
use outbe_credis::{CredisContract, CredisState, Position};
use outbe_oracle::schema::OracleContract;
use outbe_primitives::{
    block::BlockRuntimeContext,
    error::{PrecompileError, Result},
    storage::StorageHandle,
    time::{previous_date_key, timestamp_to_date_key},
};

use crate::runtime;
use crate::schema::CredisFactoryContract;

/// Max positions visited per daily run; the cursor resumes the rest on the next
/// run so one scan can never outgrow a block. An entry displaced past the cursor
/// is picked up a day later, which cannot change an outcome: the call needs a
/// multi-week breach count and the void follows a 7-day window.
pub(crate) const MAX_CREDIS_DAILY_VISITS: u32 = 4096;

/// Max positions voided per daily run, far below [`MAX_CREDIS_DAILY_VISITS`]
/// because a void is orders of magnitude more expensive than a call:
/// it makes two blocking TEE enclave round-trips (`reveal_owner` then
/// `burn_pledged_with_fidelity`) on a process-global connection.
///
/// A correlated mass-void is the *expected* shape of a call event, not a tail
/// case - a sustained breach calls every position in a currency at once, so 7
/// days later they all lapse together. Without a separate cap one run would
/// carry the whole burst.
///
/// Spending it only declines further voids; the pass continues so the call arm
/// keeps its full [`MAX_CREDIS_DAILY_VISITS`] reach.
// ponytail: a backlog larger than this drains at one budget per day. Raise it
// once real sidecar latency is measured, or batch the enclave round-trips.
pub(crate) const MAX_CREDIS_VOIDS_PER_RUN: u32 = 64;

/// Trailing finalized daily VWAPs of one `COEN/<iso>` pair, newest first.
/// `None` marks a day the pair published no reference price.
type VwapWindow = Vec<(u32, Option<U256>)>;

/// Cycle daily-trigger entry: runs the scan, discarding the count.
pub fn run_daily(ctx: &BlockRuntimeContext) -> Result<()> {
    scan_and_call(ctx)?;
    Ok(())
}

/// Runs the daily price-path scan. Returns the number of positions mutated.
///
/// Never returns `Err` for missing market data: the Cycle dispatcher propagates
/// a handler error out of the `CycleTick` system transaction, which fails the
/// block, so an unregistered pair, an unpriced currency or an unfinalized day
/// each degrade to "no transition" instead.
pub fn scan_and_call(ctx: &BlockRuntimeContext) -> Result<u32> {
    let oracle = OracleContract::new(ctx.storage.clone());

    // Most recent fully-closed UTC day. The paper counts plain UTC days, so this
    // is `timestamp_to_date_key`, NOT the UTC+14 `WorldwideDay` key.
    let last_closed_day = previous_date_key(timestamp_to_date_key(ctx.block.timestamp));

    // The Oracle begin-block hook finalizes that day earlier in this same block;
    // a lagging watermark means the ordering broke - skip loudly instead of
    // misreading an unfinalized day as one with no published price.
    let finalized = oracle.utc_day_vwap_last_finalized.read()?;
    if finalized < last_closed_day {
        tracing::warn!(
            target: "outbe::credisfactory",
            last_closed_day,
            finalized,
            "credis scan: utc-day VWAP not finalized yet, skipping run"
        );
        return Ok(0);
    }

    let mut credis = CredisContract::new(ctx.storage.clone());
    let len = credis.active_len()?;
    if len == 0 {
        return Ok(0);
    }

    let factory = CredisFactoryContract::new(ctx.storage.clone());
    // Stored as `index + 1`; 0 means "start a fresh pass from the top".
    let mut cursor = match factory.call_scan_cursor.read()? {
        0 => len - 1,
        resume => resume.saturating_sub(1).min(len - 1),
    };

    // A VWAP window belongs to one `COEN/<reference iso>` pair, but the active index
    // mixes anchors. Cache the windows and keep the single pass; the registry holds
    // a handful of codes, so a linear probe beats a map.
    let mut windows: Vec<(u16, VwapWindow)> = Vec::new();

    let now = ctx.block.timestamp;
    let mut mutated: u32 = 0;
    let mut visited: u32 = 0;
    let mut voided: u32 = 0;

    // Descending walk: `remove_active` swap-pops the tail into the hole, and the
    // tail is already behind a descending cursor, so no live entry is skipped.
    let completed = loop {
        if visited >= MAX_CREDIS_DAILY_VISITS {
            break false;
        }
        if let Some(position_id) = credis.active_at(cursor)? {
            // Structural reads stay on `?` so infra errors still propagate.
            let position = credis.get_position(position_id)?;
            let index = window_for(
                &ctx.storage,
                &oracle,
                &mut windows,
                position.reference_currency,
                last_closed_day,
            )?;
            // `window_for` only ever returns an index it just validated or
            // appended, so this cannot miss; resolving it fallibly rather than
            // by bare indexing keeps the hook path panic-free.
            let window = windows
                .get(index)
                .map(|(_, days)| days.as_slice())
                .ok_or_else(|| {
                    PrecompileError::Fatal("credis scan: window cache index out of range".into())
                })?;

            // The price-path arms are pure storage and arithmetic, so a
            // deterministic error is isolated to this position and skipped -
            // one bad position never halts the daily run. Same shape as gem's
            // and intexfactory's scans.
            let outcome = ctx
                .storage
                .with_checkpoint(|| visit_price_path(&mut credis, window, &position, now));
            match outcome {
                Ok(visit) => {
                    // The void arm is NOT isolated: it makes TEE enclave
                    // round-trips whose faults (sidecar down, socket timeout)
                    // are node-local rather than a function of committed state.
                    // Swallowing one would fork the chain silently, so it
                    // propagates and fails the block instead. The three domain
                    // errors `void_position` can raise are all pre-filtered by
                    // `void_due`, so nothing deterministic reaches here.
                    //
                    // A spent void budget declines further voids but must NOT
                    // end the pass: both arms share one cursor, so breaking here
                    // would let a void backlog throttle the call arm down to the
                    // void rate and leave the rest of the book unvisited for as
                    // many days as the backlog takes to drain.
                    // A declined position keeps its place in the active index
                    // and is voided by a later run.
                    let did_void = visit.void_due && voided < MAX_CREDIS_VOIDS_PER_RUN;
                    if did_void {
                        runtime::void_position(ctx.storage.clone(), position_id)?;
                        voided = voided.saturating_add(1);
                    }
                    // Mutually exclusive: the void needs `Called` at entry,
                    // which is not a state the call arm acts on.
                    if visit.moved || did_void {
                        mutated = mutated.saturating_add(1);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        target: "outbe::credisfactory",
                        %position_id,
                        error = ?e,
                        "credis scan: skipping position"
                    );
                }
            }
        }
        visited = visited.saturating_add(1);
        if cursor == 0 {
            break true;
        }
        cursor -= 1;
    };

    // `cursor` is the next index to visit when a budget cut the pass short.
    factory.call_scan_cursor.write(if completed {
        0
    } else {
        cursor.saturating_add(1)
    })?;
    Ok(mutated)
}

/// What one position's price-path arms decided.
struct Visit {
    /// Whether the call actually transitioned it.
    moved: bool,
    /// Whether the caller must now void the remainder.
    void_due: bool,
}

/// Applies the call, and reports whether the void is due.
///
/// A reference currency this chain cannot price yields an empty window: no call, but
/// the void arm still runs, so such a position is never stranded.
fn visit_price_path(
    credis: &mut CredisContract<'_>,
    window: &[(u32, Option<U256>)],
    position: &Position,
    now: u64,
) -> Result<Visit> {
    let entry_state = position.lifecycle_state()?;
    let moved = entry_state == CredisState::Open
        && breached_enough(window, position)
        && credis.mark_called(position.position_id, now)?;

    Ok(Visit {
        moved,
        // Gated on the state at entry, not the running one: a call stamped in
        // this same visit sets `called_at = now`, so its window cannot have
        // lapsed, and reading the deadline off the record loaded before that
        // would compare `now` against `0 + CALL_WINDOW_SECS`.
        void_due: entry_state == CredisState::Called
            && !position.outstanding.is_zero()
            && now >= outbe_credis::settlement_deadline(position),
    })
}

/// True when the daily COEN price in the position's reference currency sat
/// strictly above its call price on at least [`CALL_BREACH_DAYS`] of the window.
///
/// Days at or below the call price and days with no published price both simply
/// fail to count, so the window absorbs up to `CALL_LOOKBACK_DAYS - CALL_BREACH_DAYS`
/// of either. section 11.3 leaves missing-data days undecided; treating them as
/// non-breaches is conservative - it can only delay a call, never trigger one.
///
/// A day that predates the position ends the count: the window is newest-first,
/// so every remaining entry is older still, and a position must never inherit a
/// breach run from before it existed. Mirrors the issuance guard in
/// `outbe_gem::runtime::trigger_call`.
fn breached_enough(window: &[(u32, Option<U256>)], position: &Position) -> bool {
    let originated_day = timestamp_to_date_key(position.originated_at);
    let mut breaches: u32 = 0;
    for (day, vwap) in window {
        if *day < originated_day {
            break;
        }
        if vwap.is_some_and(|value| value > position.call_price) {
            breaches = breaches.saturating_add(1);
        }
    }
    breaches >= CALL_BREACH_DAYS
}

/// Index into `cache` of the trailing finalized-VWAP window for `COEN/<iso>`,
/// newest first, filling it on first use. Only the currencies actually present
/// in the active book are read - there is no registry walk.
///
/// An unregistered pair caches an empty window: such a position can never
/// register a breach, but it must still reach the void arm, so this skips the
/// price checks rather than the position.
fn window_for(
    storage: &StorageHandle<'_>,
    oracle: &OracleContract<'_>,
    cache: &mut Vec<(u16, VwapWindow)>,
    iso_code: u16,
    last_closed_day: u32,
) -> Result<usize> {
    if let Some(index) = cache.iter().position(|(code, _)| *code == iso_code) {
        return Ok(index);
    }
    let mut window = Vec::new();
    if let Some(pair_index) = outbe_oracle::api::coen_pair_index_opt(storage.clone(), iso_code)? {
        window.reserve(CALL_LOOKBACK_DAYS as usize);
        let mut day = last_closed_day;
        for _ in 0..CALL_LOOKBACK_DAYS {
            window.push((day, oracle.get_utc_day_vwap_for_pair(day, pair_index)?));
            day = previous_date_key(day);
        }
    }
    cache.push((iso_code, window));
    Ok(cache.len() - 1)
}
