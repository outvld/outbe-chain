//! Daily price-path scan: the multi-week breach-count call and the void of a
//! lapsed settlement window.
//!
//! Every test drives [`crate::called::scan_and_call`] through the `scan` harness
//! helper against a seeded finalized daily series, which is the only price source
//! the production trigger reads.

use alloy_primitives::{Address, U256};

use outbe_credis::constants::{CALL_BREACH_DAYS, CALL_LOOKBACK_DAYS, CALL_WINDOW_SECS};
use outbe_credis::{CredisContract, CredisState};
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::time::previous_date_key;

use crate::tests::common::*;

/// Enough headroom before `CREATED_AT` that a full lookback window never reaches
/// back past a position's origination day.
const AFTER_WINDOW: u64 = (CALL_LOOKBACK_DAYS as u64 + 2) * DAY;

/// An ISO code the fixture registers no `COEN/<iso>` pair for.
const UNPRICED_ISO: u16 = 392; // JPY

fn state_of(storage: &StorageHandle<'_>, position_id: U256) -> CredisState {
    CredisContract::new(storage.clone())
        .get_position(position_id)
        .unwrap()
        .lifecycle_state()
        .unwrap()
}

/// The `n`th closed day back from the one closed at `at` (0 = the newest).
fn day_back(at: u64, n: u32) -> u32 {
    let mut day = last_closed_day(at);
    for _ in 0..n {
        day = previous_date_key(day);
    }
    day
}

/// Opens a position and publishes `days` closed days at `price`, ending at the
/// day closed at `at`. Returns the position id.
fn open_with_series(storage: &StorageHandle<'_>, at: u64, days: u32, price: U256) -> U256 {
    let position_id = open(storage, 1);
    advance_to(storage, at);
    fill_days(storage, last_closed_day(at), days, price);
    position_id
}

#[test]
fn a_full_window_above_the_call_price_calls_the_position() {
    let mut storage = env();
    StorageHandle::enter(&mut storage, |storage| {
        bootstrap(&storage, pledge_cost());
        let at = CREATED_AT + AFTER_WINDOW;
        let position_id = open_with_series(&storage, at, CALL_LOOKBACK_DAYS, above_call());

        assert_eq!(scan(&storage, at), 1);
        assert_eq!(state_of(&storage, position_id), CredisState::Called);

        let position = CredisContract::new(storage.clone())
            .get_position(position_id)
            .unwrap();
        assert_eq!(position.called_at, at, "stamped with the run's timestamp");
        assert_eq!(
            outbe_credis::settlement_deadline(&position),
            at + CALL_WINDOW_SECS,
            "the 7-day settlement window opens at the call"
        );

        // The owner's called-position counter tracks the unresolved call.
        assert!(CredisContract::new(storage.clone())
            .has_called_position(alice())
            .unwrap());

        // Idempotent: a second run does not move the deadline.
        assert_eq!(scan(&storage, at), 0);
        assert_eq!(
            CredisContract::new(storage.clone())
                .get_position(position_id)
                .unwrap()
                .called_at,
            at
        );
    });
    teardown();
}

/// The breach test is strictly above the call price, as it is for Nod, Gem and
/// Intex. A window that closes exactly on the call price every single day must
/// therefore leave the position open.
#[test]
fn a_full_window_exactly_at_the_call_price_does_not_call_the_position() {
    let mut storage = env();
    StorageHandle::enter(&mut storage, |storage| {
        bootstrap(&storage, pledge_cost());
        let at = CREATED_AT + AFTER_WINDOW;
        let position_id = open_with_series(&storage, at, CALL_LOOKBACK_DAYS, at_call());

        assert_eq!(scan(&storage, at), 0);
        assert_eq!(state_of(&storage, position_id), CredisState::Open);

        // One minor unit higher on every day is a breach window.
        fill_days(
            &storage,
            last_closed_day(at),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );
        assert_eq!(scan(&storage, at), 1);
        assert_eq!(state_of(&storage, position_id), CredisState::Called);
    });
    teardown();
}

#[test]
fn the_window_absorbs_below_call_days_up_to_the_slack() {
    let mut storage = env();
    StorageHandle::enter(&mut storage, |storage| {
        bootstrap(&storage, pledge_cost());
        let at = CREATED_AT + AFTER_WINDOW;
        let position_id = open_with_series(&storage, at, CALL_LOOKBACK_DAYS, above_call());

        // Scatter the full slack of below-call days through the window. The rule
        // counts breach days rather than requiring a run, so their position must
        // not matter: exactly `CALL_BREACH_DAYS` still calls.
        let slack = CALL_LOOKBACK_DAYS - CALL_BREACH_DAYS;
        let stride = (CALL_LOOKBACK_DAYS - 1) / slack;
        for i in 0..slack {
            let offset = i * stride + 1;
            // Guards the boundary: a below-call day placed past the window would
            // silently leave more than `CALL_BREACH_DAYS` breaches standing and
            // make this test stop probing the threshold.
            assert!(
                offset < CALL_LOOKBACK_DAYS,
                "below-call day {offset} falls outside the lookback window"
            );
            set_vwap(&storage, day_back(at, offset), below_call());
        }

        assert_eq!(scan(&storage, at), 1);
        assert_eq!(state_of(&storage, position_id), CredisState::Called);
    });
    teardown();
}

#[test]
fn one_breach_day_short_of_the_threshold_does_not_call() {
    let mut storage = env();
    StorageHandle::enter(&mut storage, |storage| {
        bootstrap(&storage, pledge_cost());
        let at = CREATED_AT + AFTER_WINDOW;
        let position_id = open_with_series(&storage, at, CALL_LOOKBACK_DAYS, above_call());

        // One more below-call day than the window can absorb.
        let below = CALL_LOOKBACK_DAYS - CALL_BREACH_DAYS + 1;
        for i in 0..below {
            set_vwap(&storage, day_back(at, i + 1), below_call());
        }

        assert_eq!(scan(&storage, at), 0);
        assert_eq!(state_of(&storage, position_id), CredisState::Open);

        // Raising one of them back over the call price completes the threshold.
        set_vwap(&storage, day_back(at, 1), above_call());
        assert_eq!(scan(&storage, at), 1);
        assert_eq!(state_of(&storage, position_id), CredisState::Called);
    });
    teardown();
}

#[test]
fn missing_days_do_not_count_as_breaches() {
    let mut storage = env();
    StorageHandle::enter(&mut storage, |storage| {
        bootstrap(&storage, pledge_cost());
        let at = CREATED_AT + AFTER_WINDOW;
        let position_id = open(&storage, 1);
        advance_to(&storage, at);

        // Publish one day short of the threshold and leave the rest of the window
        // unpublished. section 11.3's placeholder: a day with no reference price is not
        // a breach, so it can only delay a call.
        for i in 0..CALL_BREACH_DAYS - 1 {
            set_vwap(&storage, day_back(at, i), above_call());
        }
        // The watermark must still cover the window, or the run would skip.
        finalize_through(&storage, at);

        assert_eq!(scan(&storage, at), 0);
        assert_eq!(state_of(&storage, position_id), CredisState::Open);

        // Filling one more published day reaches the threshold, even though the
        // rest of the window still has no price at all.
        set_vwap(&storage, day_back(at, CALL_BREACH_DAYS - 1), above_call());
        assert_eq!(scan(&storage, at), 1);
        assert_eq!(state_of(&storage, position_id), CredisState::Called);
    });
    teardown();
}

#[test]
fn a_breach_run_that_predates_the_position_does_not_call_it() {
    let mut storage = env();
    StorageHandle::enter(&mut storage, |storage| {
        bootstrap(&storage, pledge_cost());
        // The series is long and fully breached, but the position is 3 days old,
        // so the window reaches back before it existed.
        let at = CREATED_AT + 3 * DAY;
        let position_id = open(&storage, 1);
        advance_to(&storage, at);
        fill_days(
            &storage,
            last_closed_day(at),
            CALL_LOOKBACK_DAYS + 10,
            above_call(),
        );

        assert_eq!(scan(&storage, at), 0);
        assert_eq!(state_of(&storage, position_id), CredisState::Open);

        // Once the position is old enough for the window to sit entirely after
        // its origination day, the call fires.
        let later = CREATED_AT + AFTER_WINDOW;
        advance_to(&storage, later);
        fill_days(
            &storage,
            last_closed_day(later),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );
        assert_eq!(scan(&storage, later), 1);
        assert_eq!(state_of(&storage, position_id), CredisState::Called);
    });
    teardown();
}

#[test]
fn an_unfinalized_day_skips_the_run_without_touching_state() {
    let mut storage = env();
    StorageHandle::enter(&mut storage, |storage| {
        bootstrap(&storage, pledge_cost());
        let at = CREATED_AT + AFTER_WINDOW;
        let position_id = open_with_series(&storage, at, CALL_LOOKBACK_DAYS, above_call());

        // Rewind the watermark behind the last closed day: the oracle has not
        // closed it yet, so the run must skip rather than read it as missing.
        let oracle = outbe_oracle::schema::OracleContract::new(storage.clone());
        oracle
            .utc_day_vwap_last_finalized
            .write(previous_date_key(last_closed_day(at)))
            .unwrap();

        assert_eq!(scan(&storage, at), 0);
        assert_eq!(state_of(&storage, position_id), CredisState::Open);
    });
    teardown();
}

#[test]
fn the_call_and_the_void_compose_across_runs() {
    let mut storage = env();
    StorageHandle::enter(&mut storage, |storage| {
        bootstrap(&storage, pledge_cost());
        let at = CREATED_AT + AFTER_WINDOW;
        let position_id = open_with_series(&storage, at, CALL_LOOKBACK_DAYS, above_call());

        assert_eq!(scan(&storage, at), 1);
        assert_eq!(state_of(&storage, position_id), CredisState::Called);

        // A position called in this same run can never be voided by it: the
        // window opens at `called_at = now`.
        assert_eq!(scan(&storage, at), 0);

        // Inside the window, nothing happens.
        let inside = at + CALL_WINDOW_SECS - DAY;
        advance_to(&storage, inside);
        finalize_through(&storage, inside);
        assert_eq!(scan(&storage, inside), 0);
        assert_eq!(state_of(&storage, position_id), CredisState::Called);

        // The window lapses with the whole principal outstanding: the entire
        // collateral is burned and credited to the Promis Reserve.
        let lapsed = at + CALL_WINDOW_SECS;
        advance_to(&storage, lapsed);
        finalize_through(&storage, lapsed);
        assert_eq!(scan(&storage, lapsed), 1);
        assert_eq!(state_of(&storage, position_id), CredisState::Void);
        assert_eq!(view_pledged(&storage, alice()), U256::ZERO);
        assert_eq!(
            outbe_promislimit::PromisLimitContract::new(storage.clone())
                .get_total_unallocated()
                .unwrap(),
            pledge_cost()
        );

        // The void cleared the owner's called count and left the active index.
        assert!(!CredisContract::new(storage.clone())
            .has_called_position(alice())
            .unwrap());
        assert_eq!(
            CredisContract::new(storage.clone()).active_len().unwrap(),
            0
        );
    });
    teardown();
}

#[test]
fn each_reference_currency_prices_off_its_own_daily_series() {
    let mut storage = env();
    StorageHandle::enter(&mut storage, |storage| {
        bootstrap(&storage, pledge_cost());
        let at = CREATED_AT + AFTER_WINDOW;
        let position_id = open(&storage, 1);

        // Re-point the stored position's ANCHOR at an unregistered currency, so it
        // prices off a series that does not exist.
        {
            let credis = CredisContract::new(storage.clone());
            let mut position = credis.get_position(position_id).unwrap();
            position.reference_currency = UNPRICED_ISO;
            credis.positions.update(&position).unwrap();
        }

        // The seeded reference series is a full breach window, but this position is
        // no longer anchored to it.
        advance_to(&storage, at);
        fill_days(
            &storage,
            last_closed_day(at),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );
        assert_eq!(
            scan(&storage, at),
            0,
            "an unpriced reference currency is never called"
        );
        assert_eq!(state_of(&storage, position_id), CredisState::Open);
    });
    teardown();
}

/// The call is anchored to the reference currency, never to the issuance currency
/// the position is denominated in. Both directions, because getting the anchor
/// wrong fails silently in one of them: with the two series moving together an
/// issuance-keyed scan still reaches the right verdict by coincidence.
#[test]
fn the_call_follows_the_reference_series_and_ignores_the_issuance_one() {
    // Breach published only on the reference series -> the position is called.
    let mut storage = env();
    StorageHandle::enter(&mut storage, |storage| {
        bootstrap(&storage, pledge_cost());
        let at = CREATED_AT + AFTER_WINDOW;
        let position_id = open(&storage, 1);
        assert_ne!(
            ISSUANCE_ISO, REFERENCE_ISO,
            "the fixture must keep the two codes distinct"
        );

        advance_to(&storage, at);
        fill_days_for(
            &storage,
            REFERENCE_ISO,
            last_closed_day(at),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );
        // COEN/840 stays silent for the whole window.
        assert_eq!(scan(&storage, at), 1);
        assert_eq!(state_of(&storage, position_id), CredisState::Called);
    });
    teardown();

    // Breach published only on the issuance series -> nothing happens.
    let mut storage = env();
    StorageHandle::enter(&mut storage, |storage| {
        bootstrap(&storage, pledge_cost());
        let at = CREATED_AT + AFTER_WINDOW;
        let position_id = open(&storage, 1);

        advance_to(&storage, at);
        fill_days_for(
            &storage,
            ISSUANCE_ISO,
            last_closed_day(at),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );
        assert_eq!(
            scan(&storage, at),
            0,
            "a breach in the issuance currency must not call the position"
        );
        assert_eq!(state_of(&storage, position_id), CredisState::Open);
    });
    teardown();
}

/// Opens one position for each of three distinct owners, so none of them trips
/// the called-position gate. Returns the ids in active-index order.
fn open_three(storage: &StorageHandle<'_>) -> Vec<U256> {
    let owners: [Address; 3] = [alice(), bob(), cca()];
    for owner in owners {
        bootstrap_for(storage, owner, pledge_cost());
    }
    owners
        .iter()
        .map(|owner| open_for(storage, *owner, 1))
        .collect()
}

fn cursor_of(storage: &StorageHandle<'_>) -> u32 {
    crate::schema::CredisFactoryContract::new(storage.clone())
        .call_scan_cursor
        .read()
        .unwrap()
}

#[test]
fn a_completed_pass_resets_the_cursor() {
    let mut storage = env();
    StorageHandle::enter(&mut storage, |storage| {
        let ids = open_three(&storage);
        assert_eq!(
            CredisContract::new(storage.clone()).active_len().unwrap(),
            3
        );

        let at = CREATED_AT + AFTER_WINDOW;
        advance_to(&storage, at);
        fill_days(
            &storage,
            last_closed_day(at),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );

        assert_eq!(scan(&storage, at), 3);
        for id in &ids {
            assert_eq!(state_of(&storage, *id), CredisState::Called);
        }
        assert_eq!(cursor_of(&storage), 0, "a completed pass resets the cursor");
    });
    teardown();
}

#[test]
fn a_resumed_pass_starts_at_the_cursor_and_walks_down() {
    let mut storage = env();
    StorageHandle::enter(&mut storage, |storage| {
        let ids = open_three(&storage);

        // Pretend the previous run stopped after index 2: the stored cursor is
        // `index + 1`, so 2 means "resume at index 1".
        crate::schema::CredisFactoryContract::new(storage.clone())
            .call_scan_cursor
            .write(2)
            .unwrap();

        let at = CREATED_AT + AFTER_WINDOW;
        advance_to(&storage, at);
        fill_days(
            &storage,
            last_closed_day(at),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );

        // Only indices 1 and 0 are visited; the position at index 2 is untouched.
        assert_eq!(scan(&storage, at), 2);
        assert_eq!(state_of(&storage, ids[0]), CredisState::Called);
        assert_eq!(state_of(&storage, ids[1]), CredisState::Called);
        assert_eq!(
            state_of(&storage, ids[2]),
            CredisState::Open,
            "the entry above the resume point waits for the next pass"
        );
        assert_eq!(cursor_of(&storage), 0);

        // The next pass starts fresh from the top and picks it up.
        assert_eq!(scan(&storage, at), 1);
        assert_eq!(state_of(&storage, ids[2]), CredisState::Called);
    });
    teardown();
}

#[test]
fn voiding_several_positions_in_one_pass_skips_none() {
    let mut storage = env();
    StorageHandle::enter(&mut storage, |storage| {
        let ids = open_three(&storage);

        // Call all three by hand, then let the window lapse. The point
        // of the test is the traversal: each void swap-pops the active list, and
        // the descending walk must still visit every entry exactly once.
        let called_at = CREATED_AT;
        {
            let mut credis = CredisContract::new(storage.clone());
            for id in &ids {
                assert!(credis.mark_called(*id, called_at).unwrap());
            }
        }

        let lapsed = called_at + CALL_WINDOW_SECS;
        advance_to(&storage, lapsed);
        finalize_through(&storage, lapsed);
        assert_eq!(scan(&storage, lapsed), 3, "all three voided in one pass");

        for id in &ids {
            assert_eq!(state_of(&storage, *id), CredisState::Void);
        }
        assert_eq!(
            CredisContract::new(storage.clone()).active_len().unwrap(),
            0
        );
    });
    teardown();
}

#[test]
fn the_void_budget_bounds_one_run_without_starving_the_call_arm() {
    let mut storage = env();
    StorageHandle::enter(&mut storage, |storage| {
        let budget = crate::called::MAX_CREDIS_VOIDS_PER_RUN;
        // One Open position plus one more voidable position than the budget, so
        // a void is genuinely declined and the run still has to walk past it.
        let total = budget + 2;

        // One owner can hold many positions as long as none is called yet, so
        // open them all first and only then arm the calls.
        bootstrap_for(&storage, alice(), pledge_cost() * U256::from(total));
        let ids: Vec<U256> = (1..=u64::from(total))
            .map(|nonce| open_for(&storage, alice(), nonce))
            .collect();

        // `ids[0]` sits at active index 0, so the descending walk reaches it
        // LAST - after the void budget is already spent. Leave it Open; the rest
        // become called-and-lapsed.
        let called_at = CREATED_AT;
        {
            let mut credis = CredisContract::new(storage.clone());
            for id in &ids[1..] {
                assert!(credis.mark_called(*id, called_at).unwrap());
            }
        }

        // Far enough past the call that the window has lapsed AND a full breach
        // window sits entirely after the positions' origination day.
        let lapsed = called_at + AFTER_WINDOW;
        advance_to(&storage, lapsed);
        fill_days(
            &storage,
            last_closed_day(lapsed),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );

        // A void costs two enclave round-trips, so the run stops voiding at the
        // budget - but it must keep walking. The Open position behind the
        // exhausted budget is still called in this same run.
        assert_eq!(scan(&storage, lapsed), budget + 1, "64 voids plus the call");
        assert_eq!(
            state_of(&storage, ids[0]),
            CredisState::Called,
            "a void backlog must not throttle the call arm"
        );
        assert_eq!(
            CredisContract::new(storage.clone()).active_len().unwrap(),
            2,
            "the newly called position plus the one void the budget declined"
        );
        assert_eq!(cursor_of(&storage), 0, "the pass completed despite the cap");

        // The next run drains the remainder.
        assert_eq!(scan(&storage, lapsed), 1);
        for id in &ids[1..] {
            assert_eq!(state_of(&storage, *id), CredisState::Void);
        }
    });
    teardown();
}
