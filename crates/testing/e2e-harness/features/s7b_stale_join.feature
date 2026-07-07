@tee @min-validators-4
Feature: Stale-join guard holds an unconfirmed joiner PENDING
  # Port of scripts/e2e/s7b_stale_join.sh. A staked-but-unconfirmed joiner is
  # excluded from the frozen reshare target, so it stays PENDING across a full
  # reshare cycle; only after confirm-ready does the next reshare activate it.

  Scenario: Unconfirmed joiner does not activate until confirm-ready
    Given a fresh localnet with a 6-block voting window
    When a staked joiner has not confirmed readiness
    Then the unconfirmed joiner stays pending across a full reshare cycle
    When the joiner confirms readiness
    Then the confirmed joiner activates on the next reshare
