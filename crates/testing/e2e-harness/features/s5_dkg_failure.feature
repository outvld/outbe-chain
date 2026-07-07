@tee @min-validators-4
Feature: DKG reshare failure keeps the old committee live
  # Port of scripts/e2e/s5_dkg_failure.sh. A frozen 4->5 reshare is starved below
  # player_threshold (joiner + one committee validator offline); the existing
  # committee keeps finalizing on its 3-of-4 quorum with no hard-halt. Restoring
  # the downed validator lets a later retry complete and the set reaches 5.

  Scenario: Stalled reshare does not halt the chain, and recovers when restored
    Given a fresh localnet with a wide DKG activation grace
    When a staked joiner freezes a 4-to-5 reshare target
    And the reshare loses quorum before it can complete
    Then the old committee keeps finalizing through the stalled reshare
    When the downed validator is restored
    Then the reshare completes and the active set reaches 5
