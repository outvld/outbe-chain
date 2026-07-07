@tee @min-validators-4
Feature: Liveness survives a downed validator
  # Port of scripts/e2e/s7a_downtime_slash.sh. Killing one committee validator
  # drops the set to 3-of-4; the chain keeps finalizing on the BFT quorum. The
  # downtime felony itself is fee-settlement-gated (inactive on the ZeroFee
  # localnet), so only LIVENESS + the slashing-config read surface are asserted
  # here; the slash/evidence mechanism is covered by outbe-slashindicator tests.

  Scenario: Chain stays live after a validator is killed
    Given a fresh localnet with a 6-block voting window
    And the slashing config is readable
    And validator "validator-3" starts active
    When validator "validator-3" is killed
    Then the committee keeps finalizing on the remaining 3-of-4 quorum
