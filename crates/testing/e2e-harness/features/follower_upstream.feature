@tee @min-validators-4
Feature: Upstream followers, validator catch-up, and warm promotion
  # Port of scripts/e2e/follower_upstream.sh. A cold --upstream follower syncs a
  # reshared chain to lockstep; a second follower chains off the first; a
  # validator killed mid-epoch restarts and re-locksteps; finally follower1's
  # synced datadir is warm-promoted into an ACTIVE validator.

  Scenario: Followers sync, a validator recovers, and a follower is warm-promoted
    Given a fresh localnet with a short epoch
    When the committee drives past a reshare
    And a cold follower syncs from the committee
    Then the follower reaches lockstep with the committee
    When a second follower chains off the first
    Then the chained follower reaches lockstep with the committee
    When a validator is killed and restarted mid-epoch
    Then the restarted validator catches up to lockstep
    When the first follower is promoted to a validator with its warm datadir
    Then the promoted validator activates and stays in lockstep
