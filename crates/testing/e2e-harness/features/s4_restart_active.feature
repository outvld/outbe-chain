@tee @min-validators-4
Feature: Active validator restarts without a new DKG ceremony
  # Port of scripts/e2e/s4_restart_active.sh. An ACTIVE validator's BLS share is
  # persisted to its keys-dir on disk (not the enclave). Killing only the node —
  # the enclave container stays up — and restarting it with the same keys-dir must
  # resume signing from the recovered share with NO fresh DKG ceremony.

  Scenario: Restarted active node resumes signing from its persisted share
    Given a fresh localnet with a 6-block voting window
    When a joiner reaches active with a persisted share
    And the node is killed and restarted with the same keys
    Then it resumes signing from the persisted share without a new ceremony
