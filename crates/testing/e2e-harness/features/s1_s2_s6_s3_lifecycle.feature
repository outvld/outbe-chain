@tee @min-validators-4
Feature: Validator lifecycle — cold sync, promote, in-flight offer, exit
  # Port of scripts/e2e/s1_s2_s6_s3_lifecycle.sh — one chain through four stages:
  # S1 a cold full node syncs and matches state/supply through its own enclave;
  # S2 it stakes + confirms and is promoted to ACTIVE via a reshare;
  # S6 a tribute offer submitted during the reshare window lands exactly once;
  # S3 it deactivates, the committee reshares down, and the node demotes to a
  # verifier-follower that keeps following finality.

  Scenario: A full node syncs, is promoted, survives an in-flight offer, then exits
    Given a fresh localnet with a 6-block voting window
    When operator "validator-0" submits a tribute offer
    Then the committee processes the offer without changing the day status
    When a full node joins and syncs to the committee tip
    Then the full node matches committee supply and state root and is not a participant
    When the full node stakes and confirms readiness
    Then it is promoted to an active participant and the in-flight offer lands once
    When the promoted validator deactivates
    Then it exits, the committee reshares down, and the node demotes to a follower
