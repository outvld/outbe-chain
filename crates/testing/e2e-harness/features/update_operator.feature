@min-validators-4
Feature: Operator protocol-version update via governance vote
  # Port of scripts/e2e/update_operator_flow.sh: an operator proposes a protocol
  # update, three validators approve it, and after the voting window + activation
  # height the new version goes live with state-root parity across the committee.
  # Needs a >=4-validator committee; runs with or without TEE (--tee any).
  #
  # The voting window is measured in blocks (~1s each — consensus enforces a 1000ms
  # minimum). It must outlast the wall-clock cost of casting the votes over
  # sequential RPC round-trips, or the proposal expires before it can be approved.
  # The vote step fires the ballots without blocking and the tally is polled, so a
  # 20-block (~20s) window leaves room.

  Scenario: An update is proposed, approved, scheduled, and activated
    Given a fresh localnet with a 20-block voting window
    And the committee has reached a usable height
    When operator "validator-0" proposes an update to the next protocol version
    Then proposal 1 is pending, targets the update module, and carries the activation height
    When validators "validator-0,validator-1,validator-2" cast yes votes
    Then proposal 1 is still pending with 3 yes votes
    When the committee passes the vote deadline
    Then proposal 1 is approved and the scheduled update matches the proposal
    When the committee passes the activation height
    Then the active protocol version equals the proposed version
    And the scheduled update is marked activated
    And the committee nodes agree on the state root
