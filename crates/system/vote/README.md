# Vote

`outbe-vote` is the reusable on-chain proposal and voting module. It owns
proposal creation, validator voting, quorum calculation, and dispatch to
registered target-module handlers after a proposal is approved.

The vote precompile address is `0x000000000000000000000000000000000000EE0C`
(`VOTE_ADDRESS`).

## Flow

```text
validator -> IVote.createProposal(targetModule, payload)
validators -> IVote.castVote(proposalId, yes/no)
vote.begin_block -> tally after voting deadline
approved proposal -> target handler
expired proposal -> no target side effect
handler error -> proposal rejected
```

Proposal payloads are JSON strings. `vote` does not interpret the target payload
beyond JSON parsing; the registered target module validates and decodes it.

## Internal API

Target modules implement `VoteTarget`:

- `target_module()` returns the target precompile address.
- `validate(payload, current_height)` is called during proposal creation.
- `handle_approved(ctx, proposal_id, payload)` is called when quorum is reached.
- `handle_tally(...)` can be overridden for custom terminal-status handling.

Validation is done before the proposal is created. `handle_*` methods are called after tally results are known.

The current update target handler is `outbe_update::vote_target::UpdateVoteTarget`.

## Voting Rules

- Proposal creation requires an active validator.
- Vote casting accepts validators with `ACTIVE` or `PENDING` validator status.
- Proposal creation and vote casting require signed EVM transactions to `VOTE_ADDRESS` with zero value.
- One validator can vote once per proposal.
- Voting is open until `voting_deadline_height`.
- Tally runs in `vote.begin_block` when `block_number > voting_deadline_height`.
- Quorum is `yes_votes * 3 >= active_validator_count * 2`.
- Approved proposals are dispatched to the target handler in the same begin-block
  pass.

## External API

Write calls require signed EVM transactions to `VOTE_ADDRESS` with zero value:

```bash
VOTE_ADDR=0x000000000000000000000000000000000000EE0C
UPDATE_ADDR=0x000000000000000000000000000000000000EE0B
PAYLOAD='{"version":16777218,"activationHeight":12345,"info":"v1.2 rollout"}'

outbe-cli --private-key "$VALIDATOR_KEY" vote propose \
  --target-module "$UPDATE_ADDR" \
  --payload "$PAYLOAD"

outbe-cli --private-key "$VALIDATOR_KEY" vote cast --proposal-id 1 --yes
outbe-cli vote status --proposal-id 1
```

Precompile methods:

- `createProposal(address targetModule, string payload) -> uint256 proposalId`
- `castVote(uint256 proposalId, bool approve)`
- `getProposal(uint256 proposalId) -> ProposalInfo`
- `getProposalVoters(uint256 proposalId, uint256 index, uint256 count) -> address[]`
- `listProposals(uint256 index, uint256 count) -> uint256[]`
- `listProposalsByStatus(ProposalStatus status, uint256 index, uint256 count) -> uint256[]`

Events:

- `ProposalCreated(uint256 indexed proposalId, address indexed proposer, address targetModule, string payload, uint64 votingDeadlineHeight)`
- `VoteCast(uint256 indexed proposalId, address indexed validator, bool approve)`
- `ProposalApproved(uint256 indexed proposalId, VoteTally state)`
- `ProposalRejected(uint256 indexed proposalId, VoteTally state, uint256 indexed conflictingproposalId)`
- `ProposalExpired(uint256 indexed proposalId, VoteTally state)`
- `ProposalCancelled(uint256 indexed proposalId, address indexed proposer)`

The governance journal (`governance-journal.jsonl`) records vote proposal
lifecycle events as best-effort operator observability.
