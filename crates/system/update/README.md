# Update

`outbe-update` owns protocol update scheduling and active protocol-version reads.
It does not own proposal creation, voting, or quorum. Those live in
[`outbe-vote`](../vote/README.md), which calls the update target handler after an
update proposal is approved.

The update precompile address is `0x000000000000000000000000000000000000EE0B`
(`UPDATE_ADDRESS`).

## Internal API

Use `crates/system/update/src/api.rs` when another runtime module needs to check
the active protocol version:

- `get_active_version(storage)` returns the active `ProtocolVersion`.
- `version_at_height(storage, height)` returns the version activated at a block,
  or `0` when no update was activated there.
- `is_version_active_eq(storage, version)` checks exact active-version equality.
- `is_version_active_gte(storage, version)` checks feature availability by
  minimum active version.

`ProtocolVersion` is a `u32` encoded as `u8 major + u24 minor`. `0` means
unset/pre-upgrade. Display form is `v{major}.{minor}`.

## Vote Target Handler

`UpdateVoteTarget` is the bridge from `vote` into `update`.

- `target_module()` returns `UPDATE_ADDRESS`.
- `validate(payload, current_height)` validates the scheduled-update JSON during
  proposal creation.
- `handle_approved(ctx, proposal_id, payload)` writes the scheduled update after
  vote quorum is reached.

The accepted payload is:

```json
{"version":"1.2","activationHeight":12345,"info":"release notes or operator note"}
```

Rules:

- New scheduled version must be non-zero.
- New scheduled version must be strictly greater than current `active_version`.
- `activationHeight` must be at least `MIN_ACTIVATION_BUFFER` blocks in the future
  (the buffer is `0` on the localnet chain id so e2e updates activate promptly).
- At most one scheduled update may target a given activation height.

## Upgrade Handlers

Activation can run optional deterministic migrations before the active protocol
version is switched. This is useful for breaking changes in the schema, when some
system contracts need to perform migration of the underlying data.

- Implement `UpgradeHandler` for the version being activated.
- `version()` returns the `ProtocolVersion` handled by this migration.
- `label()` returns a stable human-readable label for errors/logs.
- `handle(ctx, scheduled)` performs deterministic storage changes.

Handlers run inside an activation checkpoint before `active_version`,
`active_version_height`, activation history, status, and `UpgradeActivated` are
written. Handler failure is fatal to block execution. Missing handler is valid:
the active version changes without a migration.

The concrete compile-time handler table is owned by the node execution layer and
passed to `UpdateLifecycle::begin_block_with_handlers`.

## External API

Read update state through `IUpdate` with `eth_call`/`cast call`:

```bash
UPDATE_ADDR=0x000000000000000000000000000000000000EE0B

cast call "$UPDATE_ADDR" 'getActiveVersion()(uint32)' --rpc-url "$RPC_URL"
cast call "$UPDATE_ADDR" 'getActiveVersionHeight()(uint64)' --rpc-url "$RPC_URL"
cast call "$UPDATE_ADDR" 'isVersionActive(uint32)(bool)' 16777218 --rpc-url "$RPC_URL"
cast call "$UPDATE_ADDR" 'getScheduledUpdate(uint256)((uint256,uint32,uint64,bytes,uint8))' 1 --rpc-url "$RPC_URL"
cast call "$UPDATE_ADDR" 'listWaitingForActivation()(uint256[])' --rpc-url "$RPC_URL"
```

Methods:

- `getActiveVersion() -> uint32`
- `getActiveVersionHeight() -> uint64`
- `isVersionActive(uint32 version) -> bool`
- `getScheduledUpdate(uint256 proposalId) -> ScheduledUpdate`
- `listWaitingForActivation() -> uint256[]`

Events:

- `ScheduledUpdateCreated(uint256 indexed proposalId, uint32 version, uint64 activationHeight, bytes info)`
- `UpgradeActivated(uint32 version, uint64 activationHeight)`
- `UpgradeCanceled(uint256 indexed proposalId, uint32 version, uint64 activationHeight)`

Update proposal and vote events are emitted by `vote`; see
[`outbe-vote`](../vote/README.md).

## Startup Gate

Use `outbe_update::startup::assert_binary_protocol_compatible(active_version)` to
fail fast when a local binary is older than the on-chain active protocol version.
This check is run before consensus/RPC startup.

At activation height, `activate_scheduled_update` also requires
`scheduled.version <= max_activatable_version(chain_id)`. On production /
unknown chains that ceiling is the binary `PROTOCOL_VERSION`. On
devnet/testnet it is raised to `v2.3` so integration tests can activate
versions ahead of the workspace package version. A scheduled version above
the ceiling returns `PrecompileError::Fatal` and aborts the block — nodes must
upgrade (or stay within the test ceiling) before that height can be applied.

Use `warn_missing_handlers_for_waiting_updates(waiting, registry)` to warn about
scheduled versions that have no migration handler. Missing handlers are warnings,
not startup failures, because version-only activation is valid.