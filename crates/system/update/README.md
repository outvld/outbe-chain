# Update

`outbe-update` stores protocol upgrade proposals and the active on-chain protocol version.

## Version Model

Semver is a version in form `MAJOR.MINOR.PATCH`. It is mainly a developer/package API convention: major means incompatible API change, minor means compatible feature, patch means compatible fix.

Linux uses version numbers more loosely. Major bumps often mark a historical or conceptual period, not strictly an incompatible API break.

### What is API in blockchain node?
To understand how semver is applicable to our versioning, we need to define what is API in blockchain node. Usually it consists of 3 layers:
- end-user interface: RPC methods, contract interfaces (and probably storage);
- operator interface: CLI arguments, storage encoding, network protocol;
- inter-node synchronization: network protocol, behaviour (precompiled contract implementation, consensus rules, etc.)

So technically, every RPC methods or CLI arguments removal should be a major version bump, from the semver perspective.

### Governance version

Governance version is more bounded to inter-node synchronization.
Every node build should be backward compatible with the previous versions. This is important for replay stage.
Thats why by it's form, the governance version should be monotonically increasing number.

### Semver usage
To avoid multiple version types, the proposal is to use following rules during development, to make it easier to map semver from github release to on-chain version:

- The `minor` should be bumped when protocol behavior changes: schema fields adding, contract logic (even subtle like rounding changes), or new on chain features.
- The `major` bumps is kept for historical or conceptual milestones. Technically, handle it like a minor version bump, but with higher priority so that `2.0` is always greater than `1.X`.
- `patch` stays binary/package-only. Use it for compatible changes: logs, optimizations, refactors, non-state behavior cleanup.
- **Security fixes may be patch releases even if behavior changes; they are urgent binary fixes, and should not be passed through the governance.**

Using this rules, the on-chain version uses one `u32` slot, encoded as `u8 major + u24 minor`.

Unset storage slots default to version `0`, which is the initial version - before upgrade governance is activated.

## Limitations

- Caps for versions: max major: `255`, max minor: `16_777_215`.
- Semver requires bump minor version when new API is added, e.g. new RPC method.
- Semver requires bump major version when old outdated API is removed.

## Alternatives

- Instead of mapping semver version on chain, we can use a separate version ID as constant, with manual bump on inter-node synchronization changes.
- We can have per-feature governance, this would require sublte contract interface changes, but will allow more granular control over each feature.