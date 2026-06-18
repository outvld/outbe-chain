# Update

`outbe-update` stores protocol upgrade proposals and the active on-chain protocol version.

## Version Model

Semver is `MAJOR.MINOR.PATCH`. It is mainly a developer/package API convention: major means incompatible API change, minor means compatible feature, patch means compatible fix.

Linux uses version numbers more loosely. Major bumps often mark a historical or conceptual period, not strictly an incompatible API break.

On-chain protocol version requires something more like linux versioning. When any new feature version, is monotonically increasing number.

To avoid multiple version types, the proposal is to use following rules during development, to make it easier to map semver from github release to on-chain version:

- The `minor` should be bumped when protocol behavior changes: schema fields, contract logic (even subtle like rounding changes), or new on chain features.
- The `major` bumps is kept for historical or conceptual milestones. Technically, handle it like a minor version bump, but with higher priority.
- `patch` stays binary/package-only. Use it for compatible changes: logs, optimizations, refactors, non-state behavior cleanup.
- **Security fixes may be patch releases even if behavior changes; they are urgent binary fixes, and should not be passed through the governance.**

Using this rules, the on-chain version uses `u32`, encoded as `u8 major + u24 minor`.

Unset storage slots default to version `0`, which is the initial version - before upgrade governance is activated.

## Limits

- Max major: `255`.
- Max minor: `16_777_215`.
