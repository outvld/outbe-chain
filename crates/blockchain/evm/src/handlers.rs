//! Node-level handler registries for vote target dispatch and upgrade migrations.
//!
//! Handler implementations live in their owning crates; this module wires them
//! into Vote and Update lifecycle at block processing time.

pub mod vote {
    use outbe_update::vote_target::UpdateVoteTarget;
    use outbe_vote::handlers::{VoteTarget, VoteTargetRegistry};

    static UPDATE_VOTE_TARGET: UpdateVoteTarget = UpdateVoteTarget;
    static ACTIVE_VOTE_TARGETS: &[&dyn VoteTarget] = &[&UPDATE_VOTE_TARGET];
    static REGISTRY: VoteTargetRegistry = VoteTargetRegistry::new(ACTIVE_VOTE_TARGETS);

    /// Returns the compile-time vote target registry for executor wiring.
    pub fn registry() -> &'static VoteTargetRegistry {
        &REGISTRY
    }
}

pub mod update {
    use outbe_update::handlers::{UpgradeHandlerRegistry, UpgradeHandlers};

    /// Active upgrade handlers for this node binary.
    ///
    /// Append entries when a protocol version requires deterministic storage
    /// migration at activation height. Versions without a handler activate as
    /// version-only switches.
    static ACTIVE_UPGRADE_HANDLERS: UpgradeHandlers = &[];
    static REGISTRY: UpgradeHandlerRegistry =
        UpgradeHandlerRegistry::new(ACTIVE_UPGRADE_HANDLERS);

    /// Returns the compile-time upgrade handler registry for executor wiring.
    pub fn registry() -> &'static UpgradeHandlerRegistry {
        &REGISTRY
    }
}
