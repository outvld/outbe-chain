//! Node startup compatibility checks against on-chain active protocol version.

use crate::constants::PROTOCOL_VERSION;
use crate::handlers::UpgradeHandlerRegistry;
use crate::state::ScheduledUpdateInfo;
use crate::version::format_protocol_version;
use crate::ProtocolVersion;

/// Returns `Ok(())` when `binary_version` is new enough for `active_version`.
///
/// Fresh/pre-vote chains use `active_version == 0` and always pass.
pub fn assert_binary_protocol_compatible(active_version: ProtocolVersion) -> Result<(), String> {
    if active_version.is_zero() || active_version <= PROTOCOL_VERSION {
        return Ok(());
    }

    Err(format_binary_mismatch(PROTOCOL_VERSION, active_version))
}

/// Emits warnings for scheduled updates whose version has no handler entry.
pub fn warn_missing_handlers_for_waiting_updates(
    waiting: &[ScheduledUpdateInfo],
    registry: &UpgradeHandlerRegistry,
) {
    for scheduled in waiting {
        if registry.lookup(scheduled.version).is_none() {
            tracing::warn!(
                proposal_id = %scheduled.proposal_id,
                version = %format_protocol_version(scheduled.version),
                activation_height = scheduled.activation_height,
                "scheduled upgrade has no registered migration handler; version-only activation is valid"
            );
        }
    }
}

fn format_binary_mismatch(binary: ProtocolVersion, active: ProtocolVersion) -> String {
    format!(
        "binary protocol version {} is older than on-chain active protocol version {}; please upgrade the binary",
        format_protocol_version(binary),
        format_protocol_version(active)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode_protocol_version;

    #[test]
    fn allows_pre_vote_active_version_zero() {
        assert_binary_protocol_compatible(ProtocolVersion::ZERO).unwrap();
    }

    #[test]
    fn allows_binary_newer_than_active() {
        assert_binary_protocol_compatible(encode_protocol_version(0, 0)).unwrap();
    }

    #[test]
    fn rejects_binary_older_than_active() {
        let err = assert_binary_protocol_compatible(encode_protocol_version(2, 0)).unwrap_err();
        assert!(err.to_string().contains("older than on-chain active"));
    }
}
