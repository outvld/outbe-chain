//! Vote payload encoding for scheduled updates.
//!
//! JSON schema:
//! ```json
//! {"version":65538, "activationHeight":12345, "info":"notes"}
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::constants::min_activation_buffer;
use crate::errors::UpdateError;
use crate::ProtocolVersion;

/// JSON payload for scheduling a protocol update via vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleUpdatePayload {
    pub version: u32,
    pub activation_height: u64,
    #[serde(default)]
    pub info: String,
}

impl ScheduleUpdatePayload {
    pub fn new(version: ProtocolVersion, activation_height: u64, info: impl Into<String>) -> Self {
        Self {
            version: version.raw(),
            activation_height,
            info: info.into(),
        }
    }

    pub fn from_value(payload: &Value) -> std::result::Result<Self, UpdateError> {
        serde_json::from_value(payload.clone()).map_err(|_| UpdateError::InvalidPayload)
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        ProtocolVersion::from(self.version)
    }

    pub fn validate(
        &self,
        current_height: u64,
        chain_id: u64,
    ) -> std::result::Result<(), UpdateError> {
        if self.protocol_version().is_zero() {
            return Err(UpdateError::InvalidVersion);
        }
        let min_activation = current_height.saturating_add(min_activation_buffer(chain_id));
        if self.activation_height < min_activation {
            return Err(UpdateError::HeightInPast);
        }
        Ok(())
    }
}

/// Encodes update fields into a vote JSON payload string.
pub fn encode_schedule_update_json(
    version: ProtocolVersion,
    activation_height: u64,
    info: &str,
) -> String {
    serde_json::to_string(&ScheduleUpdatePayload::new(
        version,
        activation_height,
        info,
    ))
    .expect("schedule update payload JSON should serialize")
}

/// Decodes a vote JSON payload into update fields.
pub fn decode_schedule_update_json(
    payload: &Value,
) -> std::result::Result<(ProtocolVersion, u64, String), UpdateError> {
    let decoded = ScheduleUpdatePayload::from_value(payload)?;
    Ok((
        decoded.protocol_version(),
        decoded.activation_height,
        decoded.info,
    ))
}

/// Validates structural update JSON fields and activation-height buffer.
pub fn validate_schedule_update_json(
    payload: &Value,
    current_height: u64,
    chain_id: u64,
) -> std::result::Result<(), UpdateError> {
    ScheduleUpdatePayload::from_value(payload)?.validate(current_height, chain_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MIN_ACTIVATION_BUFFER;

    const LOCALNET_CHAIN_ID: u64 = 54_322_345;
    const OTHER_CHAIN_ID: u64 = 1;

    fn payload(activation_height: u64) -> ScheduleUpdatePayload {
        ScheduleUpdatePayload::new(ProtocolVersion::from(2), activation_height, "notes")
    }

    #[test]
    fn localnet_allows_immediate_activation() {
        // buffer is 0 on localnet: activation at the current height is accepted.
        assert!(payload(100).validate(100, LOCALNET_CHAIN_ID).is_ok());
    }

    #[test]
    fn other_chains_still_require_the_buffer() {
        let current = 100;
        let just_under = current + MIN_ACTIVATION_BUFFER - 1;
        assert!(matches!(
            payload(just_under).validate(current, OTHER_CHAIN_ID),
            Err(UpdateError::HeightInPast)
        ));
        assert!(payload(current + MIN_ACTIVATION_BUFFER)
            .validate(current, OTHER_CHAIN_ID)
            .is_ok());
    }
}
