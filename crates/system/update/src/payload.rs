//! Vote payload encoding for scheduled updates.
//!
//! JSON schema:
//! ```json
//! {"version":65538, "activationHeight":12345, "info":"notes"}
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::constants::MIN_ACTIVATION_BUFFER;
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

    pub fn validate(&self, current_height: u64) -> std::result::Result<(), UpdateError> {
        if self.protocol_version().is_zero() {
            return Err(UpdateError::InvalidVersion);
        }
        let min_activation = current_height.saturating_add(MIN_ACTIVATION_BUFFER);
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
) -> std::result::Result<(), UpdateError> {
    ScheduleUpdatePayload::from_value(payload)?.validate(current_height)
}
