use alloy_primitives::U256;
use outbe_macros::{contract, storage_record, storage_schema};
use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::storage::types::Mapping;

use crate::errors::UpdateError;
use crate::ProtocolVersion;

/// Lifecycle status of a scheduled update (`IUpdate.ScheduledUpdateStatus`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScheduledUpdateStatus {
    Scheduled = 0,
    Activated = 1,
    Canceled = 2,
}

impl ScheduledUpdateStatus {
    pub fn from_u8(value: u8) -> std::result::Result<Self, UpdateError> {
        match value {
            0 => Ok(Self::Scheduled),
            1 => Ok(Self::Activated),
            2 => Ok(Self::Canceled),
            _ => Err(UpdateError::InvalidScheduledUpdateStatus),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Scheduled update record keyed by vote `proposal_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[storage_record(exists_field = version)]
pub struct ScheduledUpdateRecord {
    #[key]
    pub proposal_id: U256,

    #[attribute(order = 0)]
    pub version: ProtocolVersion,

    #[attribute(order = 1)]
    pub activation_height: u64,

    #[attribute(order = 2)]
    pub info: Vec<u8>,

    #[attribute(order = 3)]
    pub status: u8, // ScheduledUpdateStatus
}

impl ScheduledUpdateRecord {
    pub fn scheduled_update_status(
        &self,
    ) -> std::result::Result<ScheduledUpdateStatus, UpdateError> {
        ScheduledUpdateStatus::from_u8(self.status)
    }

    pub fn set_scheduled_update_status(&mut self, status: ScheduledUpdateStatus) {
        self.status = status.to_u8();
    }
}

/// EVM storage layout for the Update precompile.
#[storage_schema]
#[contract(addr = UPDATE_ADDRESS)]
pub struct Update {
    #[attribute(order = 0)]
    pub active_version: outbe_primitives::storage::dsl::Value<ProtocolVersion>,

    #[attribute(order = 1)]
    pub active_version_height: outbe_primitives::storage::dsl::Value<u64>,

    #[attribute(order = 2)]
    pub waiting_for_activation_proposal_ids: outbe_primitives::storage::dsl::List<U256>,

    #[attribute(order = 3)]
    pub scheduled_updates: outbe_primitives::storage::dsl::Map<U256, ScheduledUpdateRecord>,

    #[attribute(order = 4)]
    pub version_history: Mapping<u64, ProtocolVersion>,
}
