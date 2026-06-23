use alloy_primitives::U256;
use tracing::warn;

use outbe_primitives::error::Result;

use crate::errors::UpdateError;
use crate::schema::{ScheduledUpdateRecord, Update};
use crate::ProtocolVersion;

pub use crate::schema::ScheduledUpdateStatus;

/// Materialized scheduled update read from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledUpdateInfo {
    pub proposal_id: U256,
    pub version: ProtocolVersion,
    pub activation_height: u64,
    pub info: Vec<u8>,
    pub status: ScheduledUpdateStatus,
}

impl TryFrom<ScheduledUpdateRecord> for ScheduledUpdateInfo {
    type Error = UpdateError;

    fn try_from(record: ScheduledUpdateRecord) -> std::result::Result<Self, Self::Error> {
        let status = record.scheduled_update_status()?;
        Ok(Self {
            proposal_id: record.proposal_id,
            version: record.version,
            activation_height: record.activation_height,
            info: record.info,
            status,
        })
    }
}

/// Returns the major part of an encoded protocol version.
pub const fn protocol_version_major(version: ProtocolVersion) -> u8 {
    crate::version::protocol_version_major(version)
}

/// Returns the minor part of an encoded protocol version.
pub const fn protocol_version_minor(version: ProtocolVersion) -> u32 {
    crate::version::protocol_version_minor(version)
}

impl Update<'_> {
    /// Reads a scheduled update or returns `None` when absent.
    pub fn read_scheduled_update(&self, proposal_id: U256) -> Result<Option<ScheduledUpdateInfo>> {
        Ok(self
            .scheduled_updates
            .get(proposal_id)?
            .map(ScheduledUpdateInfo::try_from)
            .transpose()?)
    }

    /// Returns all proposal ids waiting for activation height.
    pub fn list_waiting_for_activation_proposal_ids(&self) -> Result<Vec<U256>> {
        self.waiting_for_activation_proposal_ids.read_all()
    }

    /// Reads the active protocol version.
    pub fn get_active_version(&self) -> Result<Option<ProtocolVersion>> {
        Ok(Some(self.active_version.read()?))
    }

    /// Reads the activation height of the current active version.
    pub fn get_active_version_height(&self) -> Result<u64> {
        self.active_version_height.read()
    }

    /// Reads the version recorded at `height`.
    pub fn version_at_height(&self, height: u64) -> Result<Option<ProtocolVersion>> {
        Ok(Some(self.version_history.read(&height)?))
    }

    /// Writes the active protocol version and records it in `version_history`.
    pub fn set_active_version(&mut self, version: ProtocolVersion, height: u64) -> Result<()> {
        self.active_version.write(version)?;
        self.active_version_height.write(height)?;
        self.version_history.write(&height, version)?;
        Ok(())
    }

    /// Persists a pending scheduled update and indexes it for activation.
    pub fn write_scheduled_update(
        &mut self,
        proposal_id: U256,
        version: ProtocolVersion,
        activation_height: u64,
        info: &[u8],
    ) -> Result<()> {
        if proposal_id.is_zero() {
            return Err(UpdateError::InvalidPayload.into());
        }

        let record = ScheduledUpdateRecord {
            proposal_id,
            version,
            activation_height,
            info: info.to_vec(),
            status: ScheduledUpdateStatus::Pending.to_u8(),
        };
        self.scheduled_updates.create(&record)?;
        self.waiting_for_activation_proposal_ids.push(proposal_id)?;
        Ok(())
    }

    /// Updates scheduled update status and moves lifecycle indexes when needed.
    pub fn set_scheduled_update_status(
        &mut self,
        proposal_id: U256,
        new_status: ScheduledUpdateStatus,
    ) -> Result<()> {
        let mut record = self
            .scheduled_updates
            .get(proposal_id)?
            .ok_or(UpdateError::ScheduledUpdateNotFound)?;
        let old_status = record.scheduled_update_status()?;

        if old_status == new_status {
            warn!("scheduled update status is already {old_status:?} for proposal {proposal_id}");
            return Ok(());
        }

        record.set_scheduled_update_status(new_status);
        self.scheduled_updates.update(&record)?;

        if old_status == ScheduledUpdateStatus::Pending {
            self.remove_waiting_for_activation_proposal_id(proposal_id)?;
        }
        Ok(())
    }

    fn remove_waiting_for_activation_proposal_id(&mut self, proposal_id: U256) -> Result<()> {
        Self::remove_proposal_id_from_list(
            &mut self.waiting_for_activation_proposal_ids,
            proposal_id,
        )
    }

    fn remove_proposal_id_from_list(
        list: &mut outbe_primitives::storage::dsl::List<U256>,
        proposal_id: U256,
    ) -> Result<()> {
        let ids = list.read_all()?;
        let Some(removed_idx) = ids.iter().position(|p| *p == proposal_id) else {
            warn!("proposal {proposal_id} not found in list");
            return Ok(());
        };

        let len = ids.len();
        if removed_idx != len - 1 {
            let last = list.get(len as u32 - 1)?.unwrap_or(U256::ZERO);
            list.set(removed_idx as u32, last)?;
        }
        let _ = list.pop()?;
        Ok(())
    }
}
