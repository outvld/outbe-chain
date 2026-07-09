use alloy_primitives::U256;
use serde_json::Value;

use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::{PrecompileError, Result};

use crate::constants::{
    max_activatable_version, min_activation_buffer, MAX_WAITING_FOR_ACTIVATION_UPDATES,
};
use crate::errors::UpdateError;
use crate::handlers::UpgradeHandlerRegistry;
use crate::payload::decode_schedule_update_json;
use crate::precompile::IUpdate;
use crate::schema::{ScheduledUpdateStatus, Update};
use crate::version::format_protocol_version;
use crate::ProtocolVersion;

impl Update<'_> {
    /// Schedules an update from an approved vote proposal payload.
    pub fn schedule_update_from_propose(
        &mut self,
        proposal_id: U256,
        payload: &Value,
        current_height: u64,
    ) -> Result<()> {
        let (version, activation_height, info) = decode_schedule_update_json(payload)?;
        self.schedule_update_from_propose_fields(
            proposal_id,
            version,
            activation_height,
            &info,
            current_height,
        )
    }

    fn schedule_update_from_propose_fields(
        &mut self,
        proposal_id: U256,
        version: ProtocolVersion,
        activation_height: u64,
        info: &str,
        current_height: u64,
    ) -> Result<()> {
        if self.read_scheduled_update(proposal_id)?.is_some() {
            return Err(UpdateError::ScheduledUpdateAlreadyExists.into());
        }

        if version.is_zero() {
            return Err(UpdateError::InvalidVersion.into());
        }

        let active = self.get_active_version()?;
        if version <= active {
            return Err(UpdateError::DowngradeNotAllowed.into());
        }

        let chain_id = self.storage.chain_id()?;
        let min_activation = current_height.saturating_add(min_activation_buffer(chain_id));
        if activation_height < min_activation {
            return Err(UpdateError::HeightInPast.into());
        }

        if self.scheduled_activation_conflict(activation_height)? {
            return Err(UpdateError::ActivationConflict.into());
        }

        let waiting_len = self.waiting_for_activation_proposal_ids.len()? as u32;
        if waiting_len >= MAX_WAITING_FOR_ACTIVATION_UPDATES {
            return Err(UpdateError::TooManyWaitingForActivation.into());
        }

        self.write_scheduled_update(proposal_id, version, activation_height, info)?;
        self.emit(IUpdate::ScheduledUpdateCreated {
            proposalId: proposal_id,
            version: version.raw(),
            activationHeight: activation_height,
            info: info.as_bytes().to_vec().into(),
        })
    }

    /// Activates scheduled updates at the current block height using `registry`.
    pub fn process_begin_block_with_handlers(
        &mut self,
        ctx: &BlockRuntimeContext,
        registry: &UpgradeHandlerRegistry,
    ) -> Result<()> {
        let block_number = ctx.block.block_number;
        let waiting_ids = self.list_waiting_for_activation_proposal_ids()?;
        for proposal_id in waiting_ids {
            let Some(scheduled) = self.read_scheduled_update(proposal_id)? else {
                return Err(UpdateError::ScheduledUpdateNotFound.into());
            };
            if scheduled.status == ScheduledUpdateStatus::Scheduled
                && block_number >= scheduled.activation_height
            {
                self.activate_scheduled_update(ctx, registry, proposal_id)?;
            }
        }
        Ok(())
    }

    fn activate_scheduled_update(
        &mut self,
        ctx: &BlockRuntimeContext,
        registry: &UpgradeHandlerRegistry,
        proposal_id: U256,
    ) -> Result<()> {
        let scheduled = self
            .read_scheduled_update(proposal_id)?
            .ok_or(UpdateError::ScheduledUpdateNotFound)?;
        if scheduled.status != ScheduledUpdateStatus::Scheduled {
            return Ok(());
        }
        let active = self.get_active_version()?;
        if scheduled.version <= active {
            return self.cancel_scheduled_update(proposal_id);
        }

        let ceiling = max_activatable_version(self.storage.chain_id()?);
        if scheduled.version > ceiling {
            return Err(PrecompileError::Fatal(format!(
                "cannot activate protocol version {}: binary supports at most {}",
                format_protocol_version(scheduled.version),
                format_protocol_version(ceiling),
            )));
        }

        ctx.with_checkpoint(|| {
            for handler in registry.lookup(scheduled.version) {
                handler.handle(ctx, &scheduled).map_err(|err| match err {
                    PrecompileError::Fatal(message) => PrecompileError::Fatal(message),
                    other => PrecompileError::Fatal(format!(
                        "upgrade handler '{}' failed: {other}",
                        handler.label()
                    )),
                })?;
            }

            self.set_active_version(scheduled.version, scheduled.activation_height)?;
            self.set_scheduled_update_status(proposal_id, ScheduledUpdateStatus::Activated)?;
            self.emit(IUpdate::UpgradeActivated {
                version: scheduled.version.raw(),
                activationHeight: scheduled.activation_height,
            })?;
            self.cancel_outdated_waiting_updates(scheduled.version)
        })
    }

    fn cancel_scheduled_update(&mut self, proposal_id: U256) -> Result<()> {
        let scheduled = self
            .read_scheduled_update(proposal_id)?
            .ok_or(UpdateError::ScheduledUpdateNotFound)?;
        if scheduled.status != ScheduledUpdateStatus::Scheduled {
            return Ok(());
        }

        self.set_scheduled_update_status(proposal_id, ScheduledUpdateStatus::Canceled)?;
        self.emit(IUpdate::UpgradeCanceled {
            proposalId: proposal_id,
            version: scheduled.version.raw(),
            activationHeight: scheduled.activation_height,
        })
    }

    fn cancel_outdated_waiting_updates(
        &mut self,
        active_version: crate::ProtocolVersion,
    ) -> Result<()> {
        let waiting_ids = self.list_waiting_for_activation_proposal_ids()?;
        for proposal_id in waiting_ids {
            let Some(scheduled) = self.read_scheduled_update(proposal_id)? else {
                continue;
            };
            if scheduled.status == ScheduledUpdateStatus::Scheduled
                && scheduled.version <= active_version
            {
                self.cancel_scheduled_update(proposal_id)?;
            }
        }
        Ok(())
    }

    fn scheduled_activation_conflict(&self, activation_height: u64) -> Result<bool> {
        for proposal_id in self.list_waiting_for_activation_proposal_ids()? {
            let Some(scheduled) = self.read_scheduled_update(proposal_id)? else {
                continue;
            };
            if scheduled.status == ScheduledUpdateStatus::Scheduled
                && scheduled.activation_height == activation_height
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
