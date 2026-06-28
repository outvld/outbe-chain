use alloy_primitives::U256;

use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::{PrecompileError, Result};

use crate::constants::MIN_ACTIVATION_BUFFER;
use crate::errors::UpdateError;
use crate::handlers::UpgradeHandlerRegistry;
use crate::payload::decode_scheduled_update_payload;
use crate::precompile::IUpdate;
use crate::schema::{ScheduledUpdateStatus, Update};

impl Update<'_> {
    /// Schedules an update from an approved vote payload.
    pub fn schedule_update_from_vote(
        &mut self,
        proposal_id: U256,
        payload: &[u8],
        current_height: u64,
    ) -> Result<()> {
        if self.read_scheduled_update(proposal_id)?.is_some() {
            return Err(UpdateError::ScheduledUpdateAlreadyExists.into());
        }

        let (version, activation_height, info) = decode_scheduled_update_payload(payload)?;
        if version.is_zero() {
            return Err(UpdateError::InvalidVersion.into());
        }

        if let Some(active) = self.get_active_version()? {
            if version <= active {
                return Err(UpdateError::DowngradeNotAllowed.into());
            }
        }

        let min_activation = current_height.saturating_add(MIN_ACTIVATION_BUFFER);
        if activation_height < min_activation {
            return Err(UpdateError::HeightInPast.into());
        }

        if self.scheduled_activation_conflict(activation_height)? {
            return Err(UpdateError::ActivationConflict.into());
        }

        self.write_scheduled_update(proposal_id, version, activation_height, &info)?;
        self.emit(IUpdate::ScheduledUpdateCreated {
            proposalId: proposal_id,
            version: version.raw(),
            activationHeight: activation_height,
            info: info.into(),
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
            if scheduled.status == ScheduledUpdateStatus::Pending
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
        if scheduled.status != ScheduledUpdateStatus::Pending {
            return Ok(());
        }

        ctx.with_checkpoint(|| {
            if let Some(spec) = registry.lookup(scheduled.version) {
                (spec.handler)(ctx, &scheduled).map_err(|err| match err {
                    PrecompileError::Fatal(message) => PrecompileError::Fatal(message),
                    other => PrecompileError::Fatal(format!(
                        "upgrade handler '{}' failed: {other}",
                        spec.label
                    )),
                })?;
            }

            self.set_active_version(scheduled.version, scheduled.activation_height)?;
            self.set_scheduled_update_status(proposal_id, ScheduledUpdateStatus::Activated)?;
            self.emit(IUpdate::UpgradeActivated {
                version: scheduled.version.raw(),
                activationHeight: scheduled.activation_height,
            })
        })
    }

    fn scheduled_activation_conflict(&self, activation_height: u64) -> Result<bool> {
        for proposal_id in self.list_waiting_for_activation_proposal_ids()? {
            let Some(scheduled) = self.read_scheduled_update(proposal_id)? else {
                continue;
            };
            if scheduled.status == ScheduledUpdateStatus::Pending
                && scheduled.activation_height == activation_height
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
