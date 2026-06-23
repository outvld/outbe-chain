//! ABI surface and EVM dispatch for the Update precompile.

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolInterface};

use outbe_primitives::dispatch::{dispatch_call, metadata, reject_value, view};
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::api::is_version_active_eq;
use crate::errors::UpdateError;
use crate::schema::Update;
use crate::schema::ScheduledUpdateStatus;
use crate::state::ScheduledUpdateInfo;
use crate::ProtocolVersion;

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IUpdate.sol"
);

/// Solidity interface path for the Update precompile ABI.
pub const UPDATE_ABI_PATH: &str = "contracts/precompiles/src/IUpdate.sol";

/// Dispatches an ABI-encoded call to the Update precompile.
pub fn dispatch(
    storage: StorageHandle<'_>,
    data: &[u8],
    _caller: Address,
    value: U256,
) -> Result<Bytes> {
    reject_value(&value)?;
    dispatch_call(
        data,
        IUpdate::IUpdateCalls::abi_decode,
        |call| dispatch_update_call(storage, call),
    )
}

fn dispatch_update_call(
    storage: StorageHandle<'_>,
    call: IUpdate::IUpdateCalls,
) -> Result<Bytes> {
    let update = Update::new(storage.clone());
    use IUpdate::IUpdateCalls::*;
    match call {
        getActiveVersion(_) => metadata::<IUpdate::getActiveVersionCall>(|| {
            Ok(update.get_active_version()?.unwrap_or_default().into())
        }),
        getActiveVersionHeight(_) => metadata::<IUpdate::getActiveVersionHeightCall>(|| {
            update.get_active_version_height()
        }),
        isVersionActive(c) => view(c, |c| {
            is_version_active_eq(storage.clone(), ProtocolVersion::from(c.version))
        }),
        getScheduledUpdate(c) => view(c, |c| {
            let scheduled = update
                .read_scheduled_update(c.proposalId)?
                .ok_or(UpdateError::ScheduledUpdateNotFound)?;
            Ok(scheduled_update_return(&scheduled))
        }),
        listWaitingForActivation(_) => {
            metadata::<IUpdate::listWaitingForActivationCall>(|| {
                update.list_waiting_for_activation_proposal_ids()
            })
        }
    }
}

fn scheduled_update_return(scheduled: &ScheduledUpdateInfo) -> IUpdate::ScheduledUpdate {
    let status = match scheduled.status {
        ScheduledUpdateStatus::Pending => IUpdate::ScheduledUpdateStatus::Pending,
        ScheduledUpdateStatus::Activated => IUpdate::ScheduledUpdateStatus::Activated,
    };
    IUpdate::ScheduledUpdate {
        proposalId: scheduled.proposal_id,
        version: scheduled.version.into(),
        activationHeight: scheduled.activation_height,
        info: scheduled.info.clone().into(),
        status,
    }
}
