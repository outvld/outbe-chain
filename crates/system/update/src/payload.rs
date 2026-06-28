//! Vote payload encoding for scheduled updates.
//!
//! Layout: `version: u32 BE` | `activation_height: u64 BE` | `info: bytes`

use crate::errors::UpdateError;
use crate::ProtocolVersion;

const HEADER_LEN: usize = 12;

/// Decodes an approved vote payload into update fields.
pub fn decode_scheduled_update_payload(
    payload: &[u8],
) -> std::result::Result<(ProtocolVersion, u64, Vec<u8>), UpdateError> {
    if payload.len() < HEADER_LEN {
        return Err(UpdateError::InvalidPayload);
    }
    let version = ProtocolVersion::from(u32::from_be_bytes(
        payload[0..4]
            .try_into()
            .map_err(|_| UpdateError::InvalidPayload)?,
    ));
    let activation_height = u64::from_be_bytes(
        payload[4..12]
            .try_into()
            .map_err(|_| UpdateError::InvalidPayload)?,
    );
    let info = payload[12..].to_vec();
    Ok((version, activation_height, info))
}

/// Encodes update fields into a vote payload.
pub fn encode_scheduled_update_payload(
    version: ProtocolVersion,
    activation_height: u64,
    info: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_LEN + info.len());
    buf.extend_from_slice(&version.raw().to_be_bytes());
    buf.extend_from_slice(&activation_height.to_be_bytes());
    buf.extend_from_slice(info);
    buf
}
