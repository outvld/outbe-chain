use alloy_primitives::U256;

use crate::constants::MAX_PROTOCOL_VERSION_MINOR;
use crate::encode_protocol_version;
use crate::schema::{ScheduledUpdateRecord, ScheduledUpdateStatus, Update};

use super::{with_update, V9_8};

#[test]
fn scheduled_update_status_roundtrip() {
    assert_eq!(ScheduledUpdateStatus::Scheduled.to_u8(), 0);
    assert_eq!(ScheduledUpdateStatus::Activated.to_u8(), 1);
    assert_eq!(ScheduledUpdateStatus::Canceled.to_u8(), 2);
    assert_eq!(
        ScheduledUpdateStatus::from_u8(0).unwrap(),
        ScheduledUpdateStatus::Scheduled
    );
}

#[test]
fn protocol_version_encoding_roundtrip() {
    let version = encode_protocol_version(7, 42);
    assert_eq!(crate::state::protocol_version_major(version), 7);
    assert_eq!(crate::state::protocol_version_minor(version), 42);
    assert_eq!(
        encode_protocol_version(1, MAX_PROTOCOL_VERSION_MINOR).raw(),
        (1 << 24) | MAX_PROTOCOL_VERSION_MINOR
    );
    assert_eq!(encode_protocol_version(0, 0).raw(), 0);
}

#[test]
fn scheduled_update_record_dynamic_fields_roundtrip() {
    with_update(|storage| {
        let update = Update::new(storage.clone());
        let proposal_id = U256::from(1);
        let record = ScheduledUpdateRecord {
            proposal_id,
            version: V9_8,
            activation_height: 200,
            info: "dynamic-string-payload".to_string(),
            status: ScheduledUpdateStatus::Scheduled.to_u8(),
        };
        update.scheduled_updates.create(&record).unwrap();
        let loaded = update.scheduled_updates.get(proposal_id).unwrap().unwrap();
        assert_eq!(loaded.version, V9_8);
        assert_eq!(loaded.info, "dynamic-string-payload");
    });
}
