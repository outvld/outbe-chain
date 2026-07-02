use alloy_primitives::U256;
use serde_json::Value;

use crate::api::{get_active_version, is_version_active_eq, version_at_height};
use crate::payload::encode_schedule_update_json;
use crate::schema::Update;
use crate::ProtocolVersion;

use super::{with_update, V1_2};

#[test]
fn get_active_version_returns_zero_on_fresh_chain() {
    with_update(|storage| {
        assert_eq!(
            get_active_version(storage.clone()).unwrap(),
            ProtocolVersion::ZERO,
            "fresh chain baseline is protocol version 0"
        );
    });
}

#[test]
fn version_at_height_returns_zero_when_unset() {
    with_update(|storage| {
        assert_eq!(
            version_at_height(storage, 100).unwrap(),
            ProtocolVersion::ZERO
        );
    });
}

#[test]
fn is_version_active_zero_on_fresh_chain() {
    with_update(|storage| {
        assert!(is_version_active_eq(storage, ProtocolVersion::ZERO).unwrap());
    });
}

#[test]
fn schedule_update_rejects_zero_version() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        let payload: Value =
            serde_json::from_str(&encode_schedule_update_json(ProtocolVersion::ZERO, 1000, ""))
                .unwrap();
        let err = update
            .schedule_update_from_propose(U256::from(1), &payload, 100)
            .unwrap_err();
        assert!(matches!(
            err,
            outbe_primitives::error::PrecompileError::Revert(msg) if msg.contains("invalid protocol version")
        ));
    });
}

#[test]
fn set_active_version_makes_helpers_return_version() {
    with_update(|storage| {
        let mut update = Update::new(storage.clone());
        update.set_active_version(V1_2, 500).unwrap();
        assert_eq!(get_active_version(storage.clone()).unwrap(), V1_2);
        assert_eq!(version_at_height(storage.clone(), 500).unwrap(), V1_2);
        assert!(is_version_active_eq(storage, V1_2).unwrap());
    });
}
