//! Const functions for protocol version parsing and formatting.
//!
//! Because string cannot be used in const functions, we use slice of bytes instead.

use alloy_primitives::U256;
use outbe_primitives::storage::types::{Storable, StorableType};

use crate::constants::{MAX_PROTOCOL_VERSION_MINOR, PROTOCOL_VERSION_MINOR_BITS};

/// On-chain protocol version: `u8 major + u24 minor` encoded as `u32`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ProtocolVersion(u32);

impl ProtocolVersion {
    pub const ZERO: Self = Self(0);

    /// Const fn impl From<u32> for ProtocolVersion.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Const fn impl Into<u32> for ProtocolVersion.
    pub const fn raw(self) -> u32 {
        self.0
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl From<u32> for ProtocolVersion {
    fn from(value: u32) -> Self {
        Self::from_raw(value)
    }
}

impl From<ProtocolVersion> for u32 {
    fn from(value: ProtocolVersion) -> Self {
        value.raw()
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "v{}.{}",
            protocol_version_major(*self),
            protocol_version_minor(*self)
        )
    }
}

impl StorableType for ProtocolVersion {
    const SLOTS: usize = 1;
}

impl Storable for ProtocolVersion {
    fn from_word(word: U256) -> Self {
        Self::from_raw(word.to::<u32>())
    }

    fn to_word(&self) -> U256 {
        U256::from(self.raw())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolVersionParseError {
    #[error("empty protocol version component")]
    Empty,
    #[error("protocol version contains a non-decimal digit")]
    InvalidDigit,
    #[error("protocol version has more than one dot")]
    TooManyComponents,
    #[error("protocol version component exceeds allowed range")]
    Overflow,
}

/// Encodes the protocol version as `u8 major + u24 minor`.
pub const fn encode_protocol_version(major: u8, minor: u32) -> ProtocolVersion {
    ProtocolVersion::from_raw(((major as u32) << PROTOCOL_VERSION_MINOR_BITS) | minor)
}

const fn parse_decimal_range(
    bytes: &[u8],
    start: usize,
    end: usize,
    max: u32,
) -> Result<u32, ProtocolVersionParseError> {
    if start == end {
        return Err(ProtocolVersionParseError::Empty);
    }

    let mut value = 0u32;
    let mut index = start;
    while index < end {
        let byte = bytes[index];
        if byte < b'0' || byte > b'9' {
            return Err(ProtocolVersionParseError::InvalidDigit);
        }

        let digit = (byte - b'0') as u32;
        if value > (max - digit) / 10 {
            return Err(ProtocolVersionParseError::Overflow);
        }
        value = value * 10 + digit;
        index += 1;
    }

    Ok(value)
}

pub const fn try_parse_protocol_version_major_component(
    input: &str,
) -> Result<u8, ProtocolVersionParseError> {
    let bytes = input.as_bytes();
    match parse_decimal_range(bytes, 0, bytes.len(), u8::MAX as u32) {
        Ok(value) => Ok(value as u8),
        Err(err) => Err(err),
    }
}

pub const fn try_parse_protocol_version_minor_component(
    input: &str,
) -> Result<u32, ProtocolVersionParseError> {
    let bytes = input.as_bytes();
    parse_decimal_range(bytes, 0, bytes.len(), MAX_PROTOCOL_VERSION_MINOR)
}

pub const fn parse_protocol_version_major_component(input: &str) -> u8 {
    match try_parse_protocol_version_major_component(input) {
        Ok(value) => value,
        Err(_) => panic!("invalid protocol version major component"),
    }
}

pub const fn parse_protocol_version_minor_component(input: &str) -> u32 {
    match try_parse_protocol_version_minor_component(input) {
        Ok(value) => value,
        Err(_) => panic!("invalid protocol version minor component"),
    }
}

pub const fn try_parse_protocol_version(
    input: &str,
) -> Result<ProtocolVersion, ProtocolVersionParseError> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    if len == 0 {
        return Err(ProtocolVersionParseError::Empty);
    }

    let mut dot_count = 0usize;
    let mut dot_index = 0usize;
    let mut index = 0usize;
    while index < len {
        if bytes[index] == b'.' {
            dot_count += 1;
            if dot_count > 1 {
                return Err(ProtocolVersionParseError::TooManyComponents);
            }
            dot_index = index;
        }
        index += 1;
    }

    if dot_count == 0 {
        return match parse_decimal_range(bytes, 0, len, u32::MAX) {
            Ok(value) => Ok(ProtocolVersion::from_raw(value)),
            Err(err) => Err(err),
        };
    }

    let major = match parse_decimal_range(bytes, 0, dot_index, u8::MAX as u32) {
        Ok(value) => value as u8,
        Err(err) => return Err(err),
    };
    let minor = match parse_decimal_range(bytes, dot_index + 1, len, MAX_PROTOCOL_VERSION_MINOR) {
        Ok(value) => value,
        Err(err) => return Err(err),
    };

    Ok(encode_protocol_version(major, minor))
}

/// Returns the major part of an encoded protocol version.
pub const fn protocol_version_major(version: ProtocolVersion) -> u8 {
    (version.raw() >> PROTOCOL_VERSION_MINOR_BITS) as u8
}

/// Returns the minor part of an encoded protocol version.
pub const fn protocol_version_minor(version: ProtocolVersion) -> u32 {
    version.raw() & MAX_PROTOCOL_VERSION_MINOR
}

/// Formats a protocol version as `v{major}.{minor} ({raw})`.
pub fn format_protocol_version(version: ProtocolVersion) -> String {
    format!("{version} ({})", version.raw())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{PROTOCOL_VERSION, PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR};

    #[test]
    fn protocol_version_constants_come_from_package_metadata() {
        assert_eq!(
            PROTOCOL_VERSION_MAJOR,
            env!("CARGO_PKG_VERSION_MAJOR").parse::<u8>().unwrap()
        );
        assert_eq!(
            PROTOCOL_VERSION_MINOR,
            env!("CARGO_PKG_VERSION_MINOR").parse::<u32>().unwrap()
        );
        assert_eq!(
            PROTOCOL_VERSION,
            encode_protocol_version(PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR)
        );
    }

    #[test]
    fn parse_protocol_version_is_const() {
        const VERSION: ProtocolVersion = const {
            match try_parse_protocol_version("1.2") {
                Ok(version) => version,
                Err(_) => panic!("invalid protocol version"),
            }
        };
        assert_eq!(VERSION, encode_protocol_version(1, 2));
    }

    #[test]
    fn parses_major_minor_and_raw_versions() {
        assert_eq!(
            try_parse_protocol_version("1.2").unwrap(),
            encode_protocol_version(1, 2)
        );
        assert_eq!(try_parse_protocol_version("65536").unwrap().raw(), 65536);
    }

    #[test]
    fn rejects_invalid_protocol_versions() {
        assert_eq!(
            try_parse_protocol_version("1.2.3").unwrap_err(),
            ProtocolVersionParseError::TooManyComponents
        );
        assert_eq!(
            try_parse_protocol_version("1.").unwrap_err(),
            ProtocolVersionParseError::Empty
        );
        assert_eq!(
            try_parse_protocol_version("256.0").unwrap_err(),
            ProtocolVersionParseError::Overflow
        );
    }

    #[test]
    fn formats_protocol_version_with_raw_value() {
        assert_eq!(encode_protocol_version(1, 2).to_string(), "v1.2");
        assert_eq!(
            format_protocol_version(encode_protocol_version(1, 2)),
            "v1.2 (16777218)"
        );
    }
}
