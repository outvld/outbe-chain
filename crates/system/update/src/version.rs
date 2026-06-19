//! Const functions for protocol version parsing and formatting.
//!
//! Because string cannot be used in const functions, we use slice of bytes instead.

use crate::constants::{MAX_PROTOCOL_VERSION_MINOR, PROTOCOL_VERSION_MINOR_BITS};
use crate::ProtocolVersion;

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
    ((major as u32) << PROTOCOL_VERSION_MINOR_BITS) | minor
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
        return parse_decimal_range(bytes, 0, len, u32::MAX);
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

pub const fn parse_protocol_version(input: &str) -> ProtocolVersion {
    match try_parse_protocol_version(input) {
        Ok(version) => version,
        Err(_) => panic!("invalid protocol version"),
    }
}

/// Returns the major part of an encoded protocol version.
pub const fn protocol_version_major(version: ProtocolVersion) -> u8 {
    (version >> PROTOCOL_VERSION_MINOR_BITS) as u8
}

/// Returns the minor part of an encoded protocol version.
pub const fn protocol_version_minor(version: ProtocolVersion) -> u32 {
    version & MAX_PROTOCOL_VERSION_MINOR
}

/// Formats a protocol version as `v{major}.{minor} ({raw})`.
pub fn format_protocol_version(version: ProtocolVersion) -> String {
    format!(
        "v{}.{} ({version})",
        protocol_version_major(version),
        protocol_version_minor(version)
    )
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
        const VERSION: ProtocolVersion = parse_protocol_version("1.2");
        assert_eq!(VERSION, encode_protocol_version(1, 2));
    }

    #[test]
    fn parses_major_minor_and_raw_versions() {
        assert_eq!(
            try_parse_protocol_version("1.2").unwrap(),
            encode_protocol_version(1, 2)
        );
        assert_eq!(try_parse_protocol_version("65536").unwrap(), 65536);
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
        assert_eq!(
            format_protocol_version(encode_protocol_version(1, 2)),
            "v1.2 (16777218)"
        );
    }
}
