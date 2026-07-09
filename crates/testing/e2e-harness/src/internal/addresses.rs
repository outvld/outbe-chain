//! Protocol precompile addresses used by the harness.
//!
//! Mirrors `scripts/e2e/lib.sh:37-40` and `bin/outbe-cli/src/abi.rs`. Typed
//! `Address` consts (the `eth` layer calls contracts by `Address`, not string).

use alloy_primitives::{address, Address};

/// TEE registry precompile (`isBootstrapped()`).
pub(crate) const TEE_ADDR: Address = address!("0x000000000000000000000000000000000000EE0A");
/// ValidatorSet precompile.
pub(crate) const VS_ADDR: Address = address!("0x000000000000000000000000000000000000EE00");
/// Staking precompile.
pub(crate) const STK_ADDR: Address = address!("0x000000000000000000000000000000000000EE02");
/// Tribute precompile (`totalSupply()`).
pub(crate) const TRIBUTE_ADDR: Address = address!("0x0000000000000000000000000000000000001101");
/// Metadosis worldwide-day registry (`getWorldwideDay(uint32)`).
pub(crate) const WWD_ADDR: Address = address!("0x000000000000000000000000000000000000100E");
/// Update precompile (protocol-version governance).
pub(crate) const UPDATE_ADDR: Address = address!("0x000000000000000000000000000000000000EE0B");
/// Vote precompile (generic proposal/voting).
pub(crate) const VOTE_ADDR: Address = address!("0x000000000000000000000000000000000000EE0C");
