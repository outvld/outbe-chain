//! Validator configuration read from chain state.
//!
//! `validators.json` is a tooling/genesis artifact only. Runtime validator
//! membership is read from the ValidatorSet precompile at specific block heights.

use alloy_primitives::{Address, B256, U256};
use commonware_codec::ReadExt as _;
use commonware_cryptography::bls12381;
use commonware_p2p::{Address as CommonwareAddress, Ingress as CommonwareIngress};
use commonware_utils::Hostname;
use eyre::{Result, WrapErr};
use outbe_consensus::bls::{self, KeyBackend};
use outbe_primitives::consensus_p2p::{decode_versioned, P2pAddress, P2pIngress};
use outbe_primitives::storage::{
    readonly::{ReadOnlyStorageProvider, StorageReader},
    StorageHandle,
};
pub use outbe_primitives::validators::{ValidatorP2pAddress, ValidatorSet};
use reth_ethereum::storage::{StateProvider as _, StateProviderBox, StateProviderFactory};
use std::path::Path;
use tracing::debug;

/// Load the BLS individual signing key from a file.
///
/// Supports all key backends: plaintext hex, AES-256-GCM encrypted, and OS keychain.
/// The backend determines how the raw key bytes are read from disk.
pub fn load_signing_key(path: &Path, backend: &KeyBackend) -> Result<bls12381::PrivateKey> {
    bls::load_individual_key(path, backend)
        .wrap_err_with(|| format!("failed to load signing key: {}", path.display()))
}

// ---------------------------------------------------------------------------
// Phase 2: Dynamic reading from EVM state
// ---------------------------------------------------------------------------

/// Wrapper that implements [`StorageReader`] for Reth's `StateProvider` (boxed).
///
/// Bridges the Reth storage API (`fn storage(Address, B256) -> Option<U256>`)
/// with the outbe primitives `StorageReader` trait.
struct RethStateReader<'a> {
    state: &'a dyn RethStateAccess,
}

/// Trait object interface for Reth state storage reads.
///
/// Implemented for [`StateProviderBox`] below, bridging the Reth storage API
/// with the outbe precompile storage layer.
pub trait RethStateAccess {
    /// Read a storage slot value. Returns `None` if the slot doesn't exist.
    fn storage_read(&self, address: Address, key: B256) -> Result<Option<U256>>;
}

impl RethStateAccess for StateProviderBox {
    fn storage_read(&self, address: Address, key: B256) -> Result<Option<U256>> {
        self.storage(address, key)
            .map_err(|e| eyre::eyre!("reth storage read failed: {e}"))
    }
}

impl<'a> StorageReader for RethStateReader<'a> {
    fn read_storage(&self, address: Address, key: B256) -> outbe_primitives::error::Result<U256> {
        self.state
            .storage_read(address, key)
            .map(|opt| opt.unwrap_or(U256::ZERO))
            .map_err(|e| {
                outbe_primitives::error::PrecompileError::Storage(format!("state read failed: {e}"))
            })
    }
}

/// Read the active validator set from on-chain state.
///
/// Queries the ValidatorSet precompile at the state referenced by `state_access`,
/// returning the active validators with their BLS MinPk public keys.
///
/// This is the Phase 2 entry point — called at consensus startup and at
/// epoch boundaries to refresh the validator set.
pub fn read_validators_from_state(state_access: &dyn RethStateAccess) -> Result<ValidatorSet> {
    read_validator_set_from_state(state_access, ValidatorSetKind::ActiveValidators)
}

/// Read the current consensus participant set from on-chain state.
///
/// This includes ACTIVE and EXITING validators that still have BLS shares.
/// It is the correct set for Simplex startup/restart because EXITING validators
/// remain accountable until a finalized DKG boundary removes their share.
pub fn read_consensus_validators_from_state(
    state_access: &dyn RethStateAccess,
) -> Result<ValidatorSet> {
    read_validator_set_from_state(state_access, ValidatorSetKind::ConsensusParticipants)
}

/// Read the DKG reshare TARGET set (`status ∈ {ACTIVE, PENDING}`) from on-chain
/// state. This is `next_players`: the committee the upcoming reshare grants shares
/// to. PENDING joiners are included (so the ceremony activates them); EXITING
/// validators are excluded (the reshare removes them). Distinct from
/// [`read_validators_from_state`] (ACTIVE-only voting set).
pub fn read_reshare_target_from_state(state_access: &dyn RethStateAccess) -> Result<ValidatorSet> {
    read_validator_set_from_state(state_access, ValidatorSetKind::ReshareTarget)
}

/// Read PENDING validators (`status == PENDING`) from on-chain state — staked
/// joiners admitted to the set but not yet share-holders. Used to admit them to
/// consensus P2P as SECONDARY peers so they sync before their activating reshare.
pub fn read_pending_validators_from_state(
    state_access: &dyn RethStateAccess,
) -> Result<ValidatorSet> {
    read_validator_set_from_state(state_access, ValidatorSetKind::PendingValidators)
}

/// Read non-voting peers admitted to consensus P2P (`status ∈ {REGISTERED, PENDING}`)
/// from on-chain state — staked PENDING joiners PLUS TEE
/// full-nodes (REGISTERED, P2P-announced, NOT staked). Used as the secondary-tier P2P
/// admission source so both sync + execute offer blocks without voting.
pub fn read_admitted_non_consensus_from_state(
    state_access: &dyn RethStateAccess,
) -> Result<ValidatorSet> {
    read_validator_set_from_state(state_access, ValidatorSetKind::AdmittedNonConsensus)
}

#[derive(Clone, Copy)]
enum ValidatorSetKind {
    ActiveValidators,
    ConsensusParticipants,
    /// DKG reshare target / `next_players`: `status ∈ {ACTIVE, PENDING}`. PENDING
    /// joiners must be in the target so the ceremony grants them a share and they
    /// are promoted PENDING→ACTIVE.
    ReshareTarget,
    /// PENDING joiners only — admitted to consensus P2P as SECONDARY peers so they
    /// sync to head before the reshare that makes them signers.
    PendingValidators,
    /// Non-voting peers admitted to consensus P2P as SECONDARY so they sync + execute
    /// offer blocks: `status ∈ {REGISTERED, PENDING}`. Adds TEE
    /// full-nodes (REGISTERED, P2P-announced, enclave-registered, NOT staked) to the
    /// staked PENDING joiners. Voting still needs `has_bls_share`, so this cannot
    /// affect consensus; distinct from `ReshareTarget` ({ACTIVE, PENDING}).
    AdmittedNonConsensus,
}

fn read_validator_set_from_state(
    state_access: &dyn RethStateAccess,
    kind: ValidatorSetKind,
) -> Result<ValidatorSet> {
    let reader = RethStateReader {
        state: state_access,
    };
    let mut provider = ReadOnlyStorageProvider::new(reader);
    let storage = StorageHandle::new(&mut provider);

    let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
    let records = match kind {
        ValidatorSetKind::ActiveValidators => vs
            .get_active_validators()
            .map_err(|e| eyre::eyre!("failed to read active validators: {e}")),
        ValidatorSetKind::ConsensusParticipants => vs
            .get_active_consensus_set()
            .map_err(|e| eyre::eyre!("failed to read active consensus set: {e}")),
        ValidatorSetKind::ReshareTarget => vs
            .get_reshare_target_set()
            .map_err(|e| eyre::eyre!("failed to read reshare target set: {e}")),
        ValidatorSetKind::PendingValidators => vs
            .get_pending_validators()
            .map_err(|e| eyre::eyre!("failed to read pending validators: {e}")),
        ValidatorSetKind::AdmittedNonConsensus => vs
            .get_admitted_non_consensus_validators()
            .map_err(|e| eyre::eyre!("failed to read admitted non-consensus validators: {e}")),
    }?;

    let mut public_keys = Vec::with_capacity(records.len());
    let mut addresses = Vec::with_capacity(records.len());
    let mut p2p_addresses = Vec::with_capacity(records.len());

    for record in &records {
        // Read full 48-byte BLS MinPk pubkey (stored across two slots by ValidatorSet).
        let pk = bls12381::PublicKey::read(&mut record.consensus_pubkey.as_slice())
            .map_err(|e| eyre::eyre!("invalid BLS pubkey for {}: {e}", record.validator_address))?;

        public_keys.push(pk);
        addresses.push(record.validator_address);
        let p2p_address = match vs.get_p2p_address(record.validator_address) {
            Ok(Some((version, encoded))) => match decode_versioned(version, &encoded) {
                Ok(decoded) => match outbe_p2p_to_commonware(decoded) {
                    Ok(addr) => ValidatorP2pAddress::Known(addr),
                    Err(err) => {
                        tracing::warn!(
                            validator = %record.validator_address,
                            version,
                            error = %err,
                            "invalid validator p2p address registry entry; excluding peer"
                        );
                        ValidatorP2pAddress::Invalid
                    }
                },
                Err(err) => {
                    tracing::warn!(
                        validator = %record.validator_address,
                        version,
                        error = %err,
                        "invalid validator p2p address registry entry; excluding peer"
                    );
                    ValidatorP2pAddress::Invalid
                }
            },
            Ok(None) => ValidatorP2pAddress::Missing,
            Err(err) => {
                tracing::warn!(
                    validator = %record.validator_address,
                    error = %err,
                    "failed to read validator p2p address registry entry; excluding peer"
                );
                ValidatorP2pAddress::Invalid
            }
        };
        p2p_addresses.push(p2p_address);
    }

    debug!(
        count = public_keys.len(),
        "read validator set from on-chain state"
    );

    Ok(ValidatorSet {
        public_keys,
        addresses,
        p2p_addresses,
    })
}

fn outbe_p2p_to_commonware(
    address: P2pAddress,
) -> std::result::Result<CommonwareAddress, eyre::Report> {
    match address {
        P2pAddress::Symmetric(socket) => Ok(CommonwareAddress::Symmetric(socket)),
        P2pAddress::Asymmetric { ingress, egress } => Ok(CommonwareAddress::Asymmetric {
            ingress: match ingress {
                P2pIngress::Socket(socket) => CommonwareIngress::Socket(socket),
                P2pIngress::Dns { host, port } => CommonwareIngress::Dns {
                    host: Hostname::new(host)
                        .map_err(|err| eyre::eyre!("invalid commonware hostname: {err}"))?,
                    port,
                },
            },
            egress,
        }),
    }
}

/// Read active validators from the EVM state at a given block hash.
///
/// Convenience wrapper that obtains a `StateProviderBox` from the factory
/// and delegates to [`read_validators_from_state`].
pub fn read_validators_at_block(
    provider: &dyn StateProviderFactory,
    block_hash: B256,
) -> Result<ValidatorSet> {
    let state = provider
        .state_by_block_hash(block_hash)
        .map_err(|e| eyre::eyre!("failed to get state at block {block_hash}: {e}"))?;
    read_validators_from_state(&state)
}

/// Read current consensus participants from the EVM state at a given block hash.
pub fn read_consensus_validators_at_block(
    provider: &dyn StateProviderFactory,
    block_hash: B256,
) -> Result<ValidatorSet> {
    let state = provider
        .state_by_block_hash(block_hash)
        .map_err(|e| eyre::eyre!("failed to get state at block {block_hash}: {e}"))?;
    read_consensus_validators_from_state(&state)
}

/// Read PENDING validators from the EVM state at a given block hash (secondary-tier
/// P2P admission candidates).
pub fn read_pending_validators_at_block(
    provider: &dyn StateProviderFactory,
    block_hash: B256,
) -> Result<ValidatorSet> {
    let state = provider
        .state_by_block_hash(block_hash)
        .map_err(|e| eyre::eyre!("failed to get state at block {block_hash}: {e}"))?;
    read_pending_validators_from_state(&state)
}

/// Read non-voting admitted peers (`status ∈ {REGISTERED, PENDING}`) from the EVM
/// state at a given block hash — the secondary-tier P2P admission candidates,
/// including TEE full-nodes.
pub fn read_admitted_non_consensus_at_block(
    provider: &dyn StateProviderFactory,
    block_hash: B256,
) -> Result<ValidatorSet> {
    let state = provider
        .state_by_block_hash(block_hash)
        .map_err(|e| eyre::eyre!("failed to get state at block {block_hash}: {e}"))?;
    read_admitted_non_consensus_from_state(&state)
}

/// Read the active validator set from the latest committed state.
///
/// Scopes the underlying `StateProviderBox` so its MDBX read transaction
/// cannot live across await points in consensus stack startup.
pub fn read_validators_at_latest(provider: &dyn StateProviderFactory) -> Result<ValidatorSet> {
    let state = provider
        .latest()
        .map_err(|e| eyre::eyre!("failed to get latest state: {e}"))?;
    read_validators_from_state(&state)
}

/// Read the consensus participant set (ACTIVE + EXITING) from the latest
/// committed state. Same lifetime guarantees as
/// [`read_validators_at_latest`].
pub fn read_consensus_validators_at_latest(
    provider: &dyn StateProviderFactory,
) -> Result<ValidatorSet> {
    let state = provider
        .latest()
        .map_err(|e| eyre::eyre!("failed to get latest state: {e}"))?;
    read_consensus_validators_from_state(&state)
}

/// Check if there's a pending validator set change in the on-chain state.
///
/// Reads the `pending_set_change` flag from the ValidatorSet contract.
/// Used by the orchestrator to detect when a DKG reshare is needed.
pub fn has_pending_set_change(state_access: &dyn RethStateAccess) -> Result<bool> {
    let reader = RethStateReader {
        state: state_access,
    };
    let mut provider = ReadOnlyStorageProvider::new(reader);
    let storage = StorageHandle::new(&mut provider);

    {
        let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
        vs.has_pending_set_change()
            .map_err(|e| eyre::eyre!("failed to check pending set change: {e}"))
    }
}

/// Read the on-chain registered tribute offer public key (`TeeRegistry` slot 1).
/// Used at startup to decide whether a joining node needs a key-handoff and as
/// the `expected_tribute_offer_public` the newcomer's enclave verifies a handoff
/// against. Returns `B256::ZERO` before the chain has bootstrapped the TEE.
pub fn read_tee_offer_public_from_state(state_access: &dyn RethStateAccess) -> Result<B256> {
    let reader = RethStateReader {
        state: state_access,
    };
    let mut provider = ReadOnlyStorageProvider::new(reader);
    let storage = StorageHandle::new(&mut provider);

    {
        let reg = outbe_teeregistry::TeeRegistry::new(storage);
        reg.offer_public_key()
            .map_err(|e| eyre::eyre!("failed to read tee offer public key: {e}"))
    }
}

/// Read the on-chain tribute offer public from the latest committed state.
pub fn read_tee_offer_public_at_latest(provider: &dyn StateProviderFactory) -> Result<B256> {
    let state = provider
        .latest()
        .map_err(|e| eyre::eyre!("failed to get latest state: {e}"))?;
    read_tee_offer_public_from_state(&state)
}

/// Read the on-chain tribute-offer epoch (`TeeRegistry` slot 4) from the latest
/// state — `0` until an offer-key rotation advances it. Passed to the key-handoff
/// so a newcomer's enclave derives the offer key for the chain's current epoch
/// instead of a hardcoded `0` (future-proofs the handoff for Stage C).
pub fn read_tee_offer_epoch_at_latest(provider: &dyn StateProviderFactory) -> Result<u64> {
    let state = provider
        .latest()
        .map_err(|e| eyre::eyre!("failed to get latest state: {e}"))?;
    let reader = RethStateReader { state: &state };
    let mut provider = ReadOnlyStorageProvider::new(reader);
    let storage = StorageHandle::new(&mut provider);
    let reg = outbe_teeregistry::TeeRegistry::new(storage);
    reg.tribute_offer_epoch()
        .map_err(|e| eyre::eyre!("failed to read tee offer epoch: {e}"))
}

/// Read a validator's on-chain registered `recipient_x25519` (`TeeRegistry` per-
/// validator slot). Returns `B256::ZERO` if the validator is not registered. Used
/// by the handoff registration binding: the responder refuses to seal the resident
/// group signature to a `recipient_x25519` that does not match this validator's
/// registered key (an on-chain identity check that substitutes for the not-yet-real
/// attestation check).
pub fn read_tee_recipient_x25519_from_state(
    state_access: &dyn RethStateAccess,
    validator: Address,
) -> Result<B256> {
    let reader = RethStateReader {
        state: state_access,
    };
    let mut provider = ReadOnlyStorageProvider::new(reader);
    let storage = StorageHandle::new(&mut provider);

    {
        let reg = outbe_teeregistry::TeeRegistry::new(storage);
        reg.registration(validator)
            .map(|r| r.recipient_x25519)
            .map_err(|e| eyre::eyre!("failed to read tee recipient_x25519: {e}"))
    }
}

/// Read a validator's on-chain registered `recipient_x25519` from the latest state.
pub fn read_tee_recipient_x25519_at_latest(
    provider: &dyn StateProviderFactory,
    validator: Address,
) -> Result<B256> {
    let state = provider
        .latest()
        .map_err(|e| eyre::eyre!("failed to get latest state: {e}"))?;
    read_tee_recipient_x25519_from_state(&state, validator)
}

/// Check if current binary version is compatible with active (or approved) proposals.
/// Also warns if there are approved versions without registered handlers.
pub fn check_binary_version_compatibility(
    provider: &dyn StateProviderFactory,
    registry: &outbe_update::handlers::UpgradeHandlerRegistry,
) -> Result<()> {
    let active_version = read_active_protocol_version_at_latest(&provider)?;
    outbe_update::startup::assert_binary_protocol_compatible(active_version)
        .map_err(eyre::Error::msg)?;
    let waiting = read_waiting_update_proposals_at_latest(&provider)?;
    outbe_update::startup::warn_missing_handlers_for_waiting_proposals(&waiting, registry);
    Ok(())
}

/// Read the on-chain active protocol version from the latest committed state.
fn read_active_protocol_version_at_latest(
    provider: &dyn StateProviderFactory,
) -> Result<outbe_update::ProtocolVersion> {
    let state = provider
        .latest()
        .map_err(|e| eyre::eyre!("failed to get latest state: {e}"))?;
    let reader = RethStateReader { state: &state };
    let mut provider = ReadOnlyStorageProvider::new(reader);
    let storage = StorageHandle::new(&mut provider);
    let update = outbe_update::schema::Update::new(storage);
    Ok(update.get_active_version()?.unwrap_or_default())
}

/// Read approved proposals waiting for activation from the latest committed state.
fn read_waiting_update_proposals_at_latest(
    provider: &dyn StateProviderFactory,
) -> Result<Vec<outbe_update::state::ProposalInfo>> {
    let state = provider
        .latest()
        .map_err(|e| eyre::eyre!("failed to get latest state: {e}"))?;
    let reader = RethStateReader { state: &state };
    let mut provider = ReadOnlyStorageProvider::new(reader);
    let storage = StorageHandle::new(&mut provider);
    let update = outbe_update::schema::Update::new(storage);
    let mut proposals = Vec::new();
    for proposal_id in update.list_waiting_for_activation_proposal_ids()? {
        if let Some(proposal) = update.read_proposal(proposal_id)? {
            proposals.push(proposal);
        }
    }
    Ok(proposals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode as _;
    use commonware_cryptography::{Signer as _, Verifier as _};
    use commonware_math::algebra::Random;
    use outbe_primitives::consensus_p2p::{encode_v1, P2pAddress, P2P_ADDRESS_VERSION_V1};
    use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const OWNER: Address = Address::repeat_byte(0xA0);

    fn valid_consensus_pubkey(seed: u8) -> [u8; 48] {
        let key = bls12381::PrivateKey::from_seed(seed as u64);
        let encoded = key.public_key().encode();
        let mut out = [0u8; 48];
        out.copy_from_slice(&encoded[..48]);
        out
    }

    /// Test implementation of [`RethStateAccess`] backed by a raw storage map.
    struct TestStateAccess {
        data: HashMap<(Address, U256), U256>,
    }

    impl RethStateAccess for TestStateAccess {
        fn storage_read(&self, address: Address, key: B256) -> Result<Option<U256>> {
            let key_u256 = U256::from_be_bytes(key.0);
            Ok(self.data.get(&(address, key_u256)).copied())
        }
    }

    fn populated_p2p_state(
        p2p_writer: impl FnOnce(&mut outbe_validatorset::contract::ValidatorSet<'_>, Address),
    ) -> TestStateAccess {
        let validator = Address::with_last_byte(0x11);
        let mut provider = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut provider, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            vs.config_owner.write(OWNER).unwrap();
            vs.config_is_initialized.write(true).unwrap();
            vs.config_max_validators.write(128).unwrap();
            vs.register_validator(OWNER, validator, &valid_consensus_pubkey(11))
                .unwrap();
            vs.activate_validator(validator).unwrap();
            p2p_writer(&mut vs, validator);
        });
        TestStateAccess {
            data: provider.storage.clone(),
        }
    }

    #[test]
    fn test_read_validators_from_state_empty() {
        let mut provider = HashMapStorageProvider::new(1);

        StorageHandle::enter(&mut provider, |storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            vs.config_is_initialized.write(true).unwrap();
            vs.config_max_validators.write(128).unwrap();
        });

        let access = TestStateAccess {
            data: provider.storage.clone(),
        };
        let result = read_validators_from_state(&access).unwrap();
        assert!(result.public_keys.is_empty());
        assert!(result.addresses.is_empty());
    }

    #[test]
    fn test_read_consensus_validators_includes_exiting_with_share() {
        let mut provider = HashMapStorageProvider::new(1);
        let active = Address::with_last_byte(0x01);
        let exiting = Address::with_last_byte(0x02);

        StorageHandle::enter(&mut provider, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            vs.config_owner.write(OWNER).unwrap();
            vs.config_is_initialized.write(true).unwrap();
            vs.config_max_validators.write(128).unwrap();
            vs.register_validator(OWNER, active, &valid_consensus_pubkey(1))
                .unwrap();
            vs.register_validator(OWNER, exiting, &valid_consensus_pubkey(2))
                .unwrap();
            vs.activate_reshared_set(&[active, exiting], B256::with_last_byte(0xAA))
                .unwrap();
            vs.deactivate_validator(OWNER, exiting).unwrap();
        });

        let access = TestStateAccess {
            data: provider.storage.clone(),
        };

        let active_only = read_validators_from_state(&access).unwrap();
        assert_eq!(active_only.addresses, vec![active]);

        let consensus = read_consensus_validators_from_state(&access).unwrap();
        assert_eq!(consensus.addresses, vec![active, exiting]);
    }

    #[test]
    fn test_read_validators_from_state_decodes_registry_p2p_address() {
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 30400);
        let encoded = encode_v1(&P2pAddress::Symmetric(socket));
        let access = populated_p2p_state(|vs, validator| {
            vs.set_p2p_address(validator, validator, P2P_ADDRESS_VERSION_V1, &encoded)
                .unwrap();
        });

        let validators = read_validators_from_state(&access).unwrap();
        assert_eq!(
            validators.p2p_addresses,
            vec![ValidatorP2pAddress::Known(CommonwareAddress::Symmetric(
                socket
            ))]
        );
    }

    #[test]
    fn test_read_validators_from_state_marks_invalid_registry_entry() {
        let access = populated_p2p_state(|vs, validator| {
            vs.val_p2p_address_version.write(&validator, 99).unwrap();
            vs.val_p2p_address_payload
                .get_bytes(&validator)
                .write(&[0])
                .unwrap();
        });

        let validators = read_validators_from_state(&access).unwrap();
        assert_eq!(validators.p2p_addresses, vec![ValidatorP2pAddress::Invalid]);
    }

    #[test]
    fn test_load_signing_key_roundtrip() {
        let key = bls12381::PrivateKey::random(rand_core::OsRng);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        outbe_consensus::bls::save_individual_key(
            tmp.path(),
            &key,
            &outbe_consensus::bls::KeyBackend::Plaintext,
        )
        .unwrap();

        let loaded =
            load_signing_key(tmp.path(), &outbe_consensus::bls::KeyBackend::Plaintext).unwrap();
        assert_eq!(key, loaded);

        // Verify the loaded key works
        let sig = loaded.sign(b"test", b"msg");
        let pk = loaded.public_key();
        assert!(pk.verify(b"test", b"msg", &sig));
    }

    #[test]
    fn test_has_pending_set_change_false_by_default() {
        let mut provider = HashMapStorageProvider::new(1);

        StorageHandle::enter(&mut provider, |storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            vs.config_is_initialized.write(true).unwrap();
            vs.config_max_validators.write(128).unwrap();
        });

        let access = TestStateAccess {
            data: provider.storage.clone(),
        };
        let result = has_pending_set_change(&access).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_has_pending_set_change_true_when_set() {
        let mut provider = HashMapStorageProvider::new(1);

        StorageHandle::enter(&mut provider, |storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            vs.config_is_initialized.write(true).unwrap();
            vs.config_max_validators.write(128).unwrap();
            vs.pending_set_change.write(true).unwrap();
        });

        let access = TestStateAccess {
            data: provider.storage.clone(),
        };
        let result = has_pending_set_change(&access).unwrap();
        assert!(result);
    }
}
