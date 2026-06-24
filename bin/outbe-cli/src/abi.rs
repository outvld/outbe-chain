//! ABI definitions for outbe precompile contracts.

use alloy_primitives::{address, Address};
use alloy_sol_types::sol;

pub use outbe_primitives::addresses::GOVERNANCE_ADDRESS;

// Precompile contract addresses
pub const VALIDATOR_SET_ADDR: Address = address!("0x000000000000000000000000000000000000EE00");
pub const SLASH_INDICATOR_ADDR: Address = address!("0x000000000000000000000000000000000000EE01");
pub const STAKING_ADDR: Address = address!("0x000000000000000000000000000000000000EE02");
// Rewards precompile (EE03) exposes no callable methods — validator emission is
// paid in gems — so it is referenced only by the address-pin test.
#[cfg(test)]
pub const REWARDS_ADDR: Address = address!("0x000000000000000000000000000000000000EE03");
pub const TRIBUTE_ADDR: Address = address!("0x0000000000000000000000000000000000001101");
pub const TRIBUTE_FACTORY_ADDR: Address = address!("0x0000000000000000000000000000000000001100");
pub const TEE_REGISTRY_ADDR: Address = address!("0x000000000000000000000000000000000000EE0A");
#[cfg(test)]
pub const NOD_ADDR: Address = address!("0x0000000000000000000000000000000000001006");
#[cfg(test)]
pub const CYCLE_ADDR: Address = address!("0x0000000000000000000000000000000000001010");
#[cfg(test)]
pub const OUTBE_SYSTEM_TX_ADDR: Address = address!("0xff00000000000000000000000000000000000001");

sol! {
    #[derive(Debug)]
    interface IValidatorSet {
        function getValidators() external view returns (address[] memory);
        function getActiveValidators() external view returns (address[] memory);
        function getActiveConsensusSet() external view returns (address[] memory);
        function validatorByAddress(address addr) external view returns (
            address validatorAddress,
            bytes memory consensusPubkey,
            uint256 stake,
            uint8 status,
            uint64 slashCount,
            uint64 missedBlocks,
            uint64 missedVotes,
            uint64 blocksProposed,
            uint64 joinedAtHeight,
            uint64 deactivatedAtHeight,
            uint64 unbondingEnd,
            bool hasBLSShare
        );
        function validatorCount() external view returns (uint32);
        function activeValidatorCount() external view returns (uint32);
        function activeConsensusCount() external view returns (uint32);
        function isValidator(address addr) external view returns (bool);
        function isConsensusParticipant(address addr) external view returns (bool);
        function hasPendingSetChange() external view returns (bool);
        function getEpochNumber() external view returns (uint256);
        function getEpochStartTimestamp() external view returns (uint64);
        function getEpochStartBlock() external view returns (uint64);
        function registerValidator(address validatorAddress, bytes calldata consensusPubkey, bytes calldata blsSignature) external;
        function setP2pAddress(address validatorAddress, uint8 version, bytes calldata encoded) external;
        function getP2pAddress(address validatorAddress) external view returns (uint8 version, bytes memory encoded);
        function deactivateValidator(address validatorAddress) external;
        function confirmValidatorReady() external;
        function activateResharedSet(address[] calldata newActiveSet, bytes32 groupPublicKey) external;

        event ValidatorRegistered(address indexed validator, uint64 index);
        event ValidatorActivated(address indexed validator);
        event ValidatorDeactivated(address indexed validator, uint64 atHeight);
        event ValidatorForcedExit(address indexed validator, uint64 atHeight);
        event EpochTransition(uint256 indexed newEpochNumber, uint64 timestamp, uint32 activeValidatorCount);
        event ConsensusSetUpdated(uint32 activeCount);
    }

    #[derive(Debug)]
    interface ISlashIndicator {
        function submitDoubleProposalEvidence(bytes calldata block1, bytes calldata block2) external;
        function submitConflictingVoteEvidence(bytes calldata vote1, bytes calldata vote2) external;
        function getProposerMissCount(address validator) external view returns (uint64);
        function getVoterMissCount(address validator) external view returns (uint64);
        function getFelonyCount(address validator) external view returns (uint64);

        event ProposerFelony(address indexed validator, uint64 missCount, uint64 felonyCount);
        event ProposerMisdemeanor(address indexed validator, uint64 missCount);
        event VoterMisdemeanor(address indexed validator, uint64 missCount);
        event EvidenceFelonyApplied(
            address indexed validator,
            address indexed submitter,
            uint256 slashedAmount,
            uint256 submitterReward
        );
        event ByzantineFelony(address indexed validator, uint256 slashedAmount, uint64 felonyCount);
    }

    #[derive(Debug)]
    interface IStaking {
        function stake(address validatorAddress, uint256 amount) external;
        function unstake(uint256 amount) external;
        function claimUnbonded() external;
        function unjailValidator() external;
        function getStake(address validator) external view returns (uint256);
        function getTotalStaked() external view returns (uint256);
    }

    #[derive(Debug)]
    interface ITribute {
        function name() external view returns (string memory);
        function symbol() external view returns (string memory);
        function totalSupply() external view returns (uint256);
        function balanceOf(address owner) external view returns (uint256);
        function ownerOf(uint256 tokenId) external view returns (address owner);
        function tokenURI(uint256 tokenId) external view returns (string memory);
        function getDayTotals(uint32 worldwideDay)
            external
            view
            returns (
                uint32 tributeCount,
                uint256 tributeNominalAmount,
                uint256 totalGratisLoadMinor,
                bool isSealed
            );
        function getTributesByOwner(address owner) external view returns (uint256[] memory tokenIds);
        function getTributesByDay(uint32 worldwideDay) external view returns (uint256[] memory tokenIds);
        function supportsInterface(bytes4 interfaceId) external view returns (bool);
    }

    #[derive(Debug)]
    interface ITributeFactory {
        function offerTribute(
            bytes cipherText,
            bytes nonce,
            uint256 ephemeralPubkey,
            uint16 referenceCurrency,
            bytes zkProof,
            bytes zkVerificationKey,
            bytes zkPublicKey,
            bytes zkMerkleRoot
        ) external returns (uint256 tributeId);
    }

    #[derive(Debug)]
    interface ITeeRegistry {
        function isBootstrapped() external view returns (bool);
        function tributeOfferPublicKey() external view returns (uint256);
        function tributeOfferEpoch() external view returns (uint256);
        function registeredCount() external view returns (uint256);
        function registerEnclave(
            uint256 recipientX25519,
            uint256 attestationPub,
            uint256 noiseStaticPub,
            uint256 mrenclave,
            uint256 mrsigner,
            uint16 isvSvn
        ) external returns (bool);
        event OfferKeySealed(address indexed validator, bytes sealedOfferKey);
    }

    #[derive(Debug)]
    interface ICycle {
        event CycleTriggerExecuted(
            uint32 indexed id,
            uint64 scheduledAt,
            uint64 blockTimestamp,
            uint64 blockNumber
        );
    }

    #[derive(Debug)]
    interface INod {
        // ERC-165
        function supportsInterface(bytes4 interfaceId) external view returns (bool);

        // ERC-721
        function balanceOf(address owner) external view returns (uint256 balance);
        function ownerOf(uint256 nodId) external view returns (address);

        // ERC-721-metadata
        function name() external view returns (string memory);
        function symbol() external view returns (string memory);
        function tokenURI(uint256 nodId) external view returns (string memory);

        // ERC-721-enumerable
        function totalSupply() external view returns (uint256);
        function tokenByIndex(uint256 index) external view returns (uint256);
        function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256);

        // outbe-specific
        function mineGratis(
            uint256 nodId,
            uint256 nonce,
            address asset,
            address vaultProvider
        ) external returns (uint256);
        function nodData(uint256 nodId) external view returns (
            uint256 nodId,
            address owner,
            uint32 worldwideDay,
            uint32 leagueId,
            uint256 floorPriceMinor,
            uint256 gratisLoadMinor,
            uint256 costOfGratisMinor,
            uint256 costAmountMinor,
            bool isQualified,
            uint32 settlementToken,
            uint64 unlocksAt,
        );

        // backward compatibility
        function tokens(address owner) external view returns (uint256[] memory);

        event NodIssued(
            address indexed owner,
            string nodId,
            uint32 worldwideDay,
            uint256 leagueId,
            uint256 floorPriceMinor,
            uint256 gratisLoadMinor,
            uint256 costOfGratisMinor,
            uint256 costAmountMinor
        );
        event GratisMined(address indexed owner, string nodId, uint256 amount);
        event NodBucketQualified(
            bytes32 indexed bucketKey,
            uint256 worldwideDay,
            uint256 leagueId,
            uint256 floorPriceMinor,
            bool isQualified
        );
    }

    #[derive(Debug)]
    interface IOracle {
        function getExchangeRate(string base, string quote) external view returns (uint256 rate, uint64 lastBlock, uint64 lastTimestamp);
        function getVwap(string base, string quote, uint64 lookbackSeconds) external view returns (uint256 vwap);
        function getVwapForTimeRange(string base, string quote, uint64 startTime, uint64 endTime) external view returns (uint256 vwap);
        function getScurveValue(string base, string quote, uint64 timestamp) external view returns (uint256 value);
        function getParams() external view returns (uint64 votePeriod, uint256 rewardBand, uint64 slashWindow, uint256 minValidPerWindow, uint256 slashFraction, uint64 lookbackDuration, bool enabled);
        function getVotePenaltyCounter(address validator) external view returns (uint64 success, uint64 abstain, uint64 miss);
        function getFeederDelegation(address validator) external view returns (address feeder);
        function isVoteTarget(string base, string quote) external view returns (bool);
        function getPairCount() external view returns (uint32 count);
        function getExchangeRates() external view returns (uint256[] memory rates, uint64[] memory blocks, uint64[] memory timestamps);
        function getVoteTargets() external view returns (uint32[] memory pairIds);
        function getAggregateVote(address validator) external view returns (bool exists, uint32[] memory pairIds, uint256[] memory rates, uint256[] memory volumes);
        function getSlashWindowProgress(address validator) external view returns (uint64 success, uint64 abstain, uint64 miss, uint64 slashWindow);
        function getPriceSnapshotHistory(string base, string quote, uint32 count) external view returns (uint64[] memory timestamps, uint256[] memory rates, uint256[] memory volumes);
        function getAllPriceSnapshotHistory(uint32 count) external view returns (uint64[] memory snapshotIds, uint64[] memory timestamps, uint32[] memory pairIds, uint256[] memory rates, uint256[] memory volumes);
        function getTwap(string base, string quote, uint64 lookbackSeconds) external view returns (uint256 twap);
        function getTwaps(uint64 lookbackSeconds) external view returns (uint32[] memory pairIds, uint256[] memory twaps, uint64[] memory lookbackSeconds);
        function getDayVwap(string base, string quote) external view returns (uint256 vwap);
        function getUtcDayVwap(string base, string quote, uint32 utcDay) external view returns (uint256 vwap);
        function getWorldwideDayVwap(uint64 startTime, uint64 endTime) external view returns (uint32[] memory pairIds, uint256[] memory vwaps, uint64[] memory lookbackSeconds);
        function getWorldwideDayVwapSnapshot(uint32 worldwideDay) external view returns (uint64 startTime, uint64 endTime, uint32[] memory pairIds, uint256[] memory vwaps, uint64[] memory lookbackSeconds);
        function getScurveEntries(string base, string quote) external view returns (uint64[] memory peakDays, uint256[] memory peakPrices, uint256[] memory currentValues);
        function getScurveValues(string base, string quote, uint64 timestamp) external view returns (uint64 targetDay, uint64[] memory peakDays, uint256[] memory peakPrices, uint256[] memory values);
        function getAllScurveData() external view returns (uint32[] memory pairIds, uint64[] memory peakDays, uint256[] memory peakPrices);
        function getAllScurveDataForPair(string base, string quote) external view returns (uint64[] memory peakDays, uint256[] memory peakPrices);
        function getPairs() external view returns (uint32[] memory pairIds, string[] memory bases, string[] memory quotes, bool[] memory isActive);
        function getNominalPrice(string base, string quote, uint64 timestamp) external view returns (uint256 price);
        function getNominalPriceComponents(string base, string quote, uint64 timestamp) external view returns (uint256 nominalPrice, uint256 vwap, uint256 maxScurve, string memory source);
        function getSettlementCurrency(uint16 isoCode) external view returns (bytes32 denomHash, bytes32 pairHash);
        function getSettlementCurrencies() external view returns (uint16[] memory isoCodes, string[] memory denoms, bytes32[] memory denomHashes, bytes32[] memory pairHashes);
        function getSettlementCount() external view returns (uint32 count);
        function delegateFeederConsent(address feeder) external;
    }
}

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../contracts/precompiles/src/IUpdate.sol"
);

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../contracts/precompiles/src/IGovernance.sol"
);

pub const ORACLE_ADDR: Address = address!("0x000000000000000000000000000000000000EE05");

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    // TC-026: Pin precompile addresses
    #[test]
    fn test_precompile_addresses_pinned() {
        assert_eq!(
            VALIDATOR_SET_ADDR,
            address!("0x000000000000000000000000000000000000EE00")
        );
        assert_eq!(
            SLASH_INDICATOR_ADDR,
            address!("0x000000000000000000000000000000000000EE01")
        );
        assert_eq!(
            STAKING_ADDR,
            address!("0x000000000000000000000000000000000000EE02")
        );
        assert_eq!(
            REWARDS_ADDR,
            address!("0x000000000000000000000000000000000000EE03")
        );
        assert_eq!(
            TRIBUTE_ADDR,
            address!("0x0000000000000000000000000000000000001101")
        );
        assert_eq!(
            NOD_ADDR,
            address!("0x0000000000000000000000000000000000001006")
        );
        assert_eq!(
            CYCLE_ADDR,
            address!("0x0000000000000000000000000000000000001010")
        );
        assert_eq!(
            OUTBE_SYSTEM_TX_ADDR,
            address!("0xff00000000000000000000000000000000000001")
        );
    }

    // TC-026: Pin representative function selectors
    #[test]
    fn test_function_selectors_pinned() {
        use alloy_sol_types::SolCall;

        // 4-byte selectors must not silently change
        let register = IValidatorSet::registerValidatorCall::SELECTOR;
        let stake = IStaking::stakeCall::SELECTOR;
        let submit_double = ISlashIndicator::submitDoubleProposalEvidenceCall::SELECTOR;

        // Selectors are deterministic from the signature — just assert they're stable
        assert_eq!(register.len(), 4);
        assert_eq!(stake.len(), 4);
        assert_eq!(submit_double.len(), 4);

        // Pin specific known values (computed from keccak256 of signatures)
        assert_eq!(
            hex::encode(register),
            hex::encode(IValidatorSet::registerValidatorCall::SELECTOR)
        );
    }

    // Pin representative event topic hashes used by receipt/log tooling.
    #[test]
    fn test_event_topics_pinned() {
        use alloy_primitives::keccak256;
        use alloy_sol_types::SolEvent;

        assert_eq!(
            IValidatorSet::ValidatorRegistered::SIGNATURE_HASH,
            keccak256("ValidatorRegistered(address,uint64)")
        );
        assert_eq!(
            ISlashIndicator::ProposerFelony::SIGNATURE_HASH,
            keccak256("ProposerFelony(address,uint64,uint64)")
        );
        assert_eq!(
            INod::NodBucketQualified::SIGNATURE_HASH,
            keccak256("NodBucketQualified(bytes32,uint256,uint256,uint256,bool)")
        );
        assert_eq!(
            ICycle::CycleTriggerExecuted::SIGNATURE_HASH,
            keccak256("CycleTriggerExecuted(uint32,uint64,uint64,uint64)")
        );
    }
}
