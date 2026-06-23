// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title IGovernance
/// @notice Generic on-chain proposal/voting precompile at 0x000000000000000000000000000000000000EE0C
interface IGovernance {
    enum ProposalStatus {
        Pending,
        Approved,
        Rejected,
        Expired
    }

    struct VoteTally {
        uint64 yes;
        uint64 no;
    }

    struct ProposalInfo {
        uint256 proposalId,
        address proposer,
        bytes32 targetModule,
        bytes32 action,
        bytes memory payload,
        uint64 createdHeight,
        uint64 votingDeadlineHeight,
        ProposalStatus status,
        VoteTally state
    }

    /// @notice New proposal was created.
    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        bytes32 targetModule,
        bytes32 action,
        bytes payload,
        uint64 votingDeadlineHeight
    );

    /// @notice Validator voted on a proposal.
    event VoteCast(uint256 indexed proposalId, address indexed validator, bool approve);

    /// @notice Proposal was rejected by conflict with another approved proposal.
    event ProposalRejected(uint256 indexed proposalId, VoteTally state, uint256 indexed conflictingproposalId);

    /// @notice Proposal was expired by voting deadline.
    event ProposalExpired(uint256 indexed proposalId, VoteTally state);

    /// @notice Proposal was cancelled by the proposer.
    event ProposalCancelled(uint256 indexed proposalId, address indexed proposer);

    /// @notice Proposal was approved by majority (2/3).
    event ProposalApproved(uint256 indexed proposalId, VoteTally state, uint64 activationHeight, uint32 version);


    /// @notice Creates a generic governance proposal.
    /// @param targetModule Target system module identifier.
    /// @param action Module-specific action identifier.
    /// @param payload Opaque action payload decoded only by the target module handler.
    function createProposal(bytes32 targetModule, bytes32 action, bytes calldata payload)
        external
        returns (uint256 proposalId);

    /// @notice Casts a vote on a pending proposal.
    /// @dev Only active validators may vote.
    function castVote(uint256 proposalId, bool approve) external;

    // ===============================================
    // VIEW API
    // ===============================================

    /// @notice Returns proposal details.
    function getProposal(uint256 proposalId) external view returns (ProposalInfo memory);

    /// @notice Returns all tracked proposal ids.
    function listProposals() external view returns (uint256[] memory);

    /// @notice Returns proposal ids filtered by status.
    function listProposalsByStatus(ProposalStatus status) external view returns (uint256[] memory);
}
