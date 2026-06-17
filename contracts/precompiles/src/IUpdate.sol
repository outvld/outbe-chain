// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title IUpdate
/// @notice On-chain upgrade governance precompile at 0x000000000000000000000000000000000000EE0B
interface IUpdate {
    enum ProposalStatus {
        Pending,
        Approved,
        Rejected,
        Expired,
        Activated,
        Cancelled,
    }
    struct VoteTally {
        uint64 yes;
        uint64 no;
    }

    
    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        string version,
        uint64 activationHeight,
        uint64 votingDeadlineHeight,
        bytes info,
    );

    event VoteCast(
        uint256 indexed proposalId,
        address indexed voter,
        bool approve,
    );

    //===============================================
    // Final states of a proposal
    //===============================================

    /// @notice Proposal was rejected by conflict with another approved proposal.
    event ProposalRejected(uint256 indexed proposalId, VoteTally state, uint256 indexed conflictingproposalId);

    /// @notice Proposal was expired by voting deadline.
    event ProposalExpired(uint256 indexed proposalId, VoteTally state);

    /// @notice Proposal was cancelled by the proposer.
    event ProposalCancelled(uint256 indexed proposalId, address indexed proposer);

    /// @notice Proposal was approved by majority (2/3).
    event ProposalApproved(uint256 indexed proposalId, VoteTally state, uint64 activationHeight, string version);

    /// @notice Emitted when the proposed plan is activated.
    event UpgradeActivated(string version, uint64 activationHeight);


    //===============================================
    // View api
    //===============================================

    /// @notice Returns the proposal details.
    function getProposal(uint256 proposalId)
        external
        view
        returns (
            uint256 proposalId,
            address proposer,
            uint64 proposedAtHeight,
            uint64 activationHeight,
            uint64 votingDeadlineHeight,
            string memory version,
            bytes memory info,
            ProposalStatus status,
            VoteTally state,
        );

    /// @notice Returns the active version.
    function getActiveVersion() external view returns (string memory);

    /// @notice Returns true if the version is active.
    function isVersionActive(string calldata version) external view returns (bool);

    /// @notice Returns the list of pending proposal ids.
    function listPendingProposals() external view returns (uint256[] memory);

    //===============================================
    // Modifying api
    //===============================================

    /// @notice Creates a new proposal.
    /// @param version The version in format of semver string: vMAJOR.MINOR.PATCH.
    /// @param activationHeight The height at which the proposal should be activated.
    /// @param info The additional information about the proposal.
    function createProposal(string calldata version, uint64 activationHeight, bytes calldata info)
        external
        returns (uint256 proposalId);

    /// @notice Casts a vote on a proposal.
    /// @dev Only validator can participate in voting.
    /// @param proposalId The ID of the proposal.
    /// @param approve The vote: true for Yes, false for No.
    function castVote(uint256 proposalId, bool approve) external;

    /// @notice Cancels a pending proposal.
    /// @dev Only the proposer may cancel propose, and propose should be in Pending status.
    function cancelProposal(uint256 proposalId) external;
}
