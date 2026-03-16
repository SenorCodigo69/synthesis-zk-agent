// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title PolicyCommitment — On-chain spending scope commitment for ZK-authorized agents
/// @notice Stores hashed policy commitments that ZK proofs reference.
///         The commitment is a Poseidon hash of (ownerPubKey, spendLimit, validUntil, nonce, salt).
///         Nothing about the policy is revealed on-chain — only the hash.
contract PolicyCommitment {
    struct Commitment {
        bytes32 policyHash;      // Poseidon hash of the policy (stored as bytes32)
        uint256 agentId;         // Agent identifier
        address owner;           // Owner's Ethereum address (for access control)
        uint256 createdAt;       // Block timestamp
        bool active;             // Can be deactivated by owner
    }

    /// @notice Mapping from commitment ID to commitment data
    mapping(uint256 => Commitment) public commitments;

    /// @notice Next commitment ID (starts at 1; 0 = no commitment)
    uint256 public nextId = 1;

    /// @notice Agent ID to active commitment ID mapping (0 = none)
    mapping(uint256 => uint256) public activeCommitment;

    /// @notice Agent ID to registered owner (first committer owns the agent ID)
    mapping(uint256 => address) public agentOwner;

    event CommitmentCreated(uint256 indexed id, uint256 indexed agentId, bytes32 policyHash);
    event CommitmentDeactivated(uint256 indexed id, uint256 indexed agentId);

    /// @notice Publish a new policy commitment on-chain
    /// @param agentId The agent this policy applies to
    /// @param policyHash The Poseidon hash of the policy parameters
    function commitPolicy(uint256 agentId, bytes32 policyHash) external returns (uint256) {
        require(policyHash != bytes32(0), "Empty policy hash");
        require(
            agentOwner[agentId] == address(0) || agentOwner[agentId] == msg.sender,
            "Not agent owner"
        );

        if (agentOwner[agentId] == address(0)) {
            agentOwner[agentId] = msg.sender;
        }

        uint256 id = nextId++;

        commitments[id] = Commitment({
            policyHash: policyHash,
            agentId: agentId,
            owner: msg.sender,
            createdAt: block.timestamp,
            active: true
        });

        activeCommitment[agentId] = id;

        emit CommitmentCreated(id, agentId, policyHash);
        return id;
    }

    /// @notice Deactivate a commitment (only owner)
    /// @param id The commitment ID to deactivate
    function deactivateCommitment(uint256 id) external {
        require(commitments[id].owner == msg.sender, "Not owner");
        require(commitments[id].active, "Already inactive");

        commitments[id].active = false;
        emit CommitmentDeactivated(id, commitments[id].agentId);
    }

    /// @notice Check if a commitment is active
    /// @param id The commitment ID
    function isActive(uint256 id) external view returns (bool) {
        return commitments[id].active;
    }

    /// @notice Get the active policy hash for an agent
    /// @param agentId The agent ID
    function getActivePolicyHash(uint256 agentId) external view returns (bytes32) {
        uint256 id = activeCommitment[agentId];
        require(id != 0, "No commitment for agent");
        require(commitments[id].active, "Commitment inactive");
        return commitments[id].policyHash;
    }

    /// @notice Verify a policy hash matches the on-chain commitment
    /// @param agentId The agent ID
    /// @param policyHash The hash to verify
    function verifyCommitment(uint256 agentId, bytes32 policyHash) external view returns (bool) {
        uint256 id = activeCommitment[agentId];
        if (id == 0) return false;
        return commitments[id].active && commitments[id].policyHash == policyHash;
    }
}
