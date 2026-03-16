// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IAuthorizationVerifier — Interface for Groth16 ZK proof verification
/// @notice Deployed at 0x2a8FBE80BDc9cb907b20acBE84F13a858CBEdAe4 on Base
interface IAuthorizationVerifier {
    /// @notice Verify a Groth16 ZK proof of agent authorization
    /// @param _pA Proof point A (G1)
    /// @param _pB Proof point B (G2)
    /// @param _pC Proof point C (G1)
    /// @param _pubSignals Public signals: [agentId, policyCommitment]
    /// @return True if the proof is valid
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[2] calldata _pubSignals
    ) external view returns (bool);
}
