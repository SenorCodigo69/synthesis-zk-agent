// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title HookMiner — Mines CREATE2 salts for Uniswap V4 hook address flag compliance
/// @notice Finds a salt such that CREATE2(deployer, salt, initCodeHash) produces
///         an address whose lower 14 bits match the required hook flags.
library HookMiner {
    /// @notice Find a salt that produces a hook address with the required flags
    /// @param deployer The CREATE2 deployer address
    /// @param flags The required hook flags (lower 14 bits of the address)
    /// @param creationCode The contract creation code
    /// @param constructorArgs The ABI-encoded constructor arguments
    /// @return hookAddress The computed hook address
    /// @return salt The salt that produces the hook address
    function find(address deployer, uint160 flags, bytes memory creationCode, bytes memory constructorArgs)
        internal
        pure
        returns (address hookAddress, bytes32 salt)
    {
        bytes memory initCode = abi.encodePacked(creationCode, constructorArgs);
        bytes32 initCodeHash = keccak256(initCode);
        uint160 flagMask = uint160((1 << 14) - 1);

        for (uint256 i = 0; i < 100_000; i++) {
            salt = bytes32(i);
            hookAddress = computeAddress(deployer, salt, initCodeHash);
            if (uint160(hookAddress) & flagMask == flags) {
                return (hookAddress, salt);
            }
        }
        revert("HookMiner: could not find salt");
    }

    /// @notice Compute the CREATE2 address
    function computeAddress(address deployer, bytes32 salt, bytes32 initCodeHash)
        internal
        pure
        returns (address)
    {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), deployer, salt, initCodeHash)))));
    }
}
