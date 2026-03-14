// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/PolicyCommitment.sol";

contract PolicyCommitmentTest is Test {
    PolicyCommitment pc;
    address owner = address(0x1);
    address attacker = address(0x2);

    function setUp() public {
        pc = new PolicyCommitment();
    }

    function test_commitPolicy_succeeds() public {
        vm.prank(owner);
        uint256 id = pc.commitPolicy(1, bytes32(uint256(0xdead)));
        assertEq(id, 1);
        assertEq(pc.agentOwner(1), owner);
        assertTrue(pc.isActive(id));
    }

    function test_commitPolicy_rejectsEmptyHash() public {
        vm.prank(owner);
        vm.expectRevert("Empty policy hash");
        pc.commitPolicy(1, bytes32(0));
    }

    function test_commitPolicy_onlyOwnerCanUpdate() public {
        vm.prank(owner);
        pc.commitPolicy(1, bytes32(uint256(0xdead)));

        vm.prank(attacker);
        vm.expectRevert("Not agent owner");
        pc.commitPolicy(1, bytes32(uint256(0xbeef)));
    }

    function test_ownerCanUpdateOwnAgent() public {
        vm.prank(owner);
        pc.commitPolicy(1, bytes32(uint256(0xdead)));

        vm.prank(owner);
        uint256 id2 = pc.commitPolicy(1, bytes32(uint256(0xbeef)));
        assertEq(id2, 2);
        assertEq(pc.getActivePolicyHash(1), bytes32(uint256(0xbeef)));
    }

    function test_deactivateCommitment() public {
        vm.prank(owner);
        uint256 id = pc.commitPolicy(1, bytes32(uint256(0xdead)));

        vm.prank(owner);
        pc.deactivateCommitment(id);
        assertFalse(pc.isActive(id));
    }

    function test_deactivate_onlyOwner() public {
        vm.prank(owner);
        uint256 id = pc.commitPolicy(1, bytes32(uint256(0xdead)));

        vm.prank(attacker);
        vm.expectRevert("Not owner");
        pc.deactivateCommitment(id);
    }

    function test_deactivate_alreadyInactive() public {
        vm.prank(owner);
        uint256 id = pc.commitPolicy(1, bytes32(uint256(0xdead)));

        vm.prank(owner);
        pc.deactivateCommitment(id);

        vm.prank(owner);
        vm.expectRevert("Already inactive");
        pc.deactivateCommitment(id);
    }

    function test_getActivePolicyHash_noCommitment() public {
        vm.expectRevert("No commitment for agent");
        pc.getActivePolicyHash(99);
    }

    function test_verifyCommitment_matches() public {
        bytes32 hash = bytes32(uint256(0xdead));
        vm.prank(owner);
        pc.commitPolicy(1, hash);

        assertTrue(pc.verifyCommitment(1, hash));
        assertFalse(pc.verifyCommitment(1, bytes32(uint256(0xbeef))));
    }

    function test_verifyCommitment_unregisteredAgent() public {
        assertFalse(pc.verifyCommitment(99, bytes32(uint256(0xdead))));
    }

    function test_nextId_startsAtOne() public {
        assertEq(pc.nextId(), 1);
    }

    function test_multipleAgents_independentOwners() public {
        vm.prank(owner);
        pc.commitPolicy(1, bytes32(uint256(0xdead)));

        vm.prank(attacker);
        pc.commitPolicy(2, bytes32(uint256(0xbeef)));

        assertEq(pc.agentOwner(1), owner);
        assertEq(pc.agentOwner(2), attacker);
    }
}
