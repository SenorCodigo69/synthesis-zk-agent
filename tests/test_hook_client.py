"""Tests for the ZK-Gated Uniswap V4 Hook client."""
import pytest
from unittest.mock import MagicMock, patch
from web3 import Web3

from src.chain.hook_client import ZKHookClient, ZK_HOOK_ABI


class TestZKHookClient:
    """Test ZKHookClient methods."""

    def setup_method(self):
        self.w3 = MagicMock(spec=Web3)
        self.w3.to_checksum_address = Web3.to_checksum_address
        self.w3.eth = MagicMock()
        self.w3.to_wei = Web3.to_wei

        # Mock contract
        self.mock_contract = MagicMock()
        self.w3.eth.contract.return_value = self.mock_contract

        self.client = ZKHookClient(
            w3=self.w3,
            hook_address="0x859Ae689bE007183aC78D364e5550EBc15324080",
        )

    def test_is_authorized_true(self):
        self.mock_contract.functions.authorized.return_value.call.return_value = True
        assert self.client.is_authorized("0x8d691720bF8C81044DB1a77b82D0eF5f5bffdE6C")

    def test_is_authorized_false(self):
        self.mock_contract.functions.authorized.return_value.call.return_value = False
        assert not self.client.is_authorized("0x0000000000000000000000000000000000000001")

    def test_authorized_count(self):
        self.mock_contract.functions.authorizedCount.return_value.call.return_value = 5
        assert self.client.authorized_count() == 5

    def test_owner(self):
        self.mock_contract.functions.owner.return_value.call.return_value = (
            "0x8d691720bF8C81044DB1a77b82D0eF5f5bffdE6C"
        )
        assert self.client.owner() == "0x8d691720bF8C81044DB1a77b82D0eF5f5bffdE6C"

    def test_pre_authorize_requires_private_key(self):
        with pytest.raises(ValueError, match="Private key required"):
            self.client.pre_authorize("0x0000000000000000000000000000000000000001")

    def test_revoke_requires_private_key(self):
        with pytest.raises(ValueError, match="Private key required"):
            self.client.revoke_authorization("0x0000000000000000000000000000000000000001")


class TestHookDataEncoding:
    """Test ZK proof → hookData encoding."""

    def test_encode_proof_as_hook_data(self):
        hook_data = ZKHookClient.encode_proof_as_hook_data(
            p_a=[1, 2],
            p_b=[[3, 4], [5, 6]],
            p_c=[7, 8],
            pub_signals=[42, 0xDEADBEEF],
        )
        # ABI encoding produces fixed-size output: 4 arrays = 10 uint256 = 320 bytes
        assert isinstance(hook_data, bytes)
        assert len(hook_data) == 320

    def test_encode_proof_roundtrip(self):
        """Verify encoding matches what Solidity's abi.decode expects."""
        p_a = [123, 456]
        p_b = [[789, 101112], [131415, 161718]]
        p_c = [192021, 222324]
        pub_signals = [42, 99]

        hook_data = ZKHookClient.encode_proof_as_hook_data(p_a, p_b, p_c, pub_signals)

        # Decode it back using Web3
        w3 = Web3()
        decoded = w3.codec.decode(
            ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256[2]"],
            hook_data,
        )
        assert list(decoded[0]) == p_a
        assert [list(row) for row in decoded[1]] == p_b
        assert list(decoded[2]) == p_c
        assert list(decoded[3]) == pub_signals

    def test_parse_calldata_to_hook_data(self):
        """Test snarkjs calldata → hookData conversion."""
        # Simulated snarkjs output
        calldata = '["0x1","0x2"],[["0x3","0x4"],["0x5","0x6"]],["0x7","0x8"],["0x2a","0xdeadbeef"]'
        hook_data = ZKHookClient.parse_calldata_to_hook_data(calldata)
        assert isinstance(hook_data, bytes)
        assert len(hook_data) == 320

    def test_parse_calldata_invalid_format(self):
        with pytest.raises(ValueError, match="Expected 4 calldata"):
            ZKHookClient.parse_calldata_to_hook_data('["0x1","0x2"]')
