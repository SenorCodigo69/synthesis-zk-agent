"""Tests for the ZK-Gated Uniswap V4 Hook client."""
import pytest
from unittest.mock import MagicMock, PropertyMock
from web3 import Web3

from src.chain.hook_client import ZKHookClient, _TransactionSigner, BASE_CHAIN_ID


class TestZKHookClient:
    """Test ZKHookClient methods."""

    def setup_method(self):
        self.w3 = MagicMock(spec=Web3)
        self.w3.to_checksum_address = Web3.to_checksum_address
        self.w3.eth = MagicMock()
        self.w3.eth.chain_id = BASE_CHAIN_ID
        self.w3.to_wei = Web3.to_wei

        # Mock contract
        self.mock_contract = MagicMock()
        self.w3.eth.contract.return_value = self.mock_contract

        self.client = ZKHookClient(
            w3=self.w3,
            hook_address="0x45eC09fB08B83f104F15f3709F4677736112c080",
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

    def test_authorized_until(self):
        self.mock_contract.functions.authorizedUntil.return_value.call.return_value = 1700000000
        assert self.client.authorized_until("0x0000000000000000000000000000000000000001") == 1700000000

    def test_is_pre_auth_disabled(self):
        self.mock_contract.functions.preAuthDisabled.return_value.call.return_value = False
        assert not self.client.is_pre_auth_disabled()

    def test_get_agent_binding(self):
        self.mock_contract.functions.agentBinding.return_value.call.return_value = (
            "0x8d691720bF8C81044DB1a77b82D0eF5f5bffdE6C"
        )
        assert self.client.get_agent_binding(42) == "0x8d691720bF8C81044DB1a77b82D0eF5f5bffdE6C"


class TestChainIdValidation:
    """SEC-L02: Chain ID validation on startup."""

    def test_wrong_chain_id_raises(self):
        w3 = MagicMock(spec=Web3)
        w3.to_checksum_address = Web3.to_checksum_address
        w3.eth = MagicMock()
        w3.eth.chain_id = 1  # Ethereum mainnet, not Base
        w3.eth.contract.return_value = MagicMock()

        with pytest.raises(ValueError, match="Wrong chain"):
            ZKHookClient(
                w3=w3,
                hook_address="0x45eC09fB08B83f104F15f3709F4677736112c080",
                private_key="0x" + "ab" * 32,
            )

    def test_correct_chain_id_passes(self):
        w3 = MagicMock(spec=Web3)
        w3.to_checksum_address = Web3.to_checksum_address
        w3.eth = MagicMock()
        w3.eth.chain_id = BASE_CHAIN_ID
        w3.eth.contract.return_value = MagicMock()
        w3.eth.account.from_key.return_value = MagicMock(address="0x" + "00" * 20)

        # Should not raise
        client = ZKHookClient(
            w3=w3,
            hook_address="0x45eC09fB08B83f104F15f3709F4677736112c080",
            private_key="0x" + "ab" * 32,
        )
        assert client._signer is not None

    def test_no_key_skips_chain_validation(self):
        """Without a private key, no chain validation needed (read-only mode)."""
        w3 = MagicMock(spec=Web3)
        w3.to_checksum_address = Web3.to_checksum_address
        w3.eth = MagicMock()
        w3.eth.chain_id = 999  # wrong chain
        w3.eth.contract.return_value = MagicMock()

        # Should not raise — no key means read-only
        client = ZKHookClient(
            w3=w3,
            hook_address="0x45eC09fB08B83f104F15f3709F4677736112c080",
        )
        assert client._signer is None


class TestTransactionSigner:
    """SEC-M02: Private key isolation."""

    def test_key_not_exposed_as_attribute(self):
        """Private key should not be accessible as a public attribute."""
        w3 = MagicMock(spec=Web3)
        w3.eth = MagicMock()
        w3.eth.account.from_key.return_value = MagicMock(address="0x" + "00" * 20)

        signer = _TransactionSigner("0x" + "ab" * 32, w3)

        # Key should not be in public attributes
        assert not hasattr(signer, "private_key")
        assert not hasattr(signer, "key")
        # Should only have address and sign
        assert hasattr(signer, "address")
        assert hasattr(signer, "sign")

    def test_signer_provides_address(self):
        w3 = MagicMock(spec=Web3)
        w3.eth = MagicMock()
        w3.eth.account.from_key.return_value = MagicMock(address="0xABCD")

        signer = _TransactionSigner("0x" + "ab" * 32, w3)
        assert signer.address == "0xABCD"


class TestHookDataEncoding:
    """Test ZK proof → hookData encoding."""

    def test_encode_proof_as_hook_data(self):
        hook_data = ZKHookClient.encode_proof_as_hook_data(
            p_a=[1, 2],
            p_b=[[3, 4], [5, 6]],
            p_c=[7, 8],
            pub_signals=[42, 0xDEADBEEF],
        )
        assert isinstance(hook_data, bytes)
        assert len(hook_data) == 320

    def test_encode_proof_roundtrip(self):
        """Verify encoding matches what Solidity's abi.decode expects."""
        p_a = [123, 456]
        p_b = [[789, 101112], [131415, 161718]]
        p_c = [192021, 222324]
        pub_signals = [42, 99]

        hook_data = ZKHookClient.encode_proof_as_hook_data(p_a, p_b, p_c, pub_signals)

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
        calldata = '["0x1","0x2"],[["0x3","0x4"],["0x5","0x6"]],["0x7","0x8"],["0x2a","0xdeadbeef"]'
        hook_data = ZKHookClient.parse_calldata_to_hook_data(calldata)
        assert isinstance(hook_data, bytes)
        assert len(hook_data) == 320

    def test_parse_calldata_invalid_format(self):
        with pytest.raises(ValueError, match="Expected 4 calldata"):
            ZKHookClient.parse_calldata_to_hook_data('["0x1","0x2"]')
