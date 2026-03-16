"""Tests for ERC-8004 agent registration module."""
import base64
import json

import pytest

from src.erc8004 import AgentRegistration, REGISTRIES, IDENTITY_REGISTRY_ABI


class TestAgentRegistration:
    def test_default_metadata(self):
        reg = AgentRegistration()
        assert reg.name == "SynthesisZKAgent"
        assert "privacy" in reg.description.lower() or "zk" in reg.description.lower()
        assert "synthesis-zk-agent" in reg.repo_url

    def test_token_uri_json_structure(self):
        reg = AgentRegistration()
        raw = reg.to_token_uri_json()
        data = json.loads(raw)

        assert data["type"] == "https://eips.ethereum.org/EIPS/eip-8004#registration-v1"
        assert data["name"] == "SynthesisZKAgent"
        assert "endpoints" in data
        assert len(data["endpoints"]) >= 1
        assert data["endpoints"][0]["endpoint"] == reg.repo_url

    def test_supported_trust_includes_zk(self):
        reg = AgentRegistration()
        data = json.loads(reg.to_token_uri_json())
        assert "zk-proof" in data["supportedTrust"]

    def test_capabilities_list(self):
        reg = AgentRegistration()
        data = json.loads(reg.to_token_uri_json())
        expected = [
            "zk-authorization",
            "budget-range-proofs",
            "cumulative-spend-proofs",
            "selective-disclosure",
            "privacy-preserving-execution",
            "groth16-verification",
        ]
        assert data["capabilities"] == expected

    def test_data_uri_format(self):
        reg = AgentRegistration()
        uri = reg.to_data_uri()
        assert uri.startswith("data:application/json;base64,")

        # Decode and verify
        encoded = uri.split(",", 1)[1]
        decoded = base64.b64decode(encoded).decode()
        data = json.loads(decoded)
        assert data["name"] == "SynthesisZKAgent"

    def test_data_uri_roundtrip(self):
        reg = AgentRegistration()
        uri = reg.to_data_uri()
        encoded = uri.split(",", 1)[1]
        decoded = json.loads(base64.b64decode(encoded))
        original = json.loads(reg.to_token_uri_json())
        assert decoded == original

    def test_custom_metadata(self):
        reg = AgentRegistration(
            name="CustomAgent",
            description="Custom description",
            repo_url="https://github.com/test/repo",
        )
        data = json.loads(reg.to_token_uri_json())
        assert data["name"] == "CustomAgent"
        assert data["description"] == "Custom description"
        assert data["endpoints"][0]["endpoint"] == "https://github.com/test/repo"


class TestRegistries:
    def test_base_sepolia_registry(self):
        info = REGISTRIES["base_sepolia"]
        assert info["chain_id"] == 84532
        assert info["identity"].startswith("0x")
        assert info["reputation"].startswith("0x")

    def test_base_mainnet_registry(self):
        info = REGISTRIES["base_mainnet"]
        assert info["chain_id"] == 8453
        assert info["identity"].startswith("0x")
        assert info["reputation"].startswith("0x")

    def test_registry_addresses_are_checksummed_length(self):
        for network, info in REGISTRIES.items():
            assert len(info["identity"]) == 42, f"{network} identity address wrong length"
            assert len(info["reputation"]) == 42, f"{network} reputation address wrong length"


class TestABI:
    def test_register_function_exists(self):
        register_fn = next(
            (f for f in IDENTITY_REGISTRY_ABI if f.get("name") == "register"), None
        )
        assert register_fn is not None
        assert register_fn["stateMutability"] == "nonpayable"
        assert register_fn["inputs"][0]["name"] == "tokenURI"
        assert register_fn["outputs"][0]["type"] == "uint256"

    def test_token_uri_view_exists(self):
        view_fn = next(
            (f for f in IDENTITY_REGISTRY_ABI if f.get("name") == "tokenURI"), None
        )
        assert view_fn is not None
        assert view_fn["stateMutability"] == "view"
