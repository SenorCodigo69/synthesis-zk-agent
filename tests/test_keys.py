"""Tests for Baby JubJub key management."""
import pytest

from src.zk.keys import generate_keys, poseidon_hash, sign_message


class TestKeyGeneration:
    def test_generate_random_keys(self):
        keys = generate_keys()
        assert keys.private_key
        assert keys.public_key_ax
        assert keys.public_key_ay
        # Public key should be large field elements
        assert len(keys.public_key_ax) > 10
        assert len(keys.public_key_ay) > 10

    def test_generate_deterministic_keys(self):
        priv_key = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        keys1 = generate_keys(priv_key)
        keys2 = generate_keys(priv_key)
        assert keys1.public_key_ax == keys2.public_key_ax
        assert keys1.public_key_ay == keys2.public_key_ay

    def test_different_keys_different_pubkeys(self):
        keys1 = generate_keys()
        keys2 = generate_keys()
        assert keys1.public_key_ax != keys2.public_key_ax


class TestPoseidonHash:
    def test_hash_two_inputs(self):
        result = poseidon_hash([1000, 42])
        assert result
        assert len(result) > 10  # Field element

    def test_hash_deterministic(self):
        h1 = poseidon_hash([100, 200])
        h2 = poseidon_hash([100, 200])
        assert h1 == h2

    def test_hash_different_inputs(self):
        h1 = poseidon_hash([100, 200])
        h2 = poseidon_hash([100, 201])
        assert h1 != h2

    def test_hash_multiple_inputs(self):
        h3 = poseidon_hash([1, 2, 3])
        h4 = poseidon_hash([1, 2, 3, 4])
        h5 = poseidon_hash([1, 2, 3, 4, 5])
        assert h3 and h4 and h5
        assert h3 != h4 != h5


class TestSigning:
    def test_sign_message(self):
        keys = generate_keys()
        result = sign_message(keys.private_key, "12345")
        assert result["S"]
        assert result["R8x"]
        assert result["R8y"]
        assert result["Ax"] == keys.public_key_ax
        assert result["Ay"] == keys.public_key_ay

    def test_sign_different_messages(self):
        keys = generate_keys()
        sig1 = sign_message(keys.private_key, "100")
        sig2 = sign_message(keys.private_key, "200")
        assert sig1["S"] != sig2["S"]
