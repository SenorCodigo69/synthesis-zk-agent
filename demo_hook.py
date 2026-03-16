"""Demo: ZK-Gated Uniswap V4 Hook on Base Mainnet.

Demonstrates the complete flow:
1. Connect to the deployed ZKGatedHook contract
2. Check authorization status
3. Encode a ZK proof as Uniswap V4 hookData
4. Show how the hook gates swaps behind ZK proofs

Run: python demo_hook.py
"""
from web3 import Web3

from src.chain.hook_client import ZKHookClient, ZK_HOOK_ADDRESS

# Base mainnet RPC
BASE_RPC = "https://mainnet.base.org"

# Contract addresses
POOL_MANAGER = "0x498581fF718922c3f8e6A244956aF099B2652b2b"
AUTH_VERIFIER = "0x2a8FBE80BDc9cb907b20acBE84F13a858CBEdAe4"
OUR_WALLET = "0x8d691720bF8C81044DB1a77b82D0eF5f5bffdE6C"


def main():
    print("=" * 60)
    print("ZK-Gated Uniswap V4 Hook — Base Mainnet Demo")
    print("=" * 60)
    print()

    # Connect
    w3 = Web3(Web3.HTTPProvider(BASE_RPC))
    assert w3.is_connected(), "Failed to connect to Base"
    print(f"Connected to Base (chain {w3.eth.chain_id})")
    print()

    # Initialize client
    client = ZKHookClient(w3)

    # ── Contract State ──
    print("── Contract State ──")
    print(f"  Hook:       {ZK_HOOK_ADDRESS}")
    print(f"  Owner:      {client.owner()}")
    print(f"  Authorized: {client.authorized_count()} agents")
    print()

    # ── Authorization Check ──
    print("── Authorization Check ──")
    our_authorized = client.is_authorized(OUR_WALLET)
    print(f"  {OUR_WALLET}: {'AUTHORIZED' if our_authorized else 'NOT AUTHORIZED'}")

    random_addr = "0x0000000000000000000000000000000000000001"
    random_authorized = client.is_authorized(random_addr)
    print(f"  {random_addr}: {'AUTHORIZED' if random_authorized else 'NOT AUTHORIZED'}")
    print()

    # ── hookData Encoding Demo ──
    print("── hookData Encoding (ZK Proof → Uniswap V4) ──")
    # Example proof (would come from snarkjs in production)
    dummy_proof = {
        "pA": [
            0x2B2D8F5A24DA3F2A8DE88E64B11E6C1F3D2CA4D4D90A8C7BF9C6D5E6F7A8B9C,
            0x1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A,
        ],
        "pB": [
            [
                0x3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B,
                0x4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C,
            ],
            [
                0x5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D,
                0x6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E,
            ],
        ],
        "pC": [
            0x7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F,
            0x8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A,
        ],
        "pubSignals": [42, 0xDEADBEEF],  # [agentId, policyCommitment]
    }

    hook_data = ZKHookClient.encode_proof_as_hook_data(
        p_a=dummy_proof["pA"],
        p_b=dummy_proof["pB"],
        p_c=dummy_proof["pC"],
        pub_signals=dummy_proof["pubSignals"],
    )
    print(f"  Encoded hookData: {len(hook_data)} bytes")
    print(f"  First 32 bytes:   0x{hook_data[:32].hex()}")
    print()

    # ── Architecture Summary ──
    print("── Architecture ──")
    print("  1. Agent generates ZK proof (Groth16 via snarkjs)")
    print("     - Proves: delegated authority from owner")
    print("     - Hides:  owner identity, spend limits, nonce")
    print("  2. Proof is ABI-encoded as hookData")
    print("  3. Agent calls Uniswap V4 swap with hookData")
    print("  4. PoolManager calls ZKGatedHook.beforeSwap()")
    print("  5. Hook decodes proof → calls AuthorizationVerifier")
    print("  6. If valid → authorize & allow swap")
    print("     If invalid → revert (swap blocked)")
    print("  7. Subsequent swaps use cached authorization")
    print()

    # ── On-Chain Artifacts ──
    print("── On-Chain Artifacts (Base Mainnet) ──")
    print(f"  ZKGatedHook:          {ZK_HOOK_ADDRESS}")
    print(f"  AuthorizationVerifier: {AUTH_VERIFIER}")
    print(f"  PoolManager (v4):      {POOL_MANAGER}")
    print(f"  Address flags:         0x80 (BEFORE_SWAP)")
    print()

    # ── Tx Hashes ──
    print("── Transaction History ──")
    print("  Hook deployment:       0xed914dfdb83d9acb90795ce54830f19cb9e010cd13c7428fa32b2ec8c7991cb5")
    print("  Pre-authorize wallet:  0xd274d79ca591590e53a53147d50247113c8dd0f59e9a115b7687d35a23684b3b")
    print()

    print("Demo complete.")


if __name__ == "__main__":
    main()
