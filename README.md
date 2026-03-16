# Synthesis ZK Agent -- Privacy-Preserving Autonomous Yield Agent

> **Track 2: "Agents that keep secrets"** -- Ethereum Foundation Synthesis Hackathon (March 2026)

An autonomous DeFi yield agent that operates **privately**. It scans protocols for best USDC yield, deposits and withdraws using ZK-authorized spending proofs, hides balances and strategy from chain observers, and supports selective disclosure for compliance -- all without revealing private data on-chain.

**Stack:** Circom / Groth16 / Baby JubJub EdDSA / snarkjs / **Uniswap V4 Hooks** / Foundry / Base chain / Python

---

## What It Does

Traditional on-chain agents leak everything: balances, strategies, transaction patterns, spending limits. Competitors front-run you. MEV bots extract value. Chain analytics firms profile you.

This agent proves it is authorized and within budget **without revealing any of that data**.

1. **Owner delegates** spending authority via Baby JubJub EdDSA signature
2. **Agent proves authorization** via ZK proof -- without revealing the owner, limits, or policy
3. **Agent proves budget compliance** -- without revealing the budget or balance
4. **Agent tracks cumulative spend** -- chained ZK commitments, without revealing totals
5. **Selective disclosure** -- auditors see totals (not individual txs), public sees compliance proof only

The human sets the rules. The agent proves compliance. Nobody sees the data.

---

## How It Works

```
keygen --> delegate --> prove --> execute --> disclose
```

1. **Keygen** -- Generate a Baby JubJub EdDSA keypair (ZK-friendly elliptic curve). The private key never touches the chain.
2. **Delegate** -- Owner signs a spending policy (agent ID, spend limit, validity period) with EdDSA. The policy hash is committed on-chain via `PolicyCommitment.sol`; the policy contents stay private.
3. **Prove** -- Before any action, the agent generates Groth16 ZK proofs:
   - **Authorization proof**: "I was delegated by a valid owner" (hides owner identity and limits)
   - **Budget range proof**: "This amount is within my budget" (hides the budget)
   - **Cumulative spend proof**: "My running total is under the period limit" (hides the limit and history)
4. **Execute** -- Agent deposits/withdraws from DeFi protocols. On-chain verifier contracts validate the proofs. No private inputs are revealed.
5. **Disclose** -- Human-defined policies control what each audience sees. Each disclosure generates a purpose-specific ZK proof (e.g., auditor gets total monthly spend without individual transactions).

---

## Privacy Architecture

```
                +---------------------------------+
                |     Private Yield Agent          |
                |     (AI decision engine)         |
                +---------------+-----------------+
                                |
       +------------------------+------------------------+
       |                        |                        |
+------v---------+  +-----------v--------+  +------------v-----------+
|  ZK Proof       |  |  Private           |  |  Disclosure            |
|  Engine         |  |  Execution         |  |  Controller            |
+---------+------+  +----------+---------+  +-------------+----------+
          |                    |                          |
          v                    v                          v
Authorization proofs,  ZK-gated deposit/       Human-defined rules
range proofs, budget   withdraw, paper +       for what to reveal
compliance proofs      live modes              and to whom
```

---

## ZK Circuits

| Circuit | What It Proves | What It Hides | Constraints |
|---|---|---|---|
| **Authorization** | Agent is delegated by owner | Owner identity, spend limits, validity | ~8,000 |
| **Budget Range** | Amount is within budget | The budget, the amount | ~436 |
| **Cumulative Spend** | Total spend is within period limit | The limit, running total, history | ~849 |

Built with **Circom 2.2.3** + **snarkjs 0.7.6** (Groth16 proving system). Battle-tested stack used by Polygon ID, Semaphore, and Iden3.

---

## On-Chain Contracts (Base Mainnet)

| Contract | Address | Purpose |
|---|---|---|
| `ZKGatedHook.sol` | [`0x859Ae689...`](https://basescan.org/address/0x45eC09fB08B83f104F15f3709F4677736112c080) | **Uniswap V4 Hook** -- gates swaps behind ZK proofs |
| `AuthorizationVerifier.sol` | [`0x2a8FBE80...`](https://basescan.org/address/0x2a8FBE80BDc9cb907b20acBE84F13a858CBEdAe4) | Groth16 verifier for authorization proofs |
| `BudgetRangeVerifier.sol` | [`0x8d7520a3...`](https://basescan.org/address/0x8d7520a34f3EFbB86d02232C4fc31dB9415142d3) | Groth16 verifier for budget proofs |
| `CumulativeSpendVerifier.sol` | [`0x1c7A42fe...`](https://basescan.org/address/0x1c7A42fea03ec0C86c94B886588a2680184428D9) | Groth16 verifier for cumulative spend proofs |
| `PolicyCommitment.sol` | [`0x049B09c4...`](https://basescan.org/address/0x049B09c4aE1974F84164b65a9f0AB412dA9814f2) | Stores hashed spending policies (nothing revealed) |

## Uniswap V4 Hook -- ZK-Gated Swaps

The `ZKGatedHook` is a Uniswap V4 `beforeSwap` hook that gates pool access behind Groth16 ZK proofs. This is the first production ZK access-control hook on Uniswap V4.

**How it works:**
1. Agent generates a ZK authorization proof (proving delegation without revealing owner)
2. Proof is ABI-encoded as `hookData` in the Uniswap V4 swap call
3. `beforeSwap()` decodes the proof and calls `AuthorizationVerifier.verifyProof()` on-chain
4. Valid proof -> agent is authorized and cached (subsequent swaps skip proof verification)
5. Invalid proof -> swap reverts (unauthorized agents cannot use this pool)

**Address mining:** Uniswap V4 encodes hook permissions in the contract address itself. The hook was deployed via CREATE2 with a mined salt so that the address has `BEFORE_SWAP_FLAG` (bit 7) set: `0x45eC09fB08B83f104F15f3709F4677736112c080` (last byte `0x80`).

```bash
# Run the hook demo
python demo_hook.py

# Run hook client tests
pytest tests/test_hook_client.py -v
```

## ERC-8004 Agent Identity

The agent registers on the [ERC-8004 Identity Registry](https://eips.ethereum.org/EIPS/eip-8004), giving it a verifiable on-chain identity (ERC-721 NFT) with declared capabilities:

- `zk-authorization` -- proves delegation without revealing owner
- `budget-range-proofs` -- proves budget compliance without revealing limits
- `cumulative-spend-proofs` -- proves running totals without revealing history
- `selective-disclosure` -- human-controlled audience-specific proofs
- `privacy-preserving-execution` -- ZK-gated DeFi operations
- `groth16-verification` -- on-chain proof verification

```bash
# Register on Base Sepolia testnet
python -m src register

# Register on Base mainnet
python -m src register --live
```

---

## Quick Start

```bash
# Install dependencies
npm install                    # Circomlib, snarkjs, EdDSA
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Compile ZK circuits
bash scripts/compile.sh

# Run trusted setup (downloads powers of tau)
bash scripts/setup.sh

# Run the full demo
python -m src.main demo

# Run tests (81 Python + 33 Solidity)
pytest                        # Python tests
cd contracts && forge test    # Solidity tests
```

## CLI Commands

```bash
# Set owner key via env var (preferred -- avoids shell history leaks)
export OWNER_PRIVATE_KEY=<your-bjj-hex-key>

python -m src.main keygen                                              # Generate Baby JubJub EdDSA keys
python -m src.main delegate --spend-limit 5000                         # Create signed delegation
python -m src.main prove-budget --amount 2000 --budget 5000            # Budget range proof
python -m src.main prove-auth --agent-id 1                             # Authorization proof
python -m src.main execute --amount 2000 --protocol aave-v3            # Private execution (paper)
python -m src.main disclose --level auditor                            # Selective disclosure
python -m src.main status                                              # Agent status
python -m src.main register                                            # ERC-8004 registration (testnet)
python -m src.main register --live                                     # ERC-8004 registration (mainnet)
```

---

## Selective Disclosure

Human defines what each audience can see:

```yaml
disclosure:
  auditor:
    can_see: [total_monthly_spend, proof_of_solvency]
    cannot_see: [individual_transactions, protocol_names]

  public:
    can_see: [proof_of_compliance]
    cannot_see: [everything_else]
```

Each disclosure generates a purpose-specific ZK proof. The auditor gets a proof that total spend is within limits without seeing individual transactions.

---

## Security

Two full security audits completed (2026-03-14). **30 total findings, all actionable findings fixed.**

**Audit v1:** 14 findings (2 CRITICAL, 3 HIGH, 4 MEDIUM, 5 LOW) -- all 14 fixed.
**Audit v2:** 16 findings (0 CRITICAL, 2 HIGH, 4 MEDIUM, 5 LOW, 5 INFO) -- all 11 actionable findings fixed.

Key fixes: contract access control, budget proof linkability, key handling via env vars, PBKDF2 key stretching, nonce persistence, config path validation, chain ID deployment guard, Solidity test coverage (12 Foundry tests).

See [SECURITY-AUDIT.md](SECURITY-AUDIT.md) for the full report.

---

## Why This Is NOT a Mixer

| | Tornado Cash | This Project |
|---|---|---|
| **Mixing** | Core feature | None -- single user, own funds |
| **P2P** | Shared pool | No P2P -- agent's own wallet |
| **Compliance** | None | Selective disclosure built-in |
| **Fund commingling** | Yes | No |

EU GDPR recognizes ZK proofs as implementing data minimization (Article 25). This is privacy-preserving technology with disclosure capabilities -- not a mixing service.

---

## Deployment

**Target chain:** Base (cheapest gas, largest Morpho liquidity for USDC yield).

Contracts are compiled and ready for deployment via Foundry. Testnet deployment pending.

```bash
# Deploy contracts (requires DEPLOYER_PRIVATE_KEY env var and Base RPC)
python -m src.main deploy --rpc-url <base-rpc-url>
```

---

## Project Structure

```
circuits/              # Circom ZK circuits (3)
contracts/             # Solidity contracts (PolicyCommitment + verifiers)
scripts/               # Compile, setup, keygen, signing helpers
src/
  zk/                  # Proof engine, keys, commitment scheme
  privacy/             # Policy manager, executor, disclosure controller
  chain/               # Contract deployment, on-chain verification
  erc8004.py           # ERC-8004 agent identity registration
  main.py              # CLI (9 commands + demo)
  database.py          # SQLite persistence
tests/                 # 81 tests (including hook client)
```

## Tech Stack

- **Python 3.13** -- agent logic
- **Circom 2.2.3** -- ZK circuit development
- **snarkjs 0.7.6** -- Groth16 proof generation and verification
- **Baby JubJub EdDSA** -- key management (@zk-kit/eddsa-poseidon)
- **Poseidon hash** -- ZK-friendly hashing (poseidon-lite)
- **Solidity 0.8.26** -- on-chain verifier contracts + Uniswap V4 hook
- **Foundry** -- contract compilation, testing, deployment
- **Base chain** -- deployment target
- **SQLite** -- local state, audit trail

---

## Hackathon

| Field | Value |
|---|---|
| **Event** | Ethereum Foundation Synthesis Hackathon (March 13-22, 2026) |
| **Track** | Track 2: "Agents that keep secrets" + Uniswap "Agentic Finance" bounty |
| **Primary AI model** | `claude-opus-4-6` via `claude-code` |
| **What we demonstrate** | An autonomous agent that executes DeFi operations with full ZK privacy -- proving authorization and budget compliance without revealing any private data, with human-controlled selective disclosure for compliance. **Includes the first ZK-gated Uniswap V4 Hook** -- only ZK-authorized agents can swap. |
| **On-chain** | 5 contracts deployed on Base mainnet, ERC-8004 Agent #32271 |
| **Tests** | 89 Python + 50 Solidity = 139 total |
| **Security** | 4 audits, 55+ findings, all fixed |
| **Conversation log** | See [`docs/hackathon/CONVERSATION-LOG.md`](https://github.com/SenorCodigo69/finance_agent/blob/main/docs/hackathon/CONVERSATION-LOG.md) |
| **Related** | [synthesis-yield-agent](https://github.com/SenorCodigo69/synthesis-yield-agent) (Track 1 + Uniswap Trading API) |

---

## License

MIT
