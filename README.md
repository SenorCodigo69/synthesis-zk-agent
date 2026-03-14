# Synthesis ZK Agent — Privacy-Preserving Yield Agent

> **Track: "Agents that keep secrets"** — Ethereum Foundation Synthesis Hackathon

An autonomous yield agent that operates **privately** — scanning DeFi protocols for best USDC yield, depositing/withdrawing with ZK-authorized spending proofs, hiding balances and strategy from chain observers, while maintaining selective disclosure for compliance.

## What It Does

1. **Owner delegates** spending authority to the agent via Baby JubJub EdDSA signature
2. **Agent proves authorization** via ZK proof — without revealing the owner, limits, or policy
3. **Agent proves budget compliance** — without revealing the budget or balance
4. **Agent tracks cumulative spend** — chained ZK commitments, without revealing totals or limits
5. **Selective disclosure** — auditors see totals (not individual txs), public sees compliance proof only

## Privacy Architecture

```
                ┌──────────────────────────────┐
                │     Private Yield Agent       │
                │     (AI decision engine)      │
                └──────────┬───────────────────┘
                           │
      ┌────────────────────┼──────────────────────┐
      │                    │                      │
┌─────▼──────────┐  ┌─────▼──────────┐  ┌────────▼───────────┐
│  ZK Proof       │  │  Private       │  │  Disclosure        │
│  Engine         │  │  Execution     │  │  Controller        │
└─────┬──────────┘  └─────┬──────────┘  └────────┬───────────┘
      │                    │                      │
      ▼                    ▼                      ▼
Authorization proofs,  ZK-gated deposit/    Human-defined rules
range proofs, budget   withdraw, paper +    for what to reveal
compliance proofs      live modes           and to whom
```

## ZK Circuits

| Circuit | What It Proves | What It Hides | Constraints |
|---|---|---|---|
| **Authorization** | Agent is delegated by owner | Owner identity, spend limits, validity | ~8,000 |
| **Budget Range** | Amount ≤ budget | The budget, the amount | ~436 |
| **Cumulative Spend** | Total spend ≤ period limit | The limit, running total, history | ~849 |

Built with **Circom 2.2.3** + **snarkjs 0.7.6** (Groth16). Battle-tested stack used by Polygon ID, Semaphore, and Iden3.

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

# Run tests (49 tests)
pytest
```

## CLI Commands

```bash
# Generate owner keys (Baby JubJub EdDSA)
python -m src.main keygen

# Create signed delegation
python -m src.main delegate --owner-key <hex> --spend-limit 5000

# Generate budget range proof
python -m src.main prove-budget --amount 2000 --budget 5000

# Generate authorization proof
python -m src.main prove-auth --owner-key <hex> --agent-id 1

# Execute private action (paper mode)
python -m src.main execute --owner-key <hex> --amount 2000 --protocol aave-v3

# Selective disclosure
python -m src.main disclose --owner-key <hex> --level auditor

# Agent status
python -m src.main status
```

## On-Chain Artifacts

- **PolicyCommitment.sol** — Stores hashed spending policies on-chain (nothing revealed)
- **BudgetRangeVerifier.sol** — Groth16 verifier for budget proofs (exported by snarkjs)
- **AuthorizationVerifier.sol** — Groth16 verifier for authorization proofs
- **CumulativeSpendVerifier.sol** — Groth16 verifier for cumulative spend proofs

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

Each disclosure generates a purpose-specific ZK proof — the auditor gets a proof that total spend is within limits without seeing individual transactions.

## Why This Is NOT a Mixer

| | Tornado Cash | This Project |
|---|---|---|
| **Mixing** | Core feature | None — single user, own funds |
| **P2P** | Shared pool | No P2P — agent's own wallet |
| **Compliance** | None | Selective disclosure built-in |
| **Fund commingling** | Yes | No |

## Tech Stack

- **Python 3.13** — agent logic
- **Circom 2.2.3** — ZK circuit development
- **snarkjs 0.7.6** — Groth16 proof generation/verification
- **Baby JubJub EdDSA** — key management (@zk-kit/eddsa-poseidon)
- **Poseidon hash** — ZK-friendly hashing (poseidon-lite)
- **Solidity 0.8.28** — on-chain verifier contracts (Foundry)
- **SQLite** — local state, audit trail
- **Base chain** — deployment target (cheapest gas, largest Morpho liquidity)

## Project Structure

```
├── circuits/              # Circom ZK circuits (3)
├── contracts/             # Solidity contracts (PolicyCommitment + verifiers)
├── scripts/               # Compile, setup, keygen, signing helpers
├── src/
│   ├── zk/               # Proof engine, keys, commitment scheme
│   ├── privacy/           # Policy manager, executor, disclosure controller
│   ├── chain/             # Contract deployment, on-chain verification
│   ├── main.py            # CLI (7 commands + demo)
│   └── database.py        # SQLite persistence
└── tests/                 # 49 tests
```

## Declarations

| Field | Value |
|---|---|
| **Primary AI model** | `claude-opus-4-6` |
| **Agent harness** | `claude-code` |
| **Track** | Track 2: "Agents that keep secrets" |
| **Conversation log** | See main repo `docs/hackathon/CONVERSATION-LOG.md` |

## License

MIT
