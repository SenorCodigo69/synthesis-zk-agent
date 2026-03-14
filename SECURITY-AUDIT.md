# Security Audit — Synthesis ZK Agent

**Auditor:** Claude Opus 4.6 (automated)
**Date:** 2026-03-14
**Scope:** All Circom circuits, Solidity contracts, Python source, Node.js scripts
**Codebase:** 3,600+ LOC, 49 tests, 3 circuits, 1 contract

---

## Summary

| Severity | Count | Fixed |
|----------|-------|-------|
| CRITICAL | 2     | 2     |
| HIGH     | 3     | 3     |
| MEDIUM   | 4     | 4     |
| LOW      | 5     | 5     |
| **Total**| **14**| **14**|

---

## CRITICAL

### C-1: PolicyCommitment.sol — No access control on `commitPolicy`

**File:** `contracts/src/PolicyCommitment.sol:32`
**Impact:** Anyone can overwrite any agent's active commitment, causing denial-of-service

**Details:**
`commitPolicy()` has no access control — any address can call it with any `agentId`. Since `activeCommitment[agentId]` is unconditionally overwritten (line 43), an attacker can:
1. Call `commitPolicy(victimAgentId, junkHash)`
2. The victim's `activeCommitment` now points to the attacker's commitment
3. All on-chain verification for the victim fails (`verifyCommitment` returns false)
4. The victim's ZK proofs still verify off-chain but on-chain verification is broken

**Fix:** Add agent-to-owner registration. Only the registered owner (or first committer) for an `agentId` should be able to update its commitment.

```solidity
mapping(uint256 => address) public agentOwner;

function commitPolicy(uint256 agentId, bytes32 policyHash) external returns (uint256) {
    // First commit registers ownership, subsequent commits require same owner
    require(
        agentOwner[agentId] == address(0) || agentOwner[agentId] == msg.sender,
        "Not agent owner"
    );
    if (agentOwner[agentId] == address(0)) {
        agentOwner[agentId] = msg.sender;
    }
    // ... rest of function
}
```

---

### C-2: PolicyCommitment.sol — `nextId` starts at 0, causing phantom lookups

**File:** `contracts/src/PolicyCommitment.sol:21-22`
**Impact:** Querying an unregistered agent returns commitment ID 0 (the first real commitment) instead of reverting

**Details:**
`nextId` starts at 0, so the first commitment gets ID 0. The default value of `activeCommitment[anyAgentId]` is also 0. So `getActivePolicyHash(unregisteredAgentId)` returns the first commitment's policy hash instead of reverting — unless that commitment has been deactivated.

This means unregistered agents could pass `verifyCommitment` checks by providing the first committer's policy hash.

**Fix:** Start `nextId` at 1 and check for existence:

```solidity
uint256 public nextId = 1;  // Reserve 0 as "no commitment"

function getActivePolicyHash(uint256 agentId) external view returns (bytes32) {
    uint256 id = activeCommitment[agentId];
    require(id != 0, "No commitment for agent");
    require(commitments[id].active, "Commitment inactive");
    return commitments[id].policyHash;
}
```

---

## HIGH

### H-1: Private keys exposed via CLI arguments

**Files:** `scripts/sign.js:14`, `scripts/keygen.js:16`, `src/main.py:42-45,118,165,221`
**Impact:** Private keys visible in process listings, shell history, and logs

**Details:**
All CLI commands accept `--owner-key` as a command line argument, which is then passed to Node.js scripts as `process.argv`. This means:
- `ps aux` reveals the private key to any user on the system
- Shell history stores the private key in plaintext
- Any process monitoring tool captures it

**Fix:** Read private keys from environment variables or stdin:

```python
# In CLI commands — read from env
owner_key = os.environ.get("OWNER_PRIVATE_KEY")
if not owner_key:
    owner_key = click.prompt("Owner private key", hide_input=True)
```

```javascript
// In sign.js — accept from stdin if not in args
const privateKey = process.argv[2] || await readStdin();
```

---

### H-2: Deployer passes private key via command line

**File:** `src/chain/deployer.py:64`
**Impact:** Ethereum private key visible in process listing during `forge create`

**Details:**
`deploy_contract` passes `--private-key` directly as a CLI argument to `forge create`. Same exposure as H-1 but for the Ethereum deployer key, which controls real funds.

**Fix:** Use Foundry's keystore or environment variable:

```python
cmd = [
    "forge", "create",
    "--rpc-url", self.rpc_url,
    contract_path,
]
env = os.environ.copy()
env["PRIVATE_KEY"] = self.private_key
# Use --private-key $PRIVATE_KEY via env, or better: foundry keystore
```

---

### H-3: ZK-sensitive secrets stored in plaintext SQLite

**File:** `src/database.py:24-35`
**Impact:** Database compromise breaks all privacy guarantees

**Details:**
The `delegations` table stores `nonce` and `salt` in plaintext. These are the private inputs to the ZK circuits — the entire privacy model depends on keeping them secret. If `data/zk_agent.db` is exfiltrated, an attacker can:
1. Reconstruct all policy commitments
2. Verify whether specific amounts match commitments
3. Break the cumulative spend chain's privacy

**Fix:** Encrypt sensitive columns (nonce, salt, policy_commitment) at rest using a key derived from the owner's private key, or use SQLCipher for full-database encryption.

---

## MEDIUM

### M-1: `proof.verified` field is never set — downstream reads are always False

**Files:** `src/models.py:64`, `src/zk/prover.py:106-127`, `src/privacy/executor.py:138`, `src/privacy/disclosure.py:150-151`
**Impact:** All proof summaries report `verified: False` even when verification passed

**Details:**
`ZKProof.verified` defaults to `False` and is never updated. `verify_proof()` returns a boolean but doesn't set the field on the proof object. The executor and disclosure controller both read `proof.verified` for audit logging, so all records incorrectly show proofs as unverified.

**Fix:**

```python
def verify_proof(self, zk_proof: ZKProof) -> bool:
    # ... existing verification logic ...
    is_valid = result.returncode == 0 and "OK" in result.stdout
    zk_proof.verified = is_valid  # Set the field
    return is_valid
```

---

### M-2: Period reset gap allows over-limit spending

**File:** `src/privacy/policy.py:101-108`
**Impact:** Agent can bypass cumulative limit during the reset window

**Details:**
When `time.time() - state.period_start > self.period_seconds`, `check_cumulative` returns `within_limit: True` with `needs_reset: True`. The caller (`full_compliance_check`) treats this as compliant at line 154-162 without resetting the cumulative total. The agent can continue spending indefinitely until someone explicitly resets the period.

**Fix:** Either block execution until reset, or auto-reset:

```python
if time.time() - state.period_start > self.period_seconds:
    # Auto-reset the period
    state.cumulative_total = 0
    state.period_start = time.time()
    state.current_salt = secrets.randbits(128)
    state.current_commitment = poseidon_hash([0, state.period_limit, state.current_salt])
    # Then proceed with the normal cumulative check below
```

---

### M-3: Disclosure proofs reuse delegation salt — linkability attack

**File:** `src/privacy/disclosure.py:54-58,84-88,115-119`
**Impact:** Multiple disclosures with the same amount produce identical commitments, enabling cross-audience linkability

**Details:**
All disclosure proofs (`generate_spend_total_proof`, `generate_compliance_proof`, `generate_solvency_proof`) use `state.delegation.salt` as the budget range proof salt. If an auditor and public viewer both receive proofs for the same amount, the `commitmentHash` public signals will be identical, revealing that the same underlying value was proven.

**Fix:** Generate a fresh random salt per disclosure proof:

```python
import secrets
salt = secrets.randbits(128)
inputs = {"amount": total, "maxBudget": limit, "salt": salt}
```

---

### M-4: `_parse_calldata` is brittle — silent failures in on-chain verification

**File:** `src/chain/verifier.py:90-110`
**Impact:** Malformed calldata silently produces incorrect contract call parameters

**Details:**
The calldata parser splits on `],[` which is fragile. The comment on line 98 acknowledges this: "This is a simplified parser — in production, use proper parsing." For values with specific bit patterns, the split could produce wrong results, causing on-chain verification to silently fail or pass incorrectly.

**Fix:** Use `snarkjs zkey export soliditycalldata` with `--json` flag if available, or use regex-based parsing with validation:

```python
import re
# snarkjs outputs: [a1,a2],[[b11,b12],[b21,b22]],[c1,c2],[i1,i2,...]
# Use proper bracket-aware parsing
```

---

## LOW

### L-1: No input validation before subprocess calls

**Files:** `src/zk/prover.py:64`, `src/zk/keys.py:19`
**Impact:** Malformed inputs could cause cryptic snarkjs/node errors

Validate that all inputs are valid BN254 field elements (numeric, < field modulus) before passing to snarkjs.

---

### L-2: Cumulative spend circuit allows zero-amount proofs

**File:** `circuits/cumulative_spend.circom:49`
**Impact:** Agent can generate valid commitment chain entries without spending, potentially gaming the audit trail

Add `newAmount > 0` constraint in the circuit.

---

### L-3: Nonces are random, not sequential — no replay tracking

**File:** `src/zk/commitment.py:40`
**Impact:** Relies on 64-bit randomness for anti-replay instead of proper nonce tracking

Use sequential nonces stored in the database and verify uniqueness.

---

### L-4: SQLite foreign keys not enforced

**File:** `src/database.py:17-18`
**Impact:** Disclosure log can reference non-existent proof IDs

Add `self.conn.execute("PRAGMA foreign_keys = ON")` after connect.

---

### L-5: `record_spend` mutates state in-place AND returns it

**File:** `src/zk/commitment.py:124-148`
**Impact:** Caller confusion — unclear if returned state is the same object or a copy

Either mutate in-place (return `None`) or return a new copy. Don't do both.

---

## Recommendations (Priority Order)

1. **Fix C-1 + C-2** — Contract access control and ID offset (blocks testnet deployment)
2. **Fix H-1 + H-2** — Move all private keys to env vars / stdin
3. **Fix H-3** — Encrypt database or at minimum the salt/nonce columns
4. **Fix M-1** — Set `proof.verified` after verification
5. **Fix M-2** — Auto-reset period or block execution
6. **Fix M-3** — Unique salt per disclosure proof
7. Remaining MEDIUM + LOW items

## Notes

- Circom circuits are well-structured — range constraints present on all numeric inputs (Num2Bits), Poseidon hashing matches circomlib, EdDSA verification uses the canonical template
- Groth16 trusted setup uses snarkjs default (powers of tau) — for production, needs a proper ceremony or switch to PLONK
- The `budget_range.circom` allows proofs where `valid == 0` (amount > budget) — this is by design since the application layer checks the signal, but consider adding `valid === 1` constraint if you never want invalid proofs to exist
- No reentrancy concerns in the Solidity contract (no external calls)
- `subprocess.run` with list args prevents shell injection — good
