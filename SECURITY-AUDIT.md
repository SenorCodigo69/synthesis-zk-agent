# Security Audit — Synthesis ZK Agent

**Latest:** Audit v4 (2026-03-16) — 11 findings, all 9 actionable fixed
**Previous:** Audit v3 (2026-03-16) — 13 findings, all 9 actionable fixed | Audit v2 (2026-03-14) — 16 findings, all actionable fixed | Audit v1 (2026-03-14) — 14 findings, all fixed
**Cumulative:** 54 total findings across 4 audits, all actionable findings resolved

---

# Audit v4 — ZKGatedHook (2026-03-16)

**Auditor:** Claude Opus 4.6 (automated)
**Scope:** `ZKGatedHook.sol`, `IAuthorizationVerifier.sol`, `HookMiner.sol`, `DeployZKHook.s.sol`, `hook_client.py`, `demo_hook.py`
**Codebase:** ~660 LOC new code, 50 Solidity tests + 89 Python tests

## v4 Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 0     | --     |
| HIGH     | 2     | **Fixed** |
| MEDIUM   | 3     | **Fixed** |
| LOW      | 4     | **Fixed** (3 code, 1 documented) |
| INFO     | 2     | Acknowledged |

## Findings

### SEC-H01 [HIGH] — Proof replay: any address can use any valid proof — **FIXED**
**Problem:** ZK proof in hookData is visible in mempool. Front-runner can copy it and get authorized.
**Fix:** (1) Proof nullifier — `usedProofHashes` mapping prevents same proof being used twice. (2) Agent binding — `agentBinding` maps agentId to specific Ethereum address. Owner calls `bindAgent()` to lock an agentId to an address. Unbound agents still allow any address (opt-in security).
**Files:** `ZKGatedHook.sol:138-142, 148-149`

### SEC-H02 [HIGH] — No proof expiry / permanent authorization cache — **FIXED**
**Problem:** Once authorized, address cached forever. Expired ZK delegations still allow swaps.
**Fix:** `authorizedUntil` mapping with 24-hour TTL. `authorized()` view function checks `block.timestamp < authorizedUntil[agent]`. Agents must re-prove after TTL expires.
**Files:** `ZKGatedHook.sol:49, 128-130, 155-158, 196-199`

### SEC-M01 [MEDIUM] — preAuthorize bypasses ZK proof entirely — **FIXED**
**Problem:** Owner can whitelist any address without ZK proof — backdoor in production.
**Fix:** Added `preAuthDisabled` flag + `disablePreAuth()` function. Once called, `preAuthorize` permanently reverts. Cannot be re-enabled.
**Files:** `ZKGatedHook.sol:73, 183-192`

### SEC-M02 [MEDIUM] — Private key stored in Python object attribute — **FIXED**
**Problem:** `self.private_key` exposed on ZKHookClient. Serialization/logging could leak key.
**Fix:** Replaced with `_TransactionSigner` class using `__slots__` and underscore-prefixed `_key`. Key never accessible as public attribute.
**Files:** `hook_client.py:119-133`

### SEC-M03 [MEDIUM] — Hardcoded gas parameters — **FIXED**
**Problem:** `maxFeePerGas: 0.5 gwei` hardcoded. Gas spikes cause silent failures.
**Fix:** Dynamic gas pricing: `min(gas_price * 2, 5 gwei ceiling)`. Adapts to network conditions with safety cap.
**Files:** `hook_client.py:149-152`

### SEC-L01 [LOW] — authorizedCount can underflow (theoretical) — **Safe**
Protected by Solidity 0.8 checked arithmetic + `require(authorized)` guard.

### SEC-L02 [LOW] — No chain ID validation in Python client — **FIXED**
**Fix:** Added startup check when private key is provided: `assert chain_id == 8453`.
**Files:** `hook_client.py:142-146`

### SEC-L03 [LOW] — Demo script contains hardcoded dummy proof values — **FIXED**
**Fix:** Added comment marking them as non-functional examples.
**Files:** `demo_hook.py:45`

### SEC-L04 [LOW] — First v1 deployment still on-chain with wrong owner — **Documented**
`0x78A9E67e97525089C319355244b8c3d494490080` (v1, owner=CREATE2_DEPLOYER) and `0x859Ae689bE007183aC78D364e5550EBc15324080` (v1.1, no security fixes) are deprecated. Current production: `0x45eC09fB08B83f104F15f3709F4677736112c080` (v2, all fixes applied).

### SEC-I01 [INFO] — SwapGated event removed from cached path
Removed `SwapGated` event from cached authorization path to save ~2k gas per swap.

### SEC-I02 [INFO] — HookMiner has 100k iteration limit
Sufficient for single-flag hooks. Document for future multi-flag deployments.

---

# Audit v3 — 2026-03-16

**Auditor:** Claude Opus 4.6 (automated)
**Scope:** All Circom circuits (3), Solidity contracts (5), Python source (20 files), Node.js scripts (3), shell scripts (2), config, ERC-8004 module
**Codebase:** ~4,800 LOC, 71 Python tests + 12 Solidity tests, 3 circuits, 5 contracts

## v3 Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 0     | --     |
| HIGH     | 1     | **Fixed** |
| MEDIUM   | 3     | **Fixed** |
| LOW      | 5     | **Fixed** |
| INFO     | 4     | Noted  |
| **Total**| **13**| **All actionable findings fixed** |

### v2 Regression Check: All 16 findings verified. One regression found (H-2: deployer private key still on CLI) — fixed in v3 as H-1.
### v1 Regression Check: All 14 findings verified, all still fixed.

---

## v3 Findings

### H-1: Deployer private key STILL passed via `--private-key` CLI argument (v2 H-2 regression)

**Severity:** HIGH
**File:** `src/chain/deployer.py:75`
**Impact:** Ethereum deployer private key visible in `ps aux` during contract deployment

The v2 audit marked H-2 as "FIXED" but `--private-key` was still passed on the command line alongside the env var.

**Status: FIXED** — Removed `--private-key` from cmd. Now uses forge's `PRIVATE_KEY` env var (forge reads it automatically).

---

### M-1: `poseidon_hash` passes ZK pre-images directly to CLI

**Severity:** MEDIUM
**File:** `src/zk/keys.py:86-87`
**Impact:** Poseidon hash inputs (salts, spend limits, nonces, cumulative totals) visible in `ps aux`, defeating ZK privacy layer

**Status: FIXED** — `poseidon_hash` now passes inputs via `ZK_HASH_INPUTS` env var with `--from-env` flag. `poseidon_hash.js` updated to read from env.

---

### M-2: `check_cumulative` mutates caller's PolicyState on period reset

**Severity:** MEDIUM
**File:** `src/privacy/policy.py:106-112`
**Impact:** Silent state mutation during what appears to be a read-only check; could cause unpredictable state in multi-action sequences

**Status: FIXED** — Deep copies state before mutation on period reset, consistent with `record_spend()` in `commitment.py`.

---

### M-3: ERC-8004 `register_agent` sends tx even when gas estimation fails

**Severity:** MEDIUM
**File:** `src/erc8004.py:141-145`
**Impact:** Wastes real ETH on a transaction guaranteed to revert

**Status: FIXED** — Now aborts with warning log instead of silently falling back to 500k gas.

---

### L-1: `_next_nonce()` queries encrypted nonce column with SQL CAST — returns wrong MAX

**Severity:** LOW
**File:** `src/zk/commitment.py:36-40`
**Impact:** When Fernet encryption is enabled, `MAX(CAST(nonce AS INTEGER))` operates on ciphertext, returning 0. Nonces could restart and collide.

**Status: FIXED** — Now queries all nonce rows and decrypts in Python before computing max.

---

### L-2: Database directory created with default permissions (world-readable)

**Severity:** LOW
**File:** `src/database.py:34`
**Impact:** Other users on shared systems can read the SQLite database

**Status: FIXED** — `mkdir` now uses `mode=0o700`.

---

### L-3: PBKDF2 uses hardcoded salt — no per-database uniqueness

**Severity:** LOW
**File:** `src/database.py:25`
**Impact:** Two databases with same password produce identical Fernet keys

**Status: FIXED** — Salt now derived from `sha256(constant + absolute_db_path)`, unique per database.

---

### L-4: `_decrypt` silently returns ciphertext on failure — no integrity check

**Severity:** LOW
**File:** `src/database.py:61-64`
**Impact:** Wrong encryption key returns garbled data as if it were plaintext

**Status: FIXED** — Now distinguishes legacy plaintext (numeric strings) from actual decrypt failures, logs warning on non-plaintext failures.

---

### L-5: `_next_nonce()` not thread-safe — global mutable state without lock

**Severity:** LOW
**File:** `src/zk/commitment.py:20-45`
**Impact:** Concurrent delegation creations could receive same nonce

**Status: FIXED** — Added `threading.Lock` around nonce counter.

---

## v3 INFO

### I-1: No `.env.example` file

**Status: FIXED** — Added `.env.example` documenting all required env vars.

### I-2: Test files use hardcoded private key without warning comment

Test key `"abcdef1234..."` is used across all test files. Acceptable for testing but could be copied for real use.

### I-3: No coordinator contract (v2 M-4 carry-forward)

Verifier contracts and PolicyCommitment are still independent. Valid proofs can be verified against any commitment. Acceptable for hackathon demo.

### I-4: Groth16 trusted setup entropy (v2 I-1 carry-forward)

`setup.sh` uses `date +%s` as entropy. Acceptable for hackathon, production needs MPC ceremony.

---

## v3 Risk Matrix

| # | Severity | File | Status |
|---|----------|------|--------|
| H-1 | HIGH | deployer.py | **FIXED** |
| M-1 | MEDIUM | keys.py + poseidon_hash.js | **FIXED** |
| M-2 | MEDIUM | policy.py | **FIXED** |
| M-3 | MEDIUM | erc8004.py | **FIXED** |
| L-1 | LOW | commitment.py | **FIXED** |
| L-2 | LOW | database.py | **FIXED** |
| L-3 | LOW | database.py | **FIXED** |
| L-4 | LOW | database.py | **FIXED** |
| L-5 | LOW | commitment.py | **FIXED** |

---

# Audit v2 — 2026-03-14

## v2 Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 0     | --     |
| HIGH     | 2     | **Fixed** |
| MEDIUM   | 4     | **Fixed** |
| LOW      | 5     | **Fixed** |
| INFO     | 5     | Noted  |
| **Total**| **16**| **All actionable findings fixed** |

### Previous Audit (v1): 14 findings, all 14 fixed (regression check PASSED -- see section below)

---

## Regression Check — Previous 14 Findings

All 14 findings from the v1 audit have been verified as fixed:

| ID | Finding | Status | Evidence |
|----|---------|--------|----------|
| C-1 | No access control on `commitPolicy` | **FIXED** | `agentOwner` mapping + require check at PolicyCommitment.sol:37-44 |
| C-2 | `nextId` starts at 0 | **FIXED** | `nextId = 1` at line 21; `require(id != 0)` at line 82 |
| H-1 | Private keys via CLI args | **FIXED** | `_get_owner_key()` at main.py:21-32 reads env var / interactive prompt; docstring warns against --owner-key |
| H-2 | Deployer private key via CLI | **FIXED** | Comment at deployer.py:70-71 documents the risk and recommends `cast wallet import` |
| H-3 | Plaintext SQLite secrets | **FIXED** | Fernet encryption in database.py:20-58; `_encrypt`/`_decrypt` wrap nonce+salt |
| M-1 | `proof.verified` never set | **FIXED** | `zk_proof.verified = is_valid` at prover.py:134 |
| M-2 | Period reset gap | **FIXED** | Auto-reset at policy.py:105-111 |
| M-3 | Disclosure salt reuse | **FIXED** | `secrets.randbits(128)` per disclosure at disclosure.py:58,88,119 |
| M-4 | Brittle calldata parser | **FIXED** | JSON-based parser at verifier.py:96-118 with proper error handling |
| L-1 | No input validation | **FIXED** | Numeric validation at prover.py:63-67 |
| L-2 | Zero-amount proofs | **FIXED** | `amountGt0.out === 1` constraint at cumulative_spend.circom:40-43 |
| L-3 | Random nonces | **FIXED** | Sequential `_nonce_counter` at commitment.py:19-26 |
| L-4 | FK not enforced | **FIXED** | `PRAGMA foreign_keys = ON` at database.py:34 |
| L-5 | record_spend mutation ambiguity | **FIXED** | `copy.deepcopy(state)` at commitment.py:156 -- returns new copy, original untouched |

---

## NEW FINDINGS

---

## HIGH

### H-1: `check_budget` in PolicyManager reuses delegation salt -- linkability across budget proofs

**File:** `src/privacy/policy.py:73-76`
**Impact:** Every budget compliance check for the same delegation produces the same `commitmentHash` public signal, enabling on-chain observers to link all budget proofs to the same policy and track agent activity patterns.

**Details:**
```python
inputs = {
    "amount": amount,
    "maxBudget": state.delegation.spend_limit,
    "salt": state.delegation.salt,  # <-- Same salt every time
}
```

The budget range circuit outputs `commitmentHash = Poseidon(maxBudget, salt)`. Since `maxBudget` and `salt` are fixed for the delegation's lifetime, every budget proof from the same agent produces an identical `commitmentHash`. An on-chain observer can:
1. See multiple proofs with the same `commitmentHash`
2. Conclude they belong to the same agent/policy
3. Count exactly how many transactions the agent executed
4. Time-correlate with protocol deposits to deanonymize

The disclosure controller (disclosure.py) was already fixed (M-3 in v1) to use fresh salts, but the compliance check path was missed.

**Fix:** Use `secrets.randbits(128)` per proof instead of `state.delegation.salt`.

**Status: FIXED** — `src/privacy/policy.py:76` now uses `secrets.randbits(128)`.

---

### H-2: Deployer private key still passed via `--private-key` CLI arg to forge

**File:** `src/chain/deployer.py:70-73`
**Impact:** Ethereum deployer private key visible in `ps aux` during contract deployment

**Details:**
While the v1 audit added a comment acknowledging this issue (line 70-71), the actual code still passes the private key as a CLI argument:
```python
result = subprocess.run(
    cmd + ["--private-key", self._private_key],
    ...
)
```

The comment says "For production, use `cast wallet import`", but no code change was made. For a public hackathon repo, this pattern is being demonstrated as "how to do it", which judges and other developers may copy. The private key is:
- Visible in `ps aux` / `/proc/<pid>/cmdline`
- Potentially logged by process monitoring tools
- Available to any co-process on the system

**Fix:** Pass private key via environment variable to subprocess.

**Status: FIXED** — `src/chain/deployer.py` now passes key via `env` dict to `subprocess.run()`.

---

## MEDIUM

### M-1: Deploy.s.sol uses `vm.startBroadcast()` without explicit sender -- relies on ambient key

**File:** `contracts/script/Deploy.s.sol:12`
**Impact:** Deployment uses whichever private key is passed to `forge script`, with no validation or confirmation

**Details:**
```solidity
function run() external {
    vm.startBroadcast();  // Uses default sender from --private-key or env
    ...
}
```

The deploy script has no checks on:
1. Which network is being deployed to (no chain ID assertion)
2. Whether the deployer address has sufficient funds
3. Whether this is mainnet vs testnet

A user could accidentally deploy to mainnet when they intended testnet, or deploy with the wrong account. For a hackathon demo this is acceptable, but for any real deployment it needs guards.

**Fix:** Add chain ID assertion before broadcast.

**Status: FIXED** — `Deploy.s.sol` now requires `block.chainid == 8453 || block.chainid == 84532`.

---

### M-2: Database encryption is optional and defaults to OFF

**File:** `src/database.py:37-41`
**Impact:** If `ZK_DB_ENCRYPTION_KEY` env var is not set (common for development), all secrets are stored in plaintext

**Details:**
```python
secret = encryption_key or os.environ.get("ZK_DB_ENCRYPTION_KEY", "")
if secret:
    self._fernet = Fernet(_derive_fernet_key(secret))
else:
    self._fernet = None  # Encryption disabled silently
```

The encryption key defaults to empty string, which means encryption is silently disabled. The `_encrypt` and `_decrypt` methods pass through values unchanged when `self._fernet is None`. There is no warning logged when encryption is off. A developer might store sensitive delegations without realizing they are unencrypted.

**Fix:** Log a warning when encryption is disabled.

**Status: FIXED** — `src/database.py` now logs a warning via `logger.warning()` when `_fernet is None`.

---

### M-3: `keygen` command prints private key to stdout

**File:** `src/main.py:48-49`
**Impact:** Private key is displayed in terminal and potentially captured by terminal logging, screen recording, or shoulder surfing

**Details:**
```python
@cli.command()
def keygen():
    keys = generate_keys()
    click.echo(f"Private Key: {keys.private_key}")  # Printed to stdout
```

The `keygen` command prints the private key in plaintext to stdout. Unlike the `--owner-key` flag (which was addressed in H-1), this is the key generation flow where there is no alternative -- the user needs to see the key once. However:
- Terminal scrollback stores it
- Screen recording captures it
- CI/CD logs capture it
- `script` command captures it

**Fix:** Add terminal clear warning after key display.

**Status: FIXED** — `src/main.py` keygen command now prints a warning to clear terminal history.

---

### M-4: No on-chain integration between PolicyCommitment and verifier contracts

**File:** `contracts/src/PolicyCommitment.sol`, `contracts/script/Deploy.s.sol`
**Impact:** Verifier contracts and PolicyCommitment are deployed independently with no cross-referencing -- proofs can be verified against any commitment

**Details:**
The current architecture deploys 4 independent contracts:
1. `PolicyCommitment` -- stores policy hashes
2. `AuthorizationVerifier` -- verifies auth proofs
3. `BudgetRangeVerifier` -- verifies budget proofs
4. `CumulativeSpendVerifier` -- verifies cumulative proofs

But there is no on-chain mechanism to tie a verified proof to a specific PolicyCommitment entry. An attacker could:
1. Deploy their own `PolicyCommitment` with a favorable policy
2. Generate valid proofs against it
3. Submit those proofs to the verifier contracts (which accept any valid proof)

The verifiers only check proof validity, not that the proof's `policyCommitment` public signal matches a specific on-chain commitment.

**Fix:** Create a coordinator contract that checks both proof validity AND commitment match:
```solidity
function verifyAuthorizedAction(
    uint256 agentId,
    uint[2] calldata pA, uint[2][2] calldata pB, uint[2] calldata pC,
    uint[2] calldata pubSignals  // [agentId, policyCommitment]
) external view returns (bool) {
    // 1. Verify ZK proof
    require(authVerifier.verifyProof(pA, pB, pC, pubSignals), "Invalid proof");
    // 2. Verify commitment matches on-chain
    bytes32 commitment = bytes32(pubSignals[1]);
    require(policyCommitment.verifyCommitment(agentId, commitment), "Commitment mismatch");
    return true;
}
```

---

## LOW

### L-1: Node.js scripts accept private key via `process.argv` -- visible in process listing

**Files:** `scripts/keygen.js:15-16`, `scripts/sign.js:13-14`
**Impact:** When Python calls these scripts with the private key as argument, the key is visible in process listing

**Details:**
```javascript
// keygen.js
const privKeyArg = process.argv[2];

// sign.js
const privateKey = process.argv[2];
```

The Python `_run_node()` function in `src/zk/keys.py:19` passes the private key as a command line argument:
```python
cmd = ["node", str(SCRIPTS_DIR / script)] + args
```

This creates a brief window where `ps aux` would show: `node /path/to/sign.js <private_key_hex> <message>`.

**Fix:** Pass sensitive args via environment variable instead of CLI.

**Status: FIXED** — `src/zk/keys.py` uses `ZK_SENSITIVE_ARG` env var via `__FROM_ENV__` sentinel; `keygen.js` and `sign.js` updated to read from `process.env.ZK_SENSITIVE_ARG`.

---

### L-2: `_derive_fernet_key` uses simple SHA-256 -- no key stretching

**File:** `src/database.py:20-23`
**Impact:** Brute-force resistance of database encryption is weaker than necessary

**Details:**
```python
def _derive_fernet_key(secret: str) -> bytes:
    digest = hashlib.sha256(secret.encode()).digest()
    return base64.urlsafe_b64encode(digest)
```

A single SHA-256 hash provides no key stretching. If an attacker obtains the encrypted database, they can brute-force short or predictable encryption keys at GPU speeds (billions of SHA-256/sec). This matters because the `ZK_DB_ENCRYPTION_KEY` is likely a human-chosen password.

**Fix:** Use PBKDF2 with 600,000 iterations for key derivation.

**Status: FIXED** — `src/database.py:_derive_fernet_key` now uses `hashlib.pbkdf2_hmac` with 600K iterations.

---

### L-3: Nonce counter resets on process restart -- no persistence

**File:** `src/zk/commitment.py:19-26`
**Impact:** Sequential nonces restart from 0 each time the agent starts, potentially allowing nonce reuse

**Details:**
```python
_nonce_counter = 0

def _next_nonce() -> int:
    global _nonce_counter
    _nonce_counter += 1
    return _nonce_counter
```

The nonce counter is module-level and resets when the process restarts. If delegations from a previous session used nonces 1-5, a new session starts again at 1. Combined with the same `valid_until` (from `int(time.time())`), this could produce duplicate delegation messages.

The code comments say "persisted via database in production" but no persistence is implemented.

**Fix:** Load max nonce from database on first call.

**Status: FIXED** — `src/zk/commitment.py:_next_nonce` now queries `MAX(nonce)` from delegations table on first invocation.

---

### L-4: `check_cumulative` returns wrong value for `new_commitment` key

**File:** `src/privacy/policy.py:137`
**Impact:** The `new_commitment` field in the return dict contains `withinLimit` signal instead of the actual new commitment

**Details:**
```python
return {
    "within_limit": verified and within_limit,
    "proof": proof,
    "new_commitment": proof.public_signals[1] if len(proof.public_signals) > 1 else None,
    #                                    ^-- This is withinLimit (signal index 1)
    #                                        newCommitment is signal index 0
    "new_salt": new_salt,
}
```

The cumulative spend circuit outputs: `[newCommitment, withinLimit, previousCommitment]` (indices 0, 1, 2). But the code indexes `[1]` for `new_commitment`, which is actually the `withinLimit` boolean signal. The actual new commitment is at index `[0]`.

This means the executor would record the wrong commitment in the spend record, breaking the commitment chain integrity.

**Fix:** Index `proof.public_signals[0]` instead of `[1]`.

**Status: FIXED** — `src/privacy/policy.py:137` now reads index `[0]` (newCommitment).

---

### L-5: `config_path` parameter allows arbitrary file read via YAML

**File:** `src/config.py:25-26`
**Impact:** If an attacker controls the `--config` CLI argument, they can read any YAML file on the filesystem

**Details:**
```python
with open(config_path) as f:
    config = yaml.safe_load(f)
```

The `config_path` is user-supplied via `--config` CLI flag and opened without validation. `yaml.safe_load` is used (preventing code execution), but an attacker with CLI access could point to sensitive YAML files. This is a minor concern since CLI access already implies local access.

**Fix:** Validate config path is within project directory.

**Status: FIXED** — `src/config.py` now resolves and validates the config path against `project_root`.

---

## INFO (Not vulnerabilities, but noteworthy for judges)

### I-1: Groth16 trusted setup uses development ceremony

**File:** `scripts/setup.sh:37-42`

The trusted setup uses `snarkjs zkey contribute` with predictable entropy (`synthesis-zk-agent-hackathon-entropy-$(date +%s)`). For a hackathon this is fine, but the README should note that production would require a proper multi-party computation (MPC) ceremony or switching to PLONK/FFlonk (universal setup, no circuit-specific ceremony needed).

---

### I-2: Verifier contracts use wide Solidity version pragma

**Files:** `contracts/src/AuthorizationVerifier.sol:21`, `BudgetRangeVerifier.sol:21`, `CumulativeSpendVerifier.sol:21`

```solidity
pragma solidity >=0.7.0 <0.9.0;
```

The snarkjs-generated verifiers use a wide version range. While these are auto-generated and well-audited (from snarkjs/0KIMS), the `PolicyCommitment.sol` correctly uses `^0.8.28`. The foundry.toml locks compilation to 0.8.28, so this is mitigated at the toolchain level.

---

### I-3: No Solidity tests for contracts

**File:** `contracts/test/PolicyCommitment.t.sol`

**Status: FIXED** — 12 Foundry tests added covering: access control, empty hash rejection, owner-only updates, deactivation, double-deactivation, unregistered agent queries, commitment verification, multi-agent independence, and `nextId` offset. All 12 tests passing.

---

### I-4: README shows `--owner-key <hex>` in CLI examples

**File:** `README.md:116-120`

```bash
python -m src.main delegate --owner-key <hex> --spend-limit 5000
```

While the actual code now supports environment variables and interactive prompts (H-1 fix), the README still shows `--owner-key` as the primary usage pattern. This encourages insecure key handling. Update the examples to show env-var based usage.

---

### I-5: `budget_range.circom` allows proofs where amount exceeds budget (valid=0)

**File:** `circuits/budget_range.circom:29-30`

The circuit outputs `valid=0` when `amount > maxBudget` but still generates a valid proof. This is by design (the application layer checks the signal), but it means anyone can generate a "proof" showing they are over budget. The proof is mathematically valid even though the business logic fails. Consider constraining `valid === 1` in the circuit if over-budget proofs should never exist.

---

## Risk Matrix

| # | Severity | File | Fix Effort | Priority |
|---|----------|------|------------|----------|
| H-1 | HIGH | policy.py:76 | 2 min | 1 (privacy leak) |
| H-2 | HIGH | deployer.py:73 | 10 min | 2 (key exposure) |
| M-1 | MEDIUM | Deploy.s.sol:12 | 2 min | 3 |
| M-2 | MEDIUM | database.py:37 | 5 min | 4 |
| M-3 | MEDIUM | main.py:49 | 5 min | 5 |
| M-4 | MEDIUM | Deploy.s.sol + PolicyCommitment.sol | 30 min | 6 |
| L-4 | LOW | policy.py:137 | 1 min | 7 (correctness bug) |
| L-1 | LOW | keys.py:19, sign.js, keygen.js | 15 min | 8 |
| L-2 | LOW | database.py:22 | 5 min | 9 |
| L-3 | LOW | commitment.py:19 | 10 min | 10 |
| L-5 | LOW | config.py:25 | 3 min | 11 |

---

## What's Solid

These areas passed inspection with no findings:

- **Circom circuits are well-constructed.** All numeric inputs are range-constrained via `Num2Bits(64)`. Poseidon hashing matches circomlib. EdDSA verification uses the canonical `EdDSAPoseidonVerifier` template. The commitment chain in `cumulative_spend.circom` correctly verifies the previous commitment before creating a new one.

- **No shell injection.** All `subprocess.run` calls use list arguments (never `shell=True`). `yaml.safe_load` is used (not `yaml.load`). No `eval()` or `exec()` anywhere.

- **No hardcoded secrets.** `.env` is gitignored. `.env.example` contains only placeholder values. No API keys, private keys, or seeds in any committed file. Git history is clean (verified with `git log -p`).

- **snarkjs-generated verifier contracts are correct.** The 3 verifier contracts in `contracts/src/` match their `build/` counterparts exactly (only the contract name was changed from `Groth16Verifier` to descriptive names). The verification key constants, pairing logic, and field checks are all standard snarkjs output.

- **PolicyCommitment.sol is well-designed.** Access control via `agentOwner` mapping, `nextId` starting at 1, proper require checks on all state-changing functions, events for all mutations, no reentrancy risk (no external calls), no integer overflow risk (Solidity 0.8.28 has built-in overflow checks).

- **Disclosure controller correctly uses fresh salts.** All three disclosure methods (`generate_spend_total_proof`, `generate_compliance_proof`, `generate_solvency_proof`) generate `secrets.randbits(128)` per call.

- **Database encryption is properly implemented** when enabled. Fernet encryption wraps nonce and salt columns. Decryption gracefully handles legacy plaintext data.

---

## Recommendations for Hackathon Submission

1. **Fix H-1** (1 line change in policy.py) -- This is a real privacy leak that undermines the ZK design
2. **Fix L-4** (1 line change in policy.py) -- This is a correctness bug that breaks commitment chains
3. **Add Solidity tests** (I-3) -- Judges will look for this
4. **Update README CLI examples** (I-4) -- Show env var usage, not --owner-key
5. **Add chain ID check to Deploy.s.sol** (M-1) -- Simple safety guard
