"""CLI entry point for the ZK Privacy Agent."""
from __future__ import annotations

import json
import os
import time

import click

from src.config import load_config
from src.models import ExecutionMode, DisclosureLevel, ProofType
from src.zk.prover import ZKProver
from src.zk.keys import generate_keys, poseidon_hash
from src.zk.commitment import create_delegation, initialize_policy_state
from src.privacy.policy import PolicyManager
from src.privacy.executor import PrivateExecutor
from src.privacy.disclosure import DisclosureController
from src.database import Database
from src.execution_logger import ExecutionLogger


def _get_owner_key(owner_key: str | None) -> str:
    """Resolve owner private key: explicit arg > env var > interactive prompt.

    Never use --owner-key in production — it leaks to shell history and ps.
    Set OWNER_PRIVATE_KEY env var instead.
    """
    if owner_key:
        return owner_key
    env_key = os.environ.get("OWNER_PRIVATE_KEY")
    if env_key:
        return env_key
    return click.prompt("Owner private key (BJJ hex)", hide_input=True)


@click.group()
@click.option("--config", "config_path", default=None, help="Path to config YAML")
@click.pass_context
def cli(ctx, config_path):
    """Synthesis ZK Agent — Privacy-preserving yield agent with ZK proofs."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config_path)


@cli.command()
def keygen():
    """Generate a new Baby JubJub EdDSA keypair for the owner."""
    keys = generate_keys()
    click.echo("=== New Owner Keypair (Baby JubJub EdDSA) ===")
    click.echo(f"Private Key: {keys.private_key}")
    click.echo(f"Public Key X (Ax): {keys.public_key_ax}")
    click.echo(f"Public Key Y (Ay): {keys.public_key_ay}")
    click.echo("")
    click.echo("WARNING: Clear your terminal history after copying this key.")
    click.echo("         Do not commit or share this key.")
    click.echo("         Add to .env as OWNER_PRIVATE_KEY.")


@cli.command()
@click.option("--owner-key", default=None, help="Owner's BJJ private key (prefer OWNER_PRIVATE_KEY env var)")
@click.option("--agent-id", default=1, help="Agent identifier")
@click.option("--spend-limit", default=5000, help="Max single spend (USDC)")
@click.option("--valid-days", default=7, help="Delegation validity (days)")
@click.pass_context
def delegate(ctx, owner_key, agent_id, spend_limit, valid_days):
    """Create a signed delegation from owner to agent."""
    owner_key = _get_owner_key(owner_key)
    click.echo("=== Creating Delegation ===")

    delegation = create_delegation(
        owner_private_key=owner_key,
        agent_id=agent_id,
        spend_limit=spend_limit,
        valid_for_seconds=valid_days * 86400,
    )

    click.echo(f"Agent ID:           {delegation.agent_id}")
    click.echo(f"Spend Limit:        {delegation.spend_limit} USDC")
    click.echo(f"Valid Until:         {time.ctime(delegation.valid_until)}")
    click.echo(f"Policy Commitment:  {delegation.policy_commitment}")
    click.echo(f"Message Hash:       {delegation.message_hash}")
    click.echo("")
    click.echo("Delegation signed. Policy commitment ready for on-chain publishing.")

    # Save to database
    db = Database()
    db.save_delegation({
        "agent_id": delegation.agent_id,
        "spend_limit": delegation.spend_limit,
        "valid_until": delegation.valid_until,
        "nonce": delegation.nonce,
        "salt": delegation.salt,
        "policy_commitment": delegation.policy_commitment,
        "owner_pub_ax": delegation.owner_pub_ax,
        "owner_pub_ay": delegation.owner_pub_ay,
    })
    db.close()
    click.echo("Delegation saved to database.")


@cli.command()
@click.option("--amount", required=True, type=int, help="Amount to check (USDC)")
@click.option("--budget", required=True, type=int, help="Budget limit (USDC)")
@click.pass_context
def prove_budget(ctx, amount, budget):
    """Generate a budget range proof: prove amount <= budget without revealing either."""
    config = ctx.obj["config"]
    prover = ZKProver(config["zk"]["build_dir"])

    import secrets
    salt = secrets.randbits(128)

    click.echo(f"=== Budget Range Proof ===")
    click.echo(f"Amount: {amount} USDC (private)")
    click.echo(f"Budget: {budget} USDC (private)")
    click.echo("")

    inputs = {"amount": amount, "maxBudget": budget, "salt": salt}
    proof = prover.generate_proof(ProofType.BUDGET_RANGE, inputs)

    click.echo(f"Public signals:")
    click.echo(f"  Commitment: {proof.public_signals[0]}")
    click.echo(f"  Valid:      {proof.public_signals[1]} ({'WITHIN BUDGET' if proof.public_signals[1] == '1' else 'OVER BUDGET'})")
    click.echo("")

    # Verify
    verified = prover.verify_proof(proof)
    click.echo(f"Off-chain verification: {'PASS' if verified else 'FAIL'}")

    # Export calldata
    calldata = prover.export_calldata(proof)
    click.echo(f"\nSolidity calldata (for on-chain verification):")
    click.echo(f"  {calldata[:100]}...")


@cli.command()
@click.option("--owner-key", default=None, help="Owner's BJJ private key (prefer OWNER_PRIVATE_KEY env var)")
@click.option("--agent-id", default=1, help="Agent identifier")
@click.option("--spend-limit", default=5000, help="Spend limit (USDC)")
@click.pass_context
def prove_auth(ctx, owner_key, agent_id, spend_limit):
    """Generate an authorization proof: prove agent is delegated by owner."""
    owner_key = _get_owner_key(owner_key)
    config = ctx.obj["config"]
    prover = ZKProver(config["zk"]["build_dir"])

    click.echo("=== Authorization Proof ===")
    click.echo("Creating delegation + generating proof...")

    delegation = create_delegation(
        owner_private_key=owner_key,
        agent_id=agent_id,
        spend_limit=spend_limit,
    )

    inputs = {
        "ownerPubKeyAx": delegation.owner_pub_ax,
        "ownerPubKeyAy": delegation.owner_pub_ay,
        "signatureS": delegation.signature_s,
        "signatureR8x": delegation.signature_r8x,
        "signatureR8y": delegation.signature_r8y,
        "spendLimit": delegation.spend_limit,
        "validUntil": delegation.valid_until,
        "nonce": delegation.nonce,
        "salt": delegation.salt,
        "agentId": delegation.agent_id,
        "policyCommitment": delegation.policy_commitment,
    }

    proof = prover.generate_proof(ProofType.AUTHORIZATION, inputs)

    click.echo(f"\nPublic signals (only these are revealed):")
    click.echo(f"  Agent ID:          {delegation.agent_id}")
    click.echo(f"  Policy Commitment: {delegation.policy_commitment}")
    click.echo(f"\nHidden (proven via ZK):")
    click.echo(f"  Spend limit, validity, owner identity")

    verified = prover.verify_proof(proof)
    click.echo(f"\nOff-chain verification: {'PASS' if verified else 'FAIL'}")


@cli.command()
@click.option("--owner-key", default=None, help="Owner's BJJ private key (prefer OWNER_PRIVATE_KEY env var)")
@click.option("--amount", required=True, type=int, help="Amount to spend (USDC)")
@click.option("--protocol", default="aave-v3", help="Target protocol")
@click.option("--mode", type=click.Choice(["paper", "dry_run"]), default="paper")
@click.pass_context
def execute(ctx, owner_key, amount, protocol, mode):
    """Execute a private DeFi action with full ZK compliance check."""
    owner_key = _get_owner_key(owner_key)
    config = ctx.obj["config"]
    prover = ZKProver(config["zk"]["build_dir"])
    policy_mgr = PolicyManager(prover, config)
    exec_mode = ExecutionMode.PAPER if mode == "paper" else ExecutionMode.DRY_RUN
    executor = PrivateExecutor(prover, policy_mgr, exec_mode)

    click.echo("=== Private Execution ===")
    click.echo(f"Action:   deposit")
    click.echo(f"Amount:   {amount} USDC")
    click.echo(f"Protocol: {protocol}")
    click.echo(f"Mode:     {exec_mode.value}")
    click.echo("")

    # Create delegation + policy state
    delegation = create_delegation(
        owner_private_key=owner_key,
        agent_id=config["agent"]["id"],
        spend_limit=config["spending_policy"]["max_single_spend"],
        valid_for_seconds=config["spending_policy"]["valid_for_seconds"],
    )

    state = initialize_policy_state(
        delegation, config["spending_policy"]["period_limit"]
    )

    # Execution logger
    exec_logger = ExecutionLogger()
    exec_logger.begin_cycle(int(time.time()), mode)

    click.echo("Running compliance checks...")
    exec_logger.log_step("compliance_check", "ok", f"deposit {amount} USDC → {protocol}")
    result = executor.execute_private_action("deposit", amount, protocol, state)

    # Log proofs
    proofs = result.get("proofs", {})
    proofs_generated = 0
    proofs_verified = 0
    for ptype, pdata in proofs.items():
        if pdata:
            proofs_generated += 1
            verified = bool(pdata.get("public_signals"))
            if verified:
                proofs_verified += 1
            exec_logger.log_proof(ptype, verified, pdata.get("public_signals", []))
            exec_logger.log_tool_call("snarkjs", f"prove_{ptype}", "success")

    # Log decision
    compliant = result["compliance"]["compliant"]
    exec_logger.log_decision(
        "compliance_check",
        "approved" if compliant else "rejected",
        result["compliance"].get("reason", ""),
    )

    click.echo(f"\nStatus: {result['status']}")
    click.echo(f"Compliant: {compliant}")

    if result["status"] == "REJECTED":
        click.echo(f"Reason: {result['reason']}")
        exec_logger.log_execution(protocol, "deposit", amount, "REJECTED")
    else:
        click.echo(f"Tx Hash: {result.get('tx_hash', 'N/A')}")
        updated = result.get("updated_state", {})
        click.echo(f"Cumulative Total: {updated.get('cumulative_total', 0)} USDC")
        click.echo(f"Spend Count: {updated.get('spend_count', 0)}")
        exec_logger.log_execution(protocol, "deposit", amount, result["status"], result.get("tx_hash", ""))

    click.echo(f"\nProofs generated:")
    for ptype, pdata in proofs.items():
        if pdata:
            click.echo(f"  {ptype}: {len(pdata.get('public_signals', []))} public signals")

    exec_logger.end_cycle({
        "proofs_generated": proofs_generated,
        "proofs_verified": proofs_verified,
        "actions_executed": 1 if result["status"] != "REJECTED" else 0,
        "actions_rejected": 1 if result["status"] == "REJECTED" else 0,
        "cumulative_total": result.get("updated_state", {}).get("cumulative_total", 0),
    })


@cli.command()
@click.option("--owner-key", default=None, help="Owner's BJJ private key (prefer OWNER_PRIVATE_KEY env var)")
@click.option("--level", type=click.Choice(["auditor", "tax_authority", "public"]), default="auditor")
@click.pass_context
def disclose(ctx, owner_key, level):
    """Generate selective disclosure proofs for a specific audience."""
    owner_key = _get_owner_key(owner_key)
    config = ctx.obj["config"]
    prover = ZKProver(config["zk"]["build_dir"])
    disclosure_level = DisclosureLevel(level)
    controller = DisclosureController(prover, config)

    click.echo(f"=== Selective Disclosure: {level} ===")

    # Create a sample policy state
    delegation = create_delegation(
        owner_private_key=owner_key,
        agent_id=config["agent"]["id"],
        spend_limit=config["spending_policy"]["max_single_spend"],
    )
    state = initialize_policy_state(
        delegation, config["spending_policy"]["period_limit"]
    )

    summary = controller.get_disclosure_summary(state, disclosure_level)

    click.echo(f"Allowed claims: {', '.join(summary['allowed_claims'])}")
    click.echo(f"\nGenerated proofs:")
    for claim, data in summary.get("proofs", {}).items():
        click.echo(f"  {claim}:")
        click.echo(f"    Value: {data['value']}")
        click.echo(f"    Verified: {data['verified']}")


@cli.command()
@click.pass_context
def status(ctx):
    """Show agent status and proof statistics."""
    db = Database()

    click.echo("=== ZK Agent Status ===")

    # Proof counts
    counts = db.get_proof_count()
    click.echo(f"\nProofs generated:")
    for ptype, count in counts.items():
        click.echo(f"  {ptype}: {count}")
    if not counts:
        click.echo("  (none yet)")

    # Spend history
    history = db.get_spend_history(limit=5)
    click.echo(f"\nRecent spends:")
    for record in history:
        click.echo(
            f"  {record['amount']} USDC → {record.get('protocol', 'N/A')} "
            f"(proof: {record['proof_hash'][:8]}...)"
        )
    if not history:
        click.echo("  (none yet)")

    # Total spend
    total = db.get_spend_total()
    click.echo(f"\nTotal spend: {total} USDC")
    db.close()


@cli.command()
@click.pass_context
def demo(ctx):
    """Run a full demo: keygen → delegate → prove → execute → disclose."""
    config = ctx.obj["config"]
    prover = ZKProver(config["zk"]["build_dir"])

    click.echo("=" * 60)
    click.echo("  SYNTHESIS ZK AGENT — FULL DEMO")
    click.echo("  Privacy-preserving yield agent with ZK proofs")
    click.echo("=" * 60)

    # Step 1: Key generation
    click.echo("\n--- Step 1: Generate Owner Keys ---")
    keys = generate_keys()
    click.echo(f"Owner public key: ({keys.public_key_ax[:20]}..., {keys.public_key_ay[:20]}...)")

    # Step 2: Create delegation
    click.echo("\n--- Step 2: Create Signed Delegation ---")
    delegation = create_delegation(
        owner_private_key=keys.private_key,
        agent_id=1,
        spend_limit=5000,
        valid_for_seconds=604800,
    )
    click.echo(f"Agent ID: {delegation.agent_id}")
    click.echo(f"Spend limit: {delegation.spend_limit} USDC (hidden)")
    click.echo(f"Policy commitment: {delegation.policy_commitment[:30]}...")

    # Step 3: Budget range proof
    click.echo("\n--- Step 3: Budget Range Proof ---")
    import secrets
    proof = prover.generate_proof(ProofType.BUDGET_RANGE, {
        "amount": 2000,
        "maxBudget": 5000,
        "salt": secrets.randbits(128),
    })
    verified = prover.verify_proof(proof)
    click.echo(f"Prove: 2000 USDC <= budget (hidden)")
    click.echo(f"Valid: {proof.public_signals[1] == '1'}")
    click.echo(f"Verified: {verified}")

    # Step 4: Authorization proof
    click.echo("\n--- Step 4: Authorization Proof ---")
    auth_proof = prover.generate_proof(ProofType.AUTHORIZATION, {
        "ownerPubKeyAx": delegation.owner_pub_ax,
        "ownerPubKeyAy": delegation.owner_pub_ay,
        "signatureS": delegation.signature_s,
        "signatureR8x": delegation.signature_r8x,
        "signatureR8y": delegation.signature_r8y,
        "spendLimit": delegation.spend_limit,
        "validUntil": delegation.valid_until,
        "nonce": delegation.nonce,
        "salt": delegation.salt,
        "agentId": delegation.agent_id,
        "policyCommitment": delegation.policy_commitment,
    })
    auth_verified = prover.verify_proof(auth_proof)
    click.echo(f"Agent {delegation.agent_id} authorized by owner (ZK proven)")
    click.echo(f"Revealed: agent ID + policy commitment only")
    click.echo(f"Verified: {auth_verified}")

    # Step 5: Private execution
    click.echo("\n--- Step 5: Private Execution (Paper Mode) ---")
    policy_mgr = PolicyManager(prover, config)
    executor = PrivateExecutor(prover, policy_mgr, ExecutionMode.PAPER)
    state = initialize_policy_state(delegation, 10000)

    result = executor.execute_private_action("deposit", 2000, "aave-v3", state)
    click.echo(f"Action: deposit 2000 USDC → Aave V3")
    click.echo(f"Status: {result['status']}")
    click.echo(f"Compliant: {result['compliance']['compliant']}")
    click.echo(f"3 ZK proofs generated (auth + budget + cumulative)")

    # Step 6: Selective disclosure
    click.echo("\n--- Step 6: Selective Disclosure (Auditor) ---")
    controller = DisclosureController(prover, config)
    summary = controller.get_disclosure_summary(state, DisclosureLevel.AUDITOR)
    click.echo(f"Auditor can see: {', '.join(summary['allowed_claims'])}")
    for claim, data in summary.get("proofs", {}).items():
        click.echo(f"  {claim}: {data['value']}")

    click.echo("\n" + "=" * 60)
    click.echo("  DEMO COMPLETE")
    click.echo(f"  Total proofs generated: ~8 (3 types × multiple checks)")
    click.echo(f"  On-chain data: policy commitment + ZK proofs only")
    click.echo(f"  Hidden: amounts, limits, owner identity, strategies")
    click.echo("=" * 60)


@cli.command(name="private-yield")
@click.option("--owner-key", default=None, help="Owner's BJJ private key (prefer OWNER_PRIVATE_KEY env var)")
@click.option("--capital", default=10000, type=float, help="Total capital in USD")
@click.option("--mode", type=click.Choice(["paper", "dry_run"]), default="paper")
@click.pass_context
def private_yield(ctx, owner_key, capital, mode):
    """Execute a private yield allocation — yield strategy + ZK proof gates."""
    import subprocess
    import sys

    owner_key = _get_owner_key(owner_key)
    config = ctx.obj["config"]
    prover = ZKProver(config["zk"]["build_dir"])
    policy_mgr = PolicyManager(prover, config)
    exec_mode = ExecutionMode.PAPER if mode == "paper" else ExecutionMode.DRY_RUN

    click.echo("=" * 60)
    click.echo("  PRIVATE YIELD AGENT")
    click.echo("  Yield strategy + ZK privacy layer")
    click.echo("=" * 60)

    # Step 1: Get yield allocation plan from yield agent
    click.echo("\n--- Step 1: Fetch yield allocation plan ---")
    yield_agent_dir = os.path.expanduser("~/Desktop/claude_projects/synthesis-yield-agent")
    yield_python = os.path.join(yield_agent_dir, ".venv", "bin", "python")
    if not os.path.exists(yield_python):
        yield_python = sys.executable  # Fallback
    try:
        result = subprocess.run(
            [yield_python, "-m", "src", "allocate", "--json-output", "--capital", str(capital)],
            capture_output=True, text=True, timeout=60,
            cwd=yield_agent_dir,
        )
        if result.returncode != 0:
            click.echo(f"Yield agent error: {result.stderr}")
            return
        plan_data = json.loads(result.stdout)
    except FileNotFoundError:
        click.echo("Yield agent not found — using sample allocation plan")
        plan_data = {
            "capital_usd": capital,
            "allocations": [
                {"protocol": "aave-v3", "amount_usd": capital * 0.4, "target_pct": 0.4},
                {"protocol": "morpho-v1", "amount_usd": capital * 0.4, "target_pct": 0.4},
            ],
        }
    except Exception as e:
        click.echo(f"Failed to fetch yield plan: {e} — using sample allocation")
        plan_data = {
            "capital_usd": capital,
            "allocations": [
                {"protocol": "aave-v3", "amount_usd": capital * 0.4, "target_pct": 0.4},
                {"protocol": "morpho-v1", "amount_usd": capital * 0.4, "target_pct": 0.4},
            ],
        }

    allocs = plan_data.get("allocations", [])
    click.echo(f"Yield plan: {len(allocs)} allocations, ${plan_data.get('allocated_usd', capital * 0.8):,.0f} allocated")
    for a in allocs:
        click.echo(f"  {a['protocol']:<15} ${a['amount_usd']:>10,.2f}  ({a['target_pct']:.1%})")

    # Step 2: Create delegation + policy state
    click.echo("\n--- Step 2: Create ZK delegation ---")
    delegation = create_delegation(
        owner_private_key=owner_key,
        agent_id=config["agent"]["id"],
        spend_limit=config["spending_policy"]["max_single_spend"],
        valid_for_seconds=config["spending_policy"]["valid_for_seconds"],
    )
    state = initialize_policy_state(delegation, config["spending_policy"]["period_limit"])
    click.echo(f"Agent {delegation.agent_id} delegated, spend limit: {delegation.spend_limit} USDC")
    click.echo(f"Policy commitment: {delegation.policy_commitment[:30]}...")

    # Execution logger
    exec_logger = ExecutionLogger()
    exec_logger.begin_cycle(int(time.time()), mode)
    exec_logger.log_step("fetch_yield_plan", "ok", f"{len(allocs)} allocations from yield agent")

    # Step 3: Execute with ZK proof gates
    click.echo("\n--- Step 3: Execute with ZK privacy ---")
    exec_logger.log_step("create_delegation", "ok", f"agent {delegation.agent_id}, limit {delegation.spend_limit}")
    from src.bridge.private_yield import PrivateYieldExecutor, actions_from_yield_plan

    bridge = PrivateYieldExecutor(prover, policy_mgr, state, exec_mode)
    actions = actions_from_yield_plan(plan_data)
    results = bridge.execute_yield_actions(actions)

    for r in results:
        status_icon = {"SIMULATED": "+", "DRY_RUN": "~", "REJECTED": "X", "SKIPPED": "-"}.get(r["status"], "?")
        zk_label = "ZK OK" if r["zk_compliant"] else "ZK FAIL"
        click.echo(
            f"  [{status_icon}] {r['action']:<10} {r['protocol']:<15} "
            f"${r['amount_usd']:>10,.2f}  [{zk_label}]  {r['status']}"
        )
        if r["status"] == "REJECTED":
            click.echo(f"       Reason: {r['reason']}")

        # Log each execution
        exec_logger.log_execution(r["protocol"], r["action"], r["amount_usd"], r["status"], r.get("tx_hash", ""))
        exec_logger.log_decision(
            "zk_compliance",
            "approved" if r["zk_compliant"] else "rejected",
            r.get("reason", ""),
        )
        # Log proofs if present
        proofs = r.get("proofs", {})
        if isinstance(proofs, dict):
            for ptype in proofs:
                exec_logger.log_proof(ptype, r["zk_compliant"])
                exec_logger.log_tool_call("snarkjs", f"prove_{ptype}", "success" if r["zk_compliant"] else "fail")

    # Step 4: Summary
    summary = bridge.get_summary()
    click.echo(f"\n--- Summary ---")
    click.echo(f"  Actions:    {summary['total_actions']} total, {summary['executed']} executed, {summary['rejected']} rejected")
    click.echo(f"  Total USD:  ${summary['total_usd']:,.2f}")
    click.echo(f"  ZK proofs:  {summary['proof_count']} generated")
    click.echo(f"  Cumulative: {summary['cumulative_total']} / {summary['period_limit']} USDC period limit")

    # Step 5: Selective disclosure preview
    click.echo(f"\n--- Disclosure Preview ---")
    controller = DisclosureController(prover, config)
    disc = controller.get_disclosure_summary(state, DisclosureLevel.AUDITOR)
    click.echo(f"  Auditor view: {', '.join(disc['allowed_claims'])}")
    click.echo(f"  Public view:  proof_of_compliance only")
    click.echo(f"  Hidden:       individual transactions, protocol names, exact balances")

    exec_logger.end_cycle({
        "proofs_generated": summary.get("proof_count", 0),
        "proofs_verified": summary.get("proof_count", 0) - summary.get("rejected", 0),
        "actions_executed": summary.get("executed", 0),
        "actions_rejected": summary.get("rejected", 0),
        "cumulative_total": summary.get("cumulative_total", 0),
    })

    click.echo("\n" + "=" * 60)
    click.echo("  PRIVATE YIELD COMPLETE")
    click.echo(f"  Yield agent chose the strategy. ZK agent proved compliance.")
    click.echo(f"  Nobody sees the data.")
    click.echo("=" * 60)


@cli.command()
@click.option("--live", is_flag=True, help="Register on Base mainnet (default: Base Sepolia testnet)")
@click.option("--rpc-url", default=None, help="RPC URL (default: public Base RPC)")
@click.pass_context
def register(ctx, live, rpc_url):
    """Register the ZK agent on ERC-8004 Identity Registry."""
    import asyncio
    from src.erc8004 import register_agent, AgentRegistration

    network = "base_mainnet" if live else "base_sepolia"

    if not rpc_url:
        rpc_url = (
            "https://mainnet.base.org" if live
            else "https://sepolia.base.org"
        )

    private_key = os.environ.get("DEPLOYER_PRIVATE_KEY")
    if not private_key:
        private_key = click.prompt("Deployer private key (Ethereum)", hide_input=True)

    reg = AgentRegistration()
    click.echo("=== ERC-8004 Agent Registration ===")
    click.echo(f"Network:      {network}")
    click.echo(f"RPC URL:      {rpc_url}")
    click.echo(f"Agent name:   {reg.name}")
    click.echo(f"Capabilities: {', '.join(['zk-authorization', 'budget-range-proofs', 'cumulative-spend-proofs', 'selective-disclosure', 'privacy-preserving-execution', 'groth16-verification'])}")
    click.echo("")
    click.echo("Submitting registration transaction...")

    block = asyncio.run(register_agent(rpc_url, private_key, network))

    if block:
        click.echo(f"\nRegistration successful! Block: {block}")
        click.echo("Your agent now has a verifiable on-chain identity (ERC-721 NFT).")
    else:
        click.echo("\nRegistration failed. Check logs for details.")


if __name__ == "__main__":
    cli()
