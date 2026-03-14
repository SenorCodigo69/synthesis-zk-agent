"""Configuration loader — .env + YAML."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv


def load_config(config_path: str | None = None) -> dict[str, Any]:
    """Load configuration from YAML + environment variables."""
    project_root = Path(__file__).parent.parent

    # Load .env
    env_file = project_root / ".env"
    if env_file.exists():
        load_dotenv(env_file)

    # Load YAML
    if config_path is None:
        config_path = str(project_root / "config" / "default.yaml")

    config_file = Path(config_path).resolve()
    if not str(config_file).startswith(str(project_root.resolve())):
        raise ValueError(f"Config path must be within project directory: {config_file}")

    with open(config_file) as f:
        config = yaml.safe_load(f)

    # Override with env vars
    config["chain"]["rpc_url"] = os.getenv("BASE_RPC_URL", config["chain"]["rpc_url"])
    config["chain"]["testnet"]["rpc_url"] = os.getenv(
        "BASE_SEPOLIA_RPC_URL", config["chain"]["testnet"]["rpc_url"]
    )

    # Build directory
    config["zk"]["build_dir"] = str(project_root / config["zk"]["build_dir"])

    # Project root for scripts
    config["_project_root"] = str(project_root)

    return config
