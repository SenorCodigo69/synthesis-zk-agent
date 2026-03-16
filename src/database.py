"""SQLite persistence for policy state, proofs, and audit trail.

Sensitive fields (nonce, salt) are encrypted at rest using Fernet
symmetric encryption derived from the ZK_DB_ENCRYPTION_KEY env var.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)


def _derive_fernet_key(secret: str, db_path: str = "") -> bytes:
    """Derive a Fernet key from a secret string using PBKDF2 key stretching.

    Uses a per-database salt derived from the db path to prevent
    cross-database attacks when the same password is reused.
    """
    # Per-database salt: hash of absolute path ensures uniqueness
    path_bytes = Path(db_path).resolve().as_posix().encode() if db_path else b""
    salt = hashlib.sha256(b"zk-agent-db-v1" + path_bytes).digest()[:16]
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, 600_000)
    return base64.urlsafe_b64encode(dk)


class Database:
    """SQLite database for ZK agent state and audit trail."""

    def __init__(self, db_path: str = "data/zk_agent.db", encryption_key: str | None = None):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")

        # Encryption for sensitive fields
        secret = encryption_key or os.environ.get("ZK_DB_ENCRYPTION_KEY", "")
        if secret:
            self._fernet = Fernet(_derive_fernet_key(secret, db_path))
        else:
            self._fernet = None
            logger.warning(
                "Database encryption DISABLED. Set ZK_DB_ENCRYPTION_KEY env var "
                "to encrypt nonces and salts at rest."
            )

        self._create_tables()

    def _encrypt(self, value: str) -> str:
        """Encrypt a value if encryption is configured."""
        if self._fernet:
            return self._fernet.encrypt(value.encode()).decode()
        return value

    def _decrypt(self, value: str) -> str:
        """Decrypt a value if encryption is configured."""
        if self._fernet:
            try:
                return self._fernet.decrypt(value.encode()).decode()
            except Exception:
                # Distinguish legacy plaintext (numeric) from actual decrypt failures
                if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
                    return value  # Legacy plaintext (pre-encryption data)
                logger.warning("Decryption failed — possible wrong key or corrupted data")
                return value
        return value

    def _create_tables(self) -> None:
        """Create tables if they don't exist."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS delegations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id INTEGER NOT NULL,
                spend_limit INTEGER NOT NULL,
                valid_until INTEGER NOT NULL,
                nonce TEXT NOT NULL,
                salt TEXT NOT NULL,
                policy_commitment TEXT NOT NULL,
                owner_pub_ax TEXT NOT NULL,
                owner_pub_ay TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS spend_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                amount INTEGER NOT NULL,
                protocol TEXT,
                tx_hash TEXT,
                proof_hash TEXT NOT NULL,
                commitment TEXT NOT NULL,
                cumulative_total INTEGER NOT NULL,
                timestamp REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS proofs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proof_type TEXT NOT NULL,
                public_signals TEXT NOT NULL,
                proof_data TEXT NOT NULL,
                verified INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS disclosure_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT NOT NULL,
                claim TEXT NOT NULL,
                proof_id INTEGER,
                requested_at REAL NOT NULL,
                FOREIGN KEY (proof_id) REFERENCES proofs(id)
            );
        """)
        self.conn.commit()

    def save_delegation(self, delegation: dict) -> int:
        """Save a delegation record. Nonce and salt are encrypted at rest."""
        cursor = self.conn.execute(
            """INSERT INTO delegations
               (agent_id, spend_limit, valid_until, nonce, salt,
                policy_commitment, owner_pub_ax, owner_pub_ay, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                delegation["agent_id"],
                delegation["spend_limit"],
                delegation["valid_until"],
                self._encrypt(str(delegation["nonce"])),
                self._encrypt(str(delegation["salt"])),
                delegation["policy_commitment"],
                delegation["owner_pub_ax"],
                delegation["owner_pub_ay"],
                time.time(),
            ),
        )
        self.conn.commit()
        return cursor.lastrowid

    def save_spend(self, record: dict) -> int:
        """Save a spend record."""
        cursor = self.conn.execute(
            """INSERT INTO spend_records
               (amount, protocol, tx_hash, proof_hash, commitment,
                cumulative_total, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                record["amount"],
                record.get("protocol"),
                record.get("tx_hash"),
                record["proof_hash"],
                record["commitment"],
                record["cumulative_total"],
                time.time(),
            ),
        )
        self.conn.commit()
        return cursor.lastrowid

    def save_proof(self, proof_type: str, public_signals: list, proof_data: dict, verified: bool) -> int:
        """Save a generated proof."""
        cursor = self.conn.execute(
            """INSERT INTO proofs (proof_type, public_signals, proof_data, verified, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                proof_type,
                json.dumps(public_signals),
                json.dumps(proof_data),
                int(verified),
                time.time(),
            ),
        )
        self.conn.commit()
        return cursor.lastrowid

    def log_disclosure(self, level: str, claim: str, proof_id: int | None = None) -> int:
        """Log a disclosure request."""
        cursor = self.conn.execute(
            """INSERT INTO disclosure_log (level, claim, proof_id, requested_at)
               VALUES (?, ?, ?, ?)""",
            (level, claim, proof_id, time.time()),
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_spend_total(self, since: float | None = None) -> int:
        """Get total spend amount, optionally since a timestamp."""
        if since:
            row = self.conn.execute(
                "SELECT COALESCE(SUM(amount), 0) as total FROM spend_records WHERE timestamp >= ?",
                (since,),
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT COALESCE(SUM(amount), 0) as total FROM spend_records"
            ).fetchone()
        return row["total"]

    def get_spend_history(self, limit: int = 20) -> list[dict]:
        """Get recent spend history."""
        rows = self.conn.execute(
            "SELECT * FROM spend_records ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_proof_count(self) -> dict[str, int]:
        """Get count of proofs by type."""
        rows = self.conn.execute(
            "SELECT proof_type, COUNT(*) as count FROM proofs GROUP BY proof_type"
        ).fetchall()
        return {row["proof_type"]: row["count"] for row in rows}

    def close(self) -> None:
        """Close the database connection."""
        self.conn.close()
