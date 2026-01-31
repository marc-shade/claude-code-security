"""
Cluster Auth: HMAC + RBAC node authentication. [Tier 4]

Per-node token derivation and validation with role-based access control.

Tokens: HMAC-SHA256(shared_secret, node_id)
Roles: admin, write, build, read (configurable via cluster_roles.json)
"""

import hashlib
import hmac
import json
import logging
import os
import sqlite3
from pathlib import Path
from typing import Optional

from claude_code_security import config

logger = logging.getLogger("claude_code_security.cluster_auth")


def _get_or_create_cluster_secret() -> bytes:
    """Get or create the shared cluster secret. Prefers vault storage."""
    try:
        from claude_code_security.key_vault import KeyVault
        vault = KeyVault()
        secret = vault.load_key("cluster_secret")
        if secret:
            return secret
        if config.CLUSTER_SECRET_PATH.exists():
            if vault.migrate_plaintext_key("cluster_secret", config.CLUSTER_SECRET_PATH):
                return vault.load_key("cluster_secret")
        secret = os.urandom(32)
        vault.store_key("cluster_secret", secret)
        return secret
    except ImportError:
        logger.debug("KeyVault not available, using plaintext secret storage")
    except Exception as e:
        logger.warning(f"Vault error, falling back to plaintext: {e}")

    if config.CLUSTER_SECRET_PATH.exists():
        return config.CLUSTER_SECRET_PATH.read_bytes()

    secret = os.urandom(32)
    config.CLUSTER_SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.CLUSTER_SECRET_PATH.write_bytes(secret)
    try:
        config.CLUSTER_SECRET_PATH.chmod(0o600)
    except OSError:
        pass
    logger.info(f"Generated new cluster secret at {config.CLUSTER_SECRET_PATH}")
    return secret


def _init_audit_db():
    config.WRITE_AUDIT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(config.WRITE_AUDIT_DB_PATH))
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS write_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            entity_name TEXT,
            authorized INTEGER NOT NULL,
            reason TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def derive_node_token(node_id: str, secret: bytes) -> str:
    """Derive a deterministic HMAC-SHA256 token for a node ID."""
    return hmac.new(secret, node_id.encode("utf-8"), hashlib.sha256).hexdigest()


class ClusterAuth:
    """
    Cluster authentication manager.

    Provides token generation and validation for node auth.
    Supports Ed25519 PKI alongside HMAC tokens.
    """

    def __init__(self, secret_path: Optional[Path] = None):
        self.secret_path = secret_path or config.CLUSTER_SECRET_PATH
        self.secret = _get_or_create_cluster_secret()
        _init_audit_db()
        self._pki = None
        try:
            from claude_code_security.cluster_pki import ClusterPKI
            self._pki = ClusterPKI()
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"PKI initialization failed: {e}")

    def get_node_token(self, node_id: str) -> str:
        return derive_node_token(node_id, self.secret)

    def validate_token(self, node_id: str, token: str) -> bool:
        """Validate a token. Supports ed25519:<challenge>:<signature> format."""
        if token.startswith("ed25519:") and self._pki:
            parts = token.split(":", 2)
            if len(parts) == 3:
                valid, _ = self._pki.verify_challenge_response(
                    node_id, parts[1], parts[2],
                )
                if valid:
                    return True
        expected = derive_node_token(node_id, self.secret)
        return hmac.compare_digest(expected, token)

    def authorize_write(
        self, node_id: str, write_token: str,
        scope: str = "shared", entity_name: str = "",
    ) -> bool:
        """Authorize a write operation. Personal scope always allowed."""
        if scope == "personal":
            self._log_attempt(node_id, scope, entity_name, True, "personal_scope")
            return True
        authorized = self.validate_token(node_id, write_token)
        reason = "valid_token" if authorized else "invalid_token"
        self._log_attempt(node_id, scope, entity_name, authorized, reason)
        if not authorized:
            logger.warning(
                f"UNAUTHORIZED write attempt: node={node_id}, scope={scope}, entity={entity_name}"
            )
        return authorized

    def _log_attempt(
        self, node_id: str, scope: str, entity_name: str,
        authorized: bool, reason: str,
    ):
        try:
            conn = sqlite3.connect(str(config.WRITE_AUDIT_DB_PATH))
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO write_attempts (node_id, scope, entity_name, authorized, reason) "
                "VALUES (?, ?, ?, ?, ?)",
                (node_id, scope, entity_name, int(authorized), reason),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to log write attempt: {e}")

    def get_audit_stats(self) -> dict:
        try:
            conn = sqlite3.connect(str(config.WRITE_AUDIT_DB_PATH))
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM write_attempts")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM write_attempts WHERE authorized = 1")
            authorized = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM write_attempts WHERE authorized = 0")
            denied = cursor.fetchone()[0]
            cursor.execute(
                "SELECT node_id, COUNT(*) as attempts, SUM(authorized) as authorized "
                "FROM write_attempts GROUP BY node_id ORDER BY attempts DESC"
            )
            per_node = {row[0]: {"attempts": row[1], "authorized": row[2]} for row in cursor.fetchall()}
            conn.close()
            return {"total_attempts": total, "authorized": authorized, "denied": denied, "per_node": per_node}
        except Exception as e:
            logger.error(f"Failed to get audit stats: {e}")
            return {"error": str(e)}


class ClusterRBAC:
    """
    Role-Based Access Control for cluster nodes.

    Roles: admin (all), write (read+write), build (read+build), read (read-only).
    Config overrides at cluster_roles.json.
    """

    def __init__(self):
        self._custom_roles = self._load_config()

    def _load_config(self) -> dict:
        if config.RBAC_CONFIG_PATH.exists():
            try:
                return json.loads(config.RBAC_CONFIG_PATH.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save_config(self):
        config.RBAC_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.RBAC_CONFIG_PATH.write_text(json.dumps(self._custom_roles, indent=2))

    def get_node_role(self, node_id: str) -> str:
        if node_id in self._custom_roles:
            return self._custom_roles[node_id]
        return config.DEFAULT_NODE_ROLES.get(node_id, "read")

    def get_node_permissions(self, node_id: str) -> set:
        role = self.get_node_role(node_id)
        return config.ROLE_PERMISSIONS.get(role, config.ROLE_PERMISSIONS["read"]).copy()

    def has_permission(self, node_id: str, permission: str) -> bool:
        return permission in self.get_node_permissions(node_id)

    def authorize_operation(self, node_id: str, operation: str) -> tuple:
        role = self.get_node_role(node_id)
        perms = self.get_node_permissions(node_id)
        if operation in perms:
            return True, f"role={role}, permission={operation} granted"
        return False, f"role={role}, permission={operation} denied"

    def assign_role(self, node_id: str, role: str) -> bool:
        if role not in config.ROLE_PERMISSIONS:
            logger.error(f"Invalid role: {role}")
            return False
        self._custom_roles[node_id] = role
        self._save_config()
        logger.info(f"Assigned role '{role}' to node '{node_id}'")
        return True
