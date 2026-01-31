"""
Cluster PKI: Ed25519 challenge-response authentication. [Tier 4]

Per-node asymmetric authentication extending the HMAC token system.

Key Storage:
    {keys_dir}/{node-id}.pub   (plaintext hex)
    Vault: cluster_ed25519_{node-id} (encrypted private key)

Authentication Flow:
    1. Challenger creates nonce + timestamp
    2. Responder signs challenge with Ed25519 private key
    3. Challenger verifies signature with responder's public key
"""

import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from claude_code_security import config

logger = logging.getLogger("claude_code_security.cluster_pki")


class ClusterPKI:
    """
    Ed25519 challenge-response authentication for cluster nodes.

    Private key encrypted via KeyVault. 5-minute challenge expiry.
    Nonce replay protection (persistent SQLite, TTL-based cleanup).
    """

    def __init__(self, keys_dir: Optional[Path] = None):
        self.keys_dir = keys_dir or config.CLUSTER_KEYS_DIR
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self._nonce_db_path = self.keys_dir / ".nonce_replay.db"
        self._init_nonce_db()

    def _init_nonce_db(self):
        """Create SQLite table for persistent nonce replay protection."""
        conn = sqlite3.connect(str(self._nonce_db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS used_nonces (
                nonce TEXT PRIMARY KEY,
                used_at REAL NOT NULL
            )
        """)
        conn.commit()
        conn.close()
        try:
            self._nonce_db_path.chmod(0o600)
        except OSError:
            pass

    def _is_nonce_used(self, nonce: str) -> bool:
        """Check if a nonce has been used (with TTL cleanup)."""
        conn = sqlite3.connect(str(self._nonce_db_path))
        try:
            cutoff = time.time() - config.CHALLENGE_EXPIRY_SECONDS - 60
            conn.execute("DELETE FROM used_nonces WHERE used_at < ?", (cutoff,))
            conn.commit()
            row = conn.execute(
                "SELECT 1 FROM used_nonces WHERE nonce = ?", (nonce,)
            ).fetchone()
            return row is not None
        finally:
            conn.close()

    def _record_nonce(self, nonce: str):
        """Record a nonce as used."""
        conn = sqlite3.connect(str(self._nonce_db_path))
        try:
            conn.execute(
                "INSERT OR IGNORE INTO used_nonces (nonce, used_at) VALUES (?, ?)",
                (nonce, time.time()),
            )
            conn.commit()
        finally:
            conn.close()

    def _get_vault(self):
        from claude_code_security.key_vault import KeyVault
        return KeyVault()

    @staticmethod
    def _validate_node_id(node_id: str):
        """Validate node_id to prevent path traversal."""
        import re
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$', node_id):
            raise ValueError(f"Invalid node_id: must match [a-zA-Z0-9][a-zA-Z0-9._-]{{0,63}}")

    def get_or_create_keypair(self, node_id: str) -> Dict:
        """Get or create an Ed25519 keypair for a node."""
        self._validate_node_id(node_id)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        pub_path = self.keys_dir / f"{node_id}.pub"
        vault_name = f"cluster_ed25519_{node_id}"

        vault = self._get_vault()
        key_bytes = vault.load_key(vault_name)
        if key_bytes and pub_path.exists():
            return {
                "node_id": node_id,
                "public_key_hex": pub_path.read_text().strip(),
                "pub_path": str(pub_path),
            }

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        priv_bytes = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        vault.store_key(vault_name, priv_bytes)

        pub_bytes = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        pub_hex = pub_bytes.hex()
        pub_path.write_text(pub_hex + "\n")

        logger.info(f"Generated Ed25519 keypair for node: {node_id}")
        return {
            "node_id": node_id,
            "public_key_hex": pub_hex,
            "pub_path": str(pub_path),
        }

    def create_auth_challenge(self) -> Dict:
        """Create an authentication challenge with nonce and timestamp."""
        nonce = os.urandom(32).hex()
        timestamp = str(int(time.time()))
        return {
            "nonce": nonce,
            "timestamp": timestamp,
            "challenge_data": f"{nonce}:{timestamp}",
        }

    def sign_challenge(self, node_id: str, challenge_data: str) -> Optional[str]:
        """Sign a challenge with the node's private key. Returns hex signature."""
        self._validate_node_id(node_id)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        vault_name = f"cluster_ed25519_{node_id}"
        vault = self._get_vault()
        key_bytes = vault.load_key(vault_name)
        if not key_bytes:
            logger.error(f"No private key found for node: {node_id}")
            return None
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
            signature = private_key.sign(challenge_data.encode("utf-8"))
            return signature.hex()
        except Exception as e:
            logger.error(f"Failed to sign challenge for {node_id}: {e}")
            return None

    def verify_challenge_response(
        self, node_id: str, challenge_data: str, signature_hex: str,
    ) -> Tuple[bool, str]:
        """Verify a challenge-response signature."""
        self._validate_node_id(node_id)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if self.is_revoked(node_id):
            return False, f"Node '{node_id}' is revoked"

        parts = challenge_data.split(":")
        if len(parts) != 2:
            return False, "Invalid challenge format"

        nonce, timestamp_str = parts
        try:
            challenge_time = int(timestamp_str)
            age = time.time() - challenge_time
            if age > config.CHALLENGE_EXPIRY_SECONDS:
                return False, f"Challenge expired ({age:.0f}s old)"
            if age < -60:
                return False, "Challenge timestamp is in the future"
        except ValueError:
            return False, "Invalid challenge timestamp"

        if self._is_nonce_used(nonce):
            return False, "Nonce replay detected"

        pub_path = self.keys_dir / f"{node_id}.pub"
        if not pub_path.exists():
            return False, f"No public key found for node: {node_id}"

        try:
            pub_hex = pub_path.read_text().strip()
            pub_bytes = bytes.fromhex(pub_hex)
            public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
            signature = bytes.fromhex(signature_hex)
            public_key.verify(signature, challenge_data.encode("utf-8"))

            self._record_nonce(nonce)

            return True, "Signature verified"
        except Exception as e:
            return False, f"Signature verification failed: {e}"

    def revoke_node(self, node_id: str, reason: str = "") -> bool:
        self._validate_node_id(node_id)
        try:
            revoked = self._load_revocation_list()
            revoked[node_id] = {"revoked_at": time.time(), "reason": reason}
            self._save_revocation_list(revoked)
            logger.warning(f"Revoked node: {node_id} (reason: {reason})")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke node {node_id}: {e}")
            return False

    def is_revoked(self, node_id: str) -> bool:
        return node_id in self._load_revocation_list()

    def get_trusted_nodes(self) -> List[str]:
        revoked = self._load_revocation_list()
        return sorted(
            p.stem for p in self.keys_dir.glob("*.pub") if p.stem not in revoked
        )

    def _load_revocation_list(self) -> Dict:
        if not config.REVOCATION_LIST_PATH.exists():
            return {}
        try:
            return json.loads(config.REVOCATION_LIST_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_revocation_list(self, revoked: Dict):
        config.REVOCATION_LIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.REVOCATION_LIST_PATH.write_text(json.dumps(revoked, indent=2))
