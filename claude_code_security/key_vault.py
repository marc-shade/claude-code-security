"""
Key Vault: AES-256-GCM encrypted key storage. [Tier 1]

Encrypts signing keys at rest using a master key derived from
machine-specific entropy via PBKDF2.

Vault Structure:
    {vault_dir}/.vault_salt   - PBKDF2 salt (32 bytes)
    {vault_dir}/{name}.enc    - Encrypted keys (nonce + ciphertext + tag)

Master Key Derivation:
    PBKDF2(machine_entropy, salt, iterations=600000, dklen=32)

Machine Entropy Sources:
    hostname + platform.node() + machine-id/IOPlatformUUID
"""

import hashlib
import json
import logging
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from claude_code_security import config

logger = logging.getLogger("claude_code_security.key_vault")


def _get_machine_entropy() -> bytes:
    """
    Collect machine-specific entropy for master key derivation.
    Uses hostname + platform.node() + machine-id/IOPlatformUUID.
    """
    import socket

    parts = [socket.gethostname(), platform.node()]

    if platform.system() == "Darwin":
        try:
            result = subprocess.run(
                ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if "IOPlatformUUID" in line:
                    uuid = line.split('"')[-2]
                    parts.append(uuid)
                    break
        except (subprocess.TimeoutExpired, OSError, IndexError):
            pass
    elif platform.system() == "Linux":
        for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
            try:
                parts.append(Path(path).read_text().strip())
                break
            except OSError:
                continue

    entropy = ":".join(parts).encode("utf-8")
    return hashlib.sha256(entropy).digest()


def _get_or_create_salt(vault_dir: Path, salt_path: Path) -> bytes:
    """Get or create the PBKDF2 salt for the vault."""
    if salt_path.exists():
        salt = salt_path.read_bytes()
        if len(salt) >= 32:
            return salt

    salt = os.urandom(32)
    vault_dir.mkdir(parents=True, exist_ok=True)
    salt_path.write_bytes(salt)
    try:
        salt_path.chmod(0o600)
    except OSError:
        pass
    logger.info("Generated new vault salt")
    return salt


def _derive_master_key(salt: bytes) -> bytes:
    """Derive the master encryption key from machine entropy and salt."""
    entropy = _get_machine_entropy()
    return hashlib.pbkdf2_hmac(
        "sha256", entropy, salt, config.PBKDF2_ITERATIONS, dklen=config.KEY_LENGTH,
    )


class KeyVault:
    """
    AES-256-GCM encrypted key vault.

    Stores cryptographic keys encrypted at rest using a master key
    derived from machine-specific entropy via PBKDF2.
    """

    def __init__(self, vault_dir: Optional[Path] = None):
        self.vault_dir = vault_dir or config.VAULT_DIR
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        salt_path = self.vault_dir / ".vault_salt"
        self._salt = _get_or_create_salt(self.vault_dir, salt_path)
        self._master_key = _derive_master_key(self._salt)

    def _key_path(self, name: str) -> Path:
        safe_name = name.replace("/", "_").replace("\\", "_")
        return self.vault_dir / f"{safe_name}.enc"

    def _meta_path(self, name: str) -> Path:
        safe_name = name.replace("/", "_").replace("\\", "_")
        return self.vault_dir / f"{safe_name}.meta"

    def encrypt_key(self, plaintext_key: bytes) -> bytes:
        """Encrypt a key using AES-256-GCM. Returns nonce + ciphertext + tag."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = os.urandom(12)
        aesgcm = AESGCM(self._master_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext_key, None)
        return nonce + ciphertext

    def decrypt_key(self, encrypted_data: bytes) -> bytes:
        """Decrypt a key from AES-256-GCM encrypted data."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(self._master_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def store_key(self, name: str, key: bytes) -> bool:
        """Encrypt and store a key. Atomic write via .tmp + os.rename()."""
        try:
            encrypted = self.encrypt_key(key)
            key_path = self._key_path(name)
            tmp_path = key_path.with_suffix(".tmp")

            tmp_path.write_bytes(encrypted)
            os.rename(str(tmp_path), str(key_path))
            try:
                key_path.chmod(0o600)
            except OSError:
                pass

            meta = {
                "name": name,
                "stored_at": datetime.now(timezone.utc).isoformat(),
                "key_length": len(key),
                "encrypted_length": len(encrypted),
                "rotated_at": None,
                "rotation_count": 0,
            }
            self._meta_path(name).write_text(json.dumps(meta, indent=2))

            logger.info(f"Stored encrypted key: {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to store key '{name}': {e}")
            try:
                self._key_path(name).with_suffix(".tmp").unlink(missing_ok=True)
            except OSError:
                pass
            return False

    def load_key(self, name: str) -> Optional[bytes]:
        """Load and decrypt a key from the vault."""
        key_path = self._key_path(name)
        if not key_path.exists():
            return None
        try:
            encrypted = key_path.read_bytes()
            return self.decrypt_key(encrypted)
        except Exception as e:
            logger.error(f"Failed to load key '{name}': {e}")
            return None

    def delete_key(self, name: str) -> bool:
        """Delete a key from the vault."""
        try:
            key_path = self._key_path(name)
            meta_path = self._meta_path(name)
            if key_path.exists():
                key_path.unlink()
            if meta_path.exists():
                meta_path.unlink()
            logger.info(f"Deleted key: {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete key '{name}': {e}")
            return False

    def migrate_plaintext_key(
        self, name: str, plaintext_path: Path, delete_original: bool = True,
    ) -> bool:
        """Migrate a plaintext key file into the vault."""
        if not plaintext_path.exists():
            logger.warning(f"Plaintext key not found: {plaintext_path}")
            return False
        try:
            plaintext_key = plaintext_path.read_bytes()
            if not self.store_key(name, plaintext_key):
                return False
            if delete_original:
                plaintext_path.unlink()
                logger.info(f"Removed plaintext key: {plaintext_path}")
            return True
        except Exception as e:
            logger.error(f"Migration failed for '{name}': {e}")
            return False

    def rotate_key(self, name: str, new_key: Optional[bytes] = None) -> bool:
        """Rotate a key: backup old, store new, update metadata."""
        old_key = self.load_key(name)
        if old_key is None:
            logger.warning(f"Cannot rotate non-existent key: {name}")
            return False

        backup_name = f"{name}_backup_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        self.store_key(backup_name, old_key)

        new_key = new_key or os.urandom(32)
        if not self.store_key(name, new_key):
            return False

        meta_path = self._meta_path(name)
        try:
            meta = json.loads(meta_path.read_text()) if meta_path.exists() else {"name": name}
            meta["rotated_at"] = datetime.now(timezone.utc).isoformat()
            meta["rotation_count"] = meta.get("rotation_count", 0) + 1
            meta["backup_name"] = backup_name
            meta_path.write_text(json.dumps(meta, indent=2))
        except Exception:
            pass

        logger.info(f"Rotated key: {name} (backup: {backup_name})")
        return True

    def list_keys(self) -> List[str]:
        """List all key names in the vault."""
        return sorted(p.stem for p in self.vault_dir.glob("*.enc"))

    def get_status(self) -> Dict:
        """Get vault status report."""
        keys = self.list_keys()
        key_details = []
        for name in keys:
            meta_path = self._meta_path(name)
            meta = {}
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text())
                except (json.JSONDecodeError, OSError):
                    pass
            key_details.append({
                "name": name,
                "stored_at": meta.get("stored_at"),
                "rotated_at": meta.get("rotated_at"),
                "rotation_count": meta.get("rotation_count", 0),
            })
        return {
            "vault_dir": str(self.vault_dir),
            "key_count": len(keys),
            "keys": key_details,
        }
