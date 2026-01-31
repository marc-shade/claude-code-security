"""
File Integrity Signing & Verification. [Tier 1]

Signs monitored files with HMAC-SHA256 and verifies at session start.

Manifest Format:
    {path: {content_hash, signature, signed_at, signed_by}}

Atomic writes via .tmp + os.rename() for crash safety.
"""

import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from claude_code_security import config

logger = logging.getLogger("claude_code_security.file_integrity")


def _get_or_create_signing_key() -> bytes:
    """
    Get or create the HMAC signing key for file integrity.
    Prefers encrypted vault storage, falls back to plaintext.
    """
    try:
        from claude_code_security.key_vault import KeyVault
        vault = KeyVault()
        key = vault.load_key("file_integrity")
        if key:
            return key
        if config.SIGNING_KEY_PATH.exists():
            if vault.migrate_plaintext_key("file_integrity", config.SIGNING_KEY_PATH):
                return vault.load_key("file_integrity")
        key = os.urandom(32)
        vault.store_key("file_integrity", key)
        return key
    except ImportError:
        logger.debug("KeyVault not available, using plaintext key storage")
    except Exception as e:
        logger.warning(f"Vault error, falling back to plaintext: {e}")

    if config.SIGNING_KEY_PATH.exists():
        return config.SIGNING_KEY_PATH.read_bytes()

    key = os.urandom(32)
    config.SIGNING_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.SIGNING_KEY_PATH.write_bytes(key)
    try:
        config.SIGNING_KEY_PATH.chmod(0o600)
    except OSError:
        pass
    logger.info(f"Generated new file integrity signing key at {config.SIGNING_KEY_PATH}")
    return key


def _hash_file(path: Path) -> str:
    """Compute SHA-256 hash of file contents."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _sign_hash(content_hash: str, key: bytes) -> str:
    """Create HMAC-SHA256 signature of a content hash."""
    return hmac.new(key, content_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def _verify_signature(content_hash: str, signature: str, key: bytes) -> bool:
    """Verify HMAC-SHA256 signature of a content hash."""
    expected = hmac.new(key, content_hash.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


class VerificationReport:
    """Result of verifying all monitored files."""

    def __init__(self):
        self.verified: List[str] = []
        self.unsigned: List[str] = []
        self.tampered: List[str] = []
        self.missing: List[str] = []
        self.errors: List[str] = []
        self.duration_ms: float = 0.0

    @property
    def total_files(self) -> int:
        return len(self.verified) + len(self.unsigned) + len(self.tampered)

    @property
    def is_clean(self) -> bool:
        return len(self.tampered) == 0

    def summary(self) -> str:
        parts = []
        if self.verified:
            parts.append(f"VERIFIED:{len(self.verified)}")
        if self.unsigned:
            parts.append(f"UNSIGNED:{len(self.unsigned)}")
        if self.tampered:
            parts.append(f"TAMPERED:{len(self.tampered)}")
        if self.missing:
            parts.append(f"MISSING:{len(self.missing)}")
        return " | ".join(parts) + f" ({self.duration_ms:.0f}ms)"

    def to_dict(self) -> Dict:
        return {
            "verified": len(self.verified),
            "unsigned": len(self.unsigned),
            "tampered": len(self.tampered),
            "missing": len(self.missing),
            "tampered_files": self.tampered[:20],
            "duration_ms": round(self.duration_ms, 1),
            "is_clean": self.is_clean,
        }


class FileIntegritySigner:
    """Signs and verifies files using HMAC-SHA256."""

    def __init__(
        self,
        manifest_path: Optional[Path] = None,
        monitored_dirs: Optional[List[Path]] = None,
        signer_id: str = "system",
    ):
        self.manifest_path = manifest_path or config.MANIFEST_PATH
        self.monitored_dirs = monitored_dirs or config.MONITORED_DIRS
        self.signer_id = signer_id
        self.key = _get_or_create_signing_key()
        self.manifest = self._load_manifest()

    def _load_manifest(self) -> Dict[str, Dict]:
        if self.manifest_path.exists():
            try:
                with open(self.manifest_path, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Failed to load manifest: {e}")
        return {}

    def _save_manifest(self):
        tmp_path = self.manifest_path.with_suffix(".tmp")
        try:
            self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp_path, "w") as f:
                json.dump(self.manifest, f, indent=2, sort_keys=True)
            os.rename(str(tmp_path), str(self.manifest_path))
        except OSError as e:
            logger.error(f"Failed to save manifest: {e}")
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def _discover_files(self) -> List[Path]:
        files = []
        for directory in self.monitored_dirs:
            if not directory.exists():
                continue
            for path in directory.rglob("*"):
                if path.is_file() and path.suffix in config.MONITORED_EXTENSIONS:
                    files.append(path)
        return sorted(files)

    def _path_key(self, path: Path) -> str:
        try:
            return str(path.relative_to(Path.home()))
        except ValueError:
            return str(path)

    def sign_file(self, path: Path) -> bool:
        try:
            if not path.exists():
                logger.warning(f"Cannot sign non-existent file: {path}")
                return False
            content_hash = _hash_file(path)
            signature = _sign_hash(content_hash, self.key)
            key = self._path_key(path)
            self.manifest[key] = {
                "content_hash": content_hash,
                "signature": signature,
                "signed_at": datetime.now().isoformat(),
                "signed_by": self.signer_id,
            }
            self._save_manifest()
            return True
        except Exception as e:
            logger.error(f"Failed to sign {path}: {e}")
            return False

    def sign_all(self) -> Tuple[int, int]:
        """Sign all discovered files. Returns (signed_count, error_count)."""
        files = self._discover_files()
        signed = 0
        errors = 0
        for path in files:
            try:
                content_hash = _hash_file(path)
                signature = _sign_hash(content_hash, self.key)
                key = self._path_key(path)
                self.manifest[key] = {
                    "content_hash": content_hash,
                    "signature": signature,
                    "signed_at": datetime.now().isoformat(),
                    "signed_by": self.signer_id,
                }
                signed += 1
            except Exception as e:
                logger.error(f"Failed to sign {path}: {e}")
                errors += 1
        self._save_manifest()
        logger.info(f"Signed {signed} files ({errors} errors)")
        return signed, errors

    def verify_file(self, path: Path) -> str:
        """Verify a single file. Returns: verified, unsigned, tampered, or missing."""
        key = self._path_key(path)
        if key not in self.manifest:
            return "unsigned"
        if not path.exists():
            return "missing"
        entry = self.manifest[key]
        content_hash = _hash_file(path)
        if content_hash != entry["content_hash"]:
            return "tampered"
        if not _verify_signature(content_hash, entry["signature"], self.key):
            return "tampered"
        return "verified"

    def verify_all(self) -> VerificationReport:
        """Verify all monitored files and manifest entries."""
        start = time.time()
        report = VerificationReport()
        files = self._discover_files()
        for path in files:
            try:
                status = self.verify_file(path)
                key = self._path_key(path)
                if status == "verified":
                    report.verified.append(key)
                elif status == "unsigned":
                    report.unsigned.append(key)
                elif status == "tampered":
                    report.tampered.append(key)
                    logger.warning(f"TAMPERED: {key}")
            except Exception as e:
                report.errors.append(f"{path}: {e}")

        discovered_keys = {self._path_key(p) for p in files}
        for key in self.manifest:
            if key not in discovered_keys:
                abs_path = Path.home() / key
                if not abs_path.exists():
                    report.missing.append(key)

        report.duration_ms = (time.time() - start) * 1000
        return report

    def re_sign_file(self, path: Path) -> bool:
        """Re-sign a file after legitimate modification."""
        return self.sign_file(path)

    def get_manifest_stats(self) -> Dict:
        signers = {}
        for entry in self.manifest.values():
            signer = entry.get("signed_by", "unknown")
            signers[signer] = signers.get(signer, 0) + 1
        return {
            "total_entries": len(self.manifest),
            "signers": signers,
            "manifest_path": str(self.manifest_path),
        }


def quick_verify() -> VerificationReport:
    """Quick verification for session start hook."""
    return FileIntegritySigner().verify_all()


def quick_sign_all() -> Tuple[int, int]:
    """Quick sign-all for initial setup."""
    return FileIntegritySigner().sign_all()


def re_sign_after_modification(path: Path, signer_id: str = "audit_hook") -> bool:
    """Re-sign a file after a tracked modification."""
    return FileIntegritySigner(signer_id=signer_id).re_sign_file(path)
