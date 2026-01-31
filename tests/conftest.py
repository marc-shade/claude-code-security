"""Shared test fixtures for claude-code-security."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure the package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def tmp_dir(tmp_path):
    """Provide a temporary directory."""
    return tmp_path


@pytest.fixture
def mock_claude_home(tmp_path, monkeypatch):
    """Set up a mock ~/.claude directory for testing."""
    claude_home = tmp_path / ".claude"
    claude_home.mkdir()
    (claude_home / "audit_logs").mkdir()
    (claude_home / ".vault").mkdir()
    (claude_home / "commands").mkdir()
    (claude_home / "hooks").mkdir()
    (claude_home / "agents").mkdir()
    (claude_home / "skills").mkdir()
    (claude_home / "rules").mkdir()

    # Override config paths
    monkeypatch.setattr("claude_code_security.config.CLAUDE_HOME", claude_home)
    monkeypatch.setattr("claude_code_security.config.VAULT_DIR", claude_home / ".vault")
    monkeypatch.setattr("claude_code_security.config.VAULT_SALT_PATH", claude_home / ".vault" / ".vault_salt")
    monkeypatch.setattr("claude_code_security.config.AUDIT_LOG_DIR", claude_home / "audit_logs")
    monkeypatch.setattr("claude_code_security.config.MANIFEST_PATH", claude_home / ".file_integrity_manifest.json")
    monkeypatch.setattr("claude_code_security.config.SIGNING_KEY_PATH", claude_home / ".file_integrity_key")
    monkeypatch.setattr("claude_code_security.config.TAMPER_PROOF_DB_PATH", claude_home / "audit_logs" / "tamper_proof.db")
    monkeypatch.setattr("claude_code_security.config.APPROVAL_LOG_PATH", claude_home / "audit_logs" / "approvals.jsonl")
    monkeypatch.setattr("claude_code_security.config.CLUSTER_SECRET_PATH", claude_home / ".cluster_secret")
    monkeypatch.setattr("claude_code_security.config.WRITE_AUDIT_DB_PATH", claude_home / "audit_logs" / "write_attempts.db")
    monkeypatch.setattr("claude_code_security.config.RBAC_CONFIG_PATH", claude_home / ".cluster_roles.json")
    monkeypatch.setattr("claude_code_security.config.REVOCATION_LIST_PATH", claude_home / "audit_logs" / "revoked_keys.json")
    monkeypatch.setattr("claude_code_security.config.CERTS_DIR", claude_home / "certs")
    monkeypatch.setattr("claude_code_security.config.CLUSTER_KEYS_DIR", tmp_path / ".ssh" / "cluster-keys")
    monkeypatch.setattr("claude_code_security.config.CUSTOM_POLICIES_PATH", claude_home / "custom_policies.json")

    monkeypatch.setattr("claude_code_security.config.MONITORED_DIRS", [
        claude_home / "commands",
        claude_home / "hooks",
        claude_home / "agents",
        claude_home / "skills",
        claude_home / "rules",
    ])

    monkeypatch.setattr("claude_code_security.config.SELF_MOD_MONITORED_PATTERNS", [
        str(claude_home / "CLAUDE.md"),
        str(claude_home / "commands"),
        str(claude_home / "hooks"),
        str(claude_home / "agents"),
        str(claude_home / "skills"),
        str(claude_home / "rules"),
    ])

    return claude_home


@pytest.fixture
def mock_vault(mock_claude_home):
    """Create a KeyVault instance using the mock home."""
    from claude_code_security.key_vault import KeyVault
    return KeyVault(vault_dir=mock_claude_home / ".vault")


@pytest.fixture
def sample_files(mock_claude_home):
    """Create sample monitored files for testing."""
    files = {}
    for subdir in ["commands", "hooks", "agents"]:
        f = mock_claude_home / subdir / "test_file.py"
        f.write_text(f"# Test file in {subdir}\nprint('hello')\n")
        files[subdir] = f
    return files
