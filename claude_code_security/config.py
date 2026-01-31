"""
Centralized configuration for claude-code-security.

All paths, thresholds, and feature flags in one place.
Override via environment variables or by modifying defaults before import.
"""

import os
from pathlib import Path


def _env_path(var: str, default: Path) -> Path:
    """Read a path from environment variable or use default."""
    val = os.environ.get(var)
    return Path(val) if val else default


def _env_bool(var: str, default: bool) -> bool:
    """Read a boolean from environment variable."""
    val = os.environ.get(var)
    if val is None:
        return default
    return val.lower() in ("1", "true", "yes")


def _env_int(var: str, default: int) -> int:
    """Read an integer from environment variable."""
    val = os.environ.get(var)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


# ============================================================================
# Base paths
# ============================================================================

CLAUDE_HOME = _env_path(
    "CLAUDE_CODE_SECURITY_HOME",
    Path.home() / ".claude",
)

VAULT_DIR = _env_path(
    "CLAUDE_CODE_SECURITY_VAULT_DIR",
    CLAUDE_HOME / ".vault",
)

AUDIT_LOG_DIR = _env_path(
    "CLAUDE_CODE_SECURITY_AUDIT_DIR",
    CLAUDE_HOME / "audit_logs",
)

CERTS_DIR = _env_path(
    "CLAUDE_CODE_SECURITY_CERTS_DIR",
    CLAUDE_HOME / "certs",
)

CLUSTER_KEYS_DIR = _env_path(
    "CLAUDE_CODE_SECURITY_CLUSTER_KEYS_DIR",
    Path.home() / ".ssh" / "cluster-keys",
)

# ============================================================================
# File integrity
# ============================================================================

MANIFEST_PATH = _env_path(
    "CLAUDE_CODE_SECURITY_MANIFEST",
    CLAUDE_HOME / ".file_integrity_manifest.json",
)

SIGNING_KEY_PATH = _env_path(
    "CLAUDE_CODE_SECURITY_SIGNING_KEY",
    CLAUDE_HOME / ".file_integrity_key",
)

MONITORED_DIRS = [
    CLAUDE_HOME / "commands",
    CLAUDE_HOME / "hooks",
    CLAUDE_HOME / "agents",
    CLAUDE_HOME / "skills",
    CLAUDE_HOME / "rules",
]

MONITORED_EXTENSIONS = {".py", ".md", ".json", ".yaml", ".yml", ".sh"}

# ============================================================================
# Key vault
# ============================================================================

VAULT_SALT_PATH = VAULT_DIR / ".vault_salt"
PBKDF2_ITERATIONS = _env_int("CLAUDE_CODE_SECURITY_PBKDF2_ITERATIONS", 600_000)
KEY_LENGTH = 32  # AES-256

# ============================================================================
# Security gate
# ============================================================================

HIGH_RISK_SOURCES = {"webfetch", "cluster_message", "external_api", "user_upload"}

# Optional LLM classifier
LLM_CLASSIFIER_ENABLED = _env_bool("CLAUDE_CODE_SECURITY_LLM_CLASSIFIER", False)
LLM_CLASSIFIER_URL = os.environ.get(
    "CLAUDE_CODE_SECURITY_LLM_URL",
    "http://localhost:11434/api/generate",
)
LLM_CLASSIFIER_MODEL = os.environ.get(
    "CLAUDE_CODE_SECURITY_LLM_MODEL",
    "llama3.2:3b",
)
LLM_CACHE_MAX = _env_int("CLAUDE_CODE_SECURITY_LLM_CACHE_MAX", 1000)
LLM_CACHE_TTL = _env_int("CLAUDE_CODE_SECURITY_LLM_CACHE_TTL", 3600)

# Custom policy patterns file
CUSTOM_POLICIES_PATH = _env_path(
    "CLAUDE_CODE_SECURITY_POLICIES",
    CLAUDE_HOME / "custom_policies.json",
)

# ============================================================================
# Approval tokens
# ============================================================================

TOKEN_VALIDITY_SECONDS = _env_int("CLAUDE_CODE_SECURITY_TOKEN_TTL", 300)
APPROVAL_LOG_PATH = AUDIT_LOG_DIR / "approvals.jsonl"

# ============================================================================
# Tamper-proof log
# ============================================================================

TAMPER_PROOF_DB_PATH = _env_path(
    "CLAUDE_CODE_SECURITY_AUDIT_DB",
    AUDIT_LOG_DIR / "tamper_proof.db",
)

GENESIS_HASH = "0" * 64

# Optional Loki forwarding
LOKI_ENABLED = _env_bool("CLAUDE_CODE_SECURITY_LOKI_ENABLED", False)
LOKI_PUSH_URL = os.environ.get(
    "CLAUDE_CODE_SECURITY_LOKI_URL",
    "http://localhost:9900/loki/api/v1/push",
)

# ============================================================================
# Self-modification auditor
# ============================================================================

SELF_MOD_MONITORED_PATTERNS = [
    str(CLAUDE_HOME / "CLAUDE.md"),
    str(CLAUDE_HOME / "commands"),
    str(CLAUDE_HOME / "hooks"),
    str(CLAUDE_HOME / "agents"),
    str(CLAUDE_HOME / "skills"),
    str(CLAUDE_HOME / "rules"),
]

# ============================================================================
# Cluster auth
# ============================================================================

CLUSTER_SECRET_PATH = _env_path(
    "CLAUDE_CODE_SECURITY_CLUSTER_SECRET",
    CLAUDE_HOME / ".cluster_secret",
)

WRITE_AUDIT_DB_PATH = AUDIT_LOG_DIR / "write_attempts.db"

RBAC_CONFIG_PATH = _env_path(
    "CLAUDE_CODE_SECURITY_RBAC_CONFIG",
    CLAUDE_HOME / ".cluster_roles.json",
)

ROLE_PERMISSIONS = {
    "admin": {"read", "write", "build", "admin", "deploy", "configure"},
    "write": {"read", "write"},
    "build": {"read", "build"},
    "read": {"read"},
}

# Default node roles (override via RBAC_CONFIG_PATH)
DEFAULT_NODE_ROLES: dict = {}

# ============================================================================
# Cluster PKI
# ============================================================================

CHALLENGE_EXPIRY_SECONDS = _env_int("CLAUDE_CODE_SECURITY_CHALLENGE_TTL", 300)
MAX_NONCES = _env_int("CLAUDE_CODE_SECURITY_MAX_NONCES", 1000)
REVOCATION_LIST_PATH = AUDIT_LOG_DIR / "revoked_keys.json"

# ============================================================================
# TLS Manager
# ============================================================================

CA_KEY_VAULT_NAME = "cluster_ca_key"
CA_VALIDITY_YEARS = _env_int("CLAUDE_CODE_SECURITY_CA_VALIDITY_YEARS", 10)
NODE_CERT_VALIDITY_DAYS = _env_int("CLAUDE_CODE_SECURITY_CERT_VALIDITY_DAYS", 365)

# ============================================================================
# Circuit breaker
# ============================================================================

CB_FAILURE_THRESHOLD = _env_int("CLAUDE_CODE_SECURITY_CB_FAILURES", 3)
CB_TIMEOUT_SECONDS = _env_int("CLAUDE_CODE_SECURITY_CB_TIMEOUT", 120)
CB_SUCCESS_THRESHOLD = _env_int("CLAUDE_CODE_SECURITY_CB_SUCCESSES", 2)
