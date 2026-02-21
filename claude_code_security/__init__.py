"""
Claude Code Security - Progressive security hardening for Claude Code.

Tiers:
    1. Foundation: Key vault + file integrity signing + token vault
    2. Active Defense: Security gate + circuit breaker + approval tokens
    3. Audit & Monitoring: Tamper-proof log + self-modification auditor + file watcher
    4. Cluster: Node auth + PKI + TLS
"""

__version__ = "1.1.0"

from claude_code_security.token_vault import TokenVault

__all__ = ["TokenVault"]
