# Claude Code Security

Progressive security hardening for [Claude Code](https://claude.com/claude-code) installations.

## Quickstart (Tier 1 in 3 commands)

```bash
git clone <this-repo> && cd claude-code-security
pip install -e .
bash setup.sh --tier 1
```

## Architecture

```
                    +--------------------------+
                    |     Claude Code CLI      |
                    +-------+--------+---------+
                            |        |
              SessionStart  | PreTool| PostTool
                  Hook      |  Hook  |  Hook
                    |        |        |
        +-----------v--------v--------v-----------+
        |         Security Hook Layer              |
        |  session_start.py | pre_tool_use.py      |
        |  security_orchestrator.py                |
        |  post_tool_use.py                        |
        +----+------+------+------+------+---------+
             |      |      |      |      |
    +--------v--+ +-v------v-+ +--v---+ +v--------+
    | File      | | Security | |Audit | | Cluster |
    | Integrity | | Gate     | |Trail | | Auth    |
    | [Tier 1]  | | [Tier 2] | |[T 3] | | [Tier 4]|
    +-----------+ +----------+ +------+ +---------+
    | HMAC-256  | | Injection| |Hash  | | HMAC    |
    | signing   | | Policy   | |chain | | Ed25519 |
    | KeyVault  | | Threat   | |SQLite| | TLS/PKI |
    |           | | Circuit  | |Watch | | RBAC    |
    +-----------+ +----------+ +------+ +---------+
```

## Security Tiers

| Tier | Name | What You Get | Deps |
|------|------|--------------|------|
| 1 | Foundation | Key vault + file integrity signing, session-start verification | None |
| 2 | Active Defense | + Injection scanner, policy gate, circuit breaker, approval tokens, pre/post hooks | None |
| 3 | Audit & Monitoring | + Hash-chained tamper-proof log, self-mod auditor, real-time file watcher | `watchdog` |
| 4 | Cluster | + Multi-node HMAC auth, Ed25519 PKI, TLS certificates, RBAC | `cryptography` |

## Installation

```bash
# Tier 1-2 (no external deps)
pip install -e .

# Tier 3 (file watcher)
pip install -e ".[watcher]"

# Tier 4 (cluster crypto)
pip install -e ".[crypto]"

# Everything
pip install -e ".[all]"

# Development
pip install -e ".[dev]"
```

## Setup

```bash
# Recommended: Tier 2 with pre/post hooks
bash setup.sh --tier 2

# Preview without changes
bash setup.sh --tier 2 --dry-run

# Full audit trail
bash setup.sh --tier 3

# Multi-node cluster
bash setup.sh --tier 4
```

The setup script:
1. Installs the Python package
2. Creates `~/.claude/` directories
3. Copies hook scripts to `~/.claude/hooks/`
4. Merges hook settings into `~/.claude/settings.json`
5. Signs all monitored files
6. Verifies the installation

## Configuration

All paths and thresholds live in `claude_code_security/config.py` and can be overridden via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAUDE_CODE_SECURITY_HOME` | `~/.claude` | Base directory |
| `CLAUDE_CODE_SECURITY_VAULT_DIR` | `~/.claude/.vault` | Encrypted key vault |
| `CLAUDE_CODE_SECURITY_AUDIT_DIR` | `~/.claude/audit_logs` | Audit trail |
| `CLAUDE_CODE_SECURITY_PBKDF2_ITERATIONS` | `600000` | Key derivation rounds |
| `CLAUDE_CODE_SECURITY_TOKEN_TTL` | `300` | Approval token lifetime (seconds) |
| `CLAUDE_CODE_SECURITY_LLM_CLASSIFIER` | `false` | Enable LLM injection classifier |
| `CLAUDE_CODE_SECURITY_LOKI_ENABLED` | `false` | Forward audit to Loki |

## Hook Exit Codes

| Code | Meaning | Effect |
|------|---------|--------|
| 0 | Allow | Tool proceeds normally |
| 1 | Error | Tool proceeds, error logged |
| 2 | Block | Tool execution rejected |

## Usage Examples

### Verify file integrity
```python
from claude_code_security.file_integrity import quick_verify
report = quick_verify()
print(report.summary())
```

### Scan content for threats
```python
from claude_code_security.security_gate import scan_content
verdict = scan_content("some text", source="webfetch")
print(verdict.action)  # ALLOW, WARN, or BLOCK
```

### Generate approval token
```python
from claude_code_security.approval_tokens import ApprovalTokenManager
mgr = ApprovalTokenManager()
token = mgr.generate_token("modify:~/.claude/CLAUDE.md")
```

### Verify audit chain
```python
from claude_code_security.tamper_proof_log import TamperProofLog
log = TamperProofLog()
print(log.verify_chain())
```

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific tier
python -m pytest tests/test_key_vault.py tests/test_file_integrity.py -v  # Tier 1
python -m pytest tests/test_security_gate.py -v                           # Tier 2
python -m pytest tests/test_tamper_proof_log.py -v                        # Tier 3
python -m pytest tests/test_cluster_pki.py tests/test_tls_manager.py -v   # Tier 4
```

## Project Structure

```
claude-code-security/
+-- claude_code_security/       # Python package
|   +-- config.py               # All paths/thresholds (env-overridable)
|   +-- key_vault.py            # AES-256-GCM encrypted key storage
|   +-- file_integrity.py       # HMAC-SHA256 file signing
|   +-- security_gate.py        # Injection + policy + threat scanning
|   +-- circuit_breaker.py      # Fail-closed pattern
|   +-- approval_tokens.py      # HMAC time-limited tokens
|   +-- tamper_proof_log.py     # Hash-chained SQLite audit
|   +-- self_modification_auditor.py  # Diff capture on config changes
|   +-- file_watcher.py         # Watchdog real-time monitoring
|   +-- cluster_auth.py         # HMAC + RBAC node auth
|   +-- cluster_pki.py          # Ed25519 challenge-response
|   +-- tls_manager.py          # ECDSA P-256 cluster CA
+-- hooks/                      # Ready-to-install hook scripts
+-- templates/                  # Settings templates per tier
+-- tests/                      # Full test suite
+-- docs/                       # Architecture, guides, reference
+-- setup.sh                    # One-command installer
+-- pyproject.toml              # pip-installable package
```

## License

MIT
