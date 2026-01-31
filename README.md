# Claude Code Security

<p align="center">
  <img width="300" alt="ChatGPT Image Jan 31, 2026, 10_02_42 AM" src="https://github.com/user-attachments/assets/b60bc0da-e299-4d0c-89aa-f23b30bc7b6a" />
</p>

Progressive security hardening for [Claude Code](https://claude.com/claude-code) installations. Protect your agent's configuration, hooks, and runtime from injection attacks, unauthorized modifications, and supply chain risks.

## Security Posture

This project was independently audited by **OpenAI Codex** and **Google Gemini** (Jan 2026). All Critical and High findings have been remediated:

| Finding | Severity | Status |
|---------|----------|--------|
| TLS hostname verification disabled | CRITICAL | Fixed |
| Audit log race condition + unkeyed chain | HIGH | Fixed |
| PKI nonce replay on restart | HIGH | Fixed |
| Command blocklist bypass | HIGH | Fixed |
| Node ID path traversal | HIGH | Fixed |
| Hook fail-open on exceptions | HIGH | Fixed |
| Ed25519 token parsing | MEDIUM | Fixed |
| Predictable key vault entropy | MEDIUM | Documented |
| Unsigned files pass session start | MEDIUM | Fixed |
| Absolute path for ioreg | LOW | Fixed |

Full audit reports: [`AUDIT_REPORT.md`](AUDIT_REPORT.md)

## Quickstart

```bash
git clone https://github.com/marc-shade/claude-code-security.git
cd claude-code-security
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
    | HMAC-256  | | Injection| |HMAC  | | HMAC    |
    | signing   | | Policy   | |chain | | Ed25519 |
    | KeyVault  | | Threat   | |SQLite| | TLS/PKI |
    |           | | Circuit  | |Watch | | RBAC    |
    +-----------+ +----------+ +------+ +---------+
```

## Security Tiers

| Tier | Name | What You Get | Deps |
|------|------|--------------|------|
| 1 | Foundation | Key vault (AES-256-GCM) + file integrity signing (HMAC-SHA256), session-start verification | None |
| 2 | Active Defense | + Injection scanner, policy gate, circuit breaker, approval tokens, pre/post hooks | None |
| 3 | Audit & Monitoring | + HMAC-keyed hash-chained tamper-proof log, self-mod auditor, real-time file watcher | `watchdog` |
| 4 | Cluster | + Multi-node HMAC auth, Ed25519 PKI (persistent nonce replay protection), TLS certificates (ECDSA P-256), RBAC | `cryptography` |

Each tier includes all protections from lower tiers. Hooks fail-closed for sensitive tools (Bash, Write, Edit) to prevent bypass on errors.

## Installation

```bash
# Tier 1-2 (no external deps beyond stdlib)
pip install -e .

# Tier 3 (file watcher)
pip install -e ".[watcher]"

# Tier 4 (cluster crypto)
pip install -e ".[crypto]"

# Everything
pip install -e ".[all]"

# Development (includes pytest)
pip install -e ".[dev]"
```

## Setup

```bash
# Preview without changes
bash setup.sh --tier 2 --dry-run

# Recommended: Tier 2 with pre/post hooks
bash setup.sh --tier 2

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

All paths and thresholds are in `claude_code_security/config.py`, overridable via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAUDE_CODE_SECURITY_HOME` | `~/.claude` | Base directory |
| `CLAUDE_CODE_SECURITY_VAULT_DIR` | `~/.claude/.vault` | Encrypted key vault |
| `CLAUDE_CODE_SECURITY_AUDIT_DIR` | `~/.claude/audit_logs` | Audit trail |
| `CLAUDE_CODE_SECURITY_PBKDF2_ITERATIONS` | `600000` | Key derivation rounds |
| `CLAUDE_CODE_SECURITY_TOKEN_TTL` | `300` | Approval token lifetime (seconds) |
| `CLAUDE_CODE_SECURITY_LLM_CLASSIFIER` | `false` | Enable optional LLM injection classifier |
| `CLAUDE_CODE_SECURITY_LOKI_ENABLED` | `false` | Forward audit entries to Loki |
| `CLAUDE_CODE_SECURITY_CB_FAILURES` | `3` | Circuit breaker failure threshold |
| `CLAUDE_CODE_SECURITY_CB_TIMEOUT` | `120` | Circuit breaker timeout (seconds) |

## Hook Behavior

| Code | Meaning | Effect |
|------|---------|--------|
| 0 | Allow | Tool proceeds normally |
| 1 | Error | Tool proceeds, error logged (non-sensitive tools only) |
| 2 | Block | Tool execution rejected |

Sensitive tools (Bash, Write, Edit) **fail-closed**: any unhandled exception in the hook results in exit code 2 (block), not 1. This prevents an attacker from crashing the hook to bypass security checks.

Command filtering uses **regex-based pattern matching** (not simple substring) to detect destructive commands, obfuscation via `eval`/`base64`, and pipe-to-shell attacks.

## Usage Examples

### Verify file integrity
```python
from claude_code_security.file_integrity import quick_verify
report = quick_verify()
print(report.summary())  # VERIFIED:42 | UNSIGNED:3 (85ms)
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

### Verify audit chain integrity
```python
from claude_code_security.tamper_proof_log import TamperProofLog
log = TamperProofLog()
result = log.verify_chain()
print(result)  # {'valid': True, 'entries_checked': 128, ...}
```

### Cluster node authentication (Tier 4)
```python
from claude_code_security.cluster_pki import ClusterPKI
pki = ClusterPKI()
pki.get_or_create_keypair("mac-studio")
challenge = pki.create_auth_challenge()
sig = pki.sign_challenge("mac-studio", challenge["challenge_data"])
valid, msg = pki.verify_challenge_response("mac-studio", challenge["challenge_data"], sig)
```

## Cryptographic Primitives

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Key Vault | AES-256-GCM + PBKDF2 (600K rounds) | Encrypt signing keys at rest |
| File Integrity | HMAC-SHA256 | Sign and verify monitored files |
| Audit Chain | HMAC-SHA256 (keyed) | Tamper-evident hash chain |
| Approval Tokens | HMAC-SHA256 + timestamp | Time-limited modification tokens |
| Cluster Auth | HMAC-SHA256 | Per-node token derivation |
| Cluster PKI | Ed25519 | Challenge-response authentication |
| TLS Certificates | ECDSA P-256 | Inter-node encrypted communication |

## Testing

```bash
# Run all 93 tests
python -m pytest tests/ -v

# By tier
python -m pytest tests/test_key_vault.py tests/test_file_integrity.py -v  # Tier 1
python -m pytest tests/test_security_gate.py -v                           # Tier 2
python -m pytest tests/test_tamper_proof_log.py -v                        # Tier 3
python -m pytest tests/test_cluster_pki.py tests/test_tls_manager.py -v   # Tier 4
```

## Project Structure

```
claude-code-security/
+-- claude_code_security/              # Python package
|   +-- config.py                      # All paths/thresholds (env-overridable)
|   +-- key_vault.py                   # AES-256-GCM encrypted key storage
|   +-- file_integrity.py              # HMAC-SHA256 file signing
|   +-- security_gate.py              # Injection + policy + threat scanning
|   +-- circuit_breaker.py            # Fail-closed pattern
|   +-- approval_tokens.py            # HMAC time-limited tokens
|   +-- tamper_proof_log.py           # HMAC-keyed hash-chained SQLite audit
|   +-- self_modification_auditor.py  # Diff capture on config changes
|   +-- file_watcher.py              # Watchdog real-time monitoring
|   +-- cluster_auth.py              # HMAC + RBAC node auth
|   +-- cluster_pki.py               # Ed25519 challenge-response
|   +-- tls_manager.py               # ECDSA P-256 cluster CA
+-- hooks/                            # Ready-to-install hook scripts
+-- templates/                         # Settings templates per tier
+-- tests/                             # 93 tests across all tiers
+-- docs/                              # Architecture, tier guide, reference
+-- setup.sh                           # One-command installer
+-- pyproject.toml                     # pip-installable package
```

## Known Limitations

- **Key Vault entropy** derives from machine identifiers (hostname, IOPlatformUUID/machine-id). This is Tier 1 protection, not hardware-backed. For higher security, integrate with OS keyring.
- **Command blocklist** is defense-in-depth, not a sandbox. Determined adversaries can bypass regex filters. For strong isolation, run Claude Code in a container or VM.
- **Self-mod auditor** stores full diffs which may contain secrets. Audit log directory should be access-controlled.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - Security model, threat model, design decisions
- [`docs/TIER_GUIDE.md`](docs/TIER_GUIDE.md) - Detailed guide per tier with tradeoffs
- [`docs/HOOKS_REFERENCE.md`](docs/HOOKS_REFERENCE.md) - How Claude Code hooks work
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) - Common issues, recovery procedures
- [`AUDIT_REPORT.md`](AUDIT_REPORT.md) - External security audit findings

## License

MIT
