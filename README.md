# Claude Code Security

<p align="center">
  <img width="300" alt="ChatGPT Image Jan 31, 2026, 10_02_42 AM" src="https://github.com/user-attachments/assets/b60bc0da-e299-4d0c-89aa-f23b30bc7b6a" />
</p>

Progressive security hardening for [Claude Code](https://claude.com/claude-code) installations. Protect your agent's configuration, hooks, and runtime from injection attacks, unauthorized modifications, and supply chain risks.

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
| 1 | Foundation | Key vault (AES-256-GCM) + token vault + file integrity signing (HMAC-SHA256), session-start verification | None |
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
| `CLAUDE_CODE_SECURITY_REDSAGE_ENABLED` | `false` | Enable RedSage local LLM deep analysis |
| `CLAUDE_CODE_SECURITY_REDSAGE_URL` | `http://localhost:8800/v1/chat/completions` | RedSage API endpoint |
| `CLAUDE_CODE_SECURITY_REDSAGE_TIMEOUT` | `30` | RedSage query timeout (seconds) |

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

### Deep analysis with RedSage (local LLM)
```python
from claude_code_security.redsage_analyzer import analyze_content, extract_iocs

# Analyze flagged content
result = analyze_content("suspicious payload", source="webfetch")
print(result)  # {"verdict": "MALICIOUS", "confidence": 0.95, ...}

# Extract IOCs from text
iocs = extract_iocs("connection to 185.220.101.34 on port 9001")
print(iocs)  # {"iocs": [{"type": "ip", ...}], "risk_summary": "..."}
```

### Verify audit chain integrity
```python
from claude_code_security.tamper_proof_log import TamperProofLog
log = TamperProofLog()
result = log.verify_chain()
print(result)  # {'valid': True, 'entries_checked': 128, ...}
```

### Store and manage API tokens
```python
from claude_code_security.token_vault import TokenVault

vault = TokenVault()

# Store tokens (auto-categorized by name)
vault.store_token("ANTHROPIC_API_KEY", "sk-ant-...")
vault.store_token("STRIPE_SECRET_KEY", "sk_live_...", category="service")

# Retrieve
key = vault.get_token("ANTHROPIC_API_KEY")

# Generate shell exports for all tokens
print(vault.export_shell())
# => export ANTHROPIC_API_KEY='sk-ant-...'
# => export STRIPE_SECRET_KEY='sk_live_...'

# Import tokens from current environment
results = vault.import_from_env(names=["OPENAI_API_KEY", "GROQ_API_KEY"])

# Status summary
print(vault.get_status())
# => {'token_count': 3, 'by_category': {'llm': 2, 'service': 1}, ...}
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

## Production Hooks

The `hooks/` directory contains battle-tested hook scripts ready for production use. Copy them to `~/.claude/hooks/` and register in `~/.claude/settings.json`.

### Bash Safety Logger (`hooks/bash_safety_logger.py`)

**Hook type:** PreToolUse (command), matcher: `Bash`

Blocks dangerous commands via regex pattern matching across six categories:

| Category | Examples |
|----------|----------|
| Credential leaks | API keys (OpenAI, Anthropic, AWS, GitHub PATs), bearer tokens, private keys |
| Reverse shells | bash -i, nc -e, socat, python/perl/ruby/php reverse shells |
| Data exfiltration | curl/wget file upload, DNS exfil, env-to-network pipes |
| Obfuscated exec | base64 decode to shell, curl pipe to sh/python, eval subshells |
| Cron/SSH injection | Crontab remote exec, SSH authorized_keys manipulation |
| Dangerous rm | rm -rf / (blocked), rm -rf /path (auto-fixed with --preserve-root) |

Localhost commands are exempted from credential and obfuscation checks (routine dev pattern). All commands are logged to `~/.claude/bash_commands.jsonl` for audit.

### Damage Control (`hooks/damage_control_check.py` + `hooks/damage_control_patterns.yaml`)

**Hook type:** PreToolUse integration (import into your pre-tool-use hook)

YAML-driven command and path protection with three path categories:

- **zeroAccessPaths**: No read, write, or any access (`.env`, `~/.ssh/`, `~/.aws/`, `*.pem`, etc.)
- **readOnlyPaths**: Read allowed, write/edit/delete blocked (`/etc/`, lock files, build artifacts)
- **noDeletePaths**: Read/write allowed, delete blocked (`~/.claude/`, `.git/`, LICENSE, CI configs)

Command patterns cover destructive operations across 20+ platforms: git, AWS, GCP, Firebase, Vercel, Netlify, Cloudflare, Docker, Kubernetes, Terraform, Heroku, Fly.io, DigitalOcean, and database CLIs. Supports glob patterns and `ask: true` for confirmation prompts on risky-but-legitimate operations (e.g., `git stash drop`).

### Permission Request (`hooks/permission_request.py`)

**Hook type:** PermissionRequest (command), matcher: `.*`

Intelligent auto-approval that reduces permission prompt fatigue:
- Auto-approves safe tools (Glob, Grep, WebSearch) unconditionally
- Auto-approves Read/Write/Edit for trusted project paths (configurable)
- Auto-approves common Bash commands (ls, cat, grep, git, python, etc.)
- Auto-denies dangerous patterns (rm -rf /, fork bombs, pipe-to-shell)
- Logs all decisions to `~/.claude/permission_log.jsonl`

### Quality Gates (Agent Teams)

Two hooks for [Agent Teams](https://docs.anthropic.com/en/docs/claude-code/agent-teams) that enforce production-quality standards:

**Task Completed (`hooks/task_completed_quality_gate.py`)**
- **Hook type:** TaskCompleted (command)
- Parses the teammate's transcript to extract actual code written (Write/Edit tool inputs)
- Checks for: unresolved TODOs/FIXMEs, NotImplementedError stubs, fake/mock data assignments, bare `except: pass`
- Exit code 2 blocks task completion with feedback

**Teammate Idle (`hooks/teammate_idle_quality_gate.py`)**
- **Hook type:** TeammateIdle (command)
- Finds recently modified files via `git diff` (scoped to 30-minute recency window)
- Runs `py_compile` on modified Python files to catch syntax errors
- Checks for forbidden patterns: TODO, FIXME, HACK, placeholder, mock data, hardcoded, proof of concept
- Exit code 2 keeps the teammate working with actionable feedback

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
# Run all tests
python -m pytest tests/ -v

# By tier
python -m pytest tests/test_key_vault.py tests/test_token_vault.py tests/test_file_integrity.py -v  # Tier 1
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
|   +-- token_vault.py                # API token management on top of KeyVault
|   +-- file_integrity.py              # HMAC-SHA256 file signing
|   +-- security_gate.py              # Injection + policy + threat scanning
|   +-- circuit_breaker.py            # Fail-closed pattern
|   +-- approval_tokens.py            # HMAC time-limited tokens
|   +-- tamper_proof_log.py           # HMAC-keyed hash-chained SQLite audit
|   +-- self_modification_auditor.py  # Diff capture on config changes
|   +-- file_watcher.py              # Watchdog real-time monitoring
|   +-- cluster_auth.py              # HMAC + RBAC node auth
|   +-- cluster_pki.py               # Ed25519 challenge-response
|   +-- redsage_analyzer.py          # Local LLM deep threat analysis
|   +-- tls_manager.py               # ECDSA P-256 cluster CA
+-- hooks/                            # Production hook scripts
|   +-- bash_safety_logger.py         # Bash command blocking + audit
|   +-- damage_control_check.py       # Path/command damage control
|   +-- damage_control_patterns.yaml  # YAML patterns for damage control
|   +-- permission_request.py         # Intelligent auto-approval
|   +-- task_completed_quality_gate.py  # Agent Teams task validation
|   +-- teammate_idle_quality_gate.py   # Agent Teams idle check
|   +-- pre_tool_use.py               # Security orchestrator hook
|   +-- post_tool_use.py              # Post-execution audit hook
|   +-- security_orchestrator.py      # Multi-phase security pipeline
|   +-- session_start.py              # Session initialization hook
+-- templates/                         # Settings templates + examples
|   +-- settings-tier[1-4].json       # Per-tier settings templates
|   +-- threat_spec_fence.json        # CVE filter template for your stack
+-- tests/                             # Tests across all tiers
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
