# Tier Guide

## Tier 1: Foundation

**What it does**: Signs all your hooks, commands, agents, skills, and rules with HMAC-SHA256. Verifies them every time Claude Code starts.

**Install**: `bash setup.sh --tier 1`

**Components**:
- `key_vault.py`: Encrypts signing keys at rest with AES-256-GCM
- `file_integrity.py`: Signs/verifies files with HMAC-SHA256
- `session_start.py` hook: Runs verification on every session start

**Tradeoffs**:
- (+) Zero external dependencies
- (+) Sub-100ms verification for hundreds of files
- (+) Detects any unauthorized modification to your Claude Code config
- (-) Does not prevent modifications, only detects them after the fact
- (-) Signing key tied to machine (cannot verify on different machine)

**When to use**: Always. This is the minimum recommended security tier.

---

## Tier 2: Active Defense

**What it does**: Scans tool inputs before execution. Blocks injection attempts, policy violations, and suspicious payloads. Adds time-limited approval tokens for sensitive changes.

**Install**: `bash setup.sh --tier 2`

**Components** (adds to Tier 1):
- `security_gate.py`: Three-phase content scanner
- `circuit_breaker.py`: Fail-closed pattern for scanner reliability
- `approval_tokens.py`: HMAC time-limited action authorization
- `pre_tool_use.py` hook: Runs security gate before every tool
- `post_tool_use.py` hook: Logs tool executions

**Tradeoffs**:
- (+) Blocks known injection patterns before execution
- (+) Configurable policy patterns via `custom_policies.json`
- (+) Circuit breaker prevents scanner failures from becoming security holes
- (-) Pattern-based detection; novel injection techniques may pass
- (-) False positives possible on legitimate content containing trigger words

**When to use**: Recommended for all installations handling untrusted content.

---

## Tier 3: Audit & Monitoring

**What it does**: Creates a tamper-proof audit trail of all tool executions. Captures diffs when configuration files change. Watches file system in real-time.

**Install**: `bash setup.sh --tier 3` (requires `pip install watchdog`)

**Components** (adds to Tier 2):
- `tamper_proof_log.py`: Hash-chained SQLite audit log
- `self_modification_auditor.py`: Unified diff capture for config changes
- `file_watcher.py`: Real-time watchdog monitoring

**Tradeoffs**:
- (+) Tamper-evident: modifying any historical audit entry breaks the hash chain
- (+) Real-time alerts for file changes
- (+) Full diff history for every configuration change
- (+) Optional Loki forwarding for centralized monitoring
- (-) Requires `watchdog` Python package
- (-) SQLite audit log grows over time (consider periodic archival)
- (-) Watchdog adds background thread and memory overhead

**When to use**: Production environments, compliance requirements, or when you need forensic capability.

---

## Tier 4: Cluster

**What it does**: Adds multi-node authentication with HMAC tokens, Ed25519 challenge-response, TLS certificates, and role-based access control.

**Install**: `bash setup.sh --tier 4` (requires `pip install cryptography`)

**Components** (adds to Tier 3):
- `cluster_auth.py`: HMAC-SHA256 per-node tokens + RBAC
- `cluster_pki.py`: Ed25519 asymmetric authentication
- `tls_manager.py`: Self-signed cluster CA with per-node certs

**Tradeoffs**:
- (+) Mutual TLS authentication between nodes
- (+) Ed25519 challenge-response prevents token replay
- (+) RBAC with admin/write/build/read roles
- (+) Key revocation list for compromised nodes
- (-) Requires `cryptography` Python package
- (-) Certificate distribution requires manual or automated SCP
- (-) Shared secret must be distributed to all nodes

**When to use**: Multi-machine Claude Code deployments where nodes communicate over a network.
