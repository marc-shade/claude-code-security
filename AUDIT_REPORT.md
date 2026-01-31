# Security Audit Report: claude-code-security

**Date:** 2026-01-31
**Auditor:** Gemini Agent
**Target:** `claude_code_security/` and `hooks/`

## Executive Summary

The `claude-code-security` library implements a multi-tiered security defense for the Claude Code agent. While it includes strong cryptographic primitives (Ed25519, AES-256-GCM, HMAC-SHA256) and good concepts (tamper-proof logs, circuit breakers), there are critical vulnerabilities in the implementation of TLS, Audit Logging, and Command Filtering that significantly undermine the security guarantees.

## Findings Summary

| ID | Severity | Category | Component | Description |
|----|----------|----------|-----------|-------------|
| 01 | **CRITICAL** | Cryptography | TLS Manager | Hostname verification disabled, enabling MITM attacks. |
| 02 | **HIGH** | Concurrency | Tamper-Proof Log | Race condition causes audit chain corruption under load. |
| 03 | **HIGH** | Auth | Cluster PKI | Nonce replay protection is ephemeral and clears on restart. |
| 04 | **HIGH** | Validation | Pre-Tool Hook | Command blocklist is easily bypassed and ineffective. |
| 05 | **MEDIUM** | Cryptography | Key Vault | Entropy source for master key is predictable/local-only. |
| 06 | **MEDIUM** | Input Validation | File Integrity | Potential path traversal in monitoring logic. |

---

## Detailed Findings

### 01. TLS Hostname Verification Disabled (Critical)

**File:** `claude_code_security/tls_manager.py`
**Line:** `194` (`ctx.check_hostname = False`)

**Description:**
The `create_ssl_context` method explicitly disables hostname verification. In the cluster architecture, every node possesses a valid certificate signed by the common Cluster CA. By disabling hostname checks, any compromised node can present its own valid certificate to impersonate the Orchestrator or any other node. A malicious node can perform a Man-in-the-Middle (MITM) attack on all inter-node traffic.

**Recommendation:**
Enable hostname verification:
```python
ctx.check_hostname = True
ctx.verify_mode = ssl.CERT_REQUIRED
```
Ensure certificates are generated with correct Subject Alternative Names (SANs) matching the nodes' addressable hostnames (which appears to be implemented, but verification must be on).

### 02. Audit Log Chain Corruption (High)

**File:** `claude_code_security/tamper_proof_log.py`
**Function:** `append`

**Description:**
The hash-chaining logic relies on a read-modify-write sequence (`get_last_hash` -> `compute_hash` -> `insert`) that is not atomic across processes. The implementation uses `threading.Lock()` which only protects threads within a single process. If multiple hook processes (e.g., `post_tool_use`) run concurrently, they may both read the same `prev_hash` and insert diverging entries. This "forks" the chain, causing subsequent validation (`verify_chain`) to fail, effectively corrupting the audit log's integrity status.

**Recommendation:**
Use SQLite transactions with `EXCLUSIVE` locking to ensure the read-compute-insert sequence is atomic across processes.
```python
conn.execute("BEGIN EXCLUSIVE")
# ... get hash, compute, insert ...
conn.commit()
```

### 03. Cluster PKI Replay Attack (High)

**File:** `claude_code_security/cluster_pki.py`
**Variable:** `_used_nonces`

**Description:**
The replay protection mechanism stores used nonces in an in-memory `OrderedDict`. This cache is lost whenever the process restarts. An attacker can capture a valid signed challenge-response from a legitimate node and replay it to a restarted server (within the 5-minute validity window) to authenticate as that node.

**Recommendation:**
Persist the `_used_nonces` state to disk (e.g., in a SQLite table similar to the audit log) or use a stateless challenge mechanism (e.g., signing a server-provided challenge that includes a server-bound secret/timestamp).

### 04. Trivial Command Blocklist Bypass (High)

**File:** `hooks/pre_tool_use.py`
**Section:** `Dangerous command blocking`

**Description:**
The blocklist relies on simple substring matching for specific commands like `"rm -rf /"`. This is ineffective against:
1. Variations: `rm -rf /etc`, `rm -fr /`, `rm  -rf /` (extra spaces).
2. Other destructive commands: `shred`, `wipe`, `> /dev/sda`.
3. Obfuscation: `eval $(base64 -d ...)`
It provides a false sense of security.

**Recommendation:**
Do not rely on blocklists for shell commands. If strict control is needed, allow *only* a specific allowlist of safe commands, or run the agent in a strictly confined sandbox (container/VM) where destructive commands cannot harm the host system. If a blocklist is retained, it must be vastly more robust (regex-based, token-aware), but this is still prone to bypass.

### 05. Predictable Key Vault Entropy (Medium)

**File:** `claude_code_security/key_vault.py`
**Function:** `_get_machine_entropy`

**Description:**
The master key is derived from `hostname`, `platform.node()`, and machine IDs. These are static values often available to any user on the system. The security of the vault relies entirely on the file permissions (`0o600`) of the `.vault_salt` file. If a local attacker can read the salt (e.g., via a backup or misconfiguration), they can deterministically regenerate the master key.

**Recommendation:**
This is acceptable for a "Tier 1" local protection scheme but should not be mistaken for hardware-backed security. For higher security, integrate with the OS keyring (macOS Keychain, Linux Secret Service, Windows Credential Locker) using a library like `keyring`.

### 06. Path Traversal & Monitoring Logic (Medium)

**File:** `claude_code_security/file_integrity.py`
**Function:** `_path_key`

**Description:**
The logic `path.relative_to(Path.home())` assumes all monitored files are under the user's home directory. If `MONITORED_DIRS` includes paths outside home (e.g., `/tmp` or project volumes), this method will raise `ValueError` and monitoring will fail.
Additionally, in `hooks/pre_tool_use.py`, the `file_path` from user input is not validated against directory traversal attacks (e.g., `../../etc/passwd`) before being checked against monitored paths.

**Recommendation:**
Use absolute paths for keys in the manifest, or calculate relative paths from the project root. Ensure all file path inputs are resolved (`Path(p).resolve()`) and checked against allowed root directories before processing.

---

## Conclusion
The repository contains solid scaffolding but requires immediate remediation of the Critical and High findings before being deployed in a production or untrusted environment.
