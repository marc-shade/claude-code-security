# Architecture

## Security Model

The system implements defense-in-depth through four progressive tiers, each adding a layer of security without requiring the layers above it.

### Threat Model

| Threat | Mitigation | Tier |
|--------|-----------|------|
| Tampered hooks/commands | HMAC-SHA256 file integrity signing | 1 |
| Plaintext signing keys | AES-256-GCM vault with machine-bound master key | 1 |
| Prompt injection via tool input | Heuristic pattern matching + circuit breaker | 2 |
| Policy violations in generated code | Configurable forbidden pattern scanner | 2 |
| Suspicious URLs/payloads | Threat intelligence patterns | 2 |
| Unauthorized config changes | Time-limited HMAC approval tokens | 2 |
| Post-hoc audit tampering | Hash-chained SQLite append-only log | 3 |
| Silent file modifications | Watchdog real-time monitoring | 3 |
| Unauthorized cluster writes | HMAC-SHA256 per-node tokens | 4 |
| Node impersonation | Ed25519 challenge-response auth | 4 |
| Cleartext inter-node traffic | ECDSA P-256 TLS with cluster CA | 4 |
| Privilege escalation | Role-based access control (RBAC) | 4 |

### Cryptographic Algorithms

| Purpose | Algorithm | Key Size | Standard |
|---------|-----------|----------|----------|
| File signing | HMAC-SHA256 | 256-bit | RFC 2104 |
| Key encryption | AES-256-GCM | 256-bit | NIST SP 800-38D |
| Key derivation | PBKDF2-SHA256 | 256-bit | RFC 8018 |
| Audit chain | SHA-256 | 256-bit | FIPS 180-4 |
| Approval tokens | HMAC-SHA256 | 256-bit | RFC 2104 |
| Node tokens | HMAC-SHA256 | 256-bit | RFC 2104 |
| Asymmetric auth | Ed25519 | 256-bit | RFC 8032 |
| TLS certificates | ECDSA P-256 | 256-bit | FIPS 186-4 |
| Content hashing | SHA-256 | 256-bit | FIPS 180-4 |

### Design Decisions

1. **Machine-bound encryption**: Master key derived from IOPlatformUUID (macOS) or /etc/machine-id (Linux). Keys cannot be decrypted on a different machine.

2. **Atomic writes**: All manifest and key file writes use `.tmp` + `os.rename()` for crash safety. No partial writes possible.

3. **Fail-closed injection scanner**: Circuit breaker pattern ensures that if the injection detector crashes repeatedly, it fails to BLOCK rather than silently allowing.

4. **Hash-chained audit**: Each audit entry's hash incorporates the previous entry's hash. Modifying any historical entry breaks the chain from that point forward.

5. **Progressive adoption**: Each tier works independently. Tier 1 requires zero running services. Tier 2-3 add scanning and audit without network dependencies.

6. **Config-driven**: All paths, thresholds, and feature flags centralized in `config.py`. Override via environment variables for CI/CD or custom deployments.

## Data Flow

### Pre-Tool-Use (Tier 2)

```
Claude Code invokes tool
    |
    v
pre_tool_use.py (stdin: JSON)
    |
    +-> Dangerous command check (Bash rm -rf, mkfs, etc.)
    |       |
    |       +-> BLOCK (exit 2)
    |
    +-> Security gate scan
    |   |
    |   +-> Injection detector (with circuit breaker)
    |   +-> Policy check (configurable patterns)
    |   +-> Threat intel (URL/IP/payload)
    |       |
    |       +-> BLOCK (exit 2) / WARN (exit 0, logged) / ALLOW (exit 0)
    |
    +-> Approval token check (for monitored file modifications)
            |
            +-> BLOCK (exit 2) if invalid token
```

### Post-Tool-Use (Tier 3)

```
Tool execution completes
    |
    v
post_tool_use.py (stdin: JSON)
    |
    +-> Self-modification audit (if monitored path)
    |   |
    |   +-> Compute unified diff
    |   +-> Store JSON audit file
    |   +-> Re-sign in integrity manifest
    |
    +-> Tamper-proof log entry
    |   |
    |   +-> Hash-chain append (SHA-256)
    |   +-> Optional Loki forward
    |
    v
exit 0 (always allow, audit-only)
```
