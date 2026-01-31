# Security Rules for CLAUDE.md

Add these rules to your `~/.claude/CLAUDE.md` or project `CLAUDE.md`.

## Security Policy

### File Integrity
- All hooks, commands, agents, and skills are HMAC-SHA256 signed
- Session start verifies integrity manifest; tampered files block execution
- After modifying any monitored file, re-sign via `python3 -c "from claude_code_security.file_integrity import quick_sign_all; quick_sign_all()"`

### Self-Modification Rules
- Changes to CLAUDE.md, hooks, commands, agents, skills, and rules are audited
- Unified diffs are stored in `~/.claude/audit_logs/`
- Modified files are automatically re-signed in the integrity manifest

### Approval Tokens
- Sensitive modifications require approval tokens (HMAC time-limited, 5min expiry)
- Never use `CHANGE_APPROVED=true` environment variable bypass
- Generate tokens: `python3 -c "from claude_code_security.approval_tokens import ApprovalTokenManager; print(ApprovalTokenManager().generate_token('modify:path'))"`

### Security Gate
- All tool inputs pass through injection detection before execution
- Content from webfetch, external APIs, and user uploads is scanned
- Dangerous Bash patterns (rm -rf /, mkfs, fork bombs) are blocked

### Audit Trail
- All tool executions are logged to hash-chained tamper-proof audit log
- Chain integrity is verifiable: `python3 -c "from claude_code_security.tamper_proof_log import TamperProofLog; print(TamperProofLog().verify_chain())"`
