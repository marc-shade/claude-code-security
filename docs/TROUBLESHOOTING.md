# Troubleshooting

## Common Issues

### Hook not executing

**Symptom**: Security hooks don't run when using Claude Code.

**Fix**:
1. Check settings: `cat ~/.claude/settings.json | python3 -m json.tool`
2. Verify hooks section exists with correct paths
3. Ensure hook files are executable: `chmod +x ~/.claude/hooks/*.py`
4. Check Python path: `which python3`

### "Module not found" errors in hooks

**Symptom**: Hook scripts fail with `ImportError: No module named 'claude_code_security'`

**Fix**:
```bash
# Re-install the package
cd /path/to/claude-code-security
pip install -e .

# Verify installation
python3 -c "import claude_code_security; print(claude_code_security.__version__)"
```

### File integrity reports all UNSIGNED

**Symptom**: Session start hook reports hundreds of unsigned files.

**Fix**: Sign all monitored files:
```bash
python3 -c "from claude_code_security.file_integrity import quick_sign_all; print(quick_sign_all())"
```

### False positive: legitimate content blocked

**Symptom**: Security gate blocks content that contains trigger words like "TODO" or "placeholder" in legitimate context.

**Fix**:
1. Edit `templates/custom_policies.json` to remove problematic patterns
2. Copy to `~/.claude/custom_policies.json`
3. Or disable policy scanning for specific tools:
```python
verdict = scan_content(content, scan_code=False)
```

### Vault decryption fails after hardware change

**Symptom**: `Failed to load key` errors after moving to a new machine.

**Cause**: Master key is derived from machine-specific entropy (IOPlatformUUID / machine-id). A different machine generates a different master key.

**Fix**:
```bash
# Remove old vault and re-initialize
rm -rf ~/.claude/.vault
python3 -c "from claude_code_security.key_vault import KeyVault; KeyVault()"
python3 -c "from claude_code_security.file_integrity import quick_sign_all; quick_sign_all()"
```

### Tamper-proof log chain broken

**Symptom**: `verify_chain()` reports `valid: false`

**Cause**: Database was modified outside the logging system.

**Fix**:
```python
from claude_code_security.tamper_proof_log import TamperProofLog
log = TamperProofLog()
result = log.verify_chain()
print(f"Chain broken at entry {result['first_broken']}")
# Review the entries around the break point
entries = log.get_entries(limit=5)
```

Note: A broken chain cannot be repaired. The entries from the break point forward may be untrustworthy. Consider archiving the corrupted log and starting fresh.

### Circuit breaker stuck in OPEN state

**Symptom**: Security gate blocks everything with "circuit OPEN" messages.

**Fix**:
```python
from claude_code_security.security_gate import _get_injection_breaker
breaker = _get_injection_breaker()
breaker.force_close()
```

### Setup script fails on settings merge

**Symptom**: `setup.sh` errors when merging settings.

**Fix**:
```bash
# Check existing settings are valid JSON
python3 -m json.tool ~/.claude/settings.json

# If corrupted, backup and start fresh
cp ~/.claude/settings.json ~/.claude/settings.json.bak
bash setup.sh --tier 2
```

## Recovery Procedures

### Full reset (start from scratch)
```bash
rm -rf ~/.claude/.vault
rm -f ~/.claude/.file_integrity_manifest.json
rm -f ~/.claude/.file_integrity_key
rm -rf ~/.claude/audit_logs
bash setup.sh --tier 2
```

### Re-sign after legitimate bulk changes
```bash
python3 -c "
from claude_code_security.file_integrity import quick_sign_all
signed, errors = quick_sign_all()
print(f'Re-signed {signed} files ({errors} errors)')
"
```

### Export audit log
```python
from claude_code_security.tamper_proof_log import TamperProofLog
import json
log = TamperProofLog()
entries = log.get_entries(limit=10000)
with open("audit_export.json", "w") as f:
    json.dump(entries, f, indent=2)
```
