#!/usr/bin/env python3
"""
PermissionRequest Hook - Intelligent auto-approval for trusted patterns

Hook type: PermissionRequest (command)

Triggers when user is shown a permission prompt to:
1. Auto-approve known safe patterns (trusted paths, read-only commands)
2. Auto-deny known dangerous patterns (rm -rf /, fork bombs, etc.)
3. Log permission decisions for analysis

New in Claude Code 2.0+ -- Streamlines agentic workflows by reducing
permission prompts for routine operations.

Install: Copy to ~/.claude/hooks/ and register in settings.json:
    {
        "hooks": {
            "PermissionRequest": [
                {
                    "matcher": ".*",
                    "hooks": [{"type": "command", "command": "python3 ~/.claude/hooks/permission_request.py"}]
                }
            ]
        }
    }

Customization:
    Edit TRUSTED_PATTERNS below to match your project layout.
    Add your project directories, trusted MCP tools, and safe commands.
"""

import json
import sys
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

# Trusted patterns for auto-approval
# Customize these for your environment
TRUSTED_PATTERNS = {
    'Read': {
        'paths': [
            r'^\./',  # Relative paths in current project
            # Add your trusted directories:
            # r'^/home/user/projects/',
            # r'^~/\.claude/',
        ],
        'auto_approve': True
    },
    'Write': {
        'paths': [
            r'^\./',
            # Add your trusted write directories:
            # r'^/home/user/projects/',
        ],
        'excluded': [
            r'\.env$',
            r'credentials',
            r'secret',
            r'\.pem$',
            r'\.key$',
        ],
        'auto_approve': True
    },
    'Edit': {
        'paths': [
            r'^\./',
            # Add your trusted edit directories:
            # r'^/home/user/projects/',
        ],
        'excluded': [
            r'\.env$',
            r'credentials',
        ],
        'auto_approve': True
    },
    'Bash': {
        'commands': [
            r'^ls\s',
            r'^cat\s',
            r'^head\s',
            r'^tail\s',
            r'^grep\s',
            r'^find\s',
            r'^python3?\s',
            r'^node\s',
            r'^npm\s',
            r'^pip3?\s',
            r'^git\s(?!(push|force|reset --hard))',
            r'^claude\s',
            r'^which\s',
            r'^echo\s',
            r'^pwd$',
            r'^date$',
        ],
        'excluded': [
            r'rm\s+-rf\s+/',
            r'sudo\s',
            r'chmod\s+777',
            r'curl.*\|\s*sh',
            r'wget.*\|\s*sh',
        ],
        'auto_approve': True
    },
    'Glob': {'auto_approve': True},
    'Grep': {'auto_approve': True},
    'WebSearch': {'auto_approve': True},
    'WebFetch': {
        'urls': [
            r'^https://github\.com/',
            r'^https://docs\.',
        ],
        'auto_approve': True
    },
    # MCP tools - trust your own servers (add prefixes here)
    # 'mcp__enhanced-memory__': {'auto_approve': True},
    # 'mcp__sequential-thinking__': {'auto_approve': True},
}

# Dangerous patterns - always deny
DANGEROUS_PATTERNS = [
    r'rm\s+-rf\s+[/~]',
    r'>\s*/dev/sd[a-z]',
    r'dd\s+if=.*of=/dev/',
    r'mkfs\.',
    r':(){ :|:& };:',  # Fork bomb
    r'wget.*-O-\s*\|\s*sh',
    r'curl.*\|\s*bash',
]

PERMISSION_LOG = Path.home() / '.claude' / 'permission_log.jsonl'


def log_permission(tool: str, decision: str, reason: str, params: Optional[dict] = None):
    """Log permission decisions."""
    entry = {
        'timestamp': datetime.now().isoformat(),
        'tool': tool,
        'decision': decision,
        'reason': reason,
        'params': params
    }
    try:
        with open(PERMISSION_LOG, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    except Exception:
        pass


def matches_pattern(value: str, patterns: list) -> bool:
    """Check if value matches any pattern."""
    for pattern in patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return True
    return False


def check_dangerous(params: dict) -> tuple:
    """Check for dangerous patterns."""
    params_str = json.dumps(params)
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, params_str, re.IGNORECASE):
            return True, f"Matched dangerous pattern: {pattern}"
    return False, None


def evaluate_permission(tool_name: str, params: dict) -> Optional[dict]:
    """Evaluate whether to auto-approve/deny permission."""

    # Check for dangerous patterns first
    is_dangerous, reason = check_dangerous(params)
    if is_dangerous:
        return {
            'decision': 'deny',
            'message': f"Blocked: {reason}",
            'interrupt': True
        }

    # Check MCP tools (match by prefix)
    for prefix, config in TRUSTED_PATTERNS.items():
        if prefix.startswith('mcp__') and tool_name.startswith(prefix):
            if config.get('auto_approve'):
                return {
                    'decision': 'allow',
                    'reason': f"Trusted MCP tool: {prefix}"
                }

    # Check specific tool patterns
    tool_config = TRUSTED_PATTERNS.get(tool_name, {})

    if not tool_config.get('auto_approve'):
        return None  # Let user decide

    # Check path-based tools
    if 'paths' in tool_config:
        file_path = params.get('file_path', params.get('path', ''))

        # Check exclusions first
        if matches_pattern(file_path, tool_config.get('excluded', [])):
            return None  # Let user decide for excluded patterns

        # Check trusted paths
        if matches_pattern(file_path, tool_config['paths']):
            return {
                'decision': 'allow',
                'reason': f"Trusted path pattern for {tool_name}"
            }

    # Check command-based tools (Bash)
    if 'commands' in tool_config:
        command = params.get('command', '')

        # Check exclusions first
        if matches_pattern(command, tool_config.get('excluded', [])):
            return None  # Let user decide

        # Check trusted commands
        if matches_pattern(command, tool_config['commands']):
            return {
                'decision': 'allow',
                'reason': f"Trusted command pattern"
            }

    # Check URL-based tools
    if 'urls' in tool_config:
        url = params.get('url', '')
        if matches_pattern(url, tool_config['urls']):
            return {
                'decision': 'allow',
                'reason': f"Trusted URL pattern"
            }

    # Simple tools with no conditions
    if tool_config.get('auto_approve') and not any(k in tool_config for k in ['paths', 'commands', 'urls']):
        return {
            'decision': 'allow',
            'reason': f"Unconditionally trusted tool: {tool_name}"
        }

    return None  # Let user decide


def main():
    try:
        hook_input = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    tool_name = hook_input.get('tool_name', '')
    tool_input = hook_input.get('tool_input', {})

    result = evaluate_permission(tool_name, tool_input)

    if result:
        decision = result.get('decision', 'ask')
        reason = result.get('reason', 'Auto-evaluated')
        log_permission(tool_name, decision, reason, tool_input)
        print(json.dumps(result))
    else:
        log_permission(tool_name, 'ask', 'No matching auto-approval rule', tool_input)

    sys.exit(0)

if __name__ == '__main__':
    main()
