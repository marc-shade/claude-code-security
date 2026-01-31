#!/usr/bin/env python3
"""
Security Orchestrator: Chains all security checks together.

Combines pre-tool-use checks into a single hook entry point.
Use this as the sole hook if you want all checks in one script.

Exit codes:
    0 = allow
    1 = error (tool proceeds)
    2 = block
"""

import json
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Tools that should fail-closed (block on error)
SENSITIVE_TOOLS = {"Bash", "Write", "Edit"}

# Same regex patterns as pre_tool_use.py for consistency
DANGEROUS_COMMAND_PATTERNS = [
    r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/",
    r"rm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\s+/",
    r"mkfs\.",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;",
    r"dd\s+.*of=/dev/[sh]d",
    r"chmod\s+-R\s+777\s+/",
    r"(curl|wget)\s+.*\|\s*(sh|bash|zsh)",
    r">\s*/dev/[sh]d",
    r"shred\s+.*(/dev/|/boot|/etc|/usr|/var)",
    r"eval\s+.*\$\(.*base64",
]


def check_dangerous_commands(tool_name: str, tool_input: dict) -> str:
    """Check for dangerous command patterns using regex. Returns block reason or empty."""
    if tool_name != "Bash":
        return ""
    command = tool_input.get("command", "")
    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern, command):
            return "Dangerous command pattern detected"
    return ""


def check_injection(tool_name: str, tool_input: dict) -> str:
    """Run security gate injection check. Returns block reason or empty string."""
    content = ""
    if tool_name in ("Write", "Edit"):
        content = json.dumps(tool_input)
    elif tool_name == "Bash":
        content = tool_input.get("command", "")

    if not content:
        return ""

    try:
        from claude_code_security.security_gate import scan_content
        verdict = scan_content(
            content=content,
            source=f"tool:{tool_name}",
            scan_code=(tool_name in ("Write", "Edit")),
        )
        if verdict.action == "BLOCK":
            return verdict.summary
    except ImportError:
        pass
    return ""


def check_file_integrity(tool_name: str, tool_input: dict) -> str:
    """Check file integrity for read operations on monitored files."""
    if tool_name != "Read":
        return ""
    file_path = tool_input.get("file_path", "")
    try:
        from claude_code_security.self_modification_auditor import is_monitored_path
        from claude_code_security.file_integrity import FileIntegritySigner
        if is_monitored_path(file_path):
            from pathlib import Path
            signer = FileIntegritySigner()
            status = signer.verify_file(Path(file_path))
            if status == "tampered":
                return f"File integrity check failed: {file_path} is TAMPERED"
    except ImportError:
        pass
    return ""


def check_approval_token(tool_name: str, tool_input: dict) -> str:
    """Check approval token for monitored file modifications."""
    if tool_name not in ("Write", "Edit"):
        return ""
    file_path = tool_input.get("file_path", "")
    try:
        from claude_code_security.self_modification_auditor import is_monitored_path
        if is_monitored_path(file_path):
            token = os.environ.get("CLAUDE_SECURITY_APPROVAL_TOKEN", "")
            if token:
                try:
                    from claude_code_security.approval_tokens import ApprovalTokenManager
                    mgr = ApprovalTokenManager()
                    valid, reason = mgr.validate_token(token, f"modify:{file_path}")
                    if not valid:
                        return f"Invalid approval token for {file_path}: {reason}"
                except ImportError:
                    pass
    except ImportError:
        pass
    return ""


def main():
    tool_name = ""
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)

        data = json.loads(raw)
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})

        checks = [
            ("dangerous_commands", check_dangerous_commands),
            ("injection", check_injection),
            ("file_integrity", check_file_integrity),
            ("approval_token", check_approval_token),
        ]

        for check_name, check_fn in checks:
            reason = check_fn(tool_name, tool_input)
            if reason:
                print(f"BLOCKED [{check_name}]: {reason}", file=sys.stdout)
                sys.exit(2)

        sys.exit(0)

    except json.JSONDecodeError:
        sys.exit(0)
    except Exception as e:
        print(f"Security orchestrator error: {e}", file=sys.stderr)
        # Fail-closed for sensitive tools
        if tool_name in SENSITIVE_TOOLS:
            sys.exit(2)
        sys.exit(1)


if __name__ == "__main__":
    main()
