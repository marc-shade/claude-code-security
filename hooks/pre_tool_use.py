#!/usr/bin/env python3
"""
Pre-Tool-Use Hook: Security checks before Claude Code executes a tool.

Reads tool invocation from stdin (JSON), runs security checks, and
exits with:
    0 = allow
    1 = error (tool proceeds, logged) -- only for non-sensitive tools
    2 = block (tool rejected)

Sensitive tools (Bash, Write, Edit) fail-closed: unhandled exceptions
result in exit 2, not exit 1, to prevent bypass via crash.

Claude Code hook contract:
    stdin: {"tool_name": "...", "tool_input": {...}}
    stdout: (optional rejection message shown to user)
    exit code: 0/1/2
"""

import json
import re
import sys
import os

# Add parent directory to path so we can import the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Tools that should fail-closed (block on error) vs fail-open
SENSITIVE_TOOLS = {"Bash", "Write", "Edit"}

# Regex-based dangerous command patterns (more robust than substring matching)
DANGEROUS_COMMAND_PATTERNS = [
    r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/",  # rm -rf /, rm -fr /, rm -rfi / etc.
    r"rm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\s+/",  # rm -fr /
    r"mkfs\.",                                       # mkfs.ext4, mkfs.xfs, etc.
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;",       # fork bomb
    r"dd\s+.*of=/dev/[sh]d",                        # dd to disk device
    r"chmod\s+-R\s+777\s+/",                        # chmod -R 777 /
    r"(curl|wget)\s+.*\|\s*(sh|bash|zsh)",          # pipe URL to shell
    r">\s*/dev/[sh]d",                              # redirect to disk device
    r"shred\s+.*(/dev/|/boot|/etc|/usr|/var)",      # shred system paths
    r"eval\s+.*\$\(.*base64",                       # eval base64 obfuscation
]


def main():
    tool_name = ""
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)

        data = json.loads(raw)
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})

        # --- Dangerous command blocking (regex-based) ---
        if tool_name == "Bash":
            command = tool_input.get("command", "")
            for pattern in DANGEROUS_COMMAND_PATTERNS:
                if re.search(pattern, command):
                    print(
                        "BLOCKED: Dangerous command pattern detected",
                        file=sys.stdout,
                    )
                    sys.exit(2)

        # --- Injection detection on content ---
        content_to_scan = ""
        if tool_name in ("Write", "Edit"):
            content_to_scan = json.dumps(tool_input)
        elif tool_name == "Bash":
            content_to_scan = tool_input.get("command", "")

        if content_to_scan:
            try:
                from claude_code_security.security_gate import scan_content
                verdict = scan_content(
                    content=content_to_scan,
                    source=f"tool:{tool_name}",
                    scan_code=(tool_name in ("Write", "Edit")),
                )
                if verdict.action == "BLOCK":
                    print(
                        f"BLOCKED by security gate: {verdict.summary}",
                        file=sys.stdout,
                    )
                    sys.exit(2)
            except ImportError:
                pass

        # --- Approval token check for sensitive modifications ---
        if tool_name in ("Write", "Edit"):
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
                                print(
                                    f"BLOCKED: Invalid approval token for {file_path}: {reason}",
                                    file=sys.stdout,
                                )
                                sys.exit(2)
                        except ImportError:
                            pass
            except ImportError:
                pass

        sys.exit(0)

    except json.JSONDecodeError:
        sys.exit(0)
    except Exception as e:
        print(f"Security hook error: {e}", file=sys.stderr)
        # Fail-closed for sensitive tools, fail-open for others
        if tool_name in SENSITIVE_TOOLS:
            sys.exit(2)
        sys.exit(1)


if __name__ == "__main__":
    main()
