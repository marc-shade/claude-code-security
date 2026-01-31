#!/usr/bin/env python3
"""
Pre-Tool-Use Hook: Security checks before Claude Code executes a tool.

Reads tool invocation from stdin (JSON), runs security checks, and
exits with:
    0 = allow
    1 = error (tool proceeds, logged)
    2 = block (tool rejected)

Claude Code hook contract:
    stdin: {"tool_name": "...", "tool_input": {...}}
    stdout: (optional rejection message shown to user)
    exit code: 0/1/2
"""

import json
import sys
import os

# Add parent directory to path so we can import the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)

        data = json.loads(raw)
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})

        # --- Dangerous command blocking ---
        if tool_name == "Bash":
            command = tool_input.get("command", "")
            dangerous_patterns = [
                "rm -rf /",
                "rm -rf /*",
                "mkfs.",
                ":(){:|:&};:",
                "dd if=/dev/zero of=/dev/sd",
                "chmod -R 777 /",
                "curl | sh",
                "wget | sh",
                "curl | bash",
                "wget | bash",
            ]
            for pattern in dangerous_patterns:
                if pattern in command:
                    print(
                        f"BLOCKED: Dangerous command pattern detected: '{pattern}'",
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
        sys.exit(1)


if __name__ == "__main__":
    main()
