#!/usr/bin/env python3
"""
Post-Tool-Use Hook: Audit trail after Claude Code executes a tool.

Reads tool result from stdin (JSON) and logs to tamper-proof audit chain.

Claude Code hook contract:
    stdin: {"tool_name": "...", "tool_input": {...}, "tool_output": "..."}
    exit code: 0 (always allow, this is audit-only)
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)

        data = json.loads(raw)
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})

        # --- Self-modification audit ---
        if tool_name in ("Write", "Edit"):
            file_path = tool_input.get("file_path", "")
            try:
                from claude_code_security.self_modification_auditor import (
                    audit_modification,
                    is_monitored_path,
                )
                if is_monitored_path(file_path):
                    old_content = tool_input.get("old_string", "")
                    new_content = tool_input.get("new_string", "")
                    if tool_name == "Write":
                        new_content = tool_input.get("content", "")
                    audit_modification(
                        tool_name=tool_name,
                        file_path=file_path,
                        old_content=old_content,
                        new_content=new_content,
                    )
            except ImportError:
                pass

        # --- Tamper-proof audit log ---
        try:
            from claude_code_security.tamper_proof_log import TamperProofLog
            audit = TamperProofLog()
            target = ""
            if tool_name in ("Write", "Edit", "Read"):
                target = tool_input.get("file_path", "")
            elif tool_name == "Bash":
                cmd = tool_input.get("command", "")
                target = cmd[:200]

            audit.append(
                event_type="tool_execution",
                actor="claude_code",
                action=tool_name,
                target=target,
                details=json.dumps({
                    k: v for k, v in tool_input.items()
                    if k not in ("content", "old_string", "new_string")
                })[:500],
            )
        except ImportError:
            pass

    except json.JSONDecodeError:
        pass
    except Exception as e:
        print(f"Post-hook error: {e}", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
