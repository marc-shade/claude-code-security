#!/usr/bin/env python3
"""TaskCompleted hook - Quality gate for Agent Teams.

Hook type: TaskCompleted (command)

Runs when a task is being marked complete. Reads JSON context from stdin
per the official hooks contract. Validates the task deliverable meets
production-quality standards. Exit code 2 prevents completion and sends
feedback via stderr.

Input (stdin JSON):
  - task_id: identifier of the task being completed
  - task_subject: title of the task
  - task_description: detailed description (may be absent)
  - teammate_name: name of the completing teammate (may be absent)
  - team_name: name of the team (may be absent)
  - transcript_path: path to the conversation transcript
  - session_id, cwd, permission_mode, hook_event_name

Install: Copy to ~/.claude/hooks/ and register in settings.json:
    {
        "hooks": {
            "TaskCompleted": [
                {
                    "matcher": ".*",
                    "hooks": [{"type": "command", "command": "python3 ~/.claude/hooks/task_completed_quality_gate.py"}]
                }
            ]
        }
    }
"""

import json
import os
import sys


# Patterns to check in actual code written by the agent (Write/Edit tool inputs).
# Each tuple: (regex_pattern, message). Patterns are case-insensitive.
import re

INCOMPLETE_PATTERNS = [
    # Match TODO/FIXME in code comments, not in tool names or prose
    (r"#\s*TODO\b", "Unresolved TODO comment in code"),
    (r"//\s*TODO\b", "Unresolved TODO comment in code"),
    (r"#\s*FIXME\b", "Unresolved FIXME comment in code"),
    (r"//\s*FIXME\b", "Unresolved FIXME comment in code"),
    # Match explicit stub/placeholder markers in code
    (r"raise\s+NotImplementedError", "Contains unimplemented code (NotImplementedError)"),
    (r"pass\s*#\s*(?:stub|placeholder|todo)", "Contains stub/placeholder pass"),
    # Match fake/mock data patterns in code (not in test files)
    (r"(?:fake|mock)_(?:data|response|result)\s*=", "Contains fake/mock data assignments"),
    (r"hardcoded_", "Contains variables prefixed with hardcoded_"),
]


def extract_written_code(transcript_path: str, max_lines: int = 500) -> str:
    """Extract only the code content from Write/Edit tool inputs in the transcript."""
    if not transcript_path or not os.path.exists(transcript_path):
        return ""

    code_chunks = []
    try:
        with open(transcript_path, "r") as f:
            lines = f.readlines()

        # Scan recent transcript lines for Write/Edit tool_use entries
        for line in lines[-max_lines:]:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            # Look for assistant messages with tool_use content
            msg = entry.get("message", {})
            if msg.get("role") != "assistant":
                continue

            for block in msg.get("content", []):
                if block.get("type") != "tool_use":
                    continue
                tool = block.get("name", "")
                inp = block.get("input", {})

                if tool == "Write":
                    code_chunks.append(inp.get("content", ""))
                elif tool == "Edit":
                    code_chunks.append(inp.get("new_string", ""))
                elif tool == "MultiEdit":
                    for edit in inp.get("edits", []):
                        code_chunks.append(edit.get("new_string", ""))
    except Exception:
        pass

    return "\n".join(code_chunks)


def check_transcript_for_issues(transcript_path: str, max_lines: int = 500) -> list[str]:
    """Check actual code written by the agent for quality issues."""
    issues = []
    code = extract_written_code(transcript_path, max_lines)
    if not code:
        return issues

    for pattern, message in INCOMPLETE_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            issues.append(message)

    # Check for bare except with pass (silently swallowed errors)
    for i, line in enumerate(code.split("\n")):
        stripped = line.strip()
        if stripped in ("except:", "except Exception:"):
            next_lines = code.split("\n")[i + 1 : i + 3]
            if any(nl.strip() == "pass" for nl in next_lines):
                issues.append("Bare except with pass - errors silently swallowed")
                break

    return issues


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)

        ctx = json.loads(raw)
        task_subject = ctx.get("task_subject", "unknown")
        transcript_path = ctx.get("transcript_path", "")

        # Check the transcript for production-quality issues
        issues = check_transcript_for_issues(transcript_path)

        if issues:
            feedback = (
                f"[Quality Gate] Task '{task_subject}' cannot be marked "
                f"complete: {'; '.join(issues[:3])}. Fix these issues first."
            )
            print(feedback, file=sys.stderr)
            sys.exit(2)

        sys.exit(0)

    except json.JSONDecodeError:
        sys.exit(0)
    except Exception:
        sys.exit(0)


if __name__ == "__main__":
    main()
