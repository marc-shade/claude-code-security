#!/usr/bin/env python3
"""TeammateIdle hook - Production quality gate for Agent Teams.

Hook type: TeammateIdle (command)

Runs when a teammate is about to go idle. Since TeammateIdle does NOT
support agent/prompt hooks, this command hook does real validation:
  1. Finds recently modified files via git
  2. Runs py_compile on modified .py files
  3. Checks modified files for forbidden patterns

Exit code 2 + stderr feedback keeps the teammate working.

Input (stdin JSON):
  - teammate_name, team_name, transcript_path
  - session_id, cwd, permission_mode, hook_event_name

Install: Copy to ~/.claude/hooks/ and register in settings.json:
    {
        "hooks": {
            "TeammateIdle": [
                {
                    "matcher": ".*",
                    "hooks": [{"type": "command", "command": "python3 ~/.claude/hooks/teammate_idle_quality_gate.py"}]
                }
            ]
        }
    }
"""

import json
import os
import subprocess
import sys
import time

# Max age in seconds for files to be considered "this session's work"
RECENCY_WINDOW = 1800  # 30 minutes

FORBIDDEN_PATTERNS = [
    "TODO",
    "FIXME",
    "HACK",
    "placeholder",
    "mock data",
    "hardcoded",
    "proof of concept",
    "dummy data",
]


def get_recently_modified_files(cwd: str) -> list[str]:
    """Get files modified recently (within RECENCY_WINDOW) from git diff.

    Scopes to files with mtime within the recency window so we only
    validate the teammate's actual work, not pre-existing dirty state.
    """
    all_dirty = []
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only"],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=cwd,
        )
        if result.returncode == 0 and result.stdout.strip():
            all_dirty = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]

        # Also include staged changes
        result = subprocess.run(
            ["git", "diff", "--name-only", "--cached"],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=cwd,
        )
        if result.returncode == 0 and result.stdout.strip():
            staged = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
            all_dirty = list(set(all_dirty + staged))
    except Exception:
        pass

    if not all_dirty:
        return []

    # Filter to files modified within the recency window
    cutoff = time.time() - RECENCY_WINDOW
    recent = []
    for filepath in all_dirty:
        full_path = os.path.join(cwd, filepath)
        try:
            if os.path.exists(full_path) and os.path.getmtime(full_path) >= cutoff:
                recent.append(filepath)
        except Exception:
            pass

    return recent


def check_python_syntax(files: list[str], cwd: str) -> list[str]:
    """Run py_compile on .py files to catch syntax errors."""
    errors = []
    py_files = [f for f in files if f.endswith(".py")]
    for py_file in py_files[:10]:  # Cap at 10 files for speed
        full_path = os.path.join(cwd, py_file)
        if not os.path.exists(full_path):
            continue
        try:
            result = subprocess.run(
                ["python3", "-m", "py_compile", full_path],
                capture_output=True,
                text=True,
                timeout=5,
                cwd=cwd,
            )
            if result.returncode != 0:
                err = result.stderr.strip().split("\n")[-1] if result.stderr else "syntax error"
                errors.append(f"Syntax error in {py_file}: {err}")
        except Exception:
            pass
    return errors


def check_forbidden_patterns(files: list[str], cwd: str) -> list[str]:
    """Check modified files for production-quality violations."""
    violations = []
    for filepath in files[:10]:  # Cap at 10 files
        full_path = os.path.join(cwd, filepath)
        if not os.path.exists(full_path):
            continue
        # Skip binary/non-text files
        if any(filepath.endswith(ext) for ext in [".pyc", ".png", ".jpg", ".gif", ".ico", ".woff", ".db", ".sqlite"]):
            continue
        try:
            with open(full_path, "r", errors="ignore") as f:
                content = f.read(50000)  # Read first 50KB
            content_lower = content.lower()
            for pattern in FORBIDDEN_PATTERNS:
                if pattern.lower() in content_lower:
                    violations.append(f"'{pattern}' found in {filepath}")
                    break  # One violation per file is enough
        except Exception:
            pass
    return violations


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)

        ctx = json.loads(raw)
        teammate_name = ctx.get("teammate_name", "unknown")
        cwd = ctx.get("cwd", os.getcwd())

        # 1. Find recently modified files (scoped to this session's work)
        modified = get_recently_modified_files(cwd)
        if not modified:
            sys.exit(0)  # No files modified, coordination-only work is fine

        issues = []

        # 2. Check Python syntax
        syntax_errors = check_python_syntax(modified, cwd)
        issues.extend(syntax_errors)

        # 3. Check for forbidden patterns in actual files
        pattern_violations = check_forbidden_patterns(modified, cwd)
        issues.extend(pattern_violations)

        if issues:
            feedback = (
                f"[Quality Gate] Teammate '{teammate_name}' has issues: "
                f"{'; '.join(issues[:3])}. Fix before going idle."
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
