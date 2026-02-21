#!/usr/bin/env python3
"""
Damage Control Check Integration
================================

Loads patterns from a YAML config file (e.g. ~/.claude/skills/damage-control/patterns.yaml)
and provides command/path checking for the pre-tool-use hook.

Checks three path categories:
  - zeroAccessPaths: no read, write, or any access allowed
  - readOnlyPaths: can read, but not write/edit/delete
  - noDeletePaths: can read/write/edit, but not delete

Based on disler/claude-code-damage-control by IndyDevDan.

Install: Import from your pre-tool-use hook or run standalone:
    python3 damage_control_check.py '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}'
"""

import json
import os
import re
import fnmatch
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


def is_glob_pattern(pattern: str) -> bool:
    """Check if pattern contains glob wildcards."""
    return '*' in pattern or '?' in pattern or '[' in pattern


def glob_to_regex(glob_pattern: str) -> str:
    """Convert a glob pattern to a regex pattern for matching in commands."""
    result = ""
    for char in glob_pattern:
        if char == '*':
            result += r'[^\s/]*'
        elif char == '?':
            result += r'[^\s/]'
        elif char in r'\.^$+{}[]|()':
            result += '\\' + char
        else:
            result += char
    return result


def match_path(file_path: str, pattern: str) -> bool:
    """Match file path against pattern, supporting both prefix and glob matching."""
    expanded_pattern = os.path.expanduser(pattern)
    normalized = os.path.normpath(file_path)
    expanded_normalized = os.path.expanduser(normalized)

    if is_glob_pattern(pattern):
        basename = os.path.basename(expanded_normalized)
        basename_lower = basename.lower()
        pattern_lower = pattern.lower()
        expanded_pattern_lower = expanded_pattern.lower()

        if fnmatch.fnmatch(basename_lower, expanded_pattern_lower):
            return True
        if fnmatch.fnmatch(basename_lower, pattern_lower):
            return True
        if fnmatch.fnmatch(expanded_normalized.lower(), expanded_pattern_lower):
            return True
        return False
    else:
        if expanded_normalized.startswith(expanded_pattern) or expanded_normalized == expanded_pattern.rstrip('/'):
            return True
        return False


# Operation patterns for path checking
DELETE_PATTERNS = [
    (r'\brm\s+.*{path}', "delete"),
    (r'\bunlink\s+.*{path}', "delete"),
    (r'\brmdir\s+.*{path}', "delete"),
    (r'\bshred\s+.*{path}', "delete"),
]


class DamageControlChecker:
    """Loads and checks damage control patterns.

    Configuration is loaded from a YAML file with the following sections:
      - bashToolPatterns: regex patterns to block/confirm for Bash commands
      - zeroAccessPaths: paths where all access is denied
      - readOnlyPaths: paths that can be read but not written
      - noDeletePaths: paths that can be read/written but not deleted
    """

    def __init__(self, config_path: Optional[Path] = None):
        self.config = self._load_config(config_path)

    def _load_config(self, explicit_path: Optional[Path] = None) -> Dict[str, Any]:
        """Load patterns from YAML config file."""
        if not YAML_AVAILABLE:
            return {"bashToolPatterns": [], "zeroAccessPaths": [], "readOnlyPaths": [], "noDeletePaths": []}

        # Check multiple locations
        config_paths = []
        if explicit_path:
            config_paths.append(explicit_path)
        config_paths.extend([
            Path.home() / ".claude" / "skills" / "damage-control" / "patterns.yaml",
            Path.home() / ".claude" / "hooks" / "damage-control" / "patterns.yaml",
        ])

        for config_path in config_paths:
            if config_path.exists():
                try:
                    with open(config_path, "r") as f:
                        return yaml.safe_load(f) or {}  # type: ignore[possibly-undefined]
                except Exception:
                    continue

        return {"bashToolPatterns": [], "zeroAccessPaths": [], "readOnlyPaths": [], "noDeletePaths": []}

    def _get_builtin_defaults(self) -> Dict[str, Any]:
        """Hardcoded safe defaults when config file is unavailable."""
        return {
            "bashToolPatterns": [
                {"pattern": r"rm\s+-rf\s+/(?!\w)", "reason": "Recursive delete from root"},
                {"pattern": r"rm\s+-rf\s+~", "reason": "Recursive delete from home"},
                {"pattern": r"mkfs\.", "reason": "Filesystem format"},
                {"pattern": r"dd\s+.*of=/dev/", "reason": "Direct disk write"},
            ],
            "zeroAccessPaths": [
                "~/.ssh/id_*",
                "~/.gnupg/",
                "~/.claude/settings.json",
            ],
            "readOnlyPaths": [
                "/etc/",
                "/usr/",
            ],
            "noDeletePaths": [
                "~/.claude/",
                "~/.ssh/",
            ],
        }

    def check_bash_command(self, command: str) -> Tuple[bool, bool, str]:
        """Check if bash command should be blocked or requires confirmation.

        Returns: (blocked, ask, reason)
        """
        patterns = self.config.get("bashToolPatterns", [])
        zero_access_paths = self.config.get("zeroAccessPaths", [])
        no_delete_paths = self.config.get("noDeletePaths", [])

        # 1. Check against patterns from YAML
        for item in patterns:
            pattern = item.get("pattern", "")
            reason = item.get("reason", "Blocked by pattern")
            should_ask = item.get("ask", False)

            try:
                if re.search(pattern, command, re.IGNORECASE):
                    if should_ask:
                        return False, True, reason
                    else:
                        return True, False, f"Blocked: {reason}"
            except re.error:
                continue

        # 2. Check for ANY access to zero-access paths
        for zero_path in zero_access_paths:
            if is_glob_pattern(zero_path):
                glob_regex = glob_to_regex(zero_path)
                try:
                    if re.search(glob_regex, command, re.IGNORECASE):
                        return True, False, f"Blocked: zero-access pattern {zero_path}"
                except re.error:
                    continue
            else:
                expanded = os.path.expanduser(zero_path)
                escaped_expanded = re.escape(expanded)
                escaped_original = re.escape(zero_path)

                if re.search(escaped_expanded, command) or re.search(escaped_original, command):
                    return True, False, f"Blocked: zero-access path {zero_path}"

        # 3. Check for deletions on no-delete paths
        for no_delete in no_delete_paths:
            for pattern_template, operation in DELETE_PATTERNS:
                if is_glob_pattern(no_delete):
                    glob_regex = glob_to_regex(no_delete)
                    try:
                        cmd_prefix = pattern_template.replace("{path}", "")
                        if cmd_prefix and re.search(cmd_prefix + glob_regex, command, re.IGNORECASE):
                            return True, False, f"Blocked: {operation} on no-delete path {no_delete}"
                    except re.error:
                        continue
                else:
                    expanded = os.path.expanduser(no_delete)
                    escaped_expanded = re.escape(expanded)
                    pattern_expanded = pattern_template.replace("{path}", escaped_expanded)
                    try:
                        if re.search(pattern_expanded, command):
                            return True, False, f"Blocked: {operation} on no-delete path {no_delete}"
                    except re.error:
                        continue

        return False, False, ""

    def check_file_path(self, file_path: str, _operation: str = "edit") -> Tuple[bool, str]:
        """Check if file path is blocked for edit/write operations.

        Returns: (blocked, reason)
        """
        zero_access_paths = self.config.get("zeroAccessPaths", [])
        read_only_paths = self.config.get("readOnlyPaths", [])

        # Check zero-access paths
        for zero_path in zero_access_paths:
            if match_path(file_path, zero_path):
                return True, f"zero-access path {zero_path}"

        # Check read-only paths (for edit/write)
        for readonly in read_only_paths:
            if match_path(file_path, readonly):
                return True, f"read-only path {readonly}"

        return False, ""


# Global instance
_checker: Optional[DamageControlChecker] = None


def get_damage_control_checker() -> DamageControlChecker:
    """Get or create the global damage control checker."""
    global _checker
    if _checker is None:
        _checker = DamageControlChecker()
    return _checker


def run_damage_control_check(hook_input: Dict[str, Any]) -> Dict[str, Any]:
    """Main entry point for pre-tool-use integration.

    Returns: {"allow": bool, "reason": str, "ask": bool}
    """
    checker = get_damage_control_checker()

    tool_name = hook_input.get("tool_name", hook_input.get("tool", ""))
    tool_input = hook_input.get("tool_input", hook_input.get("arguments", {}))

    # Check Bash commands
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if command:
            is_blocked, should_ask, reason = checker.check_bash_command(command)
            if is_blocked:
                return {"allow": False, "reason": reason, "ask": False}
            elif should_ask:
                return {"allow": True, "reason": reason, "ask": True}

    # Check Edit/Write file paths
    elif tool_name in ("Edit", "Write", "MultiEdit"):
        file_path = tool_input.get("file_path", "")
        if file_path:
            is_blocked, reason = checker.check_file_path(file_path, tool_name.lower())
            if is_blocked:
                return {"allow": False, "reason": f"Blocked {tool_name} to {reason}: {file_path}", "ask": False}

    return {"allow": True, "reason": "", "ask": False}


if __name__ == "__main__":
    # Test the checker
    import sys

    if len(sys.argv) > 1:
        test_input = json.loads(sys.argv[1])
    else:
        test_input = json.load(sys.stdin)

    result = run_damage_control_check(test_input)
    print(json.dumps(result))
