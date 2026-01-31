"""Tests for SelfModificationAuditor."""

import pytest


class TestSelfModificationAuditor:
    def test_monitored_path_detected(self, mock_claude_home):
        from claude_code_security.self_modification_auditor import is_monitored_path
        assert is_monitored_path(str(mock_claude_home / "commands" / "test.py"))
        assert is_monitored_path(str(mock_claude_home / "hooks" / "my_hook.py"))

    def test_unmonitored_path_ignored(self, mock_claude_home):
        from claude_code_security.self_modification_auditor import is_monitored_path
        assert not is_monitored_path("/tmp/random_file.py")

    def test_compute_diff(self, mock_claude_home):
        from claude_code_security.self_modification_auditor import compute_diff
        old = "line1\nline2\nline3\n"
        new = "line1\nmodified\nline3\n"
        diff = compute_diff(old, new, "test.py")
        assert "line2" in diff
        assert "modified" in diff

    def test_audit_monitored_modification(self, mock_claude_home):
        from claude_code_security.self_modification_auditor import audit_modification
        file_path = str(mock_claude_home / "commands" / "test.py")
        result = audit_modification(
            tool_name="Edit",
            file_path=file_path,
            old_content="# old\n",
            new_content="# new\n",
        )
        assert result["audited"]
        assert result["diff_lines"] > 0

    def test_unmonitored_modification_skipped(self, mock_claude_home):
        from claude_code_security.self_modification_auditor import audit_modification
        result = audit_modification(
            tool_name="Edit",
            file_path="/tmp/unmonitored.py",
            old_content="old",
            new_content="new",
        )
        assert not result["audited"]
        assert result["reason"] == "not_monitored"

    def test_no_changes_skipped(self, mock_claude_home):
        from claude_code_security.self_modification_auditor import audit_modification
        file_path = str(mock_claude_home / "commands" / "test.py")
        result = audit_modification(
            tool_name="Edit",
            file_path=file_path,
            old_content="same",
            new_content="same",
        )
        assert not result["audited"]
        assert result["reason"] == "no_changes"

    def test_audit_creates_json_file(self, mock_claude_home):
        from claude_code_security.self_modification_auditor import audit_modification
        file_path = str(mock_claude_home / "hooks" / "hook.py")
        audit_modification(
            tool_name="Write",
            file_path=file_path,
            old_content="",
            new_content="#!/usr/bin/env python3\nprint('new hook')\n",
        )
        audit_files = list(mock_claude_home.joinpath("audit_logs").glob("audit-*.json"))
        assert len(audit_files) >= 1
