"""Tests for TamperProofLog (hash-chained SQLite audit)."""

import sqlite3
import pytest


class TestTamperProofLog:
    def test_append_entry(self, mock_claude_home):
        from claude_code_security.tamper_proof_log import TamperProofLog
        log = TamperProofLog()
        entry_id = log.append("test_event", "test_actor", "test_action")
        assert entry_id >= 1

    def test_chain_integrity(self, mock_claude_home):
        from claude_code_security.tamper_proof_log import TamperProofLog
        log = TamperProofLog()
        for i in range(5):
            log.append("event", "actor", f"action_{i}")
        result = log.verify_chain()
        assert result["valid"]
        assert result["entries_checked"] == 5

    def test_tamper_detection(self, mock_claude_home):
        from claude_code_security.tamper_proof_log import TamperProofLog
        log = TamperProofLog()
        for i in range(3):
            log.append("event", "actor", f"action_{i}")

        # Tamper with an entry
        conn = sqlite3.connect(str(log.db_path))
        conn.execute("UPDATE audit_chain SET action = 'TAMPERED' WHERE id = 2")
        conn.commit()
        conn.close()

        result = log.verify_chain()
        assert not result["valid"]
        assert result["first_broken"] == 2

    def test_get_entries(self, mock_claude_home):
        from claude_code_security.tamper_proof_log import TamperProofLog
        log = TamperProofLog()
        log.append("auth_event", "node_a", "login")
        log.append("file_event", "node_b", "write")
        log.append("auth_event", "node_a", "logout")

        entries = log.get_entries(event_type="auth_event")
        assert len(entries) == 2

    def test_get_entries_by_actor(self, mock_claude_home):
        from claude_code_security.tamper_proof_log import TamperProofLog
        log = TamperProofLog()
        log.append("event", "alice", "action1")
        log.append("event", "bob", "action2")
        log.append("event", "alice", "action3")

        entries = log.get_entries(actor="bob")
        assert len(entries) == 1
        assert entries[0]["actor"] == "bob"

    def test_get_stats(self, mock_claude_home):
        from claude_code_security.tamper_proof_log import TamperProofLog
        log = TamperProofLog()
        log.append("type_a", "actor_1", "action")
        log.append("type_b", "actor_2", "action")
        stats = log.get_stats()
        assert stats["total_entries"] == 2
        assert "type_a" in stats["by_event_type"]

    def test_empty_chain_is_valid(self, mock_claude_home):
        from claude_code_security.tamper_proof_log import TamperProofLog
        log = TamperProofLog()
        result = log.verify_chain()
        assert result["valid"]
        assert result["entries_checked"] == 0

    def test_chain_limit(self, mock_claude_home):
        from claude_code_security.tamper_proof_log import TamperProofLog
        log = TamperProofLog()
        for i in range(10):
            log.append("event", "actor", f"action_{i}")
        result = log.verify_chain(limit=5)
        assert result["valid"]
        assert result["entries_checked"] == 5
