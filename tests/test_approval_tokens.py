"""Tests for ApprovalTokenManager (HMAC time-limited tokens)."""

import time
import pytest


class TestApprovalTokens:
    def test_generate_and_validate(self, mock_claude_home):
        from claude_code_security.approval_tokens import ApprovalTokenManager
        mgr = ApprovalTokenManager()
        token = mgr.generate_token("deploy:production", reason="planned release")
        valid, reason = mgr.validate_token(token, "deploy:production")
        assert valid
        assert reason == "Token valid"

    def test_action_mismatch_rejected(self, mock_claude_home):
        from claude_code_security.approval_tokens import ApprovalTokenManager
        mgr = ApprovalTokenManager()
        token = mgr.generate_token("deploy:staging")
        valid, reason = mgr.validate_token(token, "deploy:production")
        assert not valid
        assert "mismatch" in reason.lower()

    def test_expired_token_rejected(self, mock_claude_home, monkeypatch):
        from claude_code_security.approval_tokens import ApprovalTokenManager
        import claude_code_security.config as cfg
        monkeypatch.setattr(cfg, "TOKEN_VALIDITY_SECONDS", 1)

        mgr = ApprovalTokenManager()
        token = mgr.generate_token("short_lived")
        time.sleep(1.5)
        valid, reason = mgr.validate_token(token, "short_lived")
        assert not valid
        assert "expired" in reason.lower()

    def test_revoke_all_tokens(self, mock_claude_home):
        from claude_code_security.approval_tokens import ApprovalTokenManager
        mgr = ApprovalTokenManager()
        token = mgr.generate_token("some_action")
        mgr.revoke_all_tokens()
        valid, reason = mgr.validate_token(token, "some_action")
        assert not valid
        assert "revoked" in reason.lower()

    def test_invalid_token_format(self, mock_claude_home):
        from claude_code_security.approval_tokens import ApprovalTokenManager
        mgr = ApprovalTokenManager()
        valid, reason = mgr.validate_token("not-a-real-token")
        assert not valid

    def test_tampered_signature_rejected(self, mock_claude_home):
        import base64
        from claude_code_security.approval_tokens import ApprovalTokenManager
        mgr = ApprovalTokenManager()
        token = mgr.generate_token("test_action")
        decoded = base64.b64decode(token).decode("utf-8")
        parts = decoded.split(":")
        parts[2] = "f" * 64  # Fake signature
        tampered = base64.b64encode(":".join(parts).encode()).decode()
        valid, reason = mgr.validate_token(tampered, "test_action")
        assert not valid
        assert "signature" in reason.lower()

    def test_validate_without_action(self, mock_claude_home):
        from claude_code_security.approval_tokens import ApprovalTokenManager
        mgr = ApprovalTokenManager()
        token = mgr.generate_token("any_action")
        valid, reason = mgr.validate_token(token)  # No action check
        assert valid
