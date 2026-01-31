"""Tests for ClusterAuth (HMAC + RBAC)."""

import pytest


class TestClusterAuth:
    def test_token_generation(self, mock_claude_home):
        from claude_code_security.cluster_auth import ClusterAuth
        auth = ClusterAuth()
        token = auth.get_node_token("node-a")
        assert isinstance(token, str)
        assert len(token) == 64  # SHA-256 hex

    def test_token_validation(self, mock_claude_home):
        from claude_code_security.cluster_auth import ClusterAuth
        auth = ClusterAuth()
        token = auth.get_node_token("node-a")
        assert auth.validate_token("node-a", token)

    def test_wrong_node_token_rejected(self, mock_claude_home):
        from claude_code_security.cluster_auth import ClusterAuth
        auth = ClusterAuth()
        token = auth.get_node_token("node-a")
        assert not auth.validate_token("node-b", token)

    def test_invalid_token_rejected(self, mock_claude_home):
        from claude_code_security.cluster_auth import ClusterAuth
        auth = ClusterAuth()
        assert not auth.validate_token("node-a", "fakefakefake")

    def test_personal_write_always_allowed(self, mock_claude_home):
        from claude_code_security.cluster_auth import ClusterAuth
        auth = ClusterAuth()
        assert auth.authorize_write("any_node", "", scope="personal")

    def test_shared_write_requires_token(self, mock_claude_home):
        from claude_code_security.cluster_auth import ClusterAuth
        auth = ClusterAuth()
        assert not auth.authorize_write("node-a", "bad_token", scope="shared")

    def test_shared_write_with_valid_token(self, mock_claude_home):
        from claude_code_security.cluster_auth import ClusterAuth
        auth = ClusterAuth()
        token = auth.get_node_token("node-a")
        assert auth.authorize_write("node-a", token, scope="shared")

    def test_audit_stats(self, mock_claude_home):
        from claude_code_security.cluster_auth import ClusterAuth
        auth = ClusterAuth()
        auth.authorize_write("node-a", "", scope="personal")
        stats = auth.get_audit_stats()
        assert stats["total_attempts"] >= 1

    def test_deterministic_tokens(self, mock_claude_home):
        from claude_code_security.cluster_auth import ClusterAuth
        auth = ClusterAuth()
        t1 = auth.get_node_token("same-node")
        t2 = auth.get_node_token("same-node")
        assert t1 == t2


class TestClusterRBAC:
    def test_default_role(self, mock_claude_home):
        from claude_code_security.cluster_auth import ClusterRBAC
        rbac = ClusterRBAC()
        assert rbac.get_node_role("unknown-node") == "read"

    def test_assign_role(self, mock_claude_home):
        from claude_code_security.cluster_auth import ClusterRBAC
        rbac = ClusterRBAC()
        assert rbac.assign_role("test-node", "admin")
        assert rbac.get_node_role("test-node") == "admin"

    def test_invalid_role(self, mock_claude_home):
        from claude_code_security.cluster_auth import ClusterRBAC
        rbac = ClusterRBAC()
        assert not rbac.assign_role("test-node", "superadmin")

    def test_permissions(self, mock_claude_home):
        from claude_code_security.cluster_auth import ClusterRBAC
        rbac = ClusterRBAC()
        rbac.assign_role("admin-node", "admin")
        rbac.assign_role("reader-node", "read")

        assert rbac.has_permission("admin-node", "write")
        assert rbac.has_permission("admin-node", "admin")
        assert not rbac.has_permission("reader-node", "write")
        assert rbac.has_permission("reader-node", "read")

    def test_authorize_operation(self, mock_claude_home):
        from claude_code_security.cluster_auth import ClusterRBAC
        rbac = ClusterRBAC()
        rbac.assign_role("builder", "build")

        ok, _ = rbac.authorize_operation("builder", "build")
        assert ok
        ok, _ = rbac.authorize_operation("builder", "admin")
        assert not ok
