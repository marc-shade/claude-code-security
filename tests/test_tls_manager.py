"""Tests for TLSManager (ECDSA P-256 cluster CA)."""

import pytest

cryptography = pytest.importorskip("cryptography")


class TestTLSManager:
    def test_ca_creation(self, mock_claude_home):
        from claude_code_security.tls_manager import TLSManager
        certs_dir = mock_claude_home / "certs"
        certs_dir.mkdir(exist_ok=True)
        mgr = TLSManager(certs_dir=certs_dir)
        ca_cert, ca_key = mgr._get_or_create_ca()
        assert ca_cert is not None
        assert ca_key is not None
        assert (certs_dir / "cluster_ca.pem").exists()

    def test_node_cert_generation(self, mock_claude_home):
        from claude_code_security.tls_manager import TLSManager
        certs_dir = mock_claude_home / "certs"
        certs_dir.mkdir(exist_ok=True)
        mgr = TLSManager(certs_dir=certs_dir)
        result = mgr.generate_node_cert("test-node")
        assert result["node_id"] == "test-node"
        assert (certs_dir / "test-node.pem").exists()
        assert (certs_dir / "test-node.key").exists()

    def test_cert_verification(self, mock_claude_home):
        from claude_code_security.tls_manager import TLSManager
        certs_dir = mock_claude_home / "certs"
        certs_dir.mkdir(exist_ok=True)
        mgr = TLSManager(certs_dir=certs_dir)
        mgr.generate_node_cert("verify-node")
        result = mgr.verify_cert(certs_dir / "verify-node.pem")
        assert result["valid"]

    def test_cert_inventory(self, mock_claude_home):
        from claude_code_security.tls_manager import TLSManager
        certs_dir = mock_claude_home / "certs"
        certs_dir.mkdir(exist_ok=True)
        mgr = TLSManager(certs_dir=certs_dir)
        mgr.generate_node_cert("inv-a")
        mgr.generate_node_cert("inv-b")
        inv = mgr.get_cert_inventory()
        # CA + 2 nodes = 3 certs
        assert len(inv) >= 3

    def test_ssl_context_creation(self, mock_claude_home):
        from claude_code_security.tls_manager import TLSManager
        certs_dir = mock_claude_home / "certs"
        certs_dir.mkdir(exist_ok=True)
        mgr = TLSManager(certs_dir=certs_dir)
        ctx = mgr.create_ssl_context("ssl-node", purpose="client")
        assert ctx is not None

    def test_cert_expiry_check(self, mock_claude_home):
        from claude_code_security.tls_manager import TLSManager
        certs_dir = mock_claude_home / "certs"
        certs_dir.mkdir(exist_ok=True)
        mgr = TLSManager(certs_dir=certs_dir)
        mgr.generate_node_cert("expiry-node")
        # Freshly generated cert should not be expiring
        assert not mgr.is_cert_expiring("expiry-node", days_threshold=30)

    def test_missing_cert_is_expiring(self, mock_claude_home):
        from claude_code_security.tls_manager import TLSManager
        certs_dir = mock_claude_home / "certs"
        certs_dir.mkdir(exist_ok=True)
        mgr = TLSManager(certs_dir=certs_dir)
        assert mgr.is_cert_expiring("nonexistent-node")

    def test_cert_rotation(self, mock_claude_home):
        from claude_code_security.tls_manager import TLSManager
        certs_dir = mock_claude_home / "certs"
        certs_dir.mkdir(exist_ok=True)
        mgr = TLSManager(certs_dir=certs_dir)
        mgr.generate_node_cert("rotate-node")
        old_cert = (certs_dir / "rotate-node.pem").read_bytes()
        result = mgr.rotate_node_cert("rotate-node")
        new_cert = (certs_dir / "rotate-node.pem").read_bytes()
        assert old_cert != new_cert
        assert (certs_dir / "rotate-node.pem.bak").exists()
