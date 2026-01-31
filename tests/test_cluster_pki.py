"""Tests for ClusterPKI (Ed25519 challenge-response)."""

import time
import pytest

cryptography = pytest.importorskip("cryptography")


class TestClusterPKI:
    def test_generate_keypair(self, mock_claude_home):
        from claude_code_security.cluster_pki import ClusterPKI
        pki = ClusterPKI()
        result = pki.get_or_create_keypair("test-node")
        assert result["node_id"] == "test-node"
        assert len(result["public_key_hex"]) == 64  # 32 bytes hex

    def test_keypair_persistence(self, mock_claude_home):
        from claude_code_security.cluster_pki import ClusterPKI
        pki1 = ClusterPKI()
        result1 = pki1.get_or_create_keypair("persist-node")

        pki2 = ClusterPKI()
        result2 = pki2.get_or_create_keypair("persist-node")
        assert result1["public_key_hex"] == result2["public_key_hex"]

    def test_challenge_response_flow(self, mock_claude_home):
        from claude_code_security.cluster_pki import ClusterPKI
        pki = ClusterPKI()
        pki.get_or_create_keypair("auth-node")

        challenge = pki.create_auth_challenge()
        signature = pki.sign_challenge("auth-node", challenge["challenge_data"])
        assert signature is not None

        valid, reason = pki.verify_challenge_response(
            "auth-node", challenge["challenge_data"], signature,
        )
        assert valid
        assert reason == "Signature verified"

    def test_wrong_node_rejected(self, mock_claude_home):
        from claude_code_security.cluster_pki import ClusterPKI
        pki = ClusterPKI()
        pki.get_or_create_keypair("node-a")
        pki.get_or_create_keypair("node-b")

        challenge = pki.create_auth_challenge()
        sig = pki.sign_challenge("node-a", challenge["challenge_data"])

        valid, _ = pki.verify_challenge_response(
            "node-b", challenge["challenge_data"], sig,
        )
        assert not valid

    def test_nonce_replay_rejected(self, mock_claude_home):
        from claude_code_security.cluster_pki import ClusterPKI
        pki = ClusterPKI()
        pki.get_or_create_keypair("replay-node")

        challenge = pki.create_auth_challenge()
        sig = pki.sign_challenge("replay-node", challenge["challenge_data"])

        valid1, _ = pki.verify_challenge_response(
            "replay-node", challenge["challenge_data"], sig,
        )
        assert valid1

        valid2, reason = pki.verify_challenge_response(
            "replay-node", challenge["challenge_data"], sig,
        )
        assert not valid2
        assert "replay" in reason.lower()

    def test_expired_challenge_rejected(self, mock_claude_home, monkeypatch):
        import claude_code_security.config as cfg
        monkeypatch.setattr(cfg, "CHALLENGE_EXPIRY_SECONDS", 1)

        from claude_code_security.cluster_pki import ClusterPKI
        pki = ClusterPKI()
        pki.get_or_create_keypair("expire-node")

        challenge = pki.create_auth_challenge()
        sig = pki.sign_challenge("expire-node", challenge["challenge_data"])
        time.sleep(1.5)

        valid, reason = pki.verify_challenge_response(
            "expire-node", challenge["challenge_data"], sig,
        )
        assert not valid
        assert "expired" in reason.lower()

    def test_revoke_node(self, mock_claude_home):
        from claude_code_security.cluster_pki import ClusterPKI
        pki = ClusterPKI()
        pki.get_or_create_keypair("revoke-me")
        assert pki.revoke_node("revoke-me", reason="compromised")
        assert pki.is_revoked("revoke-me")

    def test_revoked_node_rejected(self, mock_claude_home):
        from claude_code_security.cluster_pki import ClusterPKI
        pki = ClusterPKI()
        pki.get_or_create_keypair("revoked-node")
        pki.revoke_node("revoked-node")

        challenge = pki.create_auth_challenge()
        sig = pki.sign_challenge("revoked-node", challenge["challenge_data"])

        valid, reason = pki.verify_challenge_response(
            "revoked-node", challenge["challenge_data"], sig,
        )
        assert not valid
        assert "revoked" in reason.lower()

    def test_trusted_nodes(self, mock_claude_home):
        from claude_code_security.cluster_pki import ClusterPKI
        pki = ClusterPKI()
        pki.get_or_create_keypair("trusted-a")
        pki.get_or_create_keypair("trusted-b")
        pki.get_or_create_keypair("untrusted")
        pki.revoke_node("untrusted")

        trusted = pki.get_trusted_nodes()
        assert "trusted-a" in trusted
        assert "trusted-b" in trusted
        assert "untrusted" not in trusted
