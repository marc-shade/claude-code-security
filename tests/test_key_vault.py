"""Tests for KeyVault (AES-256-GCM encrypted key storage)."""

import os
import pytest

cryptography = pytest.importorskip("cryptography")


class TestKeyVault:
    def test_store_and_load_key(self, mock_vault):
        key = os.urandom(32)
        assert mock_vault.store_key("test_key", key)
        loaded = mock_vault.load_key("test_key")
        assert loaded == key

    def test_load_nonexistent_key(self, mock_vault):
        assert mock_vault.load_key("nonexistent") is None

    def test_delete_key(self, mock_vault):
        key = os.urandom(32)
        mock_vault.store_key("delete_me", key)
        assert mock_vault.delete_key("delete_me")
        assert mock_vault.load_key("delete_me") is None

    def test_list_keys(self, mock_vault):
        mock_vault.store_key("alpha", os.urandom(32))
        mock_vault.store_key("beta", os.urandom(32))
        keys = mock_vault.list_keys()
        assert "alpha" in keys
        assert "beta" in keys

    def test_rotate_key(self, mock_vault):
        original = os.urandom(32)
        mock_vault.store_key("rotate_me", original)
        assert mock_vault.rotate_key("rotate_me")
        rotated = mock_vault.load_key("rotate_me")
        assert rotated is not None
        assert rotated != original

    def test_rotate_nonexistent_key(self, mock_vault):
        assert not mock_vault.rotate_key("no_such_key")

    def test_encrypt_decrypt_roundtrip(self, mock_vault):
        data = b"sensitive signing key material"
        encrypted = mock_vault.encrypt_key(data)
        assert encrypted != data
        decrypted = mock_vault.decrypt_key(encrypted)
        assert decrypted == data

    def test_different_keys_different_ciphertext(self, mock_vault):
        data = b"same data"
        enc1 = mock_vault.encrypt_key(data)
        enc2 = mock_vault.encrypt_key(data)
        # Different nonces should produce different ciphertext
        assert enc1 != enc2

    def test_tampered_ciphertext_fails(self, mock_vault):
        data = b"important key"
        encrypted = mock_vault.encrypt_key(data)
        tampered = bytearray(encrypted)
        tampered[20] ^= 0xFF
        with pytest.raises(Exception):
            mock_vault.decrypt_key(bytes(tampered))

    def test_migrate_plaintext_key(self, mock_vault, tmp_path):
        plaintext_path = tmp_path / "old_key"
        key_data = os.urandom(32)
        plaintext_path.write_bytes(key_data)

        assert mock_vault.migrate_plaintext_key("migrated", plaintext_path)
        assert not plaintext_path.exists()
        assert mock_vault.load_key("migrated") == key_data

    def test_get_status(self, mock_vault):
        mock_vault.store_key("status_test", os.urandom(32))
        status = mock_vault.get_status()
        assert status["key_count"] >= 1
        assert any(k["name"] == "status_test" for k in status["keys"])

    def test_atomic_write(self, mock_vault):
        """Verify no .tmp files are left after store."""
        mock_vault.store_key("atomic_test", os.urandom(32))
        tmp_files = list(mock_vault.vault_dir.glob("*.tmp"))
        assert len(tmp_files) == 0
