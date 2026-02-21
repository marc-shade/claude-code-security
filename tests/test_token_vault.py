"""Tests for TokenVault (encrypted API token storage)."""

import json

import pytest

cryptography = pytest.importorskip("cryptography")


@pytest.fixture
def token_vault(mock_claude_home):
    """Create a TokenVault instance using the mock home."""
    from claude_code_security.token_vault import TokenVault

    return TokenVault(vault_dir=mock_claude_home / ".vault")


class TestTokenVaultStoreGet:
    def test_store_and_get_token(self, token_vault):
        assert token_vault.store_token("MY_API_KEY", "secret-value-123")
        assert token_vault.get_token("MY_API_KEY") == "secret-value-123"

    def test_get_nonexistent_token(self, token_vault):
        assert token_vault.get_token("DOES_NOT_EXIST") is None

    def test_store_empty_name_fails(self, token_vault):
        assert not token_vault.store_token("", "some-value")

    def test_store_empty_value_fails(self, token_vault):
        assert not token_vault.store_token("MY_KEY", "")

    def test_overwrite_existing_token(self, token_vault):
        token_vault.store_token("OVERWRITE_KEY", "first-value")
        token_vault.store_token("OVERWRITE_KEY", "second-value")
        assert token_vault.get_token("OVERWRITE_KEY") == "second-value"

    def test_store_preserves_unicode(self, token_vault):
        value = "token-with-unicode-\u00e9\u00e8\u00ea"
        token_vault.store_token("UNICODE_KEY", value)
        assert token_vault.get_token("UNICODE_KEY") == value

    def test_store_long_value(self, token_vault):
        value = "x" * 4096
        assert token_vault.store_token("LONG_KEY", value)
        assert token_vault.get_token("LONG_KEY") == value


class TestTokenVaultDelete:
    def test_delete_existing_token(self, token_vault):
        token_vault.store_token("DELETE_ME", "value")
        assert token_vault.delete_token("DELETE_ME")
        assert token_vault.get_token("DELETE_ME") is None

    def test_delete_removes_metadata(self, token_vault):
        token_vault.store_token("META_DELETE", "value")
        assert token_vault.delete_token("META_DELETE")
        # Metadata file should be gone
        meta_path = token_vault._meta_path("META_DELETE")
        assert not meta_path.exists()

    def test_delete_nonexistent_token(self, token_vault):
        # Should not raise; implementation returns True even for missing keys
        result = token_vault.delete_token("NEVER_STORED")
        assert isinstance(result, bool)


class TestTokenVaultList:
    def test_list_empty_vault(self, token_vault):
        assert token_vault.list_tokens() == []

    def test_list_returns_metadata(self, token_vault):
        token_vault.store_token("LIST_KEY", "val", category="llm", note="test")
        tokens = token_vault.list_tokens()
        assert len(tokens) == 1
        assert tokens[0]["name"] == "LIST_KEY"
        assert tokens[0]["category"] == "llm"
        assert tokens[0]["note"] == "test"
        assert "stored_at" in tokens[0]
        # Actual secret value should not appear as a standalone field
        meta_str = json.dumps(tokens[0])
        assert '"val"' not in meta_str  # Raw secret not exposed as a JSON value

    def test_list_filter_by_category(self, token_vault):
        token_vault.store_token("ANTHROPIC_API_KEY", "sk-ant-xxx", category="llm")
        token_vault.store_token("STRIPE_SECRET", "sk_test_xxx", category="service")
        token_vault.store_token("GCP_TOKEN", "ya29.xxx", category="cloud")

        llm_tokens = token_vault.list_tokens(category="llm")
        assert len(llm_tokens) == 1
        assert llm_tokens[0]["name"] == "ANTHROPIC_API_KEY"

        service_tokens = token_vault.list_tokens(category="service")
        assert len(service_tokens) == 1
        assert service_tokens[0]["name"] == "STRIPE_SECRET"

    def test_list_no_match_category(self, token_vault):
        token_vault.store_token("KEY1", "val1", category="llm")
        assert token_vault.list_tokens(category="cluster") == []

    def test_list_multiple_tokens(self, token_vault):
        for i in range(5):
            token_vault.store_token(f"KEY_{i}", f"val_{i}")
        tokens = token_vault.list_tokens()
        assert len(tokens) == 5


class TestTokenVaultAutoCategory:
    def test_auto_detect_llm(self, token_vault):
        token_vault.store_token("ANTHROPIC_API_KEY", "value")
        tokens = token_vault.list_tokens()
        assert tokens[0]["category"] == "llm"

    def test_auto_detect_cloud(self, token_vault):
        token_vault.store_token("AWS_SECRET_ACCESS_KEY", "value")
        tokens = token_vault.list_tokens()
        assert tokens[0]["category"] == "cloud"

    def test_auto_detect_service(self, token_vault):
        token_vault.store_token("STRIPE_API_KEY", "value")
        tokens = token_vault.list_tokens()
        assert tokens[0]["category"] == "service"

    def test_auto_detect_cluster(self, token_vault):
        token_vault.store_token("NODE_LISTENER_AUTH_TOKEN", "value")
        tokens = token_vault.list_tokens()
        assert tokens[0]["category"] == "cluster"

    def test_auto_detect_fallback_other(self, token_vault):
        token_vault.store_token("RANDOM_SETTING", "value")
        tokens = token_vault.list_tokens()
        assert tokens[0]["category"] == "other"

    def test_explicit_category_overrides_auto(self, token_vault):
        token_vault.store_token("ANTHROPIC_API_KEY", "value", category="custom")
        tokens = token_vault.list_tokens()
        assert tokens[0]["category"] == "custom"


class TestTokenVaultExportShell:
    def test_export_shell_empty(self, token_vault):
        output = token_vault.export_shell()
        assert "# Token Vault exports" in output
        assert "export " not in output.split("\n", 3)[-1]

    def test_export_shell_format(self, token_vault):
        token_vault.store_token("MY_KEY", "my-secret-value")
        output = token_vault.export_shell()
        assert "export MY_KEY='my-secret-value'" in output

    def test_export_shell_escapes_single_quotes(self, token_vault):
        token_vault.store_token("QUOTE_KEY", "it's a value")
        output = token_vault.export_shell()
        assert "QUOTE_KEY=" in output
        # Should escape the single quote
        assert "'\\''" in output

    def test_export_shell_filter_by_category(self, token_vault):
        token_vault.store_token("LLM_KEY", "llm-val", category="llm")
        token_vault.store_token("SVC_KEY", "svc-val", category="service")

        output = token_vault.export_shell(category="llm")
        assert "LLM_KEY" in output
        assert "SVC_KEY" not in output

    def test_export_shell_groups_by_category(self, token_vault):
        token_vault.store_token("ANTHROPIC_API_KEY", "val1", category="llm")
        token_vault.store_token("OPENAI_API_KEY", "val2", category="llm")
        token_vault.store_token("STRIPE_KEY", "val3", category="service")

        output = token_vault.export_shell()
        assert "# --- llm ---" in output
        assert "# --- service ---" in output


class TestTokenVaultImportFromEnv:
    def test_import_specific_names(self, token_vault, monkeypatch):
        monkeypatch.setenv("TEST_API_KEY", "from-env-123")
        results = token_vault.import_from_env(names=["TEST_API_KEY"])
        assert results["TEST_API_KEY"] is True
        assert token_vault.get_token("TEST_API_KEY") == "from-env-123"

    def test_import_missing_env_var(self, token_vault, monkeypatch):
        monkeypatch.delenv("NONEXISTENT_KEY", raising=False)
        results = token_vault.import_from_env(names=["NONEXISTENT_KEY"])
        assert results["NONEXISTENT_KEY"] is False

    def test_import_auto_discover(self, token_vault, monkeypatch):
        monkeypatch.setenv("MY_API_KEY", "discovered-value")
        monkeypatch.setenv("SOME_SECRET", "another-value")
        results = token_vault.import_from_env()
        assert results.get("MY_API_KEY") is True
        assert results.get("SOME_SECRET") is True

    def test_import_skips_system_vars(self, token_vault, monkeypatch):
        monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock")
        results = token_vault.import_from_env()
        assert "SSH_AUTH_SOCK" not in results


class TestTokenVaultStatus:
    def test_status_empty_vault(self, token_vault):
        status = token_vault.get_status()
        assert status["token_count"] == 0
        assert status["by_category"] == {}
        assert "vault_dir" in status
        assert "categories" in status

    def test_status_with_tokens(self, token_vault):
        token_vault.store_token("ANTHROPIC_API_KEY", "val1", category="llm")
        token_vault.store_token("OPENAI_API_KEY", "val2", category="llm")
        token_vault.store_token("STRIPE_KEY", "val3", category="service")

        status = token_vault.get_status()
        assert status["token_count"] == 3
        assert status["by_category"]["llm"] == 2
        assert status["by_category"]["service"] == 1

    def test_status_after_delete(self, token_vault):
        token_vault.store_token("TEMP_KEY", "val")
        token_vault.delete_token("TEMP_KEY")
        status = token_vault.get_status()
        assert status["token_count"] == 0


class TestTokenVaultMetadata:
    def test_metadata_has_prefix(self, token_vault):
        token_vault.store_token("LONG_TOKEN", "abcdefghijklmnopqrstuvwxyz")
        tokens = token_vault.list_tokens()
        assert tokens[0]["prefix"] == "abcdefgh..."

    def test_metadata_short_value_masked(self, token_vault):
        token_vault.store_token("SHORT_TOKEN", "abc")
        tokens = token_vault.list_tokens()
        assert tokens[0]["prefix"] == "***"

    def test_metadata_has_value_length(self, token_vault):
        token_vault.store_token("LEN_TEST", "exactly-twenty-chars")
        tokens = token_vault.list_tokens()
        assert tokens[0]["value_length"] == 20

    def test_metadata_has_timestamps(self, token_vault):
        token_vault.store_token("TS_TEST", "value")
        tokens = token_vault.list_tokens()
        assert "stored_at" in tokens[0]
        assert "updated_at" in tokens[0]
