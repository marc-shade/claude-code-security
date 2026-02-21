"""
Token Vault: Encrypted storage for API tokens and service credentials.

Extends the KeyVault (AES-256-GCM) to handle string tokens with
categories, expiry tracking, and shell integration.

Usage:
    from claude_code_security.token_vault import TokenVault

    vault = TokenVault()
    vault.store_token("ANTHROPIC_API_KEY", "sk-ant-...", category="llm")
    key = vault.get_token("ANTHROPIC_API_KEY")
    env_script = vault.export_shell()  # => export ANTHROPIC_API_KEY='...'
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from claude_code_security.key_vault import KeyVault

logger = logging.getLogger("claude_code_security.token_vault")

# Token categories for organization
CATEGORIES = {
    "llm": "LLM API providers (Anthropic, OpenAI, Groq, etc.)",
    "cloud": "Cloud platforms (GCP, AWS, Azure)",
    "service": "Service APIs (Stripe, Render, Brave, etc.)",
    "cluster": "Cluster authentication tokens",
    "other": "Uncategorized tokens",
}

# Auto-detect category from token name
CATEGORY_PATTERNS = {
    "llm": re.compile(
        r"ANTHROPIC|OPENAI|GROQ|MISTRAL|OPENROUTER|TOGETHER|OLLAMA|HF_TOKEN|GEMINI",
        re.IGNORECASE,
    ),
    "cloud": re.compile(
        r"GCLOUD|GCP|AWS|AZURE|GOOGLE_API|COPERNICUS", re.IGNORECASE,
    ),
    "service": re.compile(
        r"STRIPE|RENDER|BRAVE|SLACK|DISCORD|GITHUB_TOKEN", re.IGNORECASE,
    ),
    "cluster": re.compile(
        r"CLUSTER|NODE_LISTENER|CLAWDBOT", re.IGNORECASE,
    ),
}


def _detect_category(name: str) -> str:
    """Auto-detect token category from its name."""
    for cat, pattern in CATEGORY_PATTERNS.items():
        if pattern.search(name):
            return cat
    return "other"


class TokenVault:
    """
    Encrypted token vault built on top of KeyVault.

    Stores API tokens as AES-256-GCM encrypted blobs with metadata
    including category, creation time, and usage notes.
    """

    TOKEN_PREFIX = "token_"

    def __init__(self, vault_dir: Optional[Path] = None):
        from claude_code_security import config
        self._vault_dir = vault_dir or config.VAULT_DIR
        self._kv = KeyVault(self._vault_dir)
        self._meta_dir = self._vault_dir / "token_meta"
        self._meta_dir.mkdir(parents=True, exist_ok=True)

    def _token_name(self, name: str) -> str:
        """Internal vault key name for a token."""
        return f"{self.TOKEN_PREFIX}{name}"

    def _meta_path(self, name: str) -> Path:
        safe = name.replace("/", "_").replace("\\", "_")
        return self._meta_dir / f"{safe}.json"

    def store_token(
        self,
        name: str,
        value: str,
        category: Optional[str] = None,
        note: str = "",
    ) -> bool:
        """Store an API token in the vault."""
        if not name or not value:
            logger.error("Token name and value are required")
            return False

        cat = category or _detect_category(name)
        internal_name = self._token_name(name)

        if not self._kv.store_key(internal_name, value.encode("utf-8")):
            return False

        meta = {
            "name": name,
            "category": cat,
            "note": note,
            "stored_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "value_length": len(value),
            "prefix": value[:8] + "..." if len(value) > 12 else "***",
        }
        try:
            self._meta_path(name).write_text(json.dumps(meta, indent=2))
        except OSError as e:
            logger.warning(f"Failed to write token metadata for {name}: {e}")

        logger.info(f"Stored token: {name} (category={cat})")
        return True

    def get_token(self, name: str) -> Optional[str]:
        """Retrieve a decrypted token value."""
        internal_name = self._token_name(name)
        raw = self._kv.load_key(internal_name)
        if raw is None:
            return None
        return raw.decode("utf-8")

    def delete_token(self, name: str) -> bool:
        """Delete a token from the vault."""
        internal_name = self._token_name(name)
        ok = self._kv.delete_key(internal_name)
        meta_path = self._meta_path(name)
        if meta_path.exists():
            meta_path.unlink(missing_ok=True)
        if ok:
            logger.info(f"Deleted token: {name}")
        return ok

    def list_tokens(self, category: Optional[str] = None) -> List[Dict]:
        """List all stored tokens (metadata only, no values)."""
        tokens = []
        for meta_file in sorted(self._meta_dir.glob("*.json")):
            try:
                meta = json.loads(meta_file.read_text())
                if category and meta.get("category") != category:
                    continue
                tokens.append(meta)
            except (json.JSONDecodeError, OSError):
                continue
        return tokens

    def export_shell(self, category: Optional[str] = None) -> str:
        """Generate shell export statements for all tokens.

        Returns a string like:
            export ANTHROPIC_API_KEY='sk-ant-...'
            export OPENAI_API_KEY='sk-proj-...'
        """
        lines = ["# Token Vault exports (auto-generated)"]
        lines.append(f"# Generated: {datetime.now(timezone.utc).isoformat()}")
        lines.append("")

        tokens = self.list_tokens(category=category)
        current_cat = None
        for meta in sorted(tokens, key=lambda t: (t.get("category", ""), t["name"])):
            name = meta["name"]
            cat = meta.get("category", "other")
            value = self.get_token(name)
            if value is None:
                lines.append(f"# WARN: could not decrypt {name}")
                continue
            if cat != current_cat:
                lines.append(f"# --- {cat} ---")
                current_cat = cat
            # Use single quotes to prevent shell expansion; escape embedded quotes
            safe_value = value.replace("'", "'\\''")
            lines.append(f"export {name}='{safe_value}'")

        lines.append("")
        return "\n".join(lines)

    def import_from_env(self, names: Optional[List[str]] = None) -> Dict[str, bool]:
        """Import tokens from current environment variables.

        If names is None, imports all known token-like env vars.
        Returns {name: success} mapping.
        """
        if names is None:
            names = [
                k for k in os.environ
                if any(
                    p in k.upper()
                    for p in ("API_KEY", "SECRET", "TOKEN", "AUTH_TOKEN")
                )
                and k not in ("SSH_AUTH_SOCK", "TERM_SESSION_ID")
                and not k.startswith("npm_")
            ]

        results = {}
        for name in sorted(names):
            value = os.environ.get(name)
            if not value:
                results[name] = False
                continue
            results[name] = self.store_token(name, value)
        return results

    def import_from_zshrc(self, zshrc_path: Optional[Path] = None) -> Dict[str, bool]:
        """Parse .zshrc for export statements and import tokens.

        Extracts lines matching: export NAME="value" or export NAME='value'
        Only imports token-like names (containing API_KEY, SECRET, TOKEN, etc).
        """
        zshrc = zshrc_path or Path.home() / ".zshrc"
        if not zshrc.exists():
            logger.error(f"File not found: {zshrc}")
            return {}

        token_pattern = re.compile(
            r'^export\s+([A-Z_][A-Z0-9_]*)\s*=\s*["\']([^"\']+)["\']',
        )
        token_name_filter = re.compile(
            r"API_KEY|SECRET|TOKEN|AUTH", re.IGNORECASE,
        )

        results = {}
        for line in zshrc.read_text().splitlines():
            line = line.strip()
            if line.startswith("#"):
                continue
            m = token_pattern.match(line)
            if not m:
                continue
            name, value = m.group(1), m.group(2)
            if not token_name_filter.search(name):
                continue
            # Skip placeholder values
            if "your-key-here" in value or value.startswith("xxx"):
                continue
            results[name] = self.store_token(name, value)

        return results

    def get_status(self) -> Dict:
        """Get vault status summary."""
        tokens = self.list_tokens()
        by_cat = {}
        for t in tokens:
            cat = t.get("category", "other")
            by_cat[cat] = by_cat.get(cat, 0) + 1

        return {
            "vault_dir": str(self._vault_dir),
            "token_count": len(tokens),
            "by_category": by_cat,
            "categories": CATEGORIES,
        }
