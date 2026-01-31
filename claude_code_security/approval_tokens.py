"""
Approval Tokens: HMAC time-limited tokens. [Tier 2]

Replaces insecure CHANGE_APPROVED=true env var bypass with
cryptographically verifiable, time-limited, action-specific tokens.

Token Format:
    base64(timestamp:action_hash:hmac_signature)
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional, Tuple

from claude_code_security import config

logger = logging.getLogger("claude_code_security.approval_tokens")


class ApprovalTokenManager:
    """
    HMAC-based time-limited approval tokens.

    Tokens are bound to a specific action, expire after a configurable
    TTL, and are signed with a per-session key stored in the vault.
    """

    def __init__(self):
        self._session_key = self._get_session_key()
        self._revoked = False

    def _get_session_key(self) -> bytes:
        try:
            from claude_code_security.key_vault import KeyVault
            vault = KeyVault()
            key = vault.load_key("approval_session_key")
            if key:
                return key
            key = os.urandom(32)
            vault.store_key("approval_session_key", key)
            return key
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"Vault unavailable for session key: {e}")
        return os.urandom(32)

    def generate_token(self, action: str, reason: str = "") -> str:
        """Generate a time-limited approval token for an action."""
        timestamp = str(int(time.time()))
        action_hash = hashlib.sha256(action.encode("utf-8")).hexdigest()[:16]
        message = f"{timestamp}:{action_hash}"
        signature = hmac.new(
            self._session_key, message.encode("utf-8"), hashlib.sha256,
        ).hexdigest()
        token_data = f"{timestamp}:{action_hash}:{signature}"
        token = base64.b64encode(token_data.encode("utf-8")).decode("utf-8")
        self._log("generate", action, reason, True)
        return token

    def validate_token(self, token: str, action: str = "") -> Tuple[bool, str]:
        """Validate an approval token. Returns (valid, reason)."""
        if self._revoked:
            self._log("validate", action, "all tokens revoked", False)
            return False, "All tokens have been revoked"

        try:
            token_data = base64.b64decode(token).decode("utf-8")
            parts = token_data.split(":")
            if len(parts) != 3:
                self._log("validate", action, "invalid format", False)
                return False, "Invalid token format"

            timestamp_str, action_hash, signature = parts

            token_time = int(timestamp_str)
            age = time.time() - token_time
            if age > config.TOKEN_VALIDITY_SECONDS:
                self._log("validate", action, f"expired ({age:.0f}s)", False)
                return False, f"Token expired ({age:.0f}s old, max {config.TOKEN_VALIDITY_SECONDS}s)"
            if age < -60:
                self._log("validate", action, "future timestamp", False)
                return False, "Token timestamp is in the future"

            message = f"{timestamp_str}:{action_hash}"
            expected = hmac.new(
                self._session_key, message.encode("utf-8"), hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, signature):
                self._log("validate", action, "invalid signature", False)
                return False, "Invalid token signature"

            if action:
                expected_hash = hashlib.sha256(action.encode("utf-8")).hexdigest()[:16]
                if action_hash != expected_hash:
                    self._log("validate", action, "action mismatch", False)
                    return False, "Token action mismatch"

            self._log("validate", action, "valid", True)
            return True, "Token valid"

        except Exception as e:
            self._log("validate", action, f"error: {e}", False)
            return False, f"Token validation error: {e}"

    def revoke_all_tokens(self):
        """Revoke all tokens for this session."""
        self._revoked = True
        self._session_key = os.urandom(32)
        self._log("revoke", "all", "session revoked", True)

    def _log(self, operation: str, action: str, reason: str, success: bool):
        try:
            config.APPROVAL_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "timestamp": time.time(),
                "operation": operation,
                "action": action,
                "reason": reason,
                "success": success,
            }
            with open(config.APPROVAL_LOG_PATH, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass
