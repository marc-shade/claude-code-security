"""
Self-Modification Auditor: Diff capture on config changes. [Tier 3]

Captures before/after diffs when monitored configuration files
are modified. Stores unified diffs in JSON audit files and
re-signs modified files in the integrity manifest.
"""

import difflib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from claude_code_security import config

logger = logging.getLogger("claude_code_security.self_modification_auditor")


def is_monitored_path(file_path: str) -> bool:
    """Check if a file path falls within monitored self-modification paths."""
    normalized = str(Path(file_path).resolve())
    for pattern in config.SELF_MOD_MONITORED_PATTERNS:
        if normalized.startswith(str(Path(pattern).resolve())):
            return True
    return False


def compute_diff(old_content: str, new_content: str, file_path: str) -> str:
    """Compute unified diff between old and new content."""
    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)
    diff = difflib.unified_diff(
        old_lines, new_lines,
        fromfile=f"a/{Path(file_path).name}",
        tofile=f"b/{Path(file_path).name}",
        lineterm="",
    )
    return "\n".join(diff)


def _store_audit(
    file_path: str, tool_name: str, diff_text: str,
    old_size: int, new_size: int,
) -> bool:
    """Store audit entry as JSON file in audit log directory."""
    timestamp = datetime.now().isoformat()
    entity_name = f"audit-{Path(file_path).name}-{timestamp[:19].replace(':', '-')}"

    try:
        audit_dir = config.AUDIT_LOG_DIR
        audit_dir.mkdir(parents=True, exist_ok=True)

        audit_file = audit_dir / f"{entity_name}.json"
        with open(audit_file, "w") as f:
            json.dump({
                "entity_name": entity_name,
                "entity_type": "self_modification_audit",
                "tool": tool_name,
                "path": file_path,
                "timestamp": timestamp,
                "old_size": old_size,
                "new_size": new_size,
                "diff_lines": len(diff_text.splitlines()),
                "full_diff": diff_text,
            }, f, indent=2)

        logger.info(f"Audit stored: {entity_name} -> {audit_file}")
        return True

    except Exception as e:
        logger.error(f"Failed to store audit: {e}")
        return False


def _re_sign_file(file_path: str) -> bool:
    """Re-sign file in the integrity manifest after modification."""
    try:
        from claude_code_security.file_integrity import re_sign_after_modification
        return re_sign_after_modification(Path(file_path), signer_id="audit_hook")
    except ImportError:
        logger.debug("File integrity module not available for re-signing")
        return False
    except Exception as e:
        logger.error(f"Failed to re-sign {file_path}: {e}")
        return False


def audit_modification(
    tool_name: str,
    file_path: str,
    old_content: Optional[str] = None,
    new_content: Optional[str] = None,
) -> Dict:
    """
    Audit a file modification.

    Called by PostToolUse hook when Write or Edit tools modify monitored paths.

    Args:
        tool_name: "Write" or "Edit"
        file_path: Absolute path to the modified file
        old_content: Content before modification (None if new file)
        new_content: Content after modification (None if deletion)

    Returns:
        Audit result dict with status and details
    """
    if not is_monitored_path(file_path):
        return {"audited": False, "reason": "not_monitored"}

    old_content = old_content or ""
    new_content = new_content or ""
    diff_text = compute_diff(old_content, new_content, file_path)

    if not diff_text:
        return {"audited": False, "reason": "no_changes"}

    stored = _store_audit(
        file_path=file_path,
        tool_name=tool_name,
        diff_text=diff_text,
        old_size=len(old_content.encode("utf-8")),
        new_size=len(new_content.encode("utf-8")),
    )

    re_signed = _re_sign_file(file_path)

    try:
        from claude_code_security.tamper_proof_log import TamperProofLog
        audit_log = TamperProofLog()
        audit_log.append(
            event_type="self_modification",
            actor=tool_name,
            action="modify",
            target=file_path,
            details=f"diff_lines={len(diff_text.splitlines())}, stored={stored}",
        )
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"Tamper-proof log unavailable: {e}")

    result = {
        "audited": True,
        "file": file_path,
        "tool": tool_name,
        "diff_lines": len(diff_text.splitlines()),
        "stored": stored,
        "re_signed": re_signed,
        "timestamp": datetime.now().isoformat(),
    }

    logger.info(
        f"Self-modification audited: {file_path} via {tool_name} "
        f"({len(diff_text.splitlines())} diff lines)"
    )
    return result
