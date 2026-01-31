"""
Tamper-Proof Audit Log: Hash-chained SQLite audit. [Tier 3]

Each entry's hash includes the previous entry's hash, creating a
tamper-evident chain. Any modification to past entries breaks the chain.

Schema:
    audit_chain(id, timestamp, event_type, actor, action, target, details,
                prev_hash, entry_hash)

Hash computation:
    SHA-256(prev_hash + timestamp + event_type + actor + action + target + details)

Genesis hash: '0' * 64
"""

import hashlib
import json
import logging
import sqlite3
import threading
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from claude_code_security import config

logger = logging.getLogger("claude_code_security.tamper_proof_log")


class TamperProofLog:
    """
    Hash-chained append-only audit log backed by SQLite.

    Each entry includes a hash of the previous entry, creating a
    cryptographic chain that detects any tampering with historical records.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or config.TAMPER_PROOF_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '',
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_chain(event_type)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_chain(timestamp)"
        )
        conn.commit()
        conn.close()

    def _compute_hash(
        self, prev_hash: str, timestamp: str, event_type: str,
        actor: str, action: str, target: str, details: str,
    ) -> str:
        message = f"{prev_hash}{timestamp}{event_type}{actor}{action}{target}{details}"
        return hashlib.sha256(message.encode("utf-8")).hexdigest()

    def _get_last_hash(self, conn: sqlite3.Connection) -> str:
        cursor = conn.cursor()
        cursor.execute("SELECT entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        return row[0] if row else config.GENESIS_HASH

    def append(
        self,
        event_type: str,
        actor: str,
        action: str,
        target: str = "",
        details: str = "",
        forward_to_loki: bool = False,
    ) -> int:
        """
        Append a new entry to the audit chain.

        Args:
            event_type: Category (e.g., "self_modification", "auth_failure")
            actor: Who performed the action
            action: What was done
            target: What was affected
            details: Additional context
            forward_to_loki: Forward to Loki (requires LOKI_ENABLED=True)

        Returns:
            The ID of the new entry
        """
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                timestamp = datetime.now(timezone.utc).isoformat()
                prev_hash = self._get_last_hash(conn)
                entry_hash = self._compute_hash(
                    prev_hash, timestamp, event_type, actor, action, target, details,
                )
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO audit_chain "
                    "(timestamp, event_type, actor, action, target, details, prev_hash, entry_hash) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (timestamp, event_type, actor, action, target, details, prev_hash, entry_hash),
                )
                conn.commit()
                entry_id = cursor.lastrowid

                if forward_to_loki and config.LOKI_ENABLED:
                    self._forward_to_loki(
                        timestamp, event_type, actor, action, target, details, entry_hash,
                    )

                return entry_id
            finally:
                conn.close()

    def verify_chain(self, limit: int = 0) -> Dict:
        """
        Verify the integrity of the audit chain.

        Returns dict with: valid, entries_checked, first_broken, error
        """
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.cursor()
            query = (
                "SELECT id, timestamp, event_type, actor, action, target, details, "
                "prev_hash, entry_hash FROM audit_chain ORDER BY id ASC"
            )
            if limit > 0:
                cursor.execute(query + " LIMIT ?", (limit,))
            else:
                cursor.execute(query)

            expected_prev_hash = config.GENESIS_HASH
            entries_checked = 0

            for row in cursor:
                entry_id, timestamp, event_type, actor, action, target, details, prev_hash, entry_hash = row
                entries_checked += 1

                if prev_hash != expected_prev_hash:
                    return {
                        "valid": False,
                        "entries_checked": entries_checked,
                        "first_broken": entry_id,
                        "error": f"Chain broken at entry {entry_id}",
                    }

                computed = self._compute_hash(
                    prev_hash, timestamp, event_type, actor, action, target, details,
                )
                if computed != entry_hash:
                    return {
                        "valid": False,
                        "entries_checked": entries_checked,
                        "first_broken": entry_id,
                        "error": f"Hash mismatch at entry {entry_id}: content modified",
                    }

                expected_prev_hash = entry_hash

            return {
                "valid": True,
                "entries_checked": entries_checked,
                "first_broken": None,
                "error": None,
            }
        finally:
            conn.close()

    def get_entries(
        self,
        event_type: Optional[str] = None,
        actor: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict]:
        conn = sqlite3.connect(str(self.db_path))
        try:
            conditions = []
            params: list = []
            if event_type:
                conditions.append("event_type = ?")
                params.append(event_type)
            if actor:
                conditions.append("actor = ?")
                params.append(actor)

            where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            params.extend([limit, offset])

            cursor = conn.cursor()
            cursor.execute(
                f"SELECT id, timestamp, event_type, actor, action, target, details, entry_hash "
                f"FROM audit_chain {where} ORDER BY id DESC LIMIT ? OFFSET ?",
                params,
            )
            return [
                {
                    "id": row[0], "timestamp": row[1], "event_type": row[2],
                    "actor": row[3], "action": row[4], "target": row[5],
                    "details": row[6], "entry_hash": row[7],
                }
                for row in cursor.fetchall()
            ]
        finally:
            conn.close()

    def get_stats(self) -> Dict:
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM audit_chain")
            total = cursor.fetchone()[0]

            cursor.execute(
                "SELECT event_type, COUNT(*) FROM audit_chain GROUP BY event_type ORDER BY COUNT(*) DESC"
            )
            by_type = dict(cursor.fetchall())

            cursor.execute(
                "SELECT actor, COUNT(*) FROM audit_chain GROUP BY actor ORDER BY COUNT(*) DESC"
            )
            by_actor = dict(cursor.fetchall())

            cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM audit_chain")
            row = cursor.fetchone()

            return {
                "total_entries": total,
                "by_event_type": by_type,
                "by_actor": by_actor,
                "first_entry": row[0] if row else None,
                "last_entry": row[1] if row else None,
                "db_path": str(self.db_path),
            }
        finally:
            conn.close()

    def _forward_to_loki(
        self, timestamp: str, event_type: str, actor: str,
        action: str, target: str, details: str, entry_hash: str,
    ):
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            ts_ns = str(int(dt.timestamp() * 1_000_000_000))
            log_line = json.dumps({
                "event_type": event_type, "actor": actor, "action": action,
                "target": target, "details": details, "entry_hash": entry_hash,
            })
            payload = json.dumps({
                "streams": [{
                    "stream": {"job": "security_audit", "source": "tamper_proof_log", "event_type": event_type},
                    "values": [[ts_ns, log_line]],
                }]
            }).encode("utf-8")
            req = urllib.request.Request(
                config.LOKI_PUSH_URL, data=payload,
                headers={"Content-Type": "application/json"}, method="POST",
            )
            threading.Thread(target=self._send_to_loki, args=(req,), daemon=True).start()
        except Exception as e:
            logger.debug(f"Failed to format Loki payload: {e}")

    @staticmethod
    def _send_to_loki(req):
        try:
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass
