"""
File Watcher: Watchdog real-time monitoring. [Tier 3]

Watches monitored directories for changes using watchdog and triggers
integrity re-verification. Logs events to tamper-proof audit log.

Dependencies:
    pip install watchdog (optional, graceful ImportError)
"""

import logging
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from claude_code_security import config

logger = logging.getLogger("claude_code_security.file_watcher")


try:
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    from watchdog.observers import Observer

    class IntegrityEventHandler(FileSystemEventHandler):
        """Handles file system events for integrity monitoring."""

        def __init__(
            self,
            alert_callback: Optional[Callable] = None,
            extensions: Optional[set] = None,
        ):
            super().__init__()
            self.alert_callback = alert_callback
            self.extensions = extensions or config.MONITORED_EXTENSIONS
            self._stats = {
                "modifications": 0,
                "creations": 0,
                "deletions": 0,
                "alerts_fired": 0,
            }
            self._lock = threading.Lock()

        def _should_handle(self, path: str) -> bool:
            return Path(path).suffix in self.extensions

        def on_modified(self, event: FileSystemEvent):
            if event.is_directory or not self._should_handle(event.src_path):
                return
            with self._lock:
                self._stats["modifications"] += 1
            self._handle_change("modified", event.src_path)

        def on_created(self, event: FileSystemEvent):
            if event.is_directory or not self._should_handle(event.src_path):
                return
            with self._lock:
                self._stats["creations"] += 1
            self._handle_change("created", event.src_path)

        def on_deleted(self, event: FileSystemEvent):
            if event.is_directory or not self._should_handle(event.src_path):
                return
            with self._lock:
                self._stats["deletions"] += 1
            self._handle_change("deleted", event.src_path)

        def _handle_change(self, change_type: str, file_path: str):
            logger.info(f"File {change_type}: {file_path}")

            try:
                from claude_code_security.file_integrity import FileIntegritySigner
                signer = FileIntegritySigner()
                if change_type != "deleted":
                    status = signer.verify_file(Path(file_path))
                    if status == "tampered":
                        logger.warning(f"TAMPERED file detected: {file_path}")
                else:
                    status = "deleted"
            except ImportError:
                status = "integrity_module_unavailable"
            except Exception as e:
                status = f"error: {e}"

            try:
                from claude_code_security.tamper_proof_log import TamperProofLog
                audit = TamperProofLog()
                audit.append(
                    event_type="file_integrity_change",
                    actor="file_watcher",
                    action=change_type,
                    target=file_path,
                    details=f"status={status}",
                )
            except ImportError:
                pass
            except Exception:
                pass

            if self.alert_callback:
                try:
                    self.alert_callback({
                        "change_type": change_type,
                        "file_path": file_path,
                        "status": status,
                        "timestamp": time.time(),
                    })
                    with self._lock:
                        self._stats["alerts_fired"] += 1
                except Exception as e:
                    logger.error(f"Alert callback error: {e}")

        def get_stats(self) -> Dict:
            with self._lock:
                return self._stats.copy()

    WATCHDOG_AVAILABLE = True

except ImportError:
    WATCHDOG_AVAILABLE = False
    Observer = None  # type: ignore[assignment,misc]
    IntegrityEventHandler = None  # type: ignore[assignment,misc]
    logger.debug("watchdog not installed, file monitoring unavailable")


class FileIntegrityWatcher:
    """
    Manages file system monitoring with watchdog Observer.

    Runs observer in a background daemon thread.
    """

    def __init__(
        self,
        monitored_dirs: Optional[List[Path]] = None,
        alert_callback: Optional[Callable] = None,
        extensions: Optional[set] = None,
    ):
        self.monitored_dirs = monitored_dirs or config.MONITORED_DIRS
        self.alert_callback = alert_callback
        self.extensions = extensions or config.MONITORED_EXTENSIONS
        self._observer = None
        self._handler = None
        self._running = False

    def start(self) -> bool:
        """Start monitoring. Returns False if watchdog unavailable."""
        if not WATCHDOG_AVAILABLE:
            logger.warning("Cannot start file watcher: watchdog not installed")
            return False
        if self._running:
            return True

        self._handler = IntegrityEventHandler(
            alert_callback=self.alert_callback,
            extensions=self.extensions,
        )
        self._observer = Observer()
        for directory in self.monitored_dirs:
            if directory.exists():
                self._observer.schedule(self._handler, str(directory), recursive=True)
                logger.info(f"Watching: {directory}")

        self._observer.daemon = True
        self._observer.start()
        self._running = True
        logger.info("File integrity watcher started")
        return True

    def stop(self):
        if self._observer and self._running:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._running = False
            logger.info("File integrity watcher stopped")

    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> Dict:
        handler_stats = self._handler.get_stats() if self._handler else {}
        return {
            "running": self._running,
            "watchdog_available": WATCHDOG_AVAILABLE,
            "monitored_dirs": [str(d) for d in self.monitored_dirs],
            "events": handler_stats,
        }
