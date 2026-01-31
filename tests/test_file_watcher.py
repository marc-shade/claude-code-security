"""Tests for FileIntegrityWatcher."""

import pytest


class TestFileWatcher:
    def test_watchdog_availability(self, mock_claude_home):
        from claude_code_security.file_watcher import WATCHDOG_AVAILABLE
        # Just check the import succeeds and the flag is set
        assert isinstance(WATCHDOG_AVAILABLE, bool)

    def test_watcher_init(self, mock_claude_home):
        from claude_code_security.file_watcher import FileIntegrityWatcher
        watcher = FileIntegrityWatcher()
        assert not watcher.is_running()

    def test_watcher_stats_when_stopped(self, mock_claude_home):
        from claude_code_security.file_watcher import FileIntegrityWatcher
        watcher = FileIntegrityWatcher()
        stats = watcher.get_stats()
        assert stats["running"] is False
        assert "watchdog_available" in stats

    @pytest.mark.skipif(
        not pytest.importorskip("watchdog", reason="watchdog not installed"),
        reason="watchdog required",
    )
    def test_watcher_start_stop(self, mock_claude_home, sample_files):
        from claude_code_security.file_watcher import FileIntegrityWatcher
        watcher = FileIntegrityWatcher()
        started = watcher.start()
        if started:
            assert watcher.is_running()
            watcher.stop()
            assert not watcher.is_running()

    def test_watcher_custom_dirs(self, mock_claude_home, tmp_path):
        from claude_code_security.file_watcher import FileIntegrityWatcher
        custom_dir = tmp_path / "custom_watch"
        custom_dir.mkdir()
        watcher = FileIntegrityWatcher(monitored_dirs=[custom_dir])
        assert custom_dir in watcher.monitored_dirs

    def test_alert_callback(self, mock_claude_home):
        from claude_code_security.file_watcher import FileIntegrityWatcher
        alerts = []
        watcher = FileIntegrityWatcher(alert_callback=lambda e: alerts.append(e))
        assert watcher.alert_callback is not None
