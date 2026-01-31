"""Tests for FileIntegritySigner (HMAC-SHA256 file signing)."""

import pytest
from pathlib import Path


class TestFileIntegrity:
    def test_sign_and_verify_file(self, mock_claude_home, sample_files):
        from claude_code_security.file_integrity import FileIntegritySigner
        signer = FileIntegritySigner()
        test_file = sample_files["commands"]
        assert signer.sign_file(test_file)
        assert signer.verify_file(test_file) == "verified"

    def test_unsigned_file(self, mock_claude_home, sample_files):
        from claude_code_security.file_integrity import FileIntegritySigner
        signer = FileIntegritySigner()
        assert signer.verify_file(sample_files["commands"]) == "unsigned"

    def test_tampered_file(self, mock_claude_home, sample_files):
        from claude_code_security.file_integrity import FileIntegritySigner
        signer = FileIntegritySigner()
        test_file = sample_files["commands"]
        signer.sign_file(test_file)

        # Tamper with the file
        test_file.write_text("# TAMPERED CONTENT\nprint('evil')\n")
        assert signer.verify_file(test_file) == "tampered"

    def test_missing_file(self, mock_claude_home, sample_files):
        from claude_code_security.file_integrity import FileIntegritySigner
        signer = FileIntegritySigner()
        test_file = sample_files["commands"]
        signer.sign_file(test_file)
        test_file.unlink()
        assert signer.verify_file(test_file) == "missing"

    def test_sign_all(self, mock_claude_home, sample_files):
        from claude_code_security.file_integrity import FileIntegritySigner
        signer = FileIntegritySigner()
        signed, errors = signer.sign_all()
        assert signed >= 3
        assert errors == 0

    def test_verify_all_clean(self, mock_claude_home, sample_files):
        from claude_code_security.file_integrity import FileIntegritySigner
        signer = FileIntegritySigner()
        signer.sign_all()
        report = signer.verify_all()
        assert report.is_clean
        assert len(report.tampered) == 0

    def test_verify_all_with_tamper(self, mock_claude_home, sample_files):
        from claude_code_security.file_integrity import FileIntegritySigner
        signer = FileIntegritySigner()
        signer.sign_all()

        sample_files["hooks"].write_text("# TAMPERED")

        # Need fresh signer to pick up manifest
        signer2 = FileIntegritySigner()
        report = signer2.verify_all()
        assert not report.is_clean
        assert len(report.tampered) >= 1

    def test_re_sign_file(self, mock_claude_home, sample_files):
        from claude_code_security.file_integrity import FileIntegritySigner
        signer = FileIntegritySigner()
        test_file = sample_files["commands"]
        signer.sign_file(test_file)

        test_file.write_text("# Updated legitimately\n")
        signer.re_sign_file(test_file)
        assert signer.verify_file(test_file) == "verified"

    def test_verification_report_summary(self, mock_claude_home, sample_files):
        from claude_code_security.file_integrity import FileIntegritySigner
        signer = FileIntegritySigner()
        signer.sign_all()
        report = signer.verify_all()
        summary = report.summary()
        assert "VERIFIED" in summary
        assert "ms" in summary

    def test_manifest_stats(self, mock_claude_home, sample_files):
        from claude_code_security.file_integrity import FileIntegritySigner
        signer = FileIntegritySigner()
        signer.sign_all()
        stats = signer.get_manifest_stats()
        assert stats["total_entries"] >= 3
        assert "system" in stats["signers"]

    def test_nonexistent_file_cannot_be_signed(self, mock_claude_home):
        from claude_code_security.file_integrity import FileIntegritySigner
        signer = FileIntegritySigner()
        assert not signer.sign_file(Path("/nonexistent/file.py"))
