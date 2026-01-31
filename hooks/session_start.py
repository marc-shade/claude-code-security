#!/usr/bin/env python3
"""
Session Start Hook: File integrity verification on startup.

Verifies all monitored files against the integrity manifest.
Reports tampered files and exits with:
    0 = all clean (or unsigned only)
    2 = tampered files detected
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    try:
        from claude_code_security.file_integrity import FileIntegritySigner

        signer = FileIntegritySigner()
        report = signer.verify_all()
        result = report.to_dict()

        status = "pass" if report.is_clean else "FAIL"
        print(json.dumps({
            "status": status,
            "summary": report.summary(),
            "details": result,
        }))

        if not report.is_clean:
            print(
                f"\nWARNING: {len(report.tampered)} tampered file(s) detected!",
                file=sys.stderr,
            )
            for f in report.tampered[:10]:
                print(f"  TAMPERED: {f}", file=sys.stderr)
            sys.exit(2)

        if report.unsigned:
            print(
                f"\nNOTE: {len(report.unsigned)} unsigned file(s). "
                f"Run 'python3 -m claude_code_security.file_integrity sign-all' to sign.",
                file=sys.stderr,
            )

        sys.exit(0)

    except ImportError as e:
        print(json.dumps({
            "status": "skip",
            "summary": f"File integrity module not available: {e}",
        }))
        sys.exit(0)
    except Exception as e:
        print(f"Session start hook error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
