#!/usr/bin/env python3
"""
Deprecated dynamic helper.

This script previously depended on an old Frida helper that no longer exists.
Use one of the supported entrypoints below instead:

1) CLI (recommended):
   python -m src.main apk-dynamic --case <CASE_DIR> --package <PKG> --tag <TAG> --serial <SERIAL>

2) Local API:
   POST /run/dynamic_frida
"""

from __future__ import annotations

import argparse


def main() -> int:
    ap = argparse.ArgumentParser(description="Deprecated helper. Use src.main apk-dynamic instead.")
    ap.add_argument("--serial", default="", help="ADB serial (for migration hint only)")
    ap.add_argument("--pkg", default="", help="Android package name (for migration hint only)")
    ap.add_argument("--tag", default="dyn", help="Artifact tag (for migration hint only)")
    ap.add_argument("--duration", type=int, default=60, help="Unused (legacy)")
    ap.add_argument("--monkey", type=int, default=0, help="Unused (legacy)")
    ap.add_argument("--throttle", type=int, default=100, help="Unused (legacy)")
    ap.add_argument("--outdir", default="artifacts/dynamic", help="Unused (legacy)")
    _ = ap.parse_args()

    print("[DEPRECATED] tools/apk_dynamic_auto.py is no longer supported.")
    print("Use:")
    print("  python -m src.main apk-dynamic --case <CASE_DIR> --package <PKG> --tag <TAG> --serial <SERIAL>")
    print("or the local API endpoint:")
    print("  POST /run/dynamic_frida")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
