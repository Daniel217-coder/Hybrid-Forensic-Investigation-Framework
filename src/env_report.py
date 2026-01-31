# src/env_report.py
import platform
import sys
import importlib.metadata as md
from datetime import datetime, timezone


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_versions() -> dict:
    def v(pkg: str) -> str:
        try:
            return md.version(pkg)
        except Exception:
            return "unknown"

    return {
        "timestamp_utc": utc_now_iso(),
        "python": sys.version.replace("\n", " "),
        "platform": platform.platform(),
        "packages": {
            "androguard": v("androguard"),
            "customtkinter": v("customtkinter"),
            "tkinterweb": v("tkinterweb"),
            "rich": v("rich"),
        },
    }
