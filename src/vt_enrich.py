from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from .vt_client import VirusTotalClient, sha256_file


def _safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def _case_paths(case_dir: str) -> tuple[Path, Path]:
    case_root = Path(case_dir).resolve()
    artifacts_dir = case_root / "artifacts"
    _safe_mkdir(artifacts_dir)
    return case_root, artifacts_dir


def enrich_case_with_vt(
    case_dir: str,
    apk_path: Optional[str] = None,
    sha256: Optional[str] = None,
    tag: str = "run1",
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Creates artifact:
      cases/CASE_xxx/artifacts/vt__<tag>__<sha12>.json

    Inputs:
      - apk_path OR sha256
    """
    if not case_dir:
        raise ValueError("case_dir is required")

    case_root, artifacts_dir = _case_paths(case_dir)

    if not sha256:
        if not apk_path:
            raise ValueError("Provide apk_path or sha256")
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")
        sha256 = sha256_file(apk_path)

    sha256 = (sha256 or "").strip().lower()
    if not sha256 or len(sha256) < 32:
        raise ValueError("Invalid sha256")

    vt = VirusTotalClient(api_key=api_key)
    raw = vt.get_file_report(sha256)
    normalized = vt.normalize_file_report(raw, sha256)

    # metadata for your pipeline
    normalized["case_dir"] = str(case_root)
    normalized["tag"] = tag
    if apk_path:
        normalized["apk_path"] = os.path.abspath(apk_path)

    out_name = f"vt__{tag}__{sha256[:12]}.json"
    out_path = artifacts_dir / out_name
    _write_json(out_path, normalized)

    return {
        "artifact": str(out_path),
        "sha256": sha256,
        "found": normalized.get("found", False),
        "vt_score": normalized.get("vt_score", 0),
        "confidence": normalized.get("confidence", 0.0),
        "gui_url": normalized.get("gui_url", ""),
    }
