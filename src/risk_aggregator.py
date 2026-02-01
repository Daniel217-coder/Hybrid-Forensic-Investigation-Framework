# src/risk_aggregator.py
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _clamp(x: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, int(x)))


def _load_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


def _pick_latest(artifacts_dir: Path, prefix: str, tag: Optional[str] = None) -> Optional[Path]:
    if tag:
        cand = artifacts_dir / f"{prefix}__{tag}.json"
        return cand if cand.exists() else None
    files = sorted(artifacts_dir.glob(f"{prefix}__*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def _get_score(obj: Dict[str, Any]) -> int:
    if not isinstance(obj, dict):
        return 0
    if "score" in obj:
        return _safe_int(obj.get("score"), 0)
    if "scoring" in obj and isinstance(obj["scoring"], dict):
        return _safe_int(obj["scoring"].get("score"), 0)
    return 0


def _get_reasons(obj: Dict[str, Any]) -> List[str]:
    if not isinstance(obj, dict):
        return []
    rs = obj.get("reasons")
    if isinstance(rs, list):
        return [str(x) for x in rs]
    if isinstance(obj.get("scoring"), dict) and isinstance(obj["scoring"].get("reasons"), list):
        return [str(x) for x in obj["scoring"]["reasons"]]
    return []


def _find_reason_hit(reasons: List[str], needles: List[str]) -> bool:
    text = "\n".join(reasons or []).lower()
    return any(n.lower() in text for n in needles)


def _infer_yara_unlock(yara_obj: Dict[str, Any]) -> bool:
    """
    Robust high-confidence detection:
      - Prefer explicit flag malicious_unlock
      - Fallback to reasons text that explicitly states high/critical
    """
    if not isinstance(yara_obj, dict):
        return False

    if bool(yara_obj.get("malicious_unlock")):
        return True

    reasons = _get_reasons(yara_obj)

    # strict phrases to avoid FP
    if _find_reason_hit(reasons, [
        "high/critical yara hits",
        "critical yara hits",
        "high-confidence",
        "high confidence",
        "severity: critical",
        "severity: high",
    ]):
        return True

    # exact phrase style you already output, e.g. "High/critical YARA hits: 1 (+55)"
    for r in reasons:
        if re.search(r"high/critical\s+yara\s+hits\s*:\s*[1-9]", r, flags=re.IGNORECASE):
            return True
        if re.search(r"critical\s+yara\s+hits\s*:\s*[1-9]", r, flags=re.IGNORECASE):
            return True

    return False


def aggregate_case_risk(case_dir: str, tag: Optional[str] = None) -> Dict[str, Any]:
    """
    Anti-FP aggregation (recommended):
      - Static + Dynamic = core signals
      - MemLite = weak (cap 10)
      - YARA:
          * low confidence -> capped (<=10)
          * high confidence unlock -> sets a FLOOR (>=70), not a huge additive score
      - Combo boosts only from Static+Dynamic (never from YARA/MemLite)
      - Final clamp 0..100
    """
    case_path = Path(case_dir)
    artifacts_dir = case_path / "artifacts"
    if not artifacts_dir.exists():
        raise FileNotFoundError(f"Artifacts dir not found: {artifacts_dir}")

    paths = {
        "static": _pick_latest(artifacts_dir, "apk_static", tag),
        "dynamic": _pick_latest(artifacts_dir, "apk_dynamic", tag),
        "yara": _pick_latest(artifacts_dir, "yara", tag),
        "memlite": _pick_latest(artifacts_dir, "memlite", tag),
    }

    objs: Dict[str, Dict[str, Any]] = {}
    for k, p in paths.items():
        if p and p.exists():
            try:
                objs[k] = _load_json(p)
            except Exception:
                objs[k] = {}
        else:
            objs[k] = {}

    static_s = _get_score(objs["static"])
    dyn_s = _get_score(objs["dynamic"])
    yara_s = _get_score(objs["yara"])
    mem_s = _get_score(objs["memlite"])

    static_reasons = _get_reasons(objs["static"])
    dyn_reasons = _get_reasons(objs["dynamic"])

    # weights (core engine)
    static_w = 0.35
    dyn_w = 0.85

    # caps (anti-FP)
    mem_cap = 10
    yara_low_cap = 10

    yara_unlock = _infer_yara_unlock(objs["yara"])

    base = 0
    reasons: List[str] = []

    # --- core contributions ---
    if static_s:
        add = int(round(static_s * static_w))
        base += add
        reasons.append(f"Static contributes {add} (score {static_s} * {static_w})")

    if dyn_s:
        add = int(round(dyn_s * dyn_w))
        base += add
        reasons.append(f"Dynamic contributes {add} (score {dyn_s} * {dyn_w})")

    if mem_s:
        add = min(mem_cap, mem_s)
        base += add
        reasons.append(f"MemLite contributes {add} (cap {mem_cap})")

    # --- YARA behavior ---
    # Low confidence: tiny capped add
    # High confidence: floor (>=70) to avoid double counting with dynamic/static
    if yara_s:
        if yara_unlock:
            # floor, not additive
            if base < 70:
                reasons.append("YARA high-confidence unlock (floor 70)")
            base = max(base, 70)
        else:
            add = min(yara_low_cap, yara_s)
            base += add
            reasons.append(f"YARA contributes {add} (low-confidence cap {yara_low_cap})")

    # --- Combo boosts ONLY from static+dynamic ---
    combo_reasons: List[str] = []
    combo_reasons += dyn_reasons
    combo_reasons += static_reasons

    internet = _find_reason_hit(combo_reasons, ["internet", "socket", "http", "https", "okhttp", "webview", "dns"])
    sms = _find_reason_hit(combo_reasons, ["sms", "read_sms", "receive_sms", "sendtextmessage", "sendsms"])
    if internet and sms:
        base += 45
        reasons.append("Combo boost: Internet + SMS (+45)")

    ip_like = any(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", r) for r in combo_reasons)
    onion_like = any(".onion" in r.lower() for r in combo_reasons)
    if ip_like or onion_like:
        base += 80
        reasons.append("Critical boost: .onion or direct IP observed (+80)")

    final_score = _clamp(base, 0, 100)

    if final_score < 20:
        sev = "LOW"
    elif final_score < 50:
        sev = "MEDIUM"
    elif final_score < 75:
        sev = "HIGH"
    else:
        sev = "CRITICAL"

    return {
        "module": "risk_aggregate",
        "tag": tag or "",
        "inputs": {
            "static_score": static_s,
            "dynamic_score": dyn_s,
            "yara_score": yara_s,
            "yara_unlock": yara_unlock,
            "memlite_score": mem_s,
            "paths": {k: str(v) if v else "" for k, v in paths.items()},
        },
        "score": final_score,
        "severity": sev,
        "reasons": reasons,
    }


def save_risk_artifact(case_dir: str, tag: str, obj: Dict[str, Any]) -> str:
    from src.case_manager import save_artifact
    suffix = (tag or "latest").strip()
    name = f"risk__{suffix}.json"
    return save_artifact(case_dir, name, obj)
