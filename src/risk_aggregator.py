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


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default


def _clamp(x: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, int(x)))


def _load_json(p: Path) -> Dict[str, Any]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _pick_latest(artifacts_dir: Path, prefix: str, tag: Optional[str] = None) -> Optional[Path]:
    if tag:
        # Backward compatibility: exact tag file
        #   <prefix>__<tag>.json
        # New tolerant matching: timestamped files
        #   <prefix>__<tag>__*.json
        candidates: List[Path] = []

        exact = artifacts_dir / f"{prefix}__{tag}.json"
        if exact.exists():
            candidates.append(exact)

        candidates.extend(list(artifacts_dir.glob(f"{prefix}__{tag}__*.json")))
        if not candidates:
            return None

        # de-dup and pick newest by mtime
        uniq: Dict[str, Path] = {}
        for p in candidates:
            uniq[str(p.resolve())] = p
        files = sorted(uniq.values(), key=lambda p: p.stat().st_mtime, reverse=True)
        return files[0] if files else None

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
        return [str(x) for x in rs if x is not None]
    if isinstance(obj.get("scoring"), dict) and isinstance(obj["scoring"].get("reasons"), list):
        return [str(x) for x in obj["scoring"]["reasons"] if x is not None]
    return []


def _find_reason_hit(reasons: List[str], needles: List[str]) -> bool:
    text = "\n".join(reasons or []).lower()
    return any(n.lower() in text for n in needles)


def _infer_yara_unlock(yara_obj: Dict[str, Any]) -> bool:
    """
    Robust high-confidence detection:
      - Prefer explicit flag malicious_unlock
      - Fallback to strict reason phrases (avoid FP)
    """
    if not isinstance(yara_obj, dict):
        return False

    if bool(yara_obj.get("malicious_unlock")):
        return True

    reasons = _get_reasons(yara_obj)

    if _find_reason_hit(
        reasons,
        [
            "high/critical yara hits",
            "critical yara hits",
            "high-confidence",
            "high confidence",
            "severity: critical",
            "severity: high",
        ],
    ):
        return True

    for r in reasons:
        if re.search(r"high/critical\s+yara\s+hits\s*:\s*[1-9]", r, flags=re.IGNORECASE):
            return True
        if re.search(r"critical\s+yara\s+hits\s*:\s*[1-9]", r, flags=re.IGNORECASE):
            return True

    return False


# -------------------------
# VirusTotal helpers
# -------------------------

def _vt_stats(vt_obj: Dict[str, Any]) -> Dict[str, int]:
    stats = vt_obj.get("stats") if isinstance(vt_obj, dict) else None
    if not isinstance(stats, dict):
        stats = {}
    malicious = _safe_int(stats.get("malicious"), 0)
    suspicious = _safe_int(stats.get("suspicious"), 0)
    total = _safe_int(stats.get("total"), 0)
    positives = _safe_int(stats.get("positives"), malicious + suspicious)
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "positives": positives,
    }


def _vt_score(vt_obj: Dict[str, Any]) -> int:
    if not isinstance(vt_obj, dict):
        return 0
    return _safe_int(vt_obj.get("vt_score"), 0)


def _vt_confidence(vt_obj: Dict[str, Any]) -> float:
    if not isinstance(vt_obj, dict):
        return 0.0
    c = _safe_float(vt_obj.get("confidence"), 0.0)
    if c < 0:
        c = 0.0
    if c > 1:
        c = 1.0
    return c


def _vt_detected(vt_obj: Dict[str, Any]) -> bool:
    s = _vt_stats(vt_obj)
    return (s["malicious"] > 0) or (s["suspicious"] > 0) or (s["positives"] > 0)


def _vt_contribution(vt_obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Policy:
      - VT clean => add <= 20 (or change to 15 if you want)
      - VT detected => add scales with findings + optional floors for high positives
    """
    if not isinstance(vt_obj, dict) or not vt_obj:
        return {"add": 0, "floor": 0, "why": ""}

    score = _vt_score(vt_obj)
    conf = _vt_confidence(vt_obj)
    st = _vt_stats(vt_obj)
    pos = st["positives"]
    tot = st["total"] if st["total"] > 0 else 0

    if not _vt_detected(vt_obj):
        add = int(round(score * 0.6))
        add = min(20, max(0, add))  # change 20 -> 15 if you want stricter
        why = f"VirusTotal clean (0 positives) contributes {add} (cap 20)"
        return {"add": add, "floor": 0, "why": why}

    mult = 0.8 + 0.8 * conf  # 0.8 .. 1.6
    add = int(round(score * mult))

    if pos >= 25:
        bonus = 20
    elif pos >= 15:
        bonus = 14
    elif pos >= 8:
        bonus = 9
    elif pos >= 3:
        bonus = 5
    else:
        bonus = 2

    add += bonus

    add_cap = 55
    add = min(add_cap, max(0, add))

    floor = 0
    if pos >= 20:
        floor = 75
    elif pos >= 12:
        floor = 65
    elif pos >= 7:
        floor = 55

    ratio = (pos / tot) if tot else 0.0
    why = (
        f"VirusTotal detected: {pos}/{tot or '?'} positives (ratio {ratio:.2f}), "
        f"vt_score {score}, confidence {conf:.2f} => add {add} (cap {add_cap}), floor {floor}"
    )
    return {"add": add, "floor": floor, "why": why}


# -------------------------
# Anti-FP aggregation aligned with case_report.py
# -------------------------

def _benign_cap_applies(static_score: int, dyn_score: int, yara_unlock: bool, vt_det: bool) -> bool:
    if yara_unlock:
        return False
    if vt_det:
        return False
    base = max(_safe_int(static_score, 0), _safe_int(dyn_score, 0))
    return base < 20


def aggregate_case_risk(
    case_dir: str,
    tag: Optional[str] = None,
    module_tags: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Consistent aggregation with your UI + anti-FP rules:
      - Base = max(static, dynamic)
      - MemLite cap 10
      - YARA:
          * unlock => add full yara_score + bonus +5
          * else => cap to 10
      - VirusTotal:
          * clean => small add (<=20)
          * detected => scaled add + floors for high positives
      - Combo boosts are gated (cannot turn a clean/low case into CRITICAL)
      - Benign-aware cap: if base<20 and no unlock and VT clean => final <=19
    """
    case_path = Path(case_dir)
    artifacts_dir = case_path / "artifacts"
    if not artifacts_dir.exists():
        raise FileNotFoundError(f"Artifacts dir not found: {artifacts_dir}")

    module_tags = module_tags or {}
    static_tag = module_tags.get("static", tag)
    dynamic_tag = module_tags.get("dynamic", tag)
    yara_tag = module_tags.get("yara", tag)
    memlite_tag = module_tags.get("memlite", tag)
    vt_tag = module_tags.get("vt", None)

    paths = {
        "static": _pick_latest(artifacts_dir, "apk_static", static_tag),
        "dynamic": _pick_latest(artifacts_dir, "apk_dynamic", dynamic_tag),
        "yara": _pick_latest(artifacts_dir, "yara", yara_tag),
        "memlite": _pick_latest(artifacts_dir, "memlite", memlite_tag),
        "vt": _pick_latest(artifacts_dir, "vt", tag=None),  # VT independent
    }
    if vt_tag:
        paths["vt"] = _pick_latest(artifacts_dir, "vt", vt_tag)

    objs: Dict[str, Dict[str, Any]] = {}
    for k, p in paths.items():
        if p and p.exists():
            objs[k] = _load_json(p)
        else:
            objs[k] = {}

    static_s = _get_score(objs["static"])
    dyn_s = _get_score(objs["dynamic"])
    yara_s = _get_score(objs["yara"])
    mem_s = _get_score(objs["memlite"])

    yara_unlock = _infer_yara_unlock(objs["yara"])

    vt_obj = objs.get("vt") or {}
    vt_det = _vt_detected(vt_obj) if vt_obj else False

    # --- Base (primary signal) ---
    base_primary = max(_safe_int(static_s, 0), _safe_int(dyn_s, 0))

    # --- Extras (capped) ---
    mem_cap = 10
    yara_low_cap = 10
    mem_contrib = min(_safe_int(mem_s, 0), mem_cap)

    total = base_primary + mem_contrib

    reasons: List[str] = []
    reasons.append(f"Static/Dynamic base: {base_primary}")
    reasons.append(f"MemLite contributes {mem_contrib} (cap {mem_cap})")

    # --- YARA ---
    if _safe_int(yara_s, 0) > 0:
        if yara_unlock:
            yara_contrib = _safe_int(yara_s, 0)
            bonus = 5
            total += yara_contrib + bonus
            reasons.append(f"YARA contributes {yara_contrib} (high-confidence unlock)")
            reasons.append(f"YARA unlock bonus (+{bonus})")
        else:
            yara_contrib = min(_safe_int(yara_s, 0), yara_low_cap)
            total += yara_contrib
            reasons.append(f"YARA contributes {yara_contrib} (low-confidence cap {yara_low_cap})")

    # --- VirusTotal (secondary) ---
    if vt_obj:
        vt = _vt_contribution(vt_obj)
        vt_add = _safe_int(vt.get("add"), 0)
        vt_floor = _safe_int(vt.get("floor"), 0)

        if vt_add:
            total += vt_add
            reasons.append(vt.get("why") or f"VirusTotal contributes {vt_add}")

        if vt_floor:
            if total < vt_floor:
                reasons.append(f"VirusTotal floor applied ({vt_floor})")
            total = max(total, vt_floor)

    # --- Combo boosts (GATED to avoid FP) ---
    # Only allow strong boosts if we already have:
    #   - VT detected OR YARA unlock OR base_primary >= 20
    allow_boosts = vt_det or yara_unlock or (base_primary >= 20)

    combo_reasons: List[str] = []
    combo_reasons += _get_reasons(objs["dynamic"])
    combo_reasons += _get_reasons(objs["static"])

    if allow_boosts:
        internet = _find_reason_hit(combo_reasons, ["internet", "socket", "http", "https", "okhttp", "webview", "dns"])
        sms = _find_reason_hit(combo_reasons, ["sms", "read_sms", "receive_sms", "sendtextmessage", "sendsms"])
        if internet and sms:
            total += 25  # reduced from 45 (sa nu explodeze)
            reasons.append("Combo boost: Internet + SMS (+25)")

        ip_like = any(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", r) for r in combo_reasons)
        onion_like = any(".onion" in r.lower() for r in combo_reasons)
        if ip_like or onion_like:
            # still big, but not instant-100 unless there are other signals
            total += 50  # reduced from 80
            reasons.append("Critical boost: .onion or direct IP observed (+50)")
    else:
        # Informational note (optional)
        if combo_reasons:
            reasons.append("Combo boosts suppressed (VT clean + no unlock + low base)")

    total = _clamp(total, 0, 100)

    # --- Benign-aware cap ---
    if _benign_cap_applies(static_s, dyn_s, yara_unlock, vt_det):
        total = min(total, 19)
        reasons.append("Benign-aware cap applied (no high-confidence indicators + VT clean) → score capped at 19/100.")

    # Severity bands (same as UI)
    if total < 20:
        sev = "LOW"
    elif total < 50:
        sev = "MEDIUM"
    elif total < 75:
        sev = "HIGH"
    else:
        sev = "CRITICAL"

    vt_st = _vt_stats(vt_obj) if vt_obj else {"malicious": 0, "suspicious": 0, "total": 0, "positives": 0}

    return {
        "module": "risk_aggregate",
        "tag": tag or "",
        "inputs": {
            "static_score": static_s,
            "dynamic_score": dyn_s,
            "yara_score": yara_s,
            "yara_unlock": yara_unlock,
            "memlite_score": mem_s,
            "vt_detected": vt_det,
            "vt_score": _vt_score(vt_obj) if vt_obj else 0,
            "vt_confidence": _vt_confidence(vt_obj) if vt_obj else 0.0,
            "vt_positives": vt_st.get("positives", 0),
            "module_tags": {k: v for k, v in (module_tags or {}).items() if v},
            "paths": {k: str(v) if v else "" for k, v in paths.items()},
        },
        "score": total,
        "severity": sev,
        "reasons": reasons,
    }


def save_risk_artifact(case_dir: str, tag: str, obj: Dict[str, Any]) -> str:
    from src.case_manager import save_artifact
    suffix = (tag or "latest").strip()
    name = f"risk__{suffix}.json"
    return save_artifact(case_dir, name, obj)
