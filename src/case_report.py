# src/case_report.py
from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime
from typing import Literal, Any, Optional
#De modificat si aici
RiskMode = Literal["latest", "max", "mean"]


# --------------------------- IO helpers ---------------------------

def _load_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _fmt_ts(unix_ts: float) -> str:
    try:
        return datetime.utcfromtimestamp(float(unix_ts)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(unix_ts)


def _fmt_fs_ts_mtime(p: Path) -> str:
    try:
        return datetime.utcfromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "unknown"


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


def _clamp(n: int, lo: int = 0, hi: int = 100) -> int:
    try:
        n = int(n)
    except Exception:
        n = 0
    if n < lo:
        return lo
    if n > hi:
        return hi
    return n


def _escape(s: Any) -> str:
    if s is None:
        return ""
    s = str(s)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


# --------------------------- scoring helpers ---------------------------

def _score_band(score: int) -> str:
    s = _safe_int(score, 0)
    if s < 20:
        return "SCORE_GREEN"
    if s < 50:
        return "SCORE_YELLOW"
    if s < 75:
        return "SCORE_ORANGE"
    return "SCORE_RED"


def _score_max_from_scoring(scoring: dict, default: int = 100) -> int:
    s = scoring or {}
    mx = _safe_int(s.get("score_max", default), default)
    if mx > 0:
        return mx
    risk_scale = str(s.get("risk_scale", "") or "").strip()
    if risk_scale == "0-20":
        return 20
    return default


def _score_text(score: int, score_max: int) -> str:
    mx = _safe_int(score_max, 100)
    if mx <= 0:
        mx = 100
    return f"{_safe_int(score, 0)}/{mx}"


def _score_norm_100(score: int, score_max: int) -> int:
    mx = _safe_int(score_max, 100)
    if mx <= 0:
        mx = 100
    s = _safe_int(score, 0)
    return _clamp(int(round((float(s) / float(mx)) * 100.0)), 0, 100)


def sev_badge_class(sev: str) -> str:
    sev_u = str(sev or "").upper().strip()
    if sev_u in ("SAFE", "LOW"):
        return "sev-low"
    if sev_u in ("MEDIUM", "MODERATE"):
        return "sev-med"
    if sev_u in ("HIGH",):
        return "sev-high"
    if sev_u in ("CRITICAL",):
        return "sev-crit"
    return "sev-unk"


def _normalize_static(obj: dict, artifact_name: str, artifact_path: Path) -> dict:
    scoring = (obj.get("scoring") or {})
    score_max = _score_max_from_scoring(scoring, default=20)
    return {
        "artifact_name": artifact_name,
        "artifact_path": str(artifact_path),
        "artifact_mtime_utc": _fmt_fs_ts_mtime(artifact_path),
        "module": "apk_static",
        "package": obj.get("package", ""),
        "app_name": obj.get("app_name", obj.get("app", "")),
        "severity": scoring.get("severity", "UNKNOWN"),
        "score": _safe_int(scoring.get("score", 0), 0),
        "score_max": score_max,
        "reasons": scoring.get("reasons", []) or [],
    }


def _normalize_dynamic(obj: dict, artifact_name: str, artifact_path: Path) -> dict:
    scoring = (obj.get("scoring") or {})
    score_max = _score_max_from_scoring(scoring, default=100)
    return {
        "artifact_name": artifact_name,
        "artifact_path": str(artifact_path),
        "artifact_mtime_utc": _fmt_fs_ts_mtime(artifact_path),
        "module": "apk_dynamic",
        "package": obj.get("package", ""),
        "app_name": obj.get("app_name", obj.get("app", "")),
        "device": obj.get("device", {}),
        "severity": scoring.get("severity", "UNKNOWN"),
        "score": _safe_int(scoring.get("score", 0), 0),
        "score_max": score_max,
        "reasons": scoring.get("reasons", []) or [],
        "events": obj.get("events", {}) or {},
        "iocs": obj.get("iocs", {}) or {},
    }


def _normalize_yara(obj: dict, artifact_name: str, artifact_path: Path) -> dict:
    scoring = (obj.get("scoring") or {})
    score_max = _score_max_from_scoring(scoring, default=100)
    matches = obj.get("matches", obj.get("results", obj.get("rules", [])))
    return {
        "artifact_name": artifact_name,
        "artifact_path": str(artifact_path),
        "artifact_mtime_utc": _fmt_fs_ts_mtime(artifact_path),
        "module": "yara",
        "apk_name": obj.get("apk_name", obj.get("apk", "")),
        "severity": scoring.get("severity", "UNKNOWN"),
        "score": _safe_int(scoring.get("score", 0), 0),
        "score_max": score_max,
        "reasons": scoring.get("reasons", []) or [],
        "matches": matches,
        "malicious_unlock": bool(scoring.get("malicious_unlock", obj.get("malicious_unlock", False))),
    }


def _normalize_yara_matches(matches) -> list[dict]:
    if not matches:
        return []
    if isinstance(matches, list):
        out: list[dict] = []
        for m in matches:
            if isinstance(m, dict):
                out.append(m)
            else:
                out.append({"rule": str(m)})
        return out
    if isinstance(matches, dict):
        for key in ("matches", "rules", "results"):
            v = matches.get(key)
            if isinstance(v, list):
                return _normalize_yara_matches(v)
        out: list[dict] = []
        for k, v in matches.items():
            if isinstance(v, dict):
                d = dict(v)
                d.setdefault("rule", str(k))
                out.append(d)
            else:
                out.append({"rule": str(k), "value": v})
        return out
    return []


def _normalize_memlite(obj: dict, artifact_name: str, artifact_path: Path) -> dict:
    scoring = (obj.get("scoring") or {})
    score_max = _score_max_from_scoring(scoring, default=100)
    return {
        "artifact_name": artifact_name,
        "artifact_path": str(artifact_path),
        "artifact_mtime_utc": _fmt_fs_ts_mtime(artifact_path),
        "module": "memlite",
        "package": obj.get("package", ""),
        "device": obj.get("device", {}),
        "severity": scoring.get("severity", "UNKNOWN"),
        "score": _safe_int(scoring.get("score", 0), 0),
        "score_max": score_max,
        "reasons": scoring.get("reasons", []) or [],
        "extras": obj.get("extras", {}) or {},
    }


def _normalize_vt(obj: dict, artifact_name: str, artifact_path: Path) -> dict:
    stats = obj.get("stats") if isinstance(obj.get("stats"), dict) else {}
    malicious = _safe_int(stats.get("malicious"), 0)
    suspicious = _safe_int(stats.get("suspicious"), 0)
    total = _safe_int(stats.get("total"), 0)
    positives = _safe_int(stats.get("positives"), malicious + suspicious)
    vt_score = _safe_int(obj.get("vt_score"), 0)
    confidence = _safe_float(obj.get("confidence"), 0.0)
    if confidence < 0:
        confidence = 0.0
    if confidence > 1:
        confidence = 1.0
    return {
        "artifact_name": artifact_name,
        "artifact_path": str(artifact_path),
        "artifact_mtime_utc": _fmt_fs_ts_mtime(artifact_path),
        "module": "virustotal",
        "sha256": obj.get("sha256", ""),
        "found": bool(obj.get("found", False)),
        "vt_score": vt_score,
        "confidence": confidence,
        "stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": _safe_int(stats.get("undetected"), 0),
            "harmless": _safe_int(stats.get("harmless"), 0),
            "timeout": _safe_int(stats.get("timeout"), 0),
            "total": total,
            "positives": positives,
        },
        "gui_url": obj.get("gui_url", ""),
        "apk_path": obj.get("apk_path", ""),
        "tag": obj.get("tag", ""),
    }


def _latest_by_mtime(items: list[dict]) -> dict | None:
    if not items:
        return None
    return sorted(items, key=lambda x: str(x.get("artifact_mtime_utc", "")), reverse=True)[0]


def _max_by_score(items: list[dict], score_key: str = "score") -> dict | None:
    if not items:
        return None
    return sorted(items, key=lambda x: _safe_int(x.get(score_key, 0), 0), reverse=True)[0]


def _mean_score(items: list[dict], score_key: str = "score") -> int:
    if not items:
        return 0
    vals = [_safe_int(x.get(score_key, 0), 0) for x in items]
    if not vals:
        return 0
    return int(round(sum(vals) / len(vals)))


def _pick_mode(items: list[dict], mode: RiskMode) -> dict | None:
    if mode == "latest":
        return _latest_by_mtime(items)
    if mode == "max":
        return _max_by_score(items, "score")
    return None


def _pick_mode_vt(items: list[dict], mode: RiskMode) -> dict | None:
    # VT doesn't have "score" in the same sense; we choose:
    # latest OR max by vt_score
    if mode == "latest":
        return _latest_by_mtime(items)
    if mode == "max":
        return _max_by_score(items, "vt_score")
    return None


def _severity_from_score(score: int) -> str:
    s = _safe_int(score, 0)
    if s < 20:
        return "LOW"
    if s < 50:
        return "MEDIUM"
    if s < 75:
        return "HIGH"
    return "CRITICAL"


# --------------------------- dynamic event normalization (FIX) ---------------------------

def _event_counts_any(events_obj: Any) -> dict:
    if isinstance(events_obj, dict):
        out = {}
        for k, v in events_obj.items():
            try:
                out[str(k)] = int(v)
            except Exception:
                continue
        return out

    counts: dict[str, int] = {}
    if isinstance(events_obj, list):
        for e in events_obj:
            if not isinstance(e, dict):
                continue
            tag = (e.get("tag") or e.get("type") or e.get("kind") or "").strip()
            if not tag:
                continue
            counts[tag] = counts.get(tag, 0) + 1
    return counts


# --------------------------- VirusTotal aggregation logic ---------------------------

def _vt_detected(vt_pick: Optional[dict]) -> bool:
    if not vt_pick:
        return False
    st = vt_pick.get("stats") or {}
    pos = _safe_int(st.get("positives"), 0)
    mal = _safe_int(st.get("malicious"), 0)
    sus = _safe_int(st.get("suspicious"), 0)
    return (pos > 0) or (mal > 0) or (sus > 0)


def _vt_contribution(vt_pick: Optional[dict]) -> dict:
    """
    Policy:
      - If VT clean (0 positives): contribution <= 20 (or change to 15)
      - If VT detects: contribution scales with vt_score + confidence + positives bucket,
        but still bounded (cap 55). Can apply floors for high positives.
    """
    if not vt_pick:
        return {"add": 0, "floor": 0, "reason": ""}

    vt_score = _safe_int(vt_pick.get("vt_score", 0), 0)
    conf = _safe_float(vt_pick.get("confidence", 0.0), 0.0)
    if conf < 0:
        conf = 0.0
    if conf > 1:
        conf = 1.0

    st = vt_pick.get("stats") or {}
    pos = _safe_int(st.get("positives", 0), 0)
    total = _safe_int(st.get("total", 0), 0)

    if pos <= 0:
        add = int(round(vt_score * 0.6))
        add = min(20, max(0, add))  # <=20 when clean (set to 15 if you want)
        return {"add": add, "floor": 0, "reason": f"VirusTotal clean (0 positives) contributes {add} (cap 20)"}

    mult = 0.8 + 0.8 * conf  # 0.8..1.6
    add = int(round(vt_score * mult))

    # bonuses by positives bucket
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

    add = add + bonus
    add_cap = 55
    add = min(add_cap, max(0, add))

    floor = 0
    if pos >= 20:
        floor = 75
    elif pos >= 12:
        floor = 65
    elif pos >= 7:
        floor = 55

    ratio = (pos / total) if total else 0.0
    return {
        "add": add,
        "floor": floor,
        "reason": f"VirusTotal detected {pos}/{total or '?'} positives (ratio {ratio:.2f}) => add {add} (cap {add_cap}), floor {floor}",
    }


# --------------------------- case aggregation ---------------------------

def _collect_artifacts(case_dir: Path) -> dict:
    artifacts_dir = case_dir / "artifacts"
    out = {"static": [], "dynamic": [], "yara": [], "memlite": [], "vt": []}
    if not artifacts_dir.exists():
        return out

    for p in sorted(artifacts_dir.glob("*.json")):
        name = p.name
        obj = _load_json(p)

        if name.startswith("apk_static__"):
            out["static"].append(_normalize_static(obj, name, p))
        elif name.startswith("apk_dynamic__"):
            out["dynamic"].append(_normalize_dynamic(obj, name, p))
        elif name.startswith("yara__"):
            out["yara"].append(_normalize_yara(obj, name, p))
        elif name.startswith("memlite__"):
            out["memlite"].append(_normalize_memlite(obj, name, p))
        elif name.startswith("vt__"):
            out["vt"].append(_normalize_vt(obj, name, p))

    return out


def _case_meta(case_dir: Path) -> dict:
    case_json = case_dir / "case.json"
    if not case_json.exists():
        return {"id": case_dir.name, "created_at": "unknown"}
    cj = _load_json(case_json)
    return {
        "id": cj.get("id", case_dir.name),
        "created_at": cj.get("created_at", cj.get("created", "unknown")),
        "base_dir": str(case_dir),
    }


def _benign_cap_applies(static_score: int, dyn_score: int, yara_unlock: bool, vt_detected: bool) -> bool:
    # cap only if: no strong signals AND no VT detection
    if yara_unlock:
        return False
    if vt_detected:
        return False
    base = max(_safe_int(static_score, 0), _safe_int(dyn_score, 0))
    return base < 20


def _aggregate_case_score(
    static_score: int,
    dyn_score: int,
    yara_score: int,
    mem_score: int,
    yara_unlock: bool,
    vt_pick: Optional[dict],
) -> dict:
    # Primary signals (keep your original base behavior)
    base = max(_safe_int(static_score, 0), _safe_int(dyn_score, 0))

    # Extras capped
    mem_cap = 10
    yara_low_cap = 10
    mem_contrib = min(_safe_int(mem_score, 0), mem_cap)

    # VT logic
    vt_det = _vt_detected(vt_pick)
    vt = _vt_contribution(vt_pick)
    vt_add = _safe_int(vt.get("add", 0), 0)
    vt_floor = _safe_int(vt.get("floor", 0), 0)

    reasons: list[str] = []
    reasons.append(f"Static/Dynamic base: {base}")
    reasons.append(f"MemLite contributes {mem_contrib} (cap {mem_cap})")

    total = base + mem_contrib

    if yara_unlock:
        yara_contrib = _safe_int(yara_score, 0)
        bonus = 5
        total += yara_contrib + bonus
        reasons.append(f"YARA contributes {yara_contrib} (high-confidence unlock)")
        reasons.append(f"YARA unlock bonus (+{bonus})")
    else:
        yara_contrib = min(_safe_int(yara_score, 0), yara_low_cap)
        total += yara_contrib
        reasons.append(f"YARA contributes {yara_contrib} (low-confidence cap {yara_low_cap})")

    if vt_pick:
        total += vt_add
        reasons.append(vt.get("reason", f"VirusTotal contributes {vt_add}"))
        if vt_floor:
            if total < vt_floor:
                reasons.append(f"VirusTotal floor applied ({vt_floor})")
            total = max(total, vt_floor)

    total = _clamp(total, 0, 100)

    if _benign_cap_applies(static_score, dyn_score, yara_unlock, vt_detected=vt_det):
        total = min(total, 19)
        reasons.append("Benign-aware cap applied (no high-confidence indicators + VT clean) → score capped at 19/100.")

    sev = _severity_from_score(total)
    return {"score": total, "severity": sev, "reasons": reasons, "vt_detected": vt_det}


# --------------------------- HTML template ---------------------------

CSS = r"""
:root{
  --bg:#0a0f1e;
  --panel:#0e162b;
  --panel2:#101b34;
  --text:#e8efff;
  --muted:#aab6d7;
  --line:#203055;
  --green:#2ecc71;
  --yellow:#f1c40f;
  --orange:#e67e22;
  --red:#e74c3c;
  --blue:#4aa3ff;
  --pill:#1a2a4f;
  --shadow:rgba(0,0,0,.35);
}
*{box-sizing:border-box}
body{
  margin:0;
  font-family: ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;
  color:var(--text);
  background: radial-gradient(1200px 600px at 40% -10%, rgba(74,163,255,.25), transparent),
              radial-gradient(900px 500px at 90% 10%, rgba(46,204,113,.15), transparent),
              var(--bg);
}
a{color:var(--blue); text-decoration:none}
a:hover{text-decoration:underline}
.container{max-width:1200px; margin:22px auto; padding:0 18px}
.header{
  background: linear-gradient(180deg, rgba(16,27,52,.95), rgba(14,22,43,.92));
  border:1px solid var(--line);
  border-radius:16px;
  box-shadow:0 14px 40px var(--shadow);
  padding:18px 18px 12px;
}
.h1{display:flex; align-items:center; justify-content:space-between; gap:16px}
.h1 h1{margin:0; font-size:22px; letter-spacing:.2px}
.h1 .meta{display:flex; gap:10px; flex-wrap:wrap; justify-content:flex-end}
.pill{
  background:rgba(26,42,79,.75);
  border:1px solid rgba(32,48,85,.9);
  color:var(--text);
  padding:7px 10px;
  border-radius:999px;
  font-size:12px;
  display:inline-flex; align-items:center; gap:8px;
}
.pill b{font-weight:700}
.grid{
  margin-top:16px;
  display:grid;
  grid-template-columns: 1.2fr .8fr;
  gap:14px;
}
.card{
  background: linear-gradient(180deg, rgba(16,27,52,.92), rgba(14,22,43,.90));
  border:1px solid var(--line);
  border-radius:16px;
  box-shadow:0 12px 36px var(--shadow);
  overflow:hidden;
}
.card h2{
  margin:0;
  font-size:14px;
  color:var(--muted);
  letter-spacing:.4px;
  text-transform:uppercase;
  padding:14px 14px 10px;
  border-bottom:1px solid rgba(32,48,85,.65);
}
.card .body{padding:14px}
.badge{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  padding:6px 10px;
  border-radius:999px;
  font-size:12px;
  border:1px solid rgba(255,255,255,.12);
}
.badge.sev{font-weight:700}
.sev-low{background:rgba(46,204,113,.12); border-color:rgba(46,204,113,.35); color:var(--green)}
.sev-med{background:rgba(241,196,15,.12); border-color:rgba(241,196,15,.35); color:var(--yellow)}
.sev-high{background:rgba(230,126,34,.12); border-color:rgba(230,126,34,.35); color:var(--orange)}
.sev-crit{background:rgba(231,76,60,.12); border-color:rgba(231,76,60,.35); color:var(--red)}
.sev-unk{background:rgba(170,182,215,.10); border-color:rgba(170,182,215,.25); color:var(--muted)}
.badge.score{font-weight:800}
.SCORE_GREEN{background:rgba(46,204,113,.12); border-color:rgba(46,204,113,.35)}
.SCORE_YELLOW{background:rgba(241,196,15,.12); border-color:rgba(241,196,15,.35)}
.SCORE_ORANGE{background:rgba(230,126,34,.12); border-color:rgba(230,126,34,.35)}
.SCORE_RED{background:rgba(231,76,60,.12); border-color:rgba(231,76,60,.35)}
.table{
  width:100%;
  border-collapse:collapse;
  font-size:13px;
}
.table th, .table td{
  padding:10px 10px;
  border-bottom:1px solid rgba(32,48,85,.55);
  vertical-align:top;
}
.table th{color:var(--muted); font-weight:700; text-transform:uppercase; font-size:11px; letter-spacing:.35px}
.table tr:hover td{background:rgba(26,42,79,.25)}
.small{font-size:12px; color:var(--muted)}
.muted{color:var(--muted)}
.mono{font-family: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,monospace; font-size:12px}
.section{margin-top:14px}
.compact{margin:8px 0 0; padding-left:18px}
.compact li{margin:2px 0}
.tabs{
  display:flex; gap:8px; flex-wrap:wrap;
  padding:12px 14px 0;
}
.tab{
  background: rgba(26,42,79,.45);
  border:1px solid rgba(32,48,85,.7);
  color:var(--text);
  padding:8px 10px;
  border-radius:12px 12px 0 0;
  font-size:12px;
  cursor:pointer;
  user-select:none;
}
.tab.active{
  background: rgba(74,163,255,.18);
  border-color: rgba(74,163,255,.55);
}
.tabpanels{
  padding:0 14px 14px;
}
.panel{display:none}
.panel.active{display:block}
.why-card{
  background: rgba(16,27,52,.55);
  border:1px solid rgba(32,48,85,.55);
  border-radius:14px;
  padding:12px;
  margin:10px 0;
}
.why-title{font-weight:800; margin-bottom:6px}
.why-meta{display:flex; gap:8px; flex-wrap:wrap; margin:6px 0 4px}
.footer{
  margin:18px 0 0;
  color:var(--muted);
  font-size:12px;
  text-align:center;
}
@media (max-width: 980px){
  .grid{grid-template-columns:1fr}
}
"""


def _tab_script() -> str:
    return r"""
<script>
(function(){
  function $all(sel){ return Array.from(document.querySelectorAll(sel)); }
  $all("[data-tab]").forEach(function(btn){
    btn.addEventListener("click", function(){
      var group = btn.getAttribute("data-group");
      var target = btn.getAttribute("data-tab");
      $all('[data-group="'+group+'"][data-tab]').forEach(function(b){ b.classList.remove("active"); });
      btn.classList.add("active");
      $all('[data-panel="'+group+'"]').forEach(function(p){ p.classList.remove("active"); });
      var panel = document.getElementById(target);
      if(panel) panel.classList.add("active");
    });
  });
})();
</script>
"""


def _html_page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{_escape(title)}</title>
<style>{CSS}</style>
</head>
<body>
{body}
{_tab_script()}
</body>
</html>
"""


# --------------------------- report builder ---------------------------

def write_case_html(case_dir: str, risk_mode: RiskMode = "latest") -> str:
    case_path = Path(case_dir)
    meta = _case_meta(case_path)
    artifacts = _collect_artifacts(case_path)

    static_pick = _pick_mode(artifacts["static"], risk_mode)
    dyn_pick = _pick_mode(artifacts["dynamic"], risk_mode)
    yara_pick = _pick_mode(artifacts["yara"], risk_mode)
    mem_pick = _pick_mode(artifacts["memlite"], risk_mode)
    vt_pick = _pick_mode_vt(artifacts["vt"], risk_mode)

    static_score = _safe_int((static_pick or {}).get("score", 0), 0) if risk_mode != "mean" else _mean_score(artifacts["static"])
    dyn_score = _safe_int((dyn_pick or {}).get("score", 0), 0) if risk_mode != "mean" else _mean_score(artifacts["dynamic"])
    yara_score = _safe_int((yara_pick or {}).get("score", 0), 0) if risk_mode != "mean" else _mean_score(artifacts["yara"])
    mem_score = _safe_int((mem_pick or {}).get("score", 0), 0) if risk_mode != "mean" else _mean_score(artifacts["memlite"])
    static_score_max = _safe_int((static_pick or {}).get("score_max", 20), 20) if risk_mode != "mean" else 20
    dyn_score_max = _safe_int((dyn_pick or {}).get("score_max", 100), 100) if risk_mode != "mean" else 100
    yara_score_max = _safe_int((yara_pick or {}).get("score_max", 100), 100) if risk_mode != "mean" else 100
    mem_score_max = _safe_int((mem_pick or {}).get("score_max", 100), 100) if risk_mode != "mean" else 100

    yara_unlock = bool((yara_pick or {}).get("malicious_unlock", False))
    agg = _aggregate_case_score(static_score, dyn_score, yara_score, mem_score, yara_unlock=yara_unlock, vt_pick=vt_pick)

    final_score = _safe_int(agg.get("score", 0), 0)
    final_sev = agg.get("severity", "UNKNOWN")
    final_band = _score_band(final_score)

    vt_det = bool(agg.get("vt_detected", False))
    vt_info = vt_pick or {}
    vt_stats = (vt_info.get("stats") or {}) if isinstance(vt_info, dict) else {}
    vt_pos = _safe_int(vt_stats.get("positives", 0), 0)
    vt_total = _safe_int(vt_stats.get("total", 0), 0)
    vt_score = _safe_int(vt_info.get("vt_score", 0), 0)
    vt_conf = _safe_float(vt_info.get("confidence", 0.0), 0.0)
    vt_url = str(vt_info.get("gui_url", "") or "")

    header = f"""
<div class="container">
  <div class="header">
    <div class="h1">
      <h1>CYBERSHADOW • Case Report</h1>
      <div class="meta">
        <span class="pill">Case: <b>{_escape(meta.get("id",""))}</b></span>
        <span class="pill">Created: <span class="mono">{_escape(meta.get("created_at",""))}</span></span>
        <span class="pill"><span class="badge sev {sev_badge_class(final_sev)}">{_escape(final_sev)}</span></span>
        <span class="pill"><span class="badge score {final_band}">Final Score: <b>{final_score}</b>/100</span></span>
        <span class="pill">Risk mode: <b>{_escape(risk_mode)}</b></span>
        <span class="pill">YARA unlock: <b>{"YES" if yara_unlock else "NO"}</b></span>
        <span class="pill">VT: <b>{"DETECTED" if vt_det else "CLEAN/NA"}</b></span>
      </div>
    </div>
    <div class="tabs">
      <div class="tab active" data-group="main" data-tab="panel_overview">Overview</div>
      <div class="tab" data-group="main" data-tab="panel_static">Static</div>
      <div class="tab" data-group="main" data-tab="panel_dynamic">Dynamic</div>
      <div class="tab" data-group="main" data-tab="panel_yara">YARA</div>
      <div class="tab" data-group="main" data-tab="panel_memlite">MemLite</div>
      <div class="tab" data-group="main" data-tab="panel_vt">VirusTotal</div>
      <div class="tab" data-group="main" data-tab="panel_top">Top / Why</div>
    </div>
  </div>
"""

    final_reasons = agg.get("reasons", []) or []
    reasons_html = "<ul class='compact'>" + "".join(f"<li>{_escape(r)}</li>" for r in final_reasons) + "</ul>"

    overview = f"""
  <div class="grid tabpanels">
    <div class="card panel active" id="panel_overview" data-panel="main">
      <h2>Final verdict</h2>
      <div class="body">
        <div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom:10px">
          <span class="badge sev {sev_badge_class(final_sev)}">{_escape(final_sev)}</span>
          <span class="badge score {final_band}">Score: <b>{final_score}</b>/100</span>
          <span class="pill">Static: <b class="mono">{_score_text(static_score, static_score_max)}</b></span>
          <span class="pill">Dynamic: <b class="mono">{_score_text(dyn_score, dyn_score_max)}</b></span>
          <span class="pill">YARA: <b class="mono">{_score_text(yara_score, yara_score_max)}</b></span>
          <span class="pill">MemLite: <b class="mono">{_score_text(mem_score, mem_score_max)}</b></span>
          <span class="pill">VT: <b class="mono">{vt_pos}/{vt_total if vt_total else "?"}</b></span>
        </div>
        <div class="small muted">Static/Dynamic are primary signals. YARA + MemLite are capped extras unless a high-confidence YARA unlock is present. VirusTotal is secondary (clean ⇒ capped add; detected ⇒ scaled).</div>
        <div class="section">{reasons_html}</div>
      </div>
    </div>
  </div>
"""

    # Static panel
    static_rows = ""
    for s in artifacts.get("static", []) or []:
        sev = s.get("severity", "UNKNOWN")
        score = _safe_int(s.get("score", 0), 0)
        score_max = _safe_int(s.get("score_max", 20), 20)
        band = _score_band(_score_norm_100(score, score_max))
        static_rows += (
            "<tr>"
            f"<td><code>{_escape(s.get('artifact_name',''))}</code><div class='muted small'>{_escape(s.get('artifact_mtime_utc',''))}</div></td>"
            f"<td><span class='badge sev {sev_badge_class(sev)}'>{_escape(sev)}</span></td>"
            f"<td><span class='badge score {band}'>Score: <b>{_escape(_score_text(score, score_max))}</b></span></td>"
            f"<td class='small'>{_escape(s.get('package',''))}<div class='muted'>{_escape(s.get('app_name',''))}</div></td>"
            "</tr>"
        )
    if not static_rows:
        static_rows = "<tr><td colspan='4' class='muted'>No static artifacts found.</td></tr>"

    static_panel = f"""
  <div class="card panel" id="panel_static" data-panel="main">
    <h2>Static artifacts</h2>
    <div class="body">
      <table class="table">
        <thead><tr><th>Artifact</th><th>Severity</th><th>Score</th><th>Package/App</th></tr></thead>
        <tbody>{static_rows}</tbody>
      </table>
    </div>
  </div>
"""

    # Dynamic panel
    dyn_rows = ""
    for d in artifacts.get("dynamic", []) or []:
        sev = d.get("severity", "UNKNOWN")
        score = _safe_int(d.get("score", 0), 0)
        score_max = _safe_int(d.get("score_max", 100), 100)
        band = _score_band(_score_norm_100(score, score_max))
        events_counts = _event_counts_any(d.get("events", {}) or {})
        hook = _safe_int(events_counts.get("HOOK", 0), 0)
        native = _safe_int(events_counts.get("NATIVE", 0), 0)
        ready = _safe_int(events_counts.get("READY", 0), 0)

        dyn_rows += (
            "<tr>"
            f"<td><code>{_escape(d.get('artifact_name',''))}</code><div class='muted small'>{_escape(d.get('artifact_mtime_utc',''))}</div></td>"
            f"<td><span class='badge sev {sev_badge_class(sev)}'>{_escape(sev)}</span></td>"
            f"<td><span class='badge score {band}'>Score: <b>{_escape(_score_text(score, score_max))}</b></span></td>"
            f"<td class='mono'>HOOK {hook} • NATIVE {native} • READY {ready}</td>"
            "</tr>"
        )
    if not dyn_rows:
        dyn_rows = "<tr><td colspan='4' class='muted'>No dynamic artifacts found.</td></tr>"

    dyn_panel = f"""
  <div class="card panel" id="panel_dynamic" data-panel="main">
    <h2>Dynamic artifacts</h2>
    <div class="body">
      <table class="table">
        <thead><tr><th>Artifact</th><th>Severity</th><th>Score</th><th>Events</th></tr></thead>
        <tbody>{dyn_rows}</tbody>
      </table>
    </div>
  </div>
"""

    # YARA panel
    yara_rows = ""
    yara_why = ""
    for y in artifacts.get("yara", []) or []:
        sev_y = y.get("severity", "UNKNOWN")
        score_y = _safe_int(y.get("score", 0), 0)
        score_max_y = _safe_int(y.get("score_max", 100), 100)
        band_y = _score_band(_score_norm_100(score_y, score_max_y))

        matches_list = _normalize_yara_matches(y.get("matches", None))
        mcount = len(matches_list)

        top_rules = ", ".join(
            [str(m.get("rule") or "") for m in matches_list[:6] if isinstance(m, dict) and (m.get("rule") or "")]
        ) or "(no rules listed)"

        reasons = (y.get("reasons", []) or [])
        reasons_html2 = "<ul class='compact'>" + "".join(f"<li>{_escape(r)}</li>" for r in reasons) + "</ul>"

        yara_rows += (
            "<tr>"
            f"<td><code>{_escape(y.get('artifact_name',''))}</code><div class='muted small'>{_escape(y.get('artifact_mtime_utc',''))}</div></td>"
            f"<td><span class='badge sev {sev_badge_class(sev_y)}'>{_escape(sev_y)}</span></td>"
            f"<td><span class='badge score {band_y}'>Score: <b>{_escape(_score_text(score_y, score_max_y))}</b></span></td>"
            f"<td class='mono'>{mcount}</td>"
            f"<td class='small'><span class='muted'>Top:</span> {_escape(top_rules)}</td>"
            "</tr>"
        )

        yara_why += (
            "<div class='why-card'>"
            f"<div class='why-title'>YARA scan <span class='muted'>({_escape(y.get('apk_name',''))})</span></div>"
            f"<div class='why-meta'>"
            f"<span class='badge sev {sev_badge_class(sev_y)}'>{_escape(sev_y)}</span>"
            f"<span class='badge score {band_y}'>Score: <b>{_escape(_score_text(score_y, score_max_y))}</b></span>"
            f"<span class='pill'>Matches: <span class='mono'>{mcount}</span></span>"
            f"<span class='pill'>Artifact: <code>{_escape(y.get('artifact_name',''))}</code></span>"
            f"</div>"
            f"{reasons_html2}"
            "</div>"
        )

    if not yara_rows:
        yara_rows = "<tr><td colspan='5' class='muted'>No YARA artifacts found.</td></tr>"

    yara_panel = f"""
  <div class="card panel" id="panel_yara" data-panel="main">
    <h2>YARA artifacts</h2>
    <div class="body">
      <table class="table">
        <thead><tr><th>Artifact</th><th>Severity</th><th>Score</th><th>Matches</th><th>Top rules</th></tr></thead>
        <tbody>{yara_rows}</tbody>
      </table>
      <div class="section">{yara_why}</div>
    </div>
  </div>
"""

    # MemLite panel
    mem_rows = ""
    mem_why = ""
    for m in artifacts.get("memlite", []) or []:
        sev_m = m.get("severity", "UNKNOWN")
        score_m = _safe_int(m.get("score", 0), 0)
        score_max_m = _safe_int(m.get("score_max", 100), 100)
        band_m = _score_band(_score_norm_100(score_m, score_max_m))

        reasons = (m.get("reasons", []) or [])
        reasons_html3 = "<ul class='compact'>" + "".join(f"<li>{_escape(r)}</li>" for r in reasons) + "</ul>"

        mem_rows += (
            "<tr>"
            f"<td><code>{_escape(m.get('artifact_name',''))}</code><div class='muted small'>{_escape(m.get('artifact_mtime_utc',''))}</div></td>"
            f"<td><span class='badge sev {sev_badge_class(sev_m)}'>{_escape(sev_m)}</span></td>"
            f"<td><span class='badge score {band_m}'>Score: <b>{_escape(_score_text(score_m, score_max_m))}</b></span></td>"
            f"<td class='small'>{_escape(m.get('package',''))}</td>"
            "</tr>"
        )

        mem_why += (
            "<div class='why-card'>"
            f"<div class='why-title'>MemLite snapshot <span class='muted'>({_escape(m.get('package',''))})</span></div>"
            f"<div class='why-meta'>"
            f"<span class='badge sev {sev_badge_class(sev_m)}'>{_escape(sev_m)}</span>"
            f"<span class='badge score {band_m}'>Score: <b>{_escape(_score_text(score_m, score_max_m))}</b></span>"
            f"<span class='pill'>Artifact: <code>{_escape(m.get('artifact_name',''))}</code></span>"
            f"</div>"
            f"{reasons_html3}"
            "</div>"
        )

    if not mem_rows:
        mem_rows = "<tr><td colspan='4' class='muted'>No MemLite artifacts found.</td></tr>"

    mem_panel = f"""
  <div class="card panel" id="panel_memlite" data-panel="main">
    <h2>MemLite artifacts</h2>
    <div class="body">
      <table class="table">
        <thead><tr><th>Artifact</th><th>Severity</th><th>Score</th><th>Package</th></tr></thead>
        <tbody>{mem_rows}</tbody>
      </table>
      <div class="section">{mem_why}</div>
    </div>
  </div>
"""

    # VT panel
    vt_rows = ""
    for v in artifacts.get("vt", []) or []:
        st = v.get("stats") or {}
        pos = _safe_int(st.get("positives", 0), 0)
        tot = _safe_int(st.get("total", 0), 0)
        vt_s = _safe_int(v.get("vt_score", 0), 0)
        conf = _safe_float(v.get("confidence", 0.0), 0.0)
        url = str(v.get("gui_url", "") or "")
        sha = str(v.get("sha256", "") or "")
        label = "DETECTED" if pos > 0 else "CLEAN"
        vt_rows += (
            "<tr>"
            f"<td><code>{_escape(v.get('artifact_name',''))}</code><div class='muted small'>{_escape(v.get('artifact_mtime_utc',''))}</div></td>"
            f"<td class='mono'>{_escape(label)} • {pos}/{tot if tot else '?'}</td>"
            f"<td class='mono'>vt_score {vt_s} • conf {conf:.2f}</td>"
            f"<td class='small mono'>{_escape(sha)}</td>"
            f"<td class='small'>{(f'<a href=\"{_escape(url)}\" target=\"_blank\">Open VT GUI</a>' if url else '<span class=\"muted\">(no url)</span>')}</td>"
            "</tr>"
        )
    if not vt_rows:
        vt_rows = "<tr><td colspan='5' class='muted'>No VirusTotal artifacts found.</td></tr>"

    vt_pick_line = ""
    if vt_pick:
        vt_pick_line = (
            f"<div class='why-card'>"
            f"<div class='why-title'>Picked VT result</div>"
            f"<div class='why-meta'>"
            f"<span class='pill'>positives: <b class='mono'>{vt_pos}/{vt_total if vt_total else '?'}</b></span>"
            f"<span class='pill'>vt_score: <b class='mono'>{vt_score}</b></span>"
            f"<span class='pill'>confidence: <b class='mono'>{vt_conf:.2f}</b></span>"
            f"</div>"
            f"<div class='small muted'>Rule: clean ⇒ capped add (≤20). detected ⇒ scaled add + optional floors for high positives.</div>"
            f"{(f'<div class=\"small\" style=\"margin-top:8px;\"><a href=\"{_escape(vt_url)}\" target=\"_blank\">Open in VirusTotal GUI</a></div>' if vt_url else '')}"
            f"</div>"
        )

    vt_panel = f"""
  <div class="card panel" id="panel_vt" data-panel="main">
    <h2>VirusTotal</h2>
    <div class="body">
      {vt_pick_line}
      <table class="table" style="margin-top:12px;">
        <thead><tr><th>Artifact</th><th>Verdict</th><th>Score/Conf</th><th>SHA256</th><th>Link</th></tr></thead>
        <tbody>{vt_rows}</tbody>
      </table>
    </div>
  </div>
"""

    top_panel = f"""
  <div class="card panel" id="panel_top" data-panel="main">
    <h2>Why this verdict</h2>
    <div class="body">
      <div class="why-card">
        <div class="why-title">Final aggregation</div>
        <div class="why-meta">
          <span class="badge sev {sev_badge_class(final_sev)}">{_escape(final_sev)}</span>
          <span class="badge score {final_band}">Final Score: <b>{final_score}</b>/100</span>
          <span class="pill">Base (Static/Dynamic): <b class="mono">{max(static_score, dyn_score)}</b></span>
          <span class="pill">YARA unlock: <b>{'YES' if yara_unlock else 'NO'}</b></span>
          <span class="pill">VT detected: <b>{'YES' if vt_det else 'NO'}</b></span>
        </div>
        {reasons_html}
      </div>
      <div class="small muted">Tip: keep YARA + MemLite capped to avoid benign inflation. VT clean should never push the case above ~20 by itself.</div>
    </div>
  </div>
"""

    footer = f"""
  <div class="footer">Generated by CYBERSHADOW • {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</div>
</div>
"""

    body = header + "<div class='tabpanels'>" + overview + static_panel + dyn_panel + yara_panel + mem_panel + vt_panel + top_panel + "</div>" + footer
    html = _html_page(f"CYBERSHADOW Case Report • {meta.get('id','')}", body)

    out_path = case_path / f"case__{meta.get('id', case_path.name)}.html"
    out_path.write_text(html, encoding="utf-8")
    return str(out_path)
