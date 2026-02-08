# src/case_report.py
from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime
from typing import Literal, Any

RiskMode = Literal["latest", "max", "mean"]


# --------------------------- IO helpers ---------------------------

def _load_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


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
    # minimal HTML escape
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
    # UI thresholds requested:
    # green <20, yellow <50, orange <75, red >=75 (<=100)
    s = _safe_int(score, 0)
    if s < 20:
        return "SCORE_GREEN"
    if s < 50:
        return "SCORE_YELLOW"
    if s < 75:
        return "SCORE_ORANGE"
    return "SCORE_RED"


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
    out = {
        "artifact_name": artifact_name,
        "artifact_path": str(artifact_path),
        "artifact_mtime_utc": _fmt_fs_ts_mtime(artifact_path),
        "module": "apk_static",
        "package": obj.get("package", ""),
        "app_name": obj.get("app_name", obj.get("app", "")),
        "severity": scoring.get("severity", "UNKNOWN"),
        "score": _safe_int(scoring.get("score", 0), 0),
        "reasons": scoring.get("reasons", []) or [],
    }
    return out


def _normalize_dynamic(obj: dict, artifact_name: str, artifact_path: Path) -> dict:
    scoring = (obj.get("scoring") or {})
    out = {
        "artifact_name": artifact_name,
        "artifact_path": str(artifact_path),
        "artifact_mtime_utc": _fmt_fs_ts_mtime(artifact_path),
        "module": "apk_dynamic",
        "package": obj.get("package", ""),
        "app_name": obj.get("app_name", obj.get("app", "")),
        "device": obj.get("device", {}),
        "severity": scoring.get("severity", "UNKNOWN"),
        "score": _safe_int(scoring.get("score", 0), 0),
        "reasons": scoring.get("reasons", []) or [],
        "events": obj.get("events", {}) or {},
        "iocs": obj.get("iocs", {}) or {},
    }
    return out


def _normalize_yara(obj: dict, artifact_name: str, artifact_path: Path) -> dict:
    scoring = (obj.get("scoring") or {})
    matches = obj.get("matches", obj.get("results", obj.get("rules", [])))
    out = {
        "artifact_name": artifact_name,
        "artifact_path": str(artifact_path),
        "artifact_mtime_utc": _fmt_fs_ts_mtime(artifact_path),
        "module": "yara",
        "apk_name": obj.get("apk_name", obj.get("apk", "")),
        "severity": scoring.get("severity", "UNKNOWN"),
        "score": _safe_int(scoring.get("score", 0), 0),
        "reasons": scoring.get("reasons", []) or [],
        "matches": matches,
        "malicious_unlock": bool(scoring.get("malicious_unlock", obj.get("malicious_unlock", False))),
    }
    return out


def _normalize_yara_matches(matches) -> list[dict]:
    """Coerce YARA match output into list[dict] so templates can slice safely.

    Accepts:
      - list[dict] (preferred)
      - list[str]
      - dict with a 'matches' / 'rules' / 'results' list
      - dict mapping rule_name -> meta
    """
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
    out = {
        "artifact_name": artifact_name,
        "artifact_path": str(artifact_path),
        "artifact_mtime_utc": _fmt_fs_ts_mtime(artifact_path),
        "module": "memlite",
        "package": obj.get("package", ""),
        "device": obj.get("device", {}),
        "severity": scoring.get("severity", "UNKNOWN"),
        "score": _safe_int(scoring.get("score", 0), 0),
        "reasons": scoring.get("reasons", []) or [],
        "extras": obj.get("extras", {}) or {},
    }
    return out


def _latest_by_mtime(items: list[dict]) -> dict | None:
    if not items:
        return None
    return sorted(items, key=lambda x: str(x.get("artifact_mtime_utc", "")), reverse=True)[0]


def _max_by_score(items: list[dict]) -> dict | None:
    if not items:
        return None
    return sorted(items, key=lambda x: _safe_int(x.get("score", 0), 0), reverse=True)[0]


def _mean_score(items: list[dict]) -> int:
    if not items:
        return 0
    vals = [_safe_int(x.get("score", 0), 0) for x in items]
    if not vals:
        return 0
    return int(round(sum(vals) / len(vals)))


def _pick_mode(items: list[dict], mode: RiskMode) -> dict | None:
    if mode == "latest":
        return _latest_by_mtime(items)
    if mode == "max":
        return _max_by_score(items)
    # mean returns synthetic
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
    """
    Accept:
      - dict counts: {"HOOK": 14, ...}
      - list of event dicts: [{"tag":"HOOK",...}, ...]
    Return:
      - dict counts always.
    """
    if isinstance(events_obj, dict):
        # already counts; just coerce numeric-ish values
        out = {}
        for k, v in events_obj.items():
            try:
                out[str(k)] = int(v)
            except Exception:
                # non-numeric -> ignore
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


# --------------------------- case aggregation ---------------------------

def _collect_artifacts(case_dir: Path) -> dict:
    artifacts_dir = case_dir / "artifacts"
    out = {"static": [], "dynamic": [], "yara": [], "memlite": []}
    if not artifacts_dir.exists():
        return out

    for p in sorted(artifacts_dir.glob("*.json")):
        name = p.name
        try:
            obj = _load_json(p)
        except Exception:
            continue

        if name.startswith("apk_static__"):
            out["static"].append(_normalize_static(obj, name, p))
        elif name.startswith("apk_dynamic__"):
            out["dynamic"].append(_normalize_dynamic(obj, name, p))
        elif name.startswith("yara__"):
            out["yara"].append(_normalize_yara(obj, name, p))
        elif name.startswith("memlite__"):
            out["memlite"].append(_normalize_memlite(obj, name, p))

    return out


def _case_meta(case_dir: Path) -> dict:
    case_json = case_dir / "case.json"
    if not case_json.exists():
        return {"id": case_dir.name, "created_at": "unknown"}
    try:
        cj = _load_json(case_json)
    except Exception:
        cj = {}
    return {
        "id": cj.get("id", case_dir.name),
        "created_at": cj.get("created_at", cj.get("created", "unknown")),
        "base_dir": str(case_dir),
    }


def _benign_cap_applies(static_score: int, dyn_score: int, yara_unlock: bool) -> bool:
    # If neither static nor dynamic show high-confidence malware,
    # and we don't have a high-confidence YARA unlock, cap verdict to avoid false positives.
    base = max(_safe_int(static_score, 0), _safe_int(dyn_score, 0))
    if yara_unlock:
        return False
    return base < 20


def _aggregate_case_score(static_score: int, dyn_score: int, yara_score: int, mem_score: int, yara_unlock: bool) -> dict:
    # Primary signals
    base = max(_safe_int(static_score, 0), _safe_int(dyn_score, 0))

    # Extras are intentionally capped to avoid benign -> malware inflation
    mem_cap = 10
    yara_low_cap = 10

    mem_contrib = min(_safe_int(mem_score, 0), mem_cap)

    if yara_unlock:
        yara_contrib = _safe_int(yara_score, 0)
        bonus = 5
        reasons = [
            f"Static/Dynamic base: {base}",
            f"MemLite contributes {mem_contrib} (cap {mem_cap})",
            f"YARA contributes {yara_contrib} (high-confidence unlock)",
            f"YARA unlock bonus (+{bonus})",
        ]
        total = base + mem_contrib + yara_contrib + bonus
    else:
        yara_contrib = min(_safe_int(yara_score, 0), yara_low_cap)
        reasons = [
            f"Static/Dynamic base: {base}",
            f"MemLite contributes {mem_contrib} (cap {mem_cap})",
            f"YARA contributes {yara_contrib} (low-confidence cap {yara_low_cap})",
        ]
        total = base + mem_contrib + yara_contrib

    total = _clamp(total, 0, 100)

    if _benign_cap_applies(static_score, dyn_score, yara_unlock):
        # hard cap (benign-aware)
        total = min(total, 19)
        reasons.append("Benign-aware cap applied (no high-confidence indicators) → score capped at 19/100.")

    sev = _severity_from_score(total)
    return {"score": total, "severity": sev, "reasons": reasons}


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
  function $(sel){ return document.querySelector(sel); }
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

    # Choose per-mode representative artifacts (or synth)
    static_pick = _pick_mode(artifacts["static"], risk_mode)
    dyn_pick = _pick_mode(artifacts["dynamic"], risk_mode)
    yara_pick = _pick_mode(artifacts["yara"], risk_mode)
    mem_pick = _pick_mode(artifacts["memlite"], risk_mode)

    static_score = _safe_int((static_pick or {}).get("score", 0), 0) if risk_mode != "mean" else _mean_score(artifacts["static"])
    dyn_score = _safe_int((dyn_pick or {}).get("score", 0), 0) if risk_mode != "mean" else _mean_score(artifacts["dynamic"])
    yara_score = _safe_int((yara_pick or {}).get("score", 0), 0) if risk_mode != "mean" else _mean_score(artifacts["yara"])
    mem_score = _safe_int((mem_pick or {}).get("score", 0), 0) if risk_mode != "mean" else _mean_score(artifacts["memlite"])

    # High-confidence unlock only if explicitly set by YARA scoring
    yara_unlock = bool((yara_pick or {}).get("malicious_unlock", False))
    agg = _aggregate_case_score(static_score, dyn_score, yara_score, mem_score, yara_unlock=yara_unlock)

    final_score = _safe_int(agg.get("score", 0), 0)
    final_sev = agg.get("severity", "UNKNOWN")
    final_band = _score_band(final_score)

    # summary object for HTML (keeps lists for tables)
    summary = {
        "static": artifacts["static"],
        "dynamic": artifacts["dynamic"],
        "yara": artifacts["yara"],
        "memlite": artifacts["memlite"],
        "picked": {
            "static": static_pick,
            "dynamic": dyn_pick,
            "yara": yara_pick,
            "memlite": mem_pick,
        },
        "final": {
            "score": final_score,
            "severity": final_sev,
            "reasons": agg.get("reasons", []) or [],
            "yara_unlock": yara_unlock,
        },
    }

    # render sections
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
        <span class="pill">Malicious unlock: <b>{"YES" if yara_unlock else "NO"}</b></span>
      </div>
    </div>
    <div class="tabs">
      <div class="tab active" data-group="main" data-tab="panel_overview">Overview</div>
      <div class="tab" data-group="main" data-tab="panel_static">Static</div>
      <div class="tab" data-group="main" data-tab="panel_dynamic">Dynamic</div>
      <div class="tab" data-group="main" data-tab="panel_yara">YARA</div>
      <div class="tab" data-group="main" data-tab="panel_memlite">MemLite</div>
      <div class="tab" data-group="main" data-tab="panel_top">Top / Why</div>
    </div>
  </div>
"""

    # --- Overview panel ---
    final_reasons = summary["final"]["reasons"]
    reasons_html = "<ul class='compact'>" + "".join(f"<li>{_escape(r)}</li>" for r in final_reasons) + "</ul>"

    overview = f"""
  <div class="grid tabpanels">
    <div class="card panel active" id="panel_overview" data-panel="main">
      <h2>Final verdict</h2>
      <div class="body">
        <div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom:10px">
          <span class="badge sev {sev_badge_class(final_sev)}">{_escape(final_sev)}</span>
          <span class="badge score {final_band}">Score: <b>{final_score}</b>/100</span>
          <span class="pill">Static: <b class="mono">{static_score}</b></span>
          <span class="pill">Dynamic: <b class="mono">{dyn_score}</b></span>
          <span class="pill">YARA: <b class="mono">{yara_score}</b></span>
          <span class="pill">MemLite: <b class="mono">{mem_score}</b></span>
        </div>
        <div class="small muted">Static/Dynamic are the primary risk signals. YARA + MemLite are capped “extras” unless a high-confidence YARA unlock is present.</div>
        <div class="section">{reasons_html}</div>
      </div>
    </div>

    <div class="card panel active" id="panel_overview_side" data-panel="main" style="display:none"></div>
  </div>
"""

    # --- Static panel ---
    static_rows = ""
    for s in summary.get("static", []) or []:
        sev = s.get("severity", "UNKNOWN")
        score = _safe_int(s.get("score", 0), 0)
        band = _score_band(score)
        static_rows += (
            "<tr>"
            f"<td><code>{_escape(s.get('artifact_name',''))}</code><div class='muted small'>{_escape(s.get('artifact_mtime_utc',''))}</div></td>"
            f"<td><span class='badge sev {sev_badge_class(sev)}'>{_escape(sev)}</span></td>"
            f"<td><span class='badge score {band}'>Score: <b>{score}</b>/100</span></td>"
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

    # --- Dynamic panel ---
    dyn_rows = ""
    for d in summary.get("dynamic", []) or []:
        sev = d.get("severity", "UNKNOWN")
        score = _safe_int(d.get("score", 0), 0)
        band = _score_band(score)

        # FIX: events can be dict counts OR list of event dicts
        events = d.get("events", {}) or {}
        events_counts = _event_counts_any(events)

        hook = _safe_int(events_counts.get("HOOK", 0), 0)
        native = _safe_int(events_counts.get("NATIVE", 0), 0)
        ready = _safe_int(events_counts.get("READY", 0), 0)

        dyn_rows += (
            "<tr>"
            f"<td><code>{_escape(d.get('artifact_name',''))}</code><div class='muted small'>{_escape(d.get('artifact_mtime_utc',''))}</div></td>"
            f"<td><span class='badge sev {sev_badge_class(sev)}'>{_escape(sev)}</span></td>"
            f"<td><span class='badge score {band}'>Score: <b>{score}</b>/100</span></td>"
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

    # --- YARA panel ---
    yara_rows = ""
    yara_why = ""
    for y in summary.get("yara", []) or []:
        sev_y = y.get("severity", "UNKNOWN")
        score_y = _safe_int(y.get("score", 0), 0)
        band_y = _score_band(score_y)

        matches_list = _normalize_yara_matches(y.get("matches", None))
        mcount = len(matches_list)

        top_rules = ", ".join(
            [
                str(m.get("rule") or "")
                for m in matches_list[:6]
                if isinstance(m, dict) and (m.get("rule") or "")
            ]
        )
        top_rules = top_rules if top_rules else "(no rules listed)"

        reasons = (y.get("reasons", []) or [])
        reasons_html = "<ul class='compact'>" + "".join(f"<li>{_escape(r)}</li>" for r in reasons) + "</ul>"

        yara_rows += (
            "<tr>"
            f"<td><code>{_escape(y.get('artifact_name',''))}</code><div class='muted small'>{_escape(y.get('artifact_mtime_utc',''))}</div></td>"
            f"<td><span class='badge sev {sev_badge_class(sev_y)}'>{_escape(sev_y)}</span></td>"
            f"<td><span class='badge score {band_y}'>Score: <b>{score_y}</b>/100</span></td>"
            f"<td class='mono'>{mcount}</td>"
            f"<td class='small'><span class='muted'>Top:</span> {_escape(top_rules)}</td>"
            "</tr>"
        )

        yara_why += (
            "<div class='why-card'>"
            f"<div class='why-title'>YARA scan <span class='muted'>({_escape(y.get('apk_name',''))})</span></div>"
            f"<div class='why-meta'>"
            f"<span class='badge sev {sev_badge_class(sev_y)}'>{_escape(sev_y)}</span>"
            f"<span class='badge score {band_y}'>Score: <b>{score_y}</b>/100</span>"
            f"<span class='pill'>Matches: <span class='mono'>{mcount}</span></span>"
            f"<span class='pill'>Artifact: <code>{_escape(y.get('artifact_name',''))}</code></span>"
            f"</div>"
            f"{reasons_html}"
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

    # --- MemLite panel ---
    mem_rows = ""
    mem_why = ""
    for m in summary.get("memlite", []) or []:
        sev_m = m.get("severity", "UNKNOWN")
        score_m = _safe_int(m.get("score", 0), 0)
        band_m = _score_band(score_m)

        reasons = (m.get("reasons", []) or [])
        reasons_html = "<ul class='compact'>" + "".join(f"<li>{_escape(r)}</li>" for r in reasons) + "</ul>"

        mem_rows += (
            "<tr>"
            f"<td><code>{_escape(m.get('artifact_name',''))}</code><div class='muted small'>{_escape(m.get('artifact_mtime_utc',''))}</div></td>"
            f"<td><span class='badge sev {sev_badge_class(sev_m)}'>{_escape(sev_m)}</span></td>"
            f"<td><span class='badge score {band_m}'>Score: <b>{score_m}</b>/100</span></td>"
            f"<td class='small'>{_escape(m.get('package',''))}</td>"
            "</tr>"
        )

        mem_why += (
            "<div class='why-card'>"
            f"<div class='why-title'>MemLite snapshot <span class='muted'>({_escape(m.get('package',''))})</span></div>"
            f"<div class='why-meta'>"
            f"<span class='badge sev {sev_badge_class(sev_m)}'>{_escape(sev_m)}</span>"
            f"<span class='badge score {band_m}'>Score: <b>{score_m}</b>/100</span>"
            f"<span class='pill'>Artifact: <code>{_escape(m.get('artifact_name',''))}</code></span>"
            f"</div>"
            f"{reasons_html}"
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

    # --- Top / Why panel ---
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
        </div>
        {reasons_html}
      </div>
      <div class="small muted">Tip: keep YARA + MemLite capped to avoid benign inflation. Only allow unlock on curated high-confidence rules.</div>
    </div>
  </div>
"""

    footer = f"""
  <div class="footer">Generated by CYBERSHADOW • {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</div>
</div>
"""

    body = header + "<div class='tabpanels'>" + overview + static_panel + dyn_panel + yara_panel + mem_panel + top_panel + "</div>" + footer
    html = _html_page(f"CYBERSHADOW Case Report • {meta.get('id','')}", body)

    out_path = case_path / f"case__{meta.get('id', case_path.name)}.html"
    out_path.write_text(html, encoding="utf-8")
    return str(out_path)
