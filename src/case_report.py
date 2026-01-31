# src/case_report.py
from __future__ import annotations

import json
import re
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


def _clamp(x: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(x)))


# --------------------------- UI scoring bands ---------------------------

def _score_band(score: int) -> str:
    # Requested UI thresholds:
    # green <20, yellow <50, orange <75, red >=75
    s = _clamp(_safe_int(score, 0), 0, 100)
    if s < 20:
        return "SCORE_GREEN"
    if s < 50:
        return "SCORE_YELLOW"
    if s < 75:
        return "SCORE_ORANGE"
    return "SCORE_RED"


def _final_severity_from_score(score: int) -> str:
    s = _clamp(_safe_int(score, 0), 0, 100)
    if s >= 80:
        return "CRITICAL"
    if s >= 60:
        return "HIGH"
    if s >= 35:
        return "MEDIUM"
    return "LOW"


def _dedupe_evidence(evidence: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for e in evidence or []:
        key = (e.get("type", ""), e.get("name", ""), e.get("sha256", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def sev_badge_class(sev: str) -> str:
    s = (sev or "UNKNOWN").upper().strip()
    if s not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return "UNKNOWN"
    return s


# --------------------------- Artifact parsing ---------------------------

def _pick_artifacts(artifacts_dir: Path, glob_pat: str) -> list[Path]:
    files = sorted(list(artifacts_dir.glob(glob_pat)), key=lambda p: p.stat().st_mtime, reverse=True)
    return files


def _extract_static_fields(obj: dict) -> tuple[int, str, list[str]]:
    scoring = obj.get("scoring", {}) or {}
    score = _safe_int(scoring.get("score", 0), 0)
    sev = str(scoring.get("severity", "") or "").upper().strip()
    reasons = scoring.get("reasons", []) or []
    if not sev:
        sev = _final_severity_from_score(score)
    return score, sev, [str(x) for x in reasons]


def _extract_dyn_fields(obj: dict) -> tuple[int, str, list[str], bool, bool]:
    scoring = obj.get("scoring", {}) or {}
    score = _safe_int(scoring.get("score", 0), 0)
    sev = str(scoring.get("severity", "") or "").upper().strip()
    reasons = scoring.get("reasons", []) or []
    if not sev:
        sev = _final_severity_from_score(score)

    malicious_unlock = bool(scoring.get("malicious_unlock", False))
    benign_cap_applied = bool(scoring.get("benign_cap_applied", False))
    return score, sev, [str(x) for x in reasons], malicious_unlock, benign_cap_applied


def _normalize_static(artifacts: list[Path]) -> list[dict]:
    out: list[dict] = []
    for p in artifacts:
        obj = _load_json(p)
        score, sev, reasons = _extract_static_fields(obj)
        out.append(
            {
                "artifact_name": p.name,
                "artifact_mtime_utc": _fmt_fs_ts_mtime(p),
                "score": _clamp(score, 0, 100),
                "severity": _final_severity_from_score(score),
                "engine_severity": sev,  # informational
                "reasons": reasons[:60],
                "app_name": obj.get("app_name", "") or obj.get("app", "") or "",
                "package": obj.get("package", "") or "",
                "version_name": obj.get("version_name", "") or "",
                "version_code": obj.get("version_code", "") or "",
                "kind": "apk_static",
            }
        )
    return out


def _normalize_dynamic(artifacts: list[Path]) -> list[dict]:
    out: list[dict] = []
    for p in artifacts:
        obj = _load_json(p)
        score, sev, reasons, malicious_unlock, benign_cap_applied = _extract_dyn_fields(obj)

        runtime = obj.get("runtime", {}) or {}
        tag = obj.get("tag", "") or ""
        device = obj.get("device", "") or ""
        device_serial = ""
        try:
            device_serial = str(device).split()[0]
        except Exception:
            device_serial = ""

        out.append(
            {
                "artifact_name": p.name,
                "artifact_mtime_utc": _fmt_fs_ts_mtime(p),
                "score": _clamp(score, 0, 100),
                "severity": _final_severity_from_score(score),
                "engine_score": score,      # informational
                "engine_severity": sev,     # informational
                "reasons": reasons[:80],
                "malicious_unlock": bool(malicious_unlock),
                "benign_cap_applied": bool(benign_cap_applied),
                "tag": tag,
                "device_serial": device_serial,
                "app_name": obj.get("app_name", "") or "",
                "package": obj.get("package", "") or "",
                "kind": "apk_dynamic",
                "runtime": {
                    "endpoint": runtime.get("endpoint"),
                    "gadget_ready": runtime.get("gadget_ready"),
                    "frida_attach_error": runtime.get("frida_attach_error"),
                    "event_counts": runtime.get("event_counts") or {},
                    "key_counts": runtime.get("key_counts") or {},
                    "unlock_triggers": runtime.get("unlock_triggers") or [],
                },
                # optional, if present in your pipeline
                "iocs_split": obj.get("iocs_split") or {},
            }
        )
    return out


def _mean_int(values: list[int]) -> int:
    v = [int(x) for x in values if x is not None]
    if not v:
        return 0
    return int(round(sum(v) / float(len(v))))


def _case_malicious_unlock(apk_static: list[dict], apk_dynamic: list[dict]) -> bool:
    # If ANY dynamic artifact is unlocked -> allow high scoring
    for d in apk_dynamic or []:
        if bool(d.get("malicious_unlock", False)):
            return True

    # Optional: if static has explicit high-risk reasons (keywords), unlock too
    # (kept conservative; tweak later)
    for s in apk_static or []:
        rs = " ".join([str(x) for x in (s.get("reasons") or [])]).lower()
        if any(k in rs for k in ["accessibility", "device admin", "read_sms", "send_sms", "banking trojan", "dropper"]):
            return True

    return False


def build_case_summary(case_dir: str, risk_mode: RiskMode = "latest") -> dict:
    case_path = Path(case_dir)
    case = _load_json(case_path / "case.json")
    artifacts_dir = case_path / "artifacts"

    static_paths = _pick_artifacts(artifacts_dir, "apk_static__*.json")
    dynamic_paths = _pick_artifacts(artifacts_dir, "apk_dynamic__*.json")

    apk_static = _normalize_static(static_paths)
    apk_dynamic = _normalize_dynamic(dynamic_paths)

    # build “scored items” list to support latest/max
    scored_items = []
    for row in apk_static + apk_dynamic:
        try:
            mtime = (artifacts_dir / row["artifact_name"]).stat().st_mtime
        except Exception:
            mtime = 0.0
        scored_items.append((mtime, int(row.get("score", 0)), row.get("artifact_name", ""), row.get("kind", "")))

    scored_items.sort(key=lambda t: t[0], reverse=True)
    scores = [int(s) for (_mt, s, _a, _k) in scored_items]

    latest_score = scores[0] if scores else 0
    latest_artifact = scored_items[0][2] if scored_items else ""
    latest_kind = scored_items[0][3] if scored_items else ""

    # per-module latest
    latest_static_score = _safe_int(apk_static[0]["score"], 0) if apk_static else 0
    latest_dynamic_score = _safe_int(apk_dynamic[0]["score"], 0) if apk_dynamic else 0

    rm = (risk_mode or "latest").lower().strip()
    if rm == "max":
        final_score = max(scores) if scores else 0
        risk_note = "worst-case across all artifacts"
    elif rm == "mean":
        # mean of the most recent module outputs (stable for dashboard)
        bucket = []
        if apk_static:
            bucket.append(_clamp(latest_static_score, 0, 100))
        if apk_dynamic:
            bucket.append(_clamp(latest_dynamic_score, 0, 100))
        final_score = _mean_int(bucket) if bucket else 0
        risk_note = "mean of latest static + latest dynamic"
    else:
        final_score = latest_score if scores else 0
        risk_note = "verdict from most recent artifact"

    final_score = _clamp(final_score, 0, 100)

    # benign-aware cap (GOLD RULE): benign apps must be < 20
    malicious_unlock = _case_malicious_unlock(apk_static, apk_dynamic)
    benign_cap_applied = False
    if not malicious_unlock and final_score >= 20:
        final_score = 19
        benign_cap_applied = True

    final_sev = _final_severity_from_score(final_score)
    evidence = _dedupe_evidence(case.get("evidence", []) or [])

    modules_present = []
    if apk_static:
        modules_present.append("apk_static")
    if apk_dynamic:
        modules_present.append("apk_dynamic")

    return {
        "case_id": case.get("case_id", "UNKNOWN"),
        "created_at_utc": _fmt_ts(case.get("created_at", 0)),
        "env": case.get("env", {}) or {},
        "evidence": evidence,
        "apk_static": apk_static,
        "apk_dynamic": apk_dynamic,
        "modules_present": modules_present,
        "risk": {
            "risk_mode": rm,
            "risk_note": risk_note,
            "score": int(final_score),
            "severity": final_sev,
            "latest_artifact": latest_artifact,
            "latest_kind": latest_kind,
            "latest_static_score": int(_clamp(latest_static_score, 0, 100)),
            "latest_dynamic_score": int(_clamp(latest_dynamic_score, 0, 100)),
            "malicious_unlock": bool(malicious_unlock),
            "benign_cap_applied": bool(benign_cap_applied),
        },
    }


def write_case_html(case_dir: str, risk_mode: RiskMode = "latest") -> str:
    summary = build_case_summary(case_dir, risk_mode=risk_mode)

    case_path = Path(case_dir)
    score = int(summary["risk"]["score"])
    sev = str(summary["risk"]["severity"])
    rm = str(summary["risk"]["risk_mode"])
    latest_art = str(summary["risk"]["latest_artifact"] or "")
    latest_kind = str(summary["risk"]["latest_kind"] or "")
    score_band = _score_band(score)

    benign_cap = bool(summary["risk"].get("benign_cap_applied", False))
    unlock = bool(summary["risk"].get("malicious_unlock", False))

    # Evidence table
    evidence_rows = ""
    for e in summary.get("evidence", []) or []:
        evidence_rows += (
            "<tr>"
            f"<td>{e.get('name','')}</td>"
            f"<td><span class='pill'>{e.get('type','')}</span></td>"
            f"<td class='mono'>{e.get('sha256','')}</td>"
            "</tr>"
        )
    if not evidence_rows:
        evidence_rows = "<tr><td colspan='3'><i>No evidence added yet.</i></td></tr>"

    # Static rows + why
    static_rows = ""
    static_why = ""
    for m in summary.get("apk_static", []) or []:
        sev_m = m.get("severity", "UNKNOWN")
        score_m = _safe_int(m.get("score", 0), 0)
        band_m = _score_band(score_m)

        reasons = (m.get("reasons", []) or [])
        reasons_html = "<ul class='compact'>" + "".join(f"<li>{r}</li>" for r in reasons) + "</ul>"

        engine_sev = m.get("engine_severity", None)
        ref_note = ""
        if engine_sev and engine_sev != sev_m:
            ref_note = (
                "<div class='small muted'>"
                f"Engine severity (ref): <b>{engine_sev}</b> • Derived severity (used): <b>{sev_m}</b>"
                "</div>"
            )

        static_rows += (
            "<tr>"
            f"<td>{m.get('app_name','')}</td>"
            f"<td><code>{m.get('package','')}</code></td>"
            f"<td>{m.get('version_name','')} ({m.get('version_code','')})</td>"
            f"<td><span class='badge sev {sev_badge_class(sev_m)}'>{sev_m}</span></td>"
            f"<td><span class='badge score {band_m}'>Score: <b>{score_m}</b>/100</span></td>"
            f"<td class='small'><code>{m.get('artifact_name','')}</code><div class='muted small'>{m.get('artifact_mtime_utc','')}</div></td>"
            "</tr>"
        )

        static_why += (
            "<div class='why-card'>"
            f"<div class='why-title'>{m.get('app_name','')} <span class='muted'>({m.get('package','')})</span></div>"
            f"<div class='why-meta'>"
            f"<span class='badge sev {sev_badge_class(sev_m)}'>{sev_m}</span>"
            f"<span class='badge score {band_m}'>Score: <b>{score_m}</b>/100</span>"
            f"<span class='pill'>Artifact: <code>{m.get('artifact_name','')}</code></span>"
            f"<span class='pill'>Run: <span class='mono'>{m.get('artifact_mtime_utc','')}</span></span>"
            f"</div>"
            f"{ref_note}"
            f"{reasons_html}"
            "</div>"
        )

    if not static_rows:
        static_rows = "<tr><td colspan='6'><i>No APK static artifacts found.</i></td></tr>"
    if not static_why:
        static_why = "<i>No static scoring reasons available.</i>"

    # Dynamic rows + why
    dyn_rows = ""
    dyn_why = ""
    for d in summary.get("apk_dynamic", []) or []:
        sev_d = d.get("severity", "UNKNOWN")
        score_d = _safe_int(d.get("score", 0), 0)
        band_d = _score_band(score_d)

        reasons = (d.get("reasons", []) or [])
        reasons_html = "<ul class='compact'>" + "".join(f"<li>{r}</li>" for r in reasons) + "</ul>"

        unlock_flag = bool(d.get("malicious_unlock", False))
        cap_flag = bool(d.get("benign_cap_applied", False))

        ref_note = "<div class='small muted'>"
        parts = []
        parts.append(f"Conservative score (used): <b>{score_d}</b>/100")
        parts.append(f"Unlock: <b>{'YES' if unlock_flag else 'NO'}</b>")
        parts.append(f"Cap applied: <b>{'YES' if cap_flag else 'NO'}</b>")
        ref_note += " • ".join(parts) + "</div>"

        dyn_rows += (
            "<tr>"
            f"<td>{(d.get('app_name') or '')}</td>"
            f"<td><code>{d.get('package','')}</code></td>"
            f"<td class='small'>tag=<code>{d.get('tag','')}</code><div class='muted small'>{d.get('device_serial','')}</div></td>"
            f"<td><span class='badge sev {sev_badge_class(sev_d)}'>{sev_d}</span></td>"
            f"<td><span class='badge score {band_d}'>Score: <b>{score_d}</b>/100</span></td>"
            f"<td class='small'><code>{d.get('artifact_name','')}</code><div class='muted small'>{d.get('artifact_mtime_utc','')}</div></td>"
            "</tr>"
        )

        dyn_why += (
            "<div class='why-card'>"
            f"<div class='why-title'>Dynamic run <span class='muted'>({d.get('package','')})</span></div>"
            f"<div class='why-meta'>"
            f"<span class='badge sev {sev_badge_class(sev_d)}'>{sev_d}</span>"
            f"<span class='badge score {band_d}'>Score: <b>{score_d}</b>/100</span>"
            f"<span class='pill'>Artifact: <code>{d.get('artifact_name','')}</code></span>"
            f"<span class='pill'>Run: <span class='mono'>{d.get('artifact_mtime_utc','')}</span></span>"
            f"</div>"
            f"{ref_note}"
            f"{reasons_html}"
            "</div>"
        )

    if not dyn_rows:
        dyn_rows = "<tr><td colspan='6'><i>No APK dynamic artifacts found.</i></td></tr>"
    if not dyn_why:
        dyn_why = "<i>No dynamic scoring reasons available.</i>"

    cap_note = ""
    if benign_cap and not unlock:
        cap_note = (
            "<div class='small muted' style='margin-top:8px;'>"
            "<b>Benign-aware cap:</b> no high-confidence malware indicators detected → score capped at <b>19/100</b>."
            "</div>"
        )
    if unlock:
        cap_note = (
            "<div class='small muted' style='margin-top:8px;'>"
            "<b>Malicious unlock:</b> strong indicators detected → score may exceed 19/100."
            "</div>"
        )

    html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>Case Report - {summary['case_id']}</title>
<style>
:root {{
  --bg: #0b1020;
  --border: rgba(255,255,255,0.09);
  --text: rgba(255,255,255,0.92);
  --muted: rgba(255,255,255,0.66);
}}

body {{
  margin: 0;
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
  background: radial-gradient(1200px 800px at 20% -10%, rgba(0,153,255,0.20), transparent 60%),
              radial-gradient(1000px 700px at 90% 0%, rgba(120,66,255,0.22), transparent 55%),
              radial-gradient(900px 600px at 40% 110%, rgba(0,255,170,0.12), transparent 55%),
              var(--bg);
  color: var(--text);
}}

.container {{
  max-width: 1200px;
  margin: 28px auto;
  padding: 0 18px 40px 18px;
}}

h1 {{
  margin: 0 0 8px 0;
  letter-spacing: 0.6px;
}}

.sub {{
  color: var(--muted);
  margin-bottom: 18px;
}}

.card {{
  background: linear-gradient(180deg, rgba(18,24,40,0.86), rgba(12,16,28,0.82));
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 14px 16px;
  margin: 14px 0;
  box-shadow: 0 12px 40px rgba(0,0,0,0.22);
}}

.row {{
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
}}

.badge {{
  display:inline-flex;
  align-items:center;
  gap: 8px;
  padding: 7px 12px;
  border-radius: 999px;
  font-weight: 900;
  letter-spacing: 0.2px;
  border: 1px solid rgba(255,255,255,0.14);
  line-height: 1.2;
}}

.badge.sev {{ text-transform: uppercase; }}
.badge.score {{ font-weight: 900; }}

.pill {{
  display:inline-flex;
  align-items:center;
  gap: 8px;
  padding: 7px 12px;
  border-radius: 999px;
  border: 1px solid rgba(255,255,255,0.10);
  color: var(--muted);
  background: rgba(255,255,255,0.04);
  line-height: 1.2;
}}

.muted {{ color: var(--muted); }}
.small {{ font-size: 0.92em; color: rgba(255,255,255,0.72); }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }}

code {{
  background: rgba(255,255,255,0.06);
  padding: 2px 7px;
  border-radius: 8px;
  border: 1px solid rgba(255,255,255,0.08);
  color: rgba(255,255,255,0.92);
  display: inline-block;
}}

pre {{
  background: rgba(255,255,255,0.05);
  border: 1px solid rgba(255,255,255,0.08);
  padding: 12px;
  border-radius: 14px;
  overflow:auto;
  color: rgba(255,255,255,0.90);
}}

table {{
  width: 100%;
  border-collapse: collapse;
  overflow: hidden;
  border-radius: 14px;
}}

th, td {{
  text-align: left;
  padding: 10px;
  border-bottom: 1px solid rgba(255,255,255,0.08);
  vertical-align: top;
  line-height: 1.35;
}}

th {{
  color: rgba(255,255,255,0.78);
  font-weight: 900;
  background: rgba(255,255,255,0.03);
}}

.compact {{
  margin: 8px 0 0 18px;
  padding: 0;
}}
.compact li {{ margin: 6px 0; }}

.why-card {{
  background: rgba(255,255,255,0.04);
  border: 1px solid rgba(255,255,255,0.09);
  border-radius: 14px;
  padding: 12px 14px;
  margin: 10px 0;
}}
.why-title {{
  font-weight: 950;
  letter-spacing: 0.2px;
  margin-bottom: 6px;
}}
.why-meta {{
  display:flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  margin-bottom: 8px;
}}

.LOW {{
  background: rgba(0,255,160,0.10);
  color: rgba(140,255,210,0.95);
}}
.MEDIUM {{
  background: rgba(255,190,0,0.12);
  color: rgba(255,210,110,0.95);
}}
.HIGH {{
  background: rgba(255,80,80,0.12);
  color: rgba(255,170,170,0.95);
}}
.CRITICAL {{
  background: rgba(255,40,120,0.14);
  color: rgba(255,170,210,0.95);
}}
.UNKNOWN {{
  background: rgba(255,255,255,0.06);
  color: rgba(255,255,255,0.82);
}}

.SCORE_GREEN {{
  background: rgba(0,255,170,0.10);
  color: rgba(140,255,210,0.95);
  border-color: rgba(0,255,170,0.22);
}}
.SCORE_YELLOW {{
  background: rgba(255,205,0,0.12);
  color: rgba(255,220,130,0.95);
  border-color: rgba(255,205,0,0.22);
}}
.SCORE_ORANGE {{
  background: rgba(255,130,0,0.12);
  color: rgba(255,190,140,0.95);
  border-color: rgba(255,130,0,0.22);
}}
.SCORE_RED {{
  background: rgba(255,60,60,0.12);
  color: rgba(255,175,175,0.95);
  border-color: rgba(255,60,60,0.22);
}}

.hr {{
  height: 1px;
  background: rgba(255,255,255,0.08);
  margin: 10px 0;
}}
</style>
</head>
<body>
<div class="container">
  <h1>Hybrid Forensic Case Report</h1>
  <div class="sub">CYBERSHADOW • Case-level aggregation and traceable scoring summary</div>

  <div class="card">
    <div class="row">
      <span class="pill"><b>Case ID:</b> {summary['case_id']}</span>
      <span class="pill"><b>Created:</b> {summary['created_at_utc']}</span>
      <span class="badge sev {sev_badge_class(sev)}">{sev}</span>
      <span class="badge score {score_band}">Final Score: <b>{score}</b>/100</span>
      <span class="pill"><b>Modules:</b> {", ".join(summary["modules_present"]) if summary["modules_present"] else "None"}</span>
      <span class="pill"><b>Risk mode:</b> <span class="mono">{rm}</span></span>
      <span class="pill"><b>Latest artifact:</b> <code>{latest_art}</code></span>
      <span class="pill"><b>Latest kind:</b> <span class="mono">{latest_kind}</span></span>
    </div>
    <div class="small muted" style="margin-top:10px;">
      Latest = verdict from most recent artifact • Max = worst-case across artifacts • Mean = avg(latest static, latest dynamic)
    </div>
    {cap_note}
  </div>

  <div class="card">
    <div class="row" style="justify-content:space-between;">
      <div class="row">
        <h2 style="margin:0;">Evidence Registry</h2>
        <span class="muted">({len(summary['evidence'])} unique item(s))</span>
      </div>
    </div>
    <table>
      <tr><th>Name</th><th>Type</th><th>SHA-256</th></tr>
      {evidence_rows}
    </table>
  </div>

  <div class="card">
    <div class="row">
      <h2 style="margin:0;">APK Static Analysis Summary</h2>
      <span class="muted">(one row per analyzed artifact)</span>
    </div>
    <table>
      <tr>
        <th>App</th><th>Package</th><th>Version</th><th>Severity</th><th>Score</th><th>Artifact</th>
      </tr>
      {static_rows}
    </table>

    <div class="hr"></div>
    <div class="row">
      <h2 style="margin:0;">Why this static score</h2>
      <span class="muted">weighted indicators (as reported by static scoring engine)</span>
    </div>
    {static_why}
  </div>

  <div class="card">
    <div class="row">
      <h2 style="margin:0;">APK Dynamic Analysis Summary</h2>
      <span class="muted">(artifact scoring is benign-aware)</span>
    </div>
    <table>
      <tr>
        <th>App</th><th>Package</th><th>Run</th><th>Severity</th><th>Score</th><th>Artifact</th>
      </tr>
      {dyn_rows}
    </table>

    <div class="hr"></div>
    <div class="row">
      <h2 style="margin:0;">Why this dynamic score</h2>
      <span class="muted">runtime indicators</span>
    </div>
    {dyn_why}
  </div>

  <div class="card">
    <div class="row">
      <h2 style="margin:0;">Reproducibility (Environment)</h2>
      <span class="muted">snapshot used to reproduce the run</span>
    </div>
    <pre>{json.dumps(summary.get("env",{}), indent=2, ensure_ascii=False)}</pre>
  </div>

</div>
</body>
</html>
"""
    out = case_path / "reports" / "case_report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return str(out)
