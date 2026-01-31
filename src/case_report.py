# src/case_report.py
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Literal, Optional, Any


RiskMode = Literal["latest", "max"]


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


# --------------------------- Artifact loading ---------------------------

def _load_artifacts(case_path: Path, pattern: str) -> list[dict]:
    artifacts_dir = case_path / "artifacts"
    files = sorted(artifacts_dir.glob(pattern))
    out = []
    for p in files:
        try:
            obj = _load_json(p)
            obj["_artifact_name"] = p.name
            obj["_artifact_mtime_utc"] = _fmt_fs_ts_mtime(p)
            obj["_artifact_mtime_ts"] = float(p.stat().st_mtime)
            out.append(obj)
        except Exception:
            pass
    return out


# --------------------------- Reason parsing ---------------------------

def _parse_reason_weight(reason: str) -> int:
    # Accept reasons like "Something (+45)" OR "Something +45"
    if not isinstance(reason, str):
        return 0
    m = re.search(r"\(\s*\+\s*(\d+)\s*\)", reason)
    if m:
        return _safe_int(m.group(1), 0)
    m = re.search(r"\+\s*(\d+)\b", reason)
    if m:
        return _safe_int(m.group(1), 0)
    return 0


def _sort_reasons(reasons: list[str]) -> list[tuple[str, int]]:
    rs = [(r, _parse_reason_weight(r)) for r in (reasons or []) if isinstance(r, str)]
    rs.sort(key=lambda t: (-t[1], str(t[0])))
    return rs


# --------------------------- Static normalization ---------------------------

def _normalize_apk_static(apk_list: list[dict]) -> list[dict]:
    """
    STATIC:
    - SCORE is source of truth.
    - Severity derived from score to avoid inconsistencies.
    - Engine severity kept as reference.
    """
    out = []
    for a in apk_list or []:
        scoring = a.get("scoring", {}) or {}

        score = _clamp(_safe_int(scoring.get("score", 0), 0), 0, 100)
        derived_sev = _final_severity_from_score(score)
        engine_sev = (scoring.get("severity") or "").upper().strip() or None

        reasons = scoring.get("reasons", []) or []
        reasons_sorted = _sort_reasons(reasons)

        out.append(
            {
                "kind": "apk_static",
                "artifact_name": a.get("_artifact_name", ""),
                "artifact_mtime_utc": a.get("_artifact_mtime_utc", "unknown"),
                "artifact_mtime_ts": float(a.get("_artifact_mtime_ts", 0) or 0),
                "app_name": a.get("app_name", ""),
                "package": a.get("package", ""),
                "version_name": a.get("version_name", ""),
                "version_code": a.get("version_code", ""),
                "score": score,
                "severity": derived_sev,
                "engine_severity": engine_sev,
                "sensitive_permissions": (scoring.get("sensitive_permissions", []) or []),
                "reasons": [r for r, _w in reasons_sorted] if reasons_sorted else ["No major risk indicators detected."],
                "reasons_weighted": reasons_sorted,
                "certificate_fp": (a.get("certificate", {}) or {}).get("sha256_fingerprint", "unknown"),
                "iocs": a.get("iocs", {}) or {},
            }
        )

    out.sort(key=lambda m: m.get("artifact_mtime_ts", 0), reverse=True)
    return out


# --------------------------- Dynamic normalization (artifact-truth) ---------------------------

def _extract_dyn_fields(obj: dict) -> tuple[int, str, list[str], bool, bool]:
    scoring = obj.get("scoring", {}) or {}
    score = _clamp(_safe_int(scoring.get("score", 0), 0), 0, 100)
    sev = _final_severity_from_score(score)
    reasons = scoring.get("reasons", []) or []
    malicious_unlock = bool(scoring.get("malicious_unlock", False))
    benign_cap_applied = bool(scoring.get("benign_cap_applied", False))
    return score, sev, [str(x) for x in reasons], malicious_unlock, benign_cap_applied


def _normalize_apk_dynamic(dyn_list: list[dict]) -> list[dict]:
    """
    DYNAMIC:
    - Trust the dynamic artifact scoring (already benign-aware in apk_dynamic.py)
    - Keep engine fields (if present) as reference only
    - Preserve iocs / iocs_split / iocs_scoring for UI transparency
    """
    out = []
    for d in dyn_list or []:
        score, sev, reasons, malicious_unlock, benign_cap_applied = _extract_dyn_fields(d)
        reasons_sorted = _sort_reasons(reasons)

        pkg = (d.get("package") or "")
        app_name = (d.get("app_name") or "")
        device = d.get("device", {}) or {}
        device_serial = ""
        if isinstance(device, dict):
            device_serial = str(device.get("serial", "") or "")
        elif isinstance(device, str):
            device_serial = device

        # engine reference (optional)
        engine_score = None
        engine_sev = None
        if "engine_score" in d:
            engine_score = _safe_int(d.get("engine_score", 0), 0)
        if "engine_severity" in d:
            engine_sev = (d.get("engine_severity") or "").upper().strip() or None

        iocs = d.get("iocs", {}) or {}
        iocs_split = d.get("iocs_split", {}) or {}
        iocs_scoring = d.get("iocs_scoring", {}) or {}

        # tag best-effort: from artifact name pattern
        tag = ""
        an = str(d.get("_artifact_name", "") or "")
        m = re.match(r"apk_dynamic__([^_]+)__", an)
        if m:
            tag = m.group(1)

        out.append(
            {
                "kind": "apk_dynamic",
                "artifact_name": d.get("_artifact_name", ""),
                "artifact_mtime_utc": d.get("_artifact_mtime_utc", "unknown"),
                "artifact_mtime_ts": float(d.get("_artifact_mtime_ts", 0) or 0),
                "app_name": app_name,
                "package": pkg,
                "tag": tag,
                "device_serial": device_serial,
                "score": score,
                "severity": sev,
                "reasons": [r for r, _w in reasons_sorted] if reasons_sorted else (reasons or ["No runtime indicators recorded."]),
                "reasons_weighted": reasons_sorted,
                "engine_score": engine_score,
                "engine_severity": engine_sev,
                "malicious_unlock": bool(malicious_unlock),
                "benign_cap_applied": bool(benign_cap_applied),
                "iocs": iocs,
                "iocs_split": iocs_split,
                "iocs_scoring": iocs_scoring,
            }
        )

    out.sort(key=lambda m: m.get("artifact_mtime_ts", 0), reverse=True)
    return out


def _case_malicious_unlock(apk_static: list[dict], apk_dynamic: list[dict]) -> bool:
    """
    Unlock rules:
      - any dynamic artifact says malicious_unlock
      - OR static score >= 35 (MEDIUM+) as fallback (static found serious indicators)
    """
    for d in apk_dynamic or []:
        if bool(d.get("malicious_unlock", False)):
            return True

    for s in apk_static or []:
        sc = _safe_int(s.get("score", 0), 0)
        if sc >= 35:
            return True

    return False


# --------------------------- Case summary ---------------------------

def build_case_summary(case_dir: str, risk_mode: RiskMode = "latest") -> dict:
    case_path = Path(case_dir)
    case = _load_json(case_path / "case.json")

    static_list = _load_artifacts(case_path, "apk_static__*.json")
    dyn_list = _load_artifacts(case_path, "apk_dynamic__*.json")

    apk_static = _normalize_apk_static(static_list)
    apk_dynamic = _normalize_apk_dynamic(dyn_list)

    # Aggregate IOCs across both (raw union)
    iocs = {"urls": set(), "domains": set(), "ips": set(), "emails": set()}

    def _merge_iocs(obj_iocs: dict):
        if not isinstance(obj_iocs, dict):
            return
        for k in list(iocs.keys()):
            for v in (obj_iocs.get(k, []) or []):
                if v:
                    iocs[k].add(str(v))

    # static artifacts: use their iocs dict
    for a in static_list or []:
        _merge_iocs(a.get("iocs", {}) or {})

    # dynamic artifacts: use full iocs dict (not scoring-only)
    for d in apk_dynamic or []:
        _merge_iocs(d.get("iocs", {}) or {})

    # scored items across both
    scored_items: list[tuple[float, int, str, str]] = []  # (mtime_ts, score, artifact_name, kind)
    scores: list[int] = []

    for m in apk_static:
        sc = _clamp(_safe_int(m.get("score", 0), 0), 0, 100)
        scores.append(sc)
        scored_items.append((float(m.get("artifact_mtime_ts", 0) or 0), sc, m.get("artifact_name", ""), "apk_static"))

    for d in apk_dynamic:
        sc = _clamp(_safe_int(d.get("score", 0), 0), 0, 100)
        scores.append(sc)
        scored_items.append((float(d.get("artifact_mtime_ts", 0) or 0), sc, d.get("artifact_name", ""), "apk_dynamic"))

    rm = (risk_mode or "latest").lower().strip()
    if rm not in ("latest", "max"):
        rm = "latest"

    latest_artifact = ""
    latest_kind = ""
    latest_score = 0

    if scored_items:
        scored_items.sort(key=lambda t: t[0], reverse=True)
        _mt, latest_score, latest_artifact, latest_kind = scored_items[0]

    if rm == "max":
        final_score = max(scores) if scores else 0
    else:
        final_score = latest_score if scores else 0

    final_score = _clamp(final_score, 0, 100)

    # benign-aware cap
    malicious_unlock = _case_malicious_unlock(apk_static, apk_dynamic)
    benign_cap_applied = False
    if not malicious_unlock and final_score > 20:
        final_score = 20
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
        "aggregate_iocs": {k: sorted(list(v)) for k, v in iocs.items()},
        "risk": {
            "risk_mode": rm,
            "final_score": final_score,
            "final_severity": final_sev,
            "latest_artifact": latest_artifact or "",
            "latest_kind": latest_kind or "",
            "latest_score": _clamp(latest_score, 0, 100),
            "malicious_unlock": bool(malicious_unlock),
            "benign_cap_applied": bool(benign_cap_applied),
        },
    }


# --------------------------- HTML writer ---------------------------

def write_case_html(case_dir: str, risk_mode: RiskMode = "latest") -> str:
    case_path = Path(case_dir)
    summary = build_case_summary(case_dir, risk_mode=risk_mode)

    sev = summary["risk"]["final_severity"]
    score = _safe_int(summary["risk"]["final_score"], 0)
    rm = summary["risk"].get("risk_mode", "latest")
    latest_art = summary["risk"].get("latest_artifact", "") or ""
    latest_kind = summary["risk"].get("latest_kind", "") or ""
    benign_cap = bool(summary["risk"].get("benign_cap_applied", False))
    unlock = bool(summary["risk"].get("malicious_unlock", False))

    def sev_badge_class(s: str) -> str:
        s = (s or "UNKNOWN").upper()
        return s if s in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "UNKNOWN"

    score_band = _score_band(score)

    # Evidence table rows
    evidence_rows = ""
    for e in summary["evidence"]:
        evidence_rows += (
            "<tr>"
            f"<td>{e.get('name','')}</td>"
            f"<td>{e.get('type','')}</td>"
            f"<td><code>{e.get('sha256','')}</code></td>"
            "</tr>"
        )
    if not evidence_rows:
        evidence_rows = "<tr><td colspan='3'><i>No evidence registered.</i></td></tr>"

    # APK STATIC rows + why
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
            ref_note = f"<div class='small muted'>Engine severity (ref): <b>{engine_sev}</b> • Derived severity (used): <b>{sev_m}</b></div>"

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

    # APK DYNAMIC rows + why
    dyn_rows = ""
    dyn_why = ""
    for d in summary.get("apk_dynamic", []) or []:
        sev_d = d.get("severity", "UNKNOWN")
        score_d = _safe_int(d.get("score", 0), 0)
        band_d = _score_band(score_d)

        engine_score = d.get("engine_score", None)
        engine_sev = d.get("engine_severity", None)

        reasons = (d.get("reasons", []) or [])
        reasons_html = "<ul class='compact'>" + "".join(f"<li>{r}</li>" for r in reasons) + "</ul>"

        # IOC split (if present)
        split = d.get("iocs_split", {}) or {}
        b = (split.get("benign") or {}) if isinstance(split, dict) else {}
        s = (split.get("suspicious") or {}) if isinstance(split, dict) else {}

        benign_domains = (b.get("domains") or []) if isinstance(b, dict) else []
        benign_emails = (b.get("emails") or []) if isinstance(b, dict) else []
        susp_domains = (s.get("domains") or []) if isinstance(s, dict) else []
        susp_emails = (s.get("emails") or []) if isinstance(s, dict) else []

        split_note = ""
        if benign_domains or benign_emails or susp_domains or susp_emails:
            def _fmt_list(items: list[str]) -> str:
                if not items:
                    return "<i>None</i>"
                return "<br>".join(items[:25]) + ("<br><span class='muted'>…</span>" if len(items) > 25 else "")

            split_note = (
                "<div class='small muted' style='margin-top:8px;'>"
                "<b>IOC split:</b> suspicious vs benign (noise-filtered)"
                "</div>"
                "<table style='margin-top:8px;'>"
                "<tr><th>Suspicious domains</th><td class='small'>" + _fmt_list([str(x) for x in susp_domains]) + "</td></tr>"
                "<tr><th>Suspicious emails</th><td class='small'>" + _fmt_list([str(x) for x in susp_emails]) + "</td></tr>"
                "<tr><th>Benign domains</th><td class='small'>" + _fmt_list([str(x) for x in benign_domains]) + "</td></tr>"
                "<tr><th>Benign emails</th><td class='small'>" + _fmt_list([str(x) for x in benign_emails]) + "</td></tr>"
                "</table>"
            )

        unlock_flag = bool(d.get("malicious_unlock", False))
        cap_flag = bool(d.get("benign_cap_applied", False))

        ref_note = "<div class='small muted'>"
        parts = []
        if engine_score is not None:
            parts.append(f"Engine score (ref): <b>{int(engine_score)}</b>/100")
        if engine_sev:
            parts.append(f"Engine severity (ref): <b>{engine_sev}</b>")
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
            f"{split_note}"
            "</div>"
        )

    if not dyn_rows:
        dyn_rows = "<tr><td colspan='6'><i>No APK dynamic artifacts found.</i></td></tr>"
    if not dyn_why:
        dyn_why = "<i>No dynamic scoring reasons available.</i>"

    # Aggregate IOCs (union)
    agg = summary["aggregate_iocs"]
    urls = agg.get("urls", []) or []
    domains = agg.get("domains", []) or []
    ips = agg.get("ips", []) or []
    emails = agg.get("emails", []) or []

    def _join_or_none(items: list[str]) -> str:
        return "<br>".join(items) if items else "<i>None</i>"

    cap_note = ""
    if benign_cap and not unlock:
        cap_note = "<div class='small muted' style='margin-top:8px;'><b>Benign-aware cap:</b> no high-confidence malware indicators detected → score capped at <b>20/100</b>.</div>"
    if unlock:
        cap_note = "<div class='small muted' style='margin-top:8px;'><b>Malicious unlock:</b> strong indicators detected → score may exceed 20/100.</div>"

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
  box-shadow: 0 0 16px rgba(0,255,170,0.14);
}}
.MEDIUM {{
  background: rgba(255,190,0,0.12);
  color: rgba(255,210,110,0.95);
  box-shadow: 0 0 16px rgba(255,190,0,0.12);
}}
.HIGH {{
  background: rgba(255,80,80,0.12);
  color: rgba(255,170,170,0.95);
  box-shadow: 0 0 16px rgba(255,80,80,0.12);
}}
.CRITICAL {{
  background: rgba(255,40,120,0.14);
  color: rgba(255,170,210,0.95);
  box-shadow: 0 0 16px rgba(255,40,120,0.14);
}}
.UNKNOWN {{
  background: rgba(255,255,255,0.06);
  color: rgba(255,255,255,0.82);
}}

.SCORE_GREEN {{
  background: rgba(0,255,170,0.10);
  color: rgba(140,255,210,0.95);
  box-shadow: 0 0 18px rgba(0,255,170,0.16);
  border-color: rgba(0,255,170,0.22);
}}
.SCORE_YELLOW {{
  background: rgba(255,205,0,0.12);
  color: rgba(255,220,130,0.95);
  box-shadow: 0 0 18px rgba(255,205,0,0.14);
  border-color: rgba(255,205,0,0.22);
}}
.SCORE_ORANGE {{
  background: rgba(255,130,0,0.12);
  color: rgba(255,190,140,0.95);
  box-shadow: 0 0 18px rgba(255,130,0,0.14);
  border-color: rgba(255,130,0,0.22);
}}
.SCORE_RED {{
  background: rgba(255,60,60,0.12);
  color: rgba(255,175,175,0.95);
  box-shadow: 0 0 18px rgba(255,60,60,0.14);
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
      Latest = verdict from most recent artifact • Max = worst-case across artifacts
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
      <span class="muted">(artifact scoring is benign-aware; engine fields shown only if present)</span>
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
      <span class="muted">runtime indicators + IOC split (noise-filtered)</span>
    </div>
    {dyn_why}
  </div>

  <div class="card">
    <div class="row">
      <h2 style="margin:0;">Aggregate IOCs</h2>
      <span class="muted">(raw union across APK artifacts)</span>
    </div>
    <table>
      <tr><th>URLs</th><td class="small">{_join_or_none(urls)}</td></tr>
      <tr><th>Domains</th><td class="small">{_join_or_none(domains)}</td></tr>
      <tr><th>IPs</th><td class="small">{_join_or_none(ips)}</td></tr>
      <tr><th>Emails</th><td class="small">{_join_or_none(emails)}</td></tr>
    </table>
  </div>

  <div class="card">
    <div class="row">
      <h2 style="margin:0;">Reproducibility (Environment)</h2>
      <span class="muted">snapshot used to reproduce the run</span>
    </div>
    <pre>{json.dumps(summary.get("env",{}), indent=2)}</pre>
  </div>

</div>
</body>
</html>
"""
    out = case_path / "reports" / "case_report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return str(out)
