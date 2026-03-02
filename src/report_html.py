# src/report_html.py
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


__all__ = [
    "generate_apk_html_report",
    "write_apk_html_report",
    "write_apk_html",
]


def _load_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


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


def _clamp(x: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(x)))


def _fmt_mtime_utc(p: Path) -> str:
    try:
        return datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "unknown"


def _html_escape(s: Any) -> str:
    if s is None:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _score_band(score: int) -> str:
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


def _artifact_stem(name: str) -> str:
    try:
        return Path(name).stem
    except Exception:
        return name


def _report_name_for_artifact(artifact_name: str) -> str:
    return f"apk_report__{_artifact_stem(artifact_name)}.html"


def _artifact_json_href(artifact_name: str) -> str:
    return f"../artifacts/{artifact_name}"


def _uniq(items: Any) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    if not isinstance(items, list):
        return out
    for x in items:
        if x is None:
            continue
        s = str(x).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


@dataclass
class ApkArtifactView:
    artifact_name: str
    artifact_mtime_utc: str
    kind: str
    app_name: str
    package: str
    version_name: str
    version_code: str
    tag: str
    device: str

    score_raw: int
    score_max: int
    score_normalized: int
    risk_scale: str
    severity_used: str
    engine_severity: str
    reasons: list[str]

    iocs_urls: list[str]
    iocs_domains: list[str]
    iocs_ips: list[str]
    iocs_emails: list[str]


def _detect_kind(artifact_name: str) -> str:
    n = (artifact_name or "").lower()
    if n.startswith("apk_static__"):
        return "STATIC"
    if n.startswith("apk_dynamic__"):
        return "DYNAMIC"
    return "UNKNOWN"


def _extract_scoring(obj: dict) -> tuple[int, int, int, str, list[str], str, str]:
    scoring = obj.get("scoring", {}) or {}
    score = _safe_int(scoring.get("score", scoring.get("final_score", 0)), 0)
    score_max = _safe_int(scoring.get("score_max", 100), 100)
    if score_max <= 0:
        score_max = 100
    score = max(0, min(score_max, score))

    score_norm = _clamp(int(round((float(score) / float(score_max)) * 100.0)), 0, 100)
    engine_sev = str(scoring.get("severity", "") or "").upper().strip()
    risk_scale = str(scoring.get("risk_scale", "") or "").strip()
    reasons = scoring.get("reasons", []) or []
    reasons = [str(x) for x in reasons if x is not None]
    sev_used = _final_severity_from_score(score_norm)
    return score, score_max, score_norm, sev_used, reasons, engine_sev, risk_scale


def _extract_iocs(obj: dict) -> dict:
    iocs = obj.get("iocs_scoring")
    if isinstance(iocs, dict):
        return {
            "urls": _uniq(iocs.get("urls", []) or []),
            "domains": _uniq(iocs.get("domains", []) or []),
            "ips": _uniq(iocs.get("ips", []) or []),
            "emails": _uniq(iocs.get("emails", []) or []),
        }

    scoring = obj.get("scoring", {}) or {}
    iocs_filtered = scoring.get("iocs_filtered")
    if isinstance(iocs_filtered, dict):
        raw_iocs = obj.get("iocs", {}) or {}
        return {
            "urls": _uniq(iocs_filtered.get("nonwhite_urls", []) or []),
            "domains": _uniq(iocs_filtered.get("nonwhite_domains", []) or []),
            "ips": _uniq(raw_iocs.get("ips", []) or []),
            "emails": _uniq(iocs_filtered.get("nonwhite_emails", []) or []),
        }

    iocs = obj.get("iocs")
    if isinstance(iocs, dict):
        return {
            "urls": _uniq(iocs.get("urls", []) or []),
            "domains": _uniq(iocs.get("domains", []) or []),
            "ips": _uniq(iocs.get("ips", []) or []),
            "emails": _uniq(iocs.get("emails", []) or []),
        }

    iocs = obj.get("iocs_split")
    if isinstance(iocs, dict):
        suspicious = iocs.get("suspicious")
        if isinstance(suspicious, dict):
            return {
                "urls": _uniq(suspicious.get("urls", []) or []),
                "domains": _uniq(suspicious.get("domains", []) or []),
                "ips": _uniq(suspicious.get("ips", []) or []),
                "emails": _uniq(suspicious.get("emails", []) or []),
            }
        return {
            "urls": _uniq(iocs.get("urls", []) or []),
            "domains": _uniq(iocs.get("domains", []) or []),
            "ips": _uniq(iocs.get("ips", []) or []),
            "emails": _uniq(iocs.get("emails", []) or []),
        }

    runtime = obj.get("runtime", {}) or {}
    iocs = runtime.get("iocs")
    if isinstance(iocs, dict):
        return {
            "urls": _uniq(iocs.get("urls", []) or []),
            "domains": _uniq(iocs.get("domains", []) or []),
            "ips": _uniq(iocs.get("ips", []) or []),
            "emails": _uniq(iocs.get("emails", []) or []),
        }
    return {}


def _normalize_artifact(artifact_path: Path) -> ApkArtifactView:
    obj = _load_json(artifact_path)
    score_raw, score_max, score_norm, sev_used, reasons, engine_sev, risk_scale = _extract_scoring(obj)
    kind = _detect_kind(artifact_path.name)

    iocs = _extract_iocs(obj)
    urls = _uniq(iocs.get("urls", []) or [])
    domains = _uniq(iocs.get("domains", []) or [])
    ips = _uniq(iocs.get("ips", []) or [])
    emails = _uniq(iocs.get("emails", []) or [])

    return ApkArtifactView(
        artifact_name=artifact_path.name,
        artifact_mtime_utc=_fmt_mtime_utc(artifact_path),
        kind=kind,
        app_name=str(obj.get("app_name", "") or obj.get("app", "") or ""),
        package=str(obj.get("package", "") or ""),
        version_name=str(obj.get("version_name", "") or ""),
        version_code=str(obj.get("version_code", "") or ""),
        tag=str(obj.get("tag", "") or (obj.get("meta", {}) or {}).get("tag", "") or ""),
        device=str(obj.get("device", "") or (obj.get("runtime", {}) or {}).get("device", "") or ""),
        score_raw=score_raw,
        score_max=score_max,
        score_normalized=score_norm,
        risk_scale=risk_scale,
        severity_used=sev_used,
        engine_severity=engine_sev,
        reasons=reasons[:120],
        iocs_urls=urls,
        iocs_domains=domains,
        iocs_ips=ips,
        iocs_emails=emails,
    )


# ---------------- VirusTotal: pick latest vt__*.json in same case ----------------

def _pick_latest_vt(artifacts_dir: Path) -> Optional[Path]:
    try:
        files = sorted(list(artifacts_dir.glob("vt__*.json")), key=lambda p: p.stat().st_mtime, reverse=True)
        return files[0] if files else None
    except Exception:
        return None


def _vt_card_html(vt_path: Optional[Path]) -> str:
    if not vt_path or not vt_path.exists():
        return (
            "<div class='card'>"
            "<h2 style='margin:0 0 8px 0;'>VirusTotal</h2>"
            "<div class='small muted'>(no VT artifact found)</div>"
            "</div>"
        )

    obj = _load_json(vt_path)
    stats = obj.get("stats") if isinstance(obj.get("stats"), dict) else {}
    mal = _safe_int(stats.get("malicious"), 0)
    sus = _safe_int(stats.get("suspicious"), 0)
    pos = _safe_int(stats.get("positives"), mal + sus)
    tot = _safe_int(stats.get("total"), 0)
    vt_score = _safe_int(obj.get("vt_score"), 0)
    conf = _safe_float(obj.get("confidence"), 0.0)
    if conf < 0:
        conf = 0.0
    if conf > 1:
        conf = 1.0

    verdict = "DETECTED" if pos > 0 else "CLEAN"
    gui_url = str(obj.get("gui_url", "") or "")
    sha = str(obj.get("sha256", "") or "")
    json_href = f"../artifacts/{vt_path.name}"

    note = (
        "Policy: VT is secondary. If clean (0 positives), its influence is capped (≤20). "
        "If detected, contribution scales with findings."
    )

    link_html = f"<a class='btn ghost' href='{_html_escape(gui_url)}' target='_blank'>Open VT GUI</a>" if gui_url else ""
    return f"""
<div class="card">
  <h2 style="margin:0 0 8px 0;">VirusTotal</h2>
  <div class="row">
    <span class="pill"><b>Verdict:</b> <span class="mono">{_html_escape(verdict)}</span></span>
    <span class="pill"><b>Positives:</b> <span class="mono">{pos}/{tot if tot else "?"}</span></span>
    <span class="pill"><b>vt_score:</b> <span class="mono">{vt_score}</span></span>
    <span class="pill"><b>confidence:</b> <span class="mono">{conf:.2f}</span></span>
    {f"<span class='pill'><b>sha256:</b> <span class='mono'>{_html_escape(sha[:16] + '…')}</span></span>" if sha else ""}
  </div>
  <div class="small muted" style="margin-top:10px;">{_html_escape(note)}</div>
  <div class="row" style="margin-top:12px; gap:10px;">
    <a class="btn ghost" href="{_html_escape(json_href)}">Open VT artifact JSON</a>
    {link_html}
  </div>
</div>
"""


def generate_apk_html_report(case_dir: str, apk_artifact: Optional[str] = None) -> str:
    case_path = Path(case_dir)
    artifacts_dir = case_path / "artifacts"
    reports_dir = case_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    artifact_path: Optional[Path] = None

    if apk_artifact:
        cand = Path(apk_artifact)
        if cand.exists():
            artifact_path = cand
        else:
            cand2 = artifacts_dir / apk_artifact
            if cand2.exists():
                artifact_path = cand2

    if artifact_path is None:
        if artifacts_dir.is_dir():
            files = list(artifacts_dir.glob("apk_*__*.json"))
            files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            artifact_path = files[0] if files else None

    if artifact_path is None or not artifact_path.exists():
        out = reports_dir / "apk_report__missing.html"
        out.write_text(
            "<html><body style='font-family:Arial;background:#0b1020;color:#E5E7EB;padding:24px;'>"
            "<h2>APK Report</h2><p><b>Error:</b> No artifact provided or found.</p>"
            "</body></html>",
            encoding="utf-8",
        )
        return str(out)

    v = _normalize_artifact(artifact_path)
    score_band = _score_band(v.score_normalized)
    score_text = f"{v.score_raw}/{v.score_max}" if v.score_max != 100 else f"{v.score_raw}/100"

    report_name = _report_name_for_artifact(v.artifact_name)
    json_href = _artifact_json_href(v.artifact_name)

    if v.reasons:
        reasons_html = "<ul class='compact'>" + "".join(f"<li>{_html_escape(r)}</li>" for r in v.reasons) + "</ul>"
    else:
        reasons_html = "<i>No scoring reasons available.</i>"

    def _ioc_block(title: str, items: list[str]) -> str:
        if not items:
            return (
                f"<div class='ioc'><div class='ioc-title'>{_html_escape(title)}</div>"
                f"<div class='muted small'>(none)</div></div>"
            )
        lis = "".join(f"<li class='mono'>{_html_escape(x)}</li>" for x in items[:60])
        more = ""
        if len(items) > 60:
            more = f"<div class='muted small'>… plus {len(items) - 60} more</div>"
        return (
            f"<div class='ioc'>"
            f"<div class='ioc-title'>{_html_escape(title)} <span class='muted'>({len(items)})</span></div>"
            f"<ul class='ioc-list'>{lis}</ul>{more}"
            f"</div>"
        )

    vt_path = _pick_latest_vt(artifacts_dir)
    vt_card = _vt_card_html(vt_path)

    html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>CYBERSHADOW • APK Report</title>
<style>
:root {{
  --bg: #0b1020;
  --border: rgba(255,255,255,0.09);
  --text: rgba(255,255,255,0.92);
  --muted: rgba(255,255,255,0.66);
  --shadow: 0 12px 40px rgba(0,0,0,0.22);
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
  max-width: 1250px;
  margin: 28px auto;
  padding: 0 18px 40px 18px;
}}
h1 {{ margin: 0 0 10px 0; letter-spacing: 0.6px; }}
.sub {{ color: var(--muted); margin-bottom: 18px; }}
.card {{
  background: linear-gradient(180deg, rgba(18,24,40,0.86), rgba(12,16,28,0.82));
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 14px 16px;
  margin: 14px 0;
  box-shadow: var(--shadow);
}}
.row {{ display:flex; flex-wrap:wrap; gap:10px; align-items:center; }}
.badge {{
  display:inline-flex; align-items:center; gap:8px;
  padding: 7px 12px; border-radius: 999px; font-weight: 900;
  border: 1px solid rgba(255,255,255,0.14); line-height: 1.2;
}}
.badge.sev {{ text-transform: uppercase; }}
.pill {{
  display:inline-flex; align-items:center; gap: 8px;
  padding: 7px 12px; border-radius: 999px;
  border: 1px solid rgba(255,255,255,0.10);
  color: var(--muted); background: rgba(255,255,255,0.04);
  line-height: 1.2;
}}
.muted {{ color: var(--muted); }}
.small {{ font-size: 0.92em; color: rgba(255,255,255,0.72); }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }}
code {{
  background: rgba(255,255,255,0.06);
  padding: 2px 7px; border-radius: 8px;
  border: 1px solid rgba(255,255,255,0.08);
  color: rgba(255,255,255,0.92);
  display: inline-block;
}}
.btn {{
  display:inline-flex; align-items:center; gap: 8px;
  padding: 9px 12px; border-radius: 12px;
  border: 1px solid rgba(255,255,255,0.14);
  background: rgba(255,255,255,0.06);
  color: rgba(255,255,255,0.92);
  text-decoration: none;
  font-weight: 900;
}}
.btn:hover {{ background: rgba(255,255,255,0.08); border-color: rgba(255,255,255,0.22); }}
.btn.ghost {{
  background: rgba(255,255,255,0.03);
  border-color: rgba(255,255,255,0.10);
  color: rgba(255,255,255,0.85);
}}
.btn.ghost:hover {{ background: rgba(255,255,255,0.06); }}

.compact {{ margin: 8px 0 0 18px; padding: 0; }}
.compact li {{ margin: 6px 0; }}

.ioc-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 12px;
}}
.ioc {{
  background: rgba(255,255,255,0.04);
  border: 1px solid rgba(255,255,255,0.09);
  border-radius: 14px;
  padding: 12px 14px;
  min-width: 0;
}}
.ioc-title {{ font-weight: 950; letter-spacing: 0.2px; margin-bottom: 6px; }}
.ioc-list {{
  margin: 6px 0 0 18px;
  padding: 0 6px 0 0;
  max-height: 360px;
  overflow: auto;
}}
.ioc-list li {{
  margin: 6px 0;
  overflow-wrap: anywhere;
  word-break: break-word;
}}

.LOW {{ background: rgba(0,255,160,0.10); color: rgba(140,255,210,0.95); }}
.MEDIUM {{ background: rgba(255,190,0,0.12); color: rgba(255,210,110,0.95); }}
.HIGH {{ background: rgba(255,80,80,0.12); color: rgba(255,170,170,0.95); }}
.CRITICAL {{ background: rgba(255,40,120,0.14); color: rgba(255,170,210,0.95); }}
.UNKNOWN {{ background: rgba(255,255,255,0.06); color: rgba(255,255,255,0.82); }}

.SCORE_GREEN {{
  background: rgba(0,255,170,0.10); color: rgba(140,255,210,0.95);
  border-color: rgba(0,255,170,0.22);
}}
.SCORE_YELLOW {{
  background: rgba(255,205,0,0.12); color: rgba(255,220,130,0.95);
  border-color: rgba(255,205,0,0.22);
}}
.SCORE_ORANGE {{
  background: rgba(255,130,0,0.12); color: rgba(255,190,140,0.95);
  border-color: rgba(255,130,0,0.22);
}}
.SCORE_RED {{
  background: rgba(255,60,60,0.12); color: rgba(255,175,175,0.95);
  border-color: rgba(255,60,60,0.22);
}}
</style>
</head>
<body>
<div class="container">
  <h1>CYBERSHADOW • APK Report</h1>
  <div class="sub">Single-artifact report (static or dynamic) with traceable indicators</div>

  <div class="card">
    <div class="row">
      <span class="pill"><b>Kind:</b> {_html_escape(v.kind)}</span>
      <span class="pill"><b>Artifact:</b> <code>{_html_escape(v.artifact_name)}</code></span>
      <span class="pill"><b>Run:</b> <span class="mono">{_html_escape(v.artifact_mtime_utc)}</span></span>
      <span class="badge sev {v.severity_used}">{_html_escape(v.severity_used)}</span>
      <span class="badge {score_band}">Score: <b>{_html_escape(score_text)}</b></span>
      {f"<span class='pill'><b>Normalized:</b> <span class='mono'>{_html_escape(v.score_normalized)}/100</span></span>" if v.score_max != 100 else ""}
    </div>

    <div class="row" style="margin-top:10px;">
      <span class="pill"><b>App:</b> {_html_escape(v.app_name or "(unknown)")}</span>
      <span class="pill"><b>Package:</b> <code>{_html_escape(v.package or "")}</code></span>
      <span class="pill"><b>Version:</b> {_html_escape(v.version_name)} ({_html_escape(v.version_code)})</span>
      {f"<span class='pill'><b>Tag:</b> <code>{_html_escape(v.tag)}</code></span>" if v.tag else ""}
      {f"<span class='pill'><b>Device:</b> {_html_escape(v.device)}</span>" if v.device else ""}
    </div>

    <div class="row" style="margin-top:10px;">
      <span class="pill"><b>Display severity (normalized):</b> <span class="mono">{_html_escape(v.severity_used)}</span></span>
      <span class="pill"><b>Engine severity:</b> <span class="mono">{_html_escape(v.engine_severity or "UNKNOWN")}</span></span>
      {f"<span class='pill'><b>Risk scale:</b> <span class='mono'>{_html_escape(v.risk_scale)}</span></span>" if v.risk_scale else ""}
    </div>

    <div class="row" style="margin-top:12px; gap:10px;">
      <a class="btn" href="{_html_escape(report_name)}">Reload this report</a>
      <a class="btn ghost" href="{_html_escape(json_href)}">Open artifact JSON</a>
    </div>
  </div>

  <div class="card">
    <h2 style="margin:0 0 8px 0;">Why this score</h2>
    <div class="small muted">weighted indicators as emitted by the scoring engine</div>
    {reasons_html}
  </div>

  {vt_card}

  <div class="card">
    <h2 style="margin:0 0 8px 0;">IOCs</h2>
    <div class="small muted">extracted indicators of compromise (deduplicated)</div>
    <div class="ioc-grid" style="margin-top:10px;">
      {_ioc_block("URLs", v.iocs_urls)}
      {_ioc_block("Domains", v.iocs_domains)}
      {_ioc_block("IPs", v.iocs_ips)}
      {_ioc_block("Emails", v.iocs_emails)}
    </div>
  </div>

</div>
</body>
</html>
"""

    out = reports_dir / report_name
    out.write_text(html, encoding="utf-8")
    return str(out.resolve())


def write_apk_html_report(case_dir: str, apk_artifact: Optional[str] = None) -> str:
    return generate_apk_html_report(case_dir, apk_artifact)


def write_apk_html(case_dir: str, apk_artifact: Optional[str] = None) -> str:
    return generate_apk_html_report(case_dir, apk_artifact)
