# src/report_html.py
from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime
from typing import Any, Optional


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


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


def _html_escape(s: Any) -> str:
    try:
        s = "" if s is None else str(s)
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
    except Exception:
        return ""


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


def _detect_kind_from_filename(name: str) -> str:
    n = (name or "").lower()
    if n.startswith("apk_dynamic__") or "apk_dynamic" in n:
        return "apk_dynamic"
    if n.startswith("apk_static__") or "apk_static" in n:
        return "apk_static"
    return "apk_unknown"


def _pick_latest_any_apk_artifact(artifacts_dir: Path) -> Optional[Path]:
    patterns = ["apk_dynamic__*.json", "apk_static__*.json"]
    files: list[Path] = []
    for pat in patterns:
        files.extend(list(artifacts_dir.glob(pat)))
    files = sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def _as_dict(x: Any) -> dict:
    return x if isinstance(x, dict) else {}


def _as_list(x: Any) -> list:
    return x if isinstance(x, list) else []


def _details_block(title: str, lines: list[str], limit: int = 250) -> str:
    lines = [str(ln) for ln in (lines or []) if ln is not None]
    if not lines:
        return "<div class='small muted'><i>None</i></div>"

    view = lines[-limit:]
    body = "\n".join(_html_escape(ln) for ln in view)
    extra = ""
    if len(lines) > limit:
        extra = f"\n... (showing last {limit} of {len(lines)} lines)"
    return (
        "<details class='details'>"
        f"<summary>{_html_escape(title)}</summary>"
        f"<pre class='log'>{body}{_html_escape(extra)}</pre>"
        "</details>"
    )


def generate_apk_html_report(case_dir: str, apk_artifact: str | None = None) -> str:
    case_path = Path(case_dir)
    case = _load_json(case_path / "case.json")
    artifacts_dir = case_path / "artifacts"

    if apk_artifact:
        apk_path = artifacts_dir / apk_artifact
    else:
        latest = _pick_latest_any_apk_artifact(artifacts_dir)
        apk_path = latest if latest else (artifacts_dir / "apk_static.json")

    apk = _load_json(apk_path)

    case_id = case.get("case_id", "UNKNOWN")
    created_at = _fmt_ts(case.get("created_at", 0))
    env = case.get("env", {}) or {}

    kind = _detect_kind_from_filename(apk_path.name)
    artifact_mtime = _fmt_fs_ts_mtime(apk_path)

    scoring = _as_dict(apk.get("scoring"))
    score = _clamp(_safe_int(scoring.get("score", 0), 0), 0, 100)
    severity = _final_severity_from_score(score)
    score_band = _score_band(score)

    reasons = [str(x) for x in _as_list(scoring.get("reasons"))][:40]
    reasons_html = "".join(f"<li>{_html_escape(r)}</li>" for r in reasons) or "<li><i>None</i></li>"

    package = str(apk.get("package") or "")
    app_name = str(apk.get("app_name") or apk.get("app") or "")

    runtime = _as_dict(apk.get("runtime"))
    event_counts = _as_dict(runtime.get("event_counts")) or _as_dict(apk.get("event_counts"))
    key_counts = _as_dict(runtime.get("key_counts")) or _as_dict(apk.get("key_counts"))
    unlock_triggers = _as_list(runtime.get("unlock_triggers")) or _as_list(apk.get("unlock_triggers"))

    frida_tail = _as_list(runtime.get("frida_output_tail"))
    logcat_tail = _as_list(runtime.get("logcat_tail"))
    frida_err = str(runtime.get("frida_attach_error") or "")
    gadget_ready = bool(runtime.get("gadget_ready", False))
    endpoint = str(runtime.get("endpoint") or "")
    transport = str(runtime.get("transport") or apk.get("transport") or "")
    device = str(apk.get("device") or "")

    sensitive_permissions = _as_list(scoring.get("sensitive_permissions"))
    iocs = _as_dict(apk.get("iocs"))

    def _fmt_code_list(items: list[str]) -> str:
        if not items:
            return "<i>None</i>"
        return " ".join(f"<code>{_html_escape(x)}</code>" for x in items)

    def _kv(k: str, v: Any) -> str:
        return f"<tr><th>{_html_escape(k)}</th><td>{v}</td></tr>"

    urls = [str(x) for x in _as_list(iocs.get("urls"))][:100]
    domains = [str(x) for x in _as_list(iocs.get("domains"))][:150]
    ips = [str(x) for x in _as_list(iocs.get("ips"))][:150]
    emails = [str(x) for x in _as_list(iocs.get("emails"))][:150]

    def _join(items: list[str]) -> str:
        return "<br>".join(_html_escape(x) for x in items) if items else "<i>None</i>"

    dyn_counts_table = ""
    if kind == "apk_dynamic":
        merged_counts: dict[str, int] = {}
        for src in (event_counts, key_counts):
            for k, v in (src or {}).items():
                try:
                    merged_counts[str(k)] = merged_counts.get(str(k), 0) + int(v)
                except Exception:
                    pass
        if merged_counts:
            rows = "".join(
                f"<tr><td><code>{_html_escape(k)}</code></td><td class='mono'>{int(v)}</td></tr>"
                for k, v in sorted(merged_counts.items(), key=lambda t: (-t[1], t[0]))
            )
            dyn_counts_table = (
                "<h3 style='margin:14px 0 10px 0;'>Runtime counts</h3>"
                "<table><tr><th>Key</th><th>Count</th></tr>" + rows + "</table>"
            )

    unlock_html = ""
    if kind == "apk_dynamic" and unlock_triggers:
        unlock_html = (
            "<h3 style='margin:14px 0 10px 0;'>Unlock triggers</h3>"
            + "<ul class='compact'>"
            + "".join(f"<li>{_html_escape(x)}</li>" for x in unlock_triggers[:50])
            + "</ul>"
        )

    frida_status = "OK" if (kind == "apk_dynamic" and gadget_ready and not frida_err) else "WARN"
    if kind != "apk_dynamic":
        frida_status = "N/A"

    html = f"""<!doctype html>
<html>
<head>
<meta charset='utf-8'/>
<title>APK Report - {_html_escape(case_id)}</title>
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
.container {{ max-width: 1100px; margin: 28px auto; padding: 0 18px 40px 18px; }}
h1 {{ margin: 0 0 8px 0; letter-spacing: 0.6px; }}
.sub {{ color: var(--muted); margin-bottom: 18px; }}
.card {{
  background: linear-gradient(180deg, rgba(18,24,40,0.86), rgba(12,16,28,0.82));
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 14px 16px;
  margin: 14px 0;
  box-shadow: 0 12px 40px rgba(0,0,0,0.22);
}}
.row {{ display:flex; flex-wrap:wrap; gap:10px; align-items:center; }}
.badge {{
  display:inline-flex; align-items:center; gap:8px;
  padding:7px 12px; border-radius:999px;
  font-weight:900; border:1px solid rgba(255,255,255,0.14);
}}
.pill {{
  display:inline-flex; align-items:center; gap:8px;
  padding:7px 12px; border-radius:999px;
  border:1px solid rgba(255,255,255,0.10);
  color: var(--muted); background: rgba(255,255,255,0.04);
}}
.small {{ font-size:0.92em; color: rgba(255,255,255,0.72); }}
.muted {{ color: var(--muted); }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }}
code {{ background: rgba(255,255,255,0.06); padding:2px 7px; border-radius:8px; border:1px solid rgba(255,255,255,0.08); }}
table {{ width:100%; border-collapse:collapse; border-radius:14px; overflow:hidden; }}
th,td {{ text-align:left; padding:10px; border-bottom:1px solid rgba(255,255,255,0.08); vertical-align:top; }}
th {{ color: rgba(255,255,255,0.78); font-weight:900; background: rgba(255,255,255,0.03); }}
.compact {{ margin:8px 0 0 18px; padding:0; }}
.details summary {{ cursor:pointer; color: rgba(255,255,255,0.86); padding:8px 0; }}
pre.log {{
  background: rgba(255,255,255,0.05);
  border: 1px solid rgba(255,255,255,0.08);
  padding: 12px; border-radius: 14px; overflow:auto;
}}
.SCORE_GREEN {{ background: rgba(0,255,170,0.10); border-color: rgba(0,255,170,0.22); }}
.SCORE_YELLOW {{ background: rgba(255,205,0,0.12); border-color: rgba(255,205,0,0.22); }}
.SCORE_ORANGE {{ background: rgba(255,130,0,0.12); border-color: rgba(255,130,0,0.22); }}
.SCORE_RED {{ background: rgba(255,60,60,0.12); border-color: rgba(255,60,60,0.22); }}
</style>
</head>
<body>
<div class='container'>
  <h1>APK Report</h1>
  <div class='sub'>Case <b>{_html_escape(case_id)}</b> • artifact <code>{_html_escape(apk_path.name)}</code></div>

  <div class='card'>
    <div class='row'>
      <span class='pill'><b>Created:</b> {_html_escape(created_at)}</span>
      <span class='pill'><b>Artifact mtime:</b> {_html_escape(artifact_mtime)}</span>
      <span class='pill'><b>Kind:</b> <span class='mono'>{_html_escape(kind)}</span></span>
      <span class='pill'><b>Package:</b> <code>{_html_escape(package)}</code></span>
      <span class='pill'><b>App:</b> {_html_escape(app_name)}</span>
      <span class='pill'><b>Device:</b> {_html_escape(device)}</span>
    </div>
    <div class='row' style='margin-top:10px;'>
      <span class='badge {_html_escape(score_band)}'>Score: <b>{int(score)}</b>/100</span>
      <span class='pill'><b>Severity:</b> {_html_escape(severity)}</span>
    </div>
  </div>

  <div class='card'>
    <div class='row'>
      <h2 style='margin:0;'>Why this score</h2>
      <span class='muted'>top reasons (if present)</span>
    </div>
    <ul class='compact'>{reasons_html}</ul>
  </div>

  <div class='card'>
    <div class='row'>
      <h2 style='margin:0;'>Static indicators</h2>
      <span class='muted'>permissions + extracted IOCs</span>
    </div>
    <table>
      {_kv('Sensitive permissions', _fmt_code_list([str(x) for x in sensitive_permissions]))}
      {_kv('URLs', f"<div class='small'>{_join(urls)}</div>")}
      {_kv('Domains', f"<div class='small'>{_join(domains)}</div>")}
      {_kv('IPs', f"<div class='small'>{_join(ips)}</div>")}
      {_kv('Emails', f"<div class='small'>{_join(emails)}</div>")}
    </table>
  </div>

  <div class='card'>
    <div class='row'>
      <h2 style='margin:0;'>Dynamic runtime</h2>
      <span class='muted'>counts / triggers / tails (if dynamic artifact)</span>
    </div>
    <div class='small muted'>Transport={_html_escape(transport)} • Endpoint={_html_escape(endpoint)} • GadgetReady={str(gadget_ready)} • FridaStatus={_html_escape(frida_status)} • Error={_html_escape(frida_err)}</div>
    {dyn_counts_table}
    {unlock_html}
    {_details_block('Frida output tail', frida_tail, limit=180)}
    {_details_block('Logcat tail', logcat_tail, limit=180)}
  </div>

  <div class='card'>
    <div class='row'>
      <h2 style='margin:0;'>Environment snapshot</h2>
      <span class='muted'>used for reproducibility</span>
    </div>
    <pre class='log'>{_html_escape(json.dumps(env, indent=2, ensure_ascii=False))}</pre>
  </div>

</div>
</body>
</html>
"""
    out = case_path / "reports" / f"apk_report__{apk_path.stem}.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return str(out)
