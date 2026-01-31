# src/report_html.py
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Optional, Any, Tuple


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


def _safe_int(x, default=0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _clamp(x: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(x)))


def _pick_latest_any_apk_artifact(artifacts_dir: Path) -> Path | None:
    patterns = ["apk_dynamic__*.json", "apk_static__*.json"]
    files = []
    for pat in patterns:
        files.extend(list(artifacts_dir.glob(pat)))
    files = sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def _detect_kind_from_filename(name: str) -> str:
    n = (name or "").lower()
    if n.startswith("apk_dynamic__") or "apk_dynamic" in n:
        return "apk_dynamic"
    if n.startswith("apk_static__") or "apk_static" in n:
        return "apk_static"
    return "apk_unknown"


def _score_band(score: int) -> str:
    # requested thresholds:
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


def _parse_reason_weight(reason: str) -> int:
    if not isinstance(reason, str):
        return 0
    m = re.search(r"\(\s*\+\s*(\d+)\s*\)", reason)
    if m:
        return _safe_int(m.group(1), 0)
    m = re.search(r"\+\s*(\d+)\b", reason)
    if m:
        return _safe_int(m.group(1), 0)
    return 0


def _uniq(items):
    seen = set()
    out = []
    for x in items or []:
        if not x:
            continue
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


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


def _fmt_code_list(items: list[str]) -> str:
    if not items:
        return "<i>None</i>"
    return " ".join(f"<code>{_html_escape(x)}</code>" for x in items)


def _join_or_none(items: list[str]) -> str:
    if not items:
        return "<i>None</i>"
    return "<br>".join(_html_escape(x) for x in items)


def _kv_row(k: str, v: str) -> str:
    return f"<tr><th>{_html_escape(k)}</th><td>{v}</td></tr>"


def _ioc_table(title: str, rows: list[Tuple[str, str, str]]) -> str:
    """
    rows: [(category, value, note)]
    """
    if not rows:
        body = "<tr><td colspan='3'><i>None</i></td></tr>"
    else:
        body = ""
        for cat, val, note in rows:
            body += (
                "<tr>"
                f"<td><span class='pill {cat}'>{cat}</span></td>"
                f"<td class='mono'>{_html_escape(val)}</td>"
                f"<td class='small'>{_html_escape(note)}</td>"
                "</tr>"
            )

    return f"""
      <h3 style="margin: 14px 0 10px 0;">{_html_escape(title)}</h3>
      <table>
        <tr><th>Category</th><th>Value</th><th>Note</th></tr>
        {body}
      </table>
    """


def _rows_from_iocs_basic(iocs: dict) -> tuple[list, list, list, list]:
    urls = [str(x) for x in _uniq((iocs.get("urls", []) or []))]
    domains = [str(x) for x in _uniq((iocs.get("domains", []) or []))]
    ips = [str(x) for x in _uniq((iocs.get("ips", []) or []))]
    emails = [str(x) for x in _uniq((iocs.get("emails", []) or []))]

    # Minimal categorization (no heuristic guessing):
    # - URLs: CLEAR_HTTP if http:// else THIRD_PARTY
    url_rows = []
    for u in urls:
        if u.lower().startswith("http://"):
            url_rows.append(("CLEAR_HTTP", u, "Cleartext HTTP endpoint"))
        else:
            url_rows.append(("THIRD_PARTY", u, "Endpoint extracted"))
    url_rows.sort(key=lambda t: (t[0], t[1]))

    dom_rows = [("THIRD_PARTY", d, "Domain extracted") for d in domains]
    dom_rows.sort(key=lambda t: t[1])

    ip_rows = [("THIRD_PARTY", ip, "IP indicator extracted") for ip in ips]
    ip_rows.sort(key=lambda t: t[1])

    em_rows = [("THIRD_PARTY", em, "Email indicator extracted") for em in emails]
    em_rows.sort(key=lambda t: t[1])

    return url_rows, dom_rows, ip_rows, em_rows


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
    evidence = case.get("evidence", []) or []
    env = case.get("env", {}) or {}

    kind = _detect_kind_from_filename(apk_path.name)

    scoring = apk.get("scoring", {}) or {}
    score = _safe_int(scoring.get("score", 0), 0)

    # severity always derived from score
    derived_severity = _final_severity_from_score(score)
    engine_severity = (scoring.get("severity") or "").upper().strip()  # informational only
    severity = derived_severity

    reasons = scoring.get("reasons", []) or []
    reasons_sorted = sorted(
        [(str(r), _parse_reason_weight(str(r))) for r in reasons],
        key=lambda t: (-t[1], str(t[0])),
    )

    # ---- Static fields ----
    perms = apk.get("permissions", []) or []
    cert = apk.get("certificate", {}) or {}
    exp = apk.get("exported_components", {}) or {}

    exported_activities = exp.get("exported_activities", []) or []
    exported_services = exp.get("exported_services", []) or []
    exported_receivers = exp.get("exported_receivers", []) or []

    # ---- Dynamic fields (if present) ----
    features = apk.get("features", {}) or {}
    iocs = apk.get("iocs", {}) or {}

    # dynamic-specific splits (preferred if present)
    iocs_split = apk.get("iocs_split", {}) or {}
    iocs_scoring = apk.get("iocs_scoring", {}) or {}

    malicious_unlock = bool(scoring.get("malicious_unlock", False))
    benign_cap_applied = bool(scoring.get("benign_cap_applied", False))

    # Evidence rows
    evidence_rows = "".join(
        f"<tr><td>{_html_escape(e.get('name',''))}</td><td>{_html_escape(e.get('type',''))}</td><td><code>{_html_escape(e.get('sha256',''))}</code></td></tr>"
        for e in evidence
    ) or "<tr><td colspan='3'><i>No evidence registered.</i></td></tr>"

    # Why
    if reasons_sorted:
        why_html = "<ul class='compact'>" + "".join(
            (f"<li><b>+{w}</b> — {_html_escape(r)}</li>" if w > 0 else f"<li>{_html_escape(r)}</li>")
            for r, w in reasons_sorted
        ) + "</ul>"
    else:
        why_html = "<i>No reasons provided by scoring engine.</i>"

    score_band = _score_band(score)

    def sev_badge_class(s: str) -> str:
        s = (s or "UNKNOWN").upper()
        return s if s in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "UNKNOWN"

    # KPI counts
    perms_count = len(perms)
    exp_count = len(exported_activities) + len(exported_services) + len(exported_receivers)

    ioc_counts = {
        "urls": len(_uniq(iocs.get("urls", []) or [])),
        "domains": len(_uniq(iocs.get("domains", []) or [])),
        "ips": len(_uniq(iocs.get("ips", []) or [])),
        "emails": len(_uniq(iocs.get("emails", []) or [])),
    }

    # Exec notes
    exec_notes = []
    if kind == "apk_static":
        if exp_count > 0:
            exec_notes.append(f"Exported components detected: {exp_count} (potentially increases attack surface).")
        if ioc_counts["urls"] > 0 or ioc_counts["domains"] > 0 or ioc_counts["ips"] > 0:
            exec_notes.append("Network indicators were found in strings/resources (review IOC section below).")
        if any(str(u).lower().startswith("http://") for u in (iocs.get("urls", []) or [])):
            exec_notes.append("Cleartext HTTP endpoints were detected (consider network security configuration).")
        if engine_severity and engine_severity != derived_severity:
            exec_notes.append(f"Note: engine severity '{engine_severity}' differs from score-derived severity '{derived_severity}'.")
        if not exec_notes:
            exec_notes.append("No high-signal static indicators were extracted beyond baseline application metadata.")
    elif kind == "apk_dynamic":
        install_ok = bool(features.get("install_ok", False))
        launch_ok = bool(features.get("launch_ok", False))
        crashed = bool(features.get("crash_detected", False))
        if not install_ok:
            exec_notes.append("Install did not succeed (environment/device issue or APK incompatibility).")
        if not launch_ok:
            exec_notes.append("Launch/monkey did not succeed (no launcher activity or runtime restrictions).")
        if crashed:
            exec_notes.append("Crash detected during observation (low confidence by itself).")
        if malicious_unlock:
            exec_notes.append("Malicious unlock triggered by strong indicator combination (score not capped).")
        if benign_cap_applied and not malicious_unlock:
            exec_notes.append("Benign dampening/cap applied by dynamic engine (no strong malicious combo).")
        if ioc_counts["urls"] or ioc_counts["domains"] or ioc_counts["ips"] or ioc_counts["emails"]:
            exec_notes.append("IOCs extracted from APK strings and/or runtime logcat.")
        if not exec_notes:
            exec_notes.append("No high-signal runtime indicators recorded during this short observation window.")
    else:
        exec_notes.append("Unknown artifact schema; displaying best-effort fields.")

    # IOC tables:
    # For dynamic, prefer split/scoring sections if present.
    # Otherwise fallback to raw iocs.
    ioc_section_html = ""
    if kind == "apk_dynamic" and isinstance(iocs_split, dict) and (iocs_split.get("suspicious") or iocs_split.get("benign")):
        benign = iocs_split.get("benign", {}) or {}
        suspicious = iocs_split.get("suspicious", {}) or {}

        s_domains = [str(x) for x in _uniq((suspicious.get("domains", []) or []))]
        s_emails = [str(x) for x in _uniq((suspicious.get("emails", []) or []))]
        b_domains = [str(x) for x in _uniq((benign.get("domains", []) or []))]
        b_emails = [str(x) for x in _uniq((benign.get("emails", []) or []))]

        # scoring IOCs (what actually matters)
        sc_urls = [str(x) for x in _uniq((iocs_scoring.get("urls", []) or []))] if isinstance(iocs_scoring, dict) else []
        sc_domains = [str(x) for x in _uniq((iocs_scoring.get("domains", []) or []))] if isinstance(iocs_scoring, dict) else []
        sc_ips = [str(x) for x in _uniq((iocs_scoring.get("ips", []) or []))] if isinstance(iocs_scoring, dict) else []
        sc_emails = [str(x) for x in _uniq((iocs_scoring.get("emails", []) or []))] if isinstance(iocs_scoring, dict) else []

        def _rows(cat: str, items: list[str], note: str) -> list[Tuple[str, str, str]]:
            return [(cat, x, note) for x in items]

        ioc_section_html = f"""
          <div class="small muted" style="margin-bottom:10px;">
            Dynamic artifact includes noise-filtered IOC split (<b>suspicious</b> vs <b>benign</b>). Scoring uses only suspicious domains/emails.
          </div>

          {_ioc_table("IOCs used for scoring (dynamic)", _rows("SUSPICIOUS", sc_urls, "URL (scoring)") + _rows("SUSPICIOUS", sc_domains, "Domain (scoring)") + _rows("THIRD_PARTY", sc_ips, "IP (scoring)") + _rows("SUSPICIOUS", sc_emails, "Email (scoring)"))}

          {_ioc_table("Suspicious split (dynamic)", _rows("SUSPICIOUS", s_domains, "Suspicious domain") + _rows("SUSPICIOUS", s_emails, "Suspicious email"))}

          {_ioc_table("Benign split (dynamic)", _rows("BENIGN", b_domains, "Benign domain") + _rows("BENIGN", b_emails, "Benign email"))}
        """
    else:
        url_rows, dom_rows, ip_rows, em_rows = _rows_from_iocs_basic(iocs if isinstance(iocs, dict) else {})
        ioc_section_html = (
            "<div class='small muted' style='margin-bottom:10px;'>"
            "IOCs are shown as extracted from the artifact. Categories are minimal (no aggressive guessing)."
            "</div>"
            + _ioc_table("URLs", url_rows)
            + _ioc_table("Domains", dom_rows)
            + _ioc_table("IPs", ip_rows)
            + _ioc_table("Emails", em_rows)
        )

    # Header subtitle depends on kind
    kind_label = "APK Static" if kind == "apk_static" else ("APK Dynamic" if kind == "apk_dynamic" else "APK Report")
    kind_hint = (
        "Static analysis only • Evidence-derived artifacts • No runtime execution"
        if kind == "apk_static"
        else "Dynamic smoke-test • ADB install/launch • Short logcat observation"
        if kind == "apk_dynamic"
        else "Artifact-driven report"
    )

    # Artifact info table (kind-aware)
    artifact_info_rows = ""
    if kind == "apk_static":
        artifact_info_rows += _kv_row("App Name", _html_escape(apk.get("app_name", "")))
        artifact_info_rows += _kv_row("Package", f"<code>{_html_escape(apk.get('package',''))}</code>")
        artifact_info_rows += _kv_row("Version", _html_escape(f"{apk.get('version_name','')} (code {apk.get('version_code','')})"))
        artifact_info_rows += _kv_row("minSdk / targetSdk", _html_escape(f"{apk.get('min_sdk','')} / {apk.get('target_sdk','')}"))
        artifact_info_rows += _kv_row("Evidence path", f"<code>{_html_escape(apk.get('apk_path',''))}</code>")
    elif kind == "apk_dynamic":
        device = apk.get("device", {}) or {}
        dev_serial = device.get("serial", "") if isinstance(device, dict) else str(device)
        artifact_info_rows += _kv_row("App Name", _html_escape(apk.get("app_name", "")))
        artifact_info_rows += _kv_row("Package", f"<code>{_html_escape(apk.get('package',''))}</code>")
        artifact_info_rows += _kv_row("Device serial", f"<code>{_html_escape(dev_serial)}</code>")
        artifact_info_rows += _kv_row("Duration (sec)", _html_escape(features.get("duration_sec", "")))
        artifact_info_rows += _kv_row("Monkey events", _html_escape(features.get("monkey_events", "")))
        artifact_info_rows += _kv_row("Install OK", _html_escape(features.get("install_ok", "")))
        artifact_info_rows += _kv_row("Launch OK", _html_escape(features.get("launch_ok", "")))
        artifact_info_rows += _kv_row("Crash detected", _html_escape(features.get("crash_detected", "")))
        artifact_info_rows += _kv_row("Classes total / kept / removed", _html_escape(f"{features.get('classes_total','')} / {features.get('classes_kept','')} / {features.get('classes_removed','')}"))
        libs = features.get("benign_libs_observed", []) or []
        artifact_info_rows += _kv_row("Benign libs observed", _join_or_none([str(x) for x in libs]))
        artifact_info_rows += _kv_row("Risky permissions", _join_or_none([str(x) for x in (features.get("risky_permissions", []) or [])]))
        artifact_info_rows += _kv_row("Malicious unlock", _html_escape(malicious_unlock))
        artifact_info_rows += _kv_row("Benign cap applied", _html_escape(benign_cap_applied))
    else:
        artifact_info_rows += _kv_row("Artifact", f"<code>{_html_escape(apk_path.name)}</code>")

    # Exported section only for static
    exported_section_html = ""
    if kind == "apk_static":
        exported_section_html = f"""
        <div class="card">
          <h2>Exported Components</h2>
          <table>
            <tr><th>Exported Activities</th><td>{_join_or_none([str(x) for x in exported_activities])}</td></tr>
            <tr><th>Exported Services</th><td>{_join_or_none([str(x) for x in exported_services])}</td></tr>
            <tr><th>Exported Receivers</th><td>{_join_or_none([str(x) for x in exported_receivers])}</td></tr>
          </table>
          <div class="small muted" style="margin-top: 10px;">
            Exported components can increase exposure to Intent-based attacks. Validate intent-filters and permission guards.
          </div>
        </div>
        """

    # Permissions section:
    perms_section_html = ""
    if kind == "apk_static":
        perms_section_html = f"""
        <div class="card">
          <h2>Permissions</h2>
          <div class="small muted" style="margin-bottom: 8px;">
            Extracted from AndroidManifest. Presence does not imply misuse; interpret with app context.
          </div>
          <div style="line-height: 2.0;">
            {_fmt_code_list([str(x) for x in perms])}
          </div>
        </div>
        """
    elif kind == "apk_dynamic":
        # show permissions_count/risky_permissions from features (already present)
        perms_section_html = f"""
        <div class="card">
          <h2>Permissions (dynamic snapshot)</h2>
          <div class="small muted" style="margin-bottom: 8px;">
            Extracted during dynamic run using APK parsing. Presence does not imply misuse.
          </div>
          <table>
            <tr><th>Permissions count</th><td class="mono">{_html_escape(features.get("permissions_count",""))}</td></tr>
            <tr><th>Risky permissions</th><td>{_join_or_none([str(x) for x in (features.get("risky_permissions", []) or [])])}</td></tr>
          </table>
        </div>
        """

    # Certificate section only if present (static)
    cert_section_html = ""
    if isinstance(cert, dict) and (cert.get("sha256_fingerprint") or cert.get("issuer") or cert.get("subject")):
        cert_section_html = f"""
        <div class="card">
          <h2>Signing Certificate</h2>
          <table>
            <tr><th>SHA-256 Fingerprint</th><td><code>{_html_escape(cert.get('sha256_fingerprint',''))}</code></td></tr>
            <tr><th>Issuer</th><td class="small mono">{_html_escape(cert.get('issuer',''))}</td></tr>
            <tr><th>Subject</th><td class="small mono">{_html_escape(cert.get('subject',''))}</td></tr>
          </table>
          <div class="small muted" style="margin-top: 10px;">
            Fingerprint can be used for clustering and provenance checks across cases (certificate reuse).
          </div>
        </div>
        """

    # Engine info note (static)
    engine_note = ""
    if engine_severity:
        engine_note = f"<div class='small muted' style='margin-top:10px;'>Engine severity: <b>{_html_escape(engine_severity)}</b> (informational)</div>"

    # KPI grid: adapt to kind
    if kind == "apk_static":
        kpi_html = f"""
          <div class="grid" style="margin-top: 12px;">
            <div class="kpi"><div class="label">Permissions (count)</div><div class="value mono">{perms_count}</div></div>
            <div class="kpi"><div class="label">Exported components (count)</div><div class="value mono">{exp_count}</div></div>
            <div class="kpi"><div class="label">IOCs (URLs/Domains)</div><div class="value mono">{ioc_counts["urls"]} / {ioc_counts["domains"]}</div></div>
            <div class="kpi"><div class="label">IOCs (IPs/Emails)</div><div class="value mono">{ioc_counts["ips"]} / {ioc_counts["emails"]}</div></div>
          </div>
        """
    else:
        kpi_html = f"""
          <div class="grid" style="margin-top: 12px;">
            <div class="kpi"><div class="label">Install / Launch</div><div class="value mono">{_html_escape(features.get("install_ok",""))} / {_html_escape(features.get("launch_ok",""))}</div></div>
            <div class="kpi"><div class="label">Crash detected</div><div class="value mono">{_html_escape(features.get("crash_detected",""))}</div></div>
            <div class="kpi"><div class="label">Classes (total/kept)</div><div class="value mono">{_html_escape(features.get("classes_total",""))} / {_html_escape(features.get("classes_kept",""))}</div></div>
            <div class="kpi"><div class="label">IOCs (URLs/Domains)</div><div class="value mono">{ioc_counts["urls"]} / {ioc_counts["domains"]}</div></div>
          </div>
        """

    # Notes block
    notes_html = f"""
      <div class="small muted" style="margin-top: 10px;">
        Notes:
        <ul class="compact">
          {''.join(f'<li>{_html_escape(n)}</li>' for n in exec_notes)}
        </ul>
      </div>
    """

    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>APK Report - { _html_escape(case_id) }</title>
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

    h1 {{ margin: 0 0 8px 0; letter-spacing: 0.6px; }}
    h2 {{ margin: 0 0 10px 0; letter-spacing: 0.3px; }}

    .sub {{ color: var(--muted); margin-bottom: 18px; }}

    .card {{
      background: linear-gradient(180deg, rgba(18,24,40,0.82), rgba(12,16,28,0.78));
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 14px 16px;
      margin: 14px 0;
      box-shadow: 0 12px 40px rgba(0,0,0,0.22);
      backdrop-filter: blur(10px);
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
      background: rgba(255,255,255,0.05);
    }}

    .badge.sev {{ text-transform: uppercase; }}

    .pill {{
      display:inline-flex;
      align-items:center;
      padding: 6px 10px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,0.12);
      background: rgba(255,255,255,0.04);
      color: rgba(255,255,255,0.88);
      font-weight: 900;
      font-size: 0.92em;
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
      word-break: break-word;
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
    }}

    th {{
      color: rgba(255,255,255,0.78);
      font-weight: 900;
      background: rgba(255,255,255,0.03);
    }}

    pre {{
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.08);
      padding: 12px;
      border-radius: 14px;
      overflow:auto;
      color: rgba(255,255,255,0.90);
    }}

    .grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
    }}

    .kpi {{
      border: 1px solid rgba(255,255,255,0.10);
      border-radius: 14px;
      padding: 12px;
      background: rgba(255,255,255,0.035);
    }}

    .kpi .label {{
      color: rgba(255,255,255,0.68);
      font-weight: 800;
      font-size: 0.90em;
    }}

    .kpi .value {{
      margin-top: 6px;
      font-weight: 950;
      font-size: 1.15em;
      letter-spacing: 0.2px;
    }}

    .compact {{
      margin: 8px 0 0 18px;
      padding: 0;
    }}
    .compact li {{ margin: 6px 0; }}

    .LOW {{ background: rgba(0,255,160,0.10); color: rgba(140,255,210,0.95); }}
    .MEDIUM {{ background: rgba(255,190,0,0.12); color: rgba(255,210,110,0.95); }}
    .HIGH {{ background: rgba(255,80,80,0.12); color: rgba(255,170,170,0.95); }}
    .CRITICAL {{ background: rgba(255,40,120,0.14); color: rgba(255,170,210,0.95); }}
    .UNKNOWN {{ background: rgba(255,255,255,0.06); color: rgba(255,255,255,0.82); }}

    .SCORE_GREEN {{ background: rgba(0,255,170,0.10); border-color: rgba(0,255,170,0.22); }}
    .SCORE_YELLOW {{ background: rgba(255,205,0,0.12); border-color: rgba(255,205,0,0.22); }}
    .SCORE_ORANGE {{ background: rgba(255,120,0,0.14); border-color: rgba(255,120,0,0.24); }}
    .SCORE_RED {{ background: rgba(255,50,80,0.14); border-color: rgba(255,50,80,0.24); }}

    .BENIGN {{ background: rgba(120,170,255,0.10); border-color: rgba(120,170,255,0.22); }}
    .THIRD_PARTY {{ background: rgba(255,255,255,0.06); border-color: rgba(255,255,255,0.18); }}
    .CLEAR_HTTP {{ background: rgba(255,120,0,0.14); border-color: rgba(255,120,0,0.24); }}
    .SUSPICIOUS {{ background: rgba(255,50,80,0.14); border-color: rgba(255,50,80,0.24); }}

    @media (max-width: 980px) {{
      .grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    }}
    @media (max-width: 520px) {{
      .grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Hybrid Forensic { _html_escape(kind_label) } Report</h1>
    <div class="sub">
      <span class="muted"><b>Case ID:</b></span> <span class="mono">{ _html_escape(case_id) }</span>
      &nbsp; • &nbsp;
      <span class="muted"><b>Created:</b></span> { _html_escape(created_at) }
      &nbsp; • &nbsp;
      <span class="muted"><b>Artifact:</b></span> <code>{ _html_escape(apk_path.name) }</code>
      &nbsp; • &nbsp;
      <span class="muted"><b>Artifact mtime:</b></span> <span class="mono">{ _fmt_fs_ts_mtime(apk_path) }</span>
    </div>

    <div class="card">
      <div class="row" style="justify-content: space-between;">
        <div class="row">
          <span class="badge sev {sev_badge_class(severity)}">{sev_badge_class(severity)}</span>
          <span class="badge {score_band}">SCORE: <span class="mono">{score}</span>/100</span>
        </div>
        <div class="small muted">
          { _html_escape(kind_hint) }
        </div>
      </div>

      {kpi_html}

      <div style="margin-top: 12px;">
        <h2 style="margin-top: 10px;">Why this score</h2>
        {why_html}
        {notes_html}
      </div>
    </div>

    <div class="card">
      <h2>Artifact Identification</h2>
      <table>
        {artifact_info_rows}
      </table>
      {engine_note}
    </div>

    <div class="card">
      <h2>Evidence Registry</h2>
      <table>
        <tr><th>Name</th><th>Type</th><th>SHA-256</th></tr>
        {evidence_rows}
      </table>
    </div>

    {perms_section_html}

    {exported_section_html}

    <div class="card">
      <h2>Extracted Network & IOC Indicators</h2>
      {ioc_section_html}
    </div>

    {cert_section_html}

    <div class="card">
      <h2>Reproducibility (Environment)</h2>
      <table>
        <tr><th>Timestamp (UTC)</th><td class="mono">{_html_escape(env.get("timestamp_utc",""))}</td></tr>
        <tr><th>Python</th><td class="mono">{_html_escape(env.get("python",""))}</td></tr>
        <tr><th>Platform</th><td class="mono">{_html_escape(env.get("platform",""))}</td></tr>
        <tr><th>Packages</th><td><pre>{_html_escape(json.dumps(env.get("packages", {}), indent=2, default=str))}</pre></td></tr>
      </table>
    </div>

    <div class="small muted" style="margin-top: 18px;">
      Generated by Hybrid Forensic Framework • Report type: { _html_escape(kind_label) } • Artifact-driven & deterministic formatting
    </div>
  </div>
</body>
</html>
"""
    out_dir = case_path / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"apk_report__{apk_path.stem}.html"
    out.write_text(html, encoding="utf-8")
    return str(out)
