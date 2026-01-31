# src/frida_auto.py
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any

# Optional project hooks (safe fallback)
try:
    from src.case_report import write_case_html  # type: ignore
except Exception:
    write_case_html = None

try:
    from src.report_html import write_apk_dynamic_html  # type: ignore
except Exception:
    write_apk_dynamic_html = None


# ----------------------------
# Helpers
# ----------------------------

def _utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _utc_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _run(cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def _which(exe: str) -> Optional[str]:
    return shutil.which(exe)


def _find_adb() -> str:
    r"""
    Finds adb in this order:
    1) env ADB_PATH (explicit)
    2) adb in PATH
    3) %LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe
    """
    env_adb = os.environ.get("ADB_PATH", "").strip().strip('"')
    if env_adb and Path(env_adb).exists():
        return env_adb

    adb_in_path = _which("adb") or _which("adb.exe")
    if adb_in_path:
        return adb_in_path

    localapp = os.environ.get("LOCALAPPDATA", "")
    candidate = Path(localapp) / "Android" / "Sdk" / "platform-tools" / "adb.exe"
    if candidate.exists():
        return str(candidate)

    raise FileNotFoundError(
        "ADB not found. Set ADB_PATH or install Android platform-tools.\n"
        "PowerShell quick-fix:\n"
        '$env:ADB_PATH="$env:LOCALAPPDATA\\Android\\Sdk\\platform-tools\\adb.exe"\n'
        '$env:Path += ";$env:LOCALAPPDATA\\Android\\Sdk\\platform-tools"\n'
    )


def _find_frida_cli() -> str:
    frida = _which("frida") or _which("frida.exe")
    if frida:
        return frida
    raise FileNotFoundError("frida CLI not found. Install: pip install frida-tools")


def _find_frida_ps() -> str:
    fridaps = _which("frida-ps") or _which("frida-ps.exe")
    if fridaps:
        return fridaps
    raise FileNotFoundError("frida-ps not found. Install: pip install frida-tools")


def _ensure_case_structure(case_dir: Path) -> Path:
    _safe_mkdir(case_dir)
    _safe_mkdir(case_dir / "artifacts")
    _safe_mkdir(case_dir / "reports")

    case_json = case_dir / "case.json"
    if not case_json.exists():
        minimal = {
            "case_id": case_dir.name,
            "created_utc": _utc_now_str(),
            "notes": "Auto-created by frida_auto.py (minimal case.json).",
            "evidence": [],
        }
        case_json.write_text(json.dumps(minimal, indent=2), encoding="utf-8")
    return case_json


@dataclass
class Adb:
    adb_path: str
    serial: Optional[str] = None

    def _base(self) -> List[str]:
        base = [self.adb_path]
        if self.serial:
            base += ["-s", self.serial]
        return base

    def devices(self) -> str:
        cp = _run(self._base() + ["devices"], timeout=20)
        return (cp.stdout or "") + (cp.stderr or "")

    def shell(self, cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
        return _run(self._base() + ["shell", cmd], timeout=timeout)

    def install(self, apk: Path, timeout: int = 180) -> subprocess.CompletedProcess:
        return _run(self._base() + ["install", "-r", str(apk)], timeout=timeout)

    def uninstall(self, package: str, timeout: int = 120) -> subprocess.CompletedProcess:
        return _run(self._base() + ["uninstall", package], timeout=timeout)

    def force_stop(self, package: str) -> subprocess.CompletedProcess:
        return self.shell(f"am force-stop {package}", timeout=30)

    def launch(self, package: str) -> subprocess.CompletedProcess:
        return self.shell(f"monkey -p {package} -c android.intent.category.LAUNCHER 1", timeout=60)

    def pidof(self, package: str) -> Optional[int]:
        cp = self.shell(f"pidof {package}", timeout=15)
        out = (cp.stdout or "").strip()
        if cp.returncode == 0 and out:
            try:
                return int(out.split()[0])
            except Exception:
                return None
        return None


def _pick_device_serial(adb: Adb) -> Optional[str]:
    out = adb.devices()
    lines = out.splitlines()
    serials = []
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("List of devices"):
            continue
        parts = ln.split()
        if len(parts) >= 2 and parts[1] == "device":
            serials.append(parts[0])
    return serials[0] if len(serials) == 1 else None


def _frida_server_healthcheck(adb: Adb) -> str:
    cp = adb.shell("pidof frida-server", timeout=15)
    if cp.returncode == 0 and (cp.stdout or "").strip():
        return "OK: frida-server running (pidof)."

    cp2 = adb.shell("ps -A", timeout=30)
    txt = (cp2.stdout or "") + (cp2.stderr or "")
    if "frida-server" in txt:
        return "OK: frida-server running (ps -A)."
    return "WARN: frida-server not detected via pidof/ps -A."


def _parse_events(frida_output: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for ln in frida_output.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        tag = ln.split(maxsplit=1)[0]
        if tag.isupper() and len(tag) <= 16:
            counts[tag] = counts.get(tag, 0) + 1
    return counts


def score_dynamic(counts: Dict[str, int], frida_ok: bool) -> Tuple[int, str, List[str]]:
    reasons: List[str] = []
    score = 0

    if not frida_ok:
        reasons.append("Frida instrumentation failed or produced no recognizable output (+0)")
        return 0, "LOW", reasons

    if counts.get("READY", 0) > 0:
        score += 5
        reasons.append("Frida READY observed (+5)")

    hooks = counts.get("HOOK", 0)
    if hooks:
        add = min(25, hooks)
        score += add
        reasons.append(f"HOOK events: {hooks} (+{add})")

    if counts.get("NATIVE", 0) > 0:
        score += 10
        reasons.append("Native activity observed (+10)")

    score = max(0, min(100, score))

    if score < 20:
        sev = "LOW"
    elif score < 50:
        sev = "MEDIUM"
    elif score < 75:
        sev = "HIGH"
    else:
        sev = "CRITICAL"

    return score, sev, reasons


def _frida_cmd(frida_cli: str, mode: str, package: str, script_path: Path) -> List[str]:
    base = [frida_cli, "-U", "-l", str(script_path)]
    if mode == "spawn":
        return base + ["-f", package, "--no-pause"]
    return base + ["-n", package]


def _wait_for_pid(adb: Adb, package: str, max_wait_s: int = 12) -> Optional[int]:
    t0 = time.time()
    while time.time() - t0 < max_wait_s:
        pid = adb.pidof(package)
        if pid:
            return pid
        time.sleep(0.5)
    return None


def run_frida_instrumentation(
    package: str,
    script_path: Path,
    duration: int,
    mode: str,
    adb: Adb
) -> Tuple[bool, int, str]:
    frida_cli = _find_frida_cli()
    frida_ps = _find_frida_ps()

    # quick sanity (best effort)
    try:
        _run([frida_ps, "-U"], timeout=20)
    except Exception:
        pass

    if mode == "attach":
        adb.launch(package)
        pid = _wait_for_pid(adb, package, max_wait_s=12)
        if not pid:
            # attach will likely fail, but we still try and capture output
            pass

    cmd = _frida_cmd(frida_cli, mode, package, script_path)
    print(f"[INFO] Frida cmd: {' '.join(cmd)}")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    captured: List[str] = []
    t0 = time.time()

    try:
        while True:
            if proc.poll() is not None:
                break

            if proc.stdout:
                line = proc.stdout.readline()
                if line:
                    line = line.rstrip("\n")
                    captured.append(line)
                    # Also echo to console so you see errors live
                    print(line)

            if time.time() - t0 >= duration:
                break

        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except Exception:
                proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    out = "\n".join(captured).strip()
    rc = proc.returncode if proc.returncode is not None else -1

    counts = _parse_events(out)
    ok = (counts.get("READY", 0) > 0) or (counts.get("HOOK", 0) > 0) or (rc == 0 and len(out) > 0)

    return ok, rc, out


def _guess_package_from_apk_name(apk_path: Path) -> str:
    base = apk_path.stem
    return base.split("_")[0].strip()


def main() -> int:
    ap = argparse.ArgumentParser(description="CyberShadow Frida automation (device -U).")
    ap.add_argument("--case", required=True, help="Case directory, e.g., cases/CASE_X")
    ap.add_argument("--apk", required=True, help="Path to APK file")
    ap.add_argument("--package", default="", help="Override package name (recommended if APK name guess fails)")
    ap.add_argument("--tag", default="frida_run", help="Run tag for artifact naming")
    ap.add_argument("--duration", type=int, default=25, help="Capture duration (seconds)")
    ap.add_argument("--mode", choices=["attach", "spawn"], default="attach", help="Frida mode")
    ap.add_argument("--script", default="src/cybershadow_dyn.js", help="Frida JS script path")
    ap.add_argument("--serial", default="", help="ADB device serial (optional)")
    ap.add_argument("--keep-installed", action="store_true", help="Do not uninstall app after run")
    ap.add_argument("--no-force-stop", action="store_true", help="Do not force-stop app at end")
    args = ap.parse_args()

    case_dir = Path(args.case)
    _ensure_case_structure(case_dir)

    artifacts_dir = case_dir / "artifacts"
    reports_dir = case_dir / "reports"

    apk_path = Path(args.apk).expanduser()
    if not apk_path.exists():
        print(f"[ERROR] APK not found: {apk_path}")
        return 2

    script_path = Path(args.script)
    if not script_path.exists():
        print(f"[ERROR] Frida script not found: {script_path}")
        return 2

    adb_path = _find_adb()
    adb = Adb(adb_path=adb_path, serial=(args.serial.strip() or None))

    if adb.serial is None:
        picked = _pick_device_serial(adb)
        if picked:
            adb.serial = picked

    frida_note = _frida_server_healthcheck(adb)

    print(f"[INFO] Using adb: {adb.adb_path}")
    if adb.serial:
        print(f"[INFO] Using device serial: {adb.serial}")

    install_cp = adb.install(apk_path)
    install_ok = (install_cp.returncode == 0) or ("Success" in (install_cp.stdout or ""))

    package = args.package.strip() if args.package.strip() else _guess_package_from_apk_name(apk_path)

    cp_pkg = adb.shell(f"pm path {package}", timeout=30)
    if cp_pkg.returncode != 0 or "package:" not in (cp_pkg.stdout or ""):
        print("[ERROR] Package not found on device after install.")
        print(f"       Tried: {package}")
        print("       Fix: pass explicit --package com.real.package.name")
        print("       Tip: list installed apps: adb shell pm list packages -3")
        return 3

    frida_ok, frida_rc, frida_out = run_frida_instrumentation(
        package=package,
        script_path=script_path,
        duration=args.duration,
        mode=args.mode,
        adb=adb
    )

    counts = _parse_events(frida_out)
    score, severity, reasons = score_dynamic(counts, frida_ok)

    ts = _utc_compact()
    artifact_name = f"apk_dynamic__{args.tag}__{ts}.json"
    artifact_path = artifacts_dir / artifact_name

    artifact: Dict[str, Any] = {
        "type": "apk_dynamic",
        "created_utc": _utc_now_str(),
        "case": str(case_dir),
        "apk_path": str(apk_path),
        "package": package,
        "tag": args.tag,
        "mode": args.mode,
        "duration_s": args.duration,
        "adb_serial": adb.serial or "",
        "install_ok": bool(install_ok),
        "install_stdout": (install_cp.stdout or "")[-4000:],
        "install_stderr": (install_cp.stderr or "")[-4000:],
        "frida_server_note": frida_note,
        "frida_ok": bool(frida_ok),
        "frida_return_code": int(frida_rc),
        "event_counts": counts,
        "reasons": reasons,
        "severity": severity,
        "score": int(score),
        "frida_output_tail": "\n".join(frida_out.splitlines()[-300:]),
    }

    artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")

    apk_report_path = None
    if write_apk_dynamic_html:
        try:
            apk_report_path = reports_dir / f"apk_dynamic_report__{artifact_path.stem}.html"
            write_apk_dynamic_html(artifact_path, apk_report_path)
        except Exception as e:
            print(f"[WARN] Failed to write APK HTML report: {e}")

    if write_case_html:
        try:
            write_case_html(case_dir, reports_dir / "case_report.html")
        except Exception as e:
            print(f"[WARN] Failed to write Case HTML report: {e}")

    if not args.no_force_stop:
        adb.force_stop(package)

    if not args.keep_installed:
        adb.uninstall(package)

    print("\n== PIPELINE SUMMARY ==")
    print(f"Case: {case_dir}")
    print("Risk mode: latest")
    print(f"APK: {package}")
    print(f"Instrumentation: {'OK' if frida_ok else 'FAILED'}")
    print(f"Severity: {severity}")
    print(f"Score: {score} / 100")
    print(f"Artifact: {artifact_path}")
    if apk_report_path:
        print(f"APK Report: {apk_report_path}")
    print(f"Case Report: {reports_dir / 'case_report.html'}")
    print("\n[DONE] return code: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
