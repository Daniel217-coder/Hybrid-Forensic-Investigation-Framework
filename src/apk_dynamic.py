# src/apk_dynamic.py
"""
APK Dynamic (Lightweight) Analysis
---------------------------------
Goal: provide *dynamic* smoke signals + IOC extraction + noise filtering,
then output an artifact JSON compatible with your case pipeline.

What this module DOES:
- Uses ADB + emulator/device to install and launch an APK
- Runs a small "monkey" launch + short observation window
- Captures logcat + basic process snapshots
- Extracts IOCs (urls/domains/ips/emails) from:
    (a) APK contents (strings in dex/resources)  [static-ish but used for enrichment]
    (b) logcat capture (runtime hints)
- Filters noise aggressively (Android/Google SDK classes, benign domains/emails)
- Scores conservatively so benign apps stay *low*, usually < 20/100

What this module DOES NOT (yet):
- Full sandbox, Frida hooking, full PCAP capture, complex UI automation

NEW (REAL DEVICE HARDENING):
- package -> UID (best-effort) + /proc/net/tcp* parsing to count *external* sockets for this UID
- IOC scoring is gated by net evidence (reduces false positives from generic strings)
- malicious_unlock + benign_cap_applied are also present at TOP LEVEL (for case_report unlock)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
import zipfile
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.case_manager import add_evidence, save_artifact, new_case


def _ensure_case_exists(case_dir: str) -> None:
    case_path = Path(case_dir)
    if case_path.exists() and (case_path / "case.json").exists():
        return
    base = str(case_path.parent) if str(case_path.parent) not in ("", ".") else "cases"
    cid = case_path.name
    new_case(base, cid)

# noise rules
try:
    from src.dyn_noise_rules import DynNoiseRules, extract_domains_from_urls  # type: ignore
except Exception:
    DynNoiseRules = None  # type: ignore

    def extract_domains_from_urls(urls: List[str]) -> List[str]:
        out = []
        for u in urls or []:
            try:
                m = re.search(r"https?://([^/]+)/?", u, re.IGNORECASE)
                if m:
                    out.append(m.group(1).strip().lower())
            except Exception:
                pass
        return out


# ============================================================
# Basics
# ============================================================

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def _utc_stamp_for_filename() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

def _clamp(x: int, lo: int, hi: int) -> int:
    try:
        x = int(x)
    except Exception:
        x = lo
    return max(lo, min(hi, x))

def _severity_from_score(score: int) -> str:
    s = _clamp(score, 0, 100)
    if s >= 80:
        return "CRITICAL"
    if s >= 60:
        return "HIGH"
    if s >= 35:
        return "MEDIUM"
    return "LOW"

def _run(cmd: List[str], timeout: int = 60, check: bool = False) -> Tuple[int, str]:
    try:
        cp = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=check,
        )
        return int(cp.returncode), (cp.stdout or "")
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"
    except Exception as e:
        return 1, f"ERROR: {e}"


# ============================================================
# ADB helpers
# ============================================================

@dataclass
class Adb:
    adb_path: str
    serial: Optional[str] = None

    def cmd(self, *args: str) -> List[str]:
        base = [self.adb_path]
        if self.serial:
            base += ["-s", self.serial]
        base += list(args)
        return base

    def run(self, *args: str, timeout: int = 60, check: bool = False) -> Tuple[int, str]:
        return _run(self.cmd(*args), timeout=timeout, check=check)

    def shell(self, *args: str, timeout: int = 60, check: bool = False) -> Tuple[int, str]:
        return _run(self.cmd("shell", *args), timeout=timeout, check=check)


def _find_adb() -> str:
    adb = os.environ.get("ADB_PATH", "").strip()
    if adb and Path(adb).exists():
        return adb
    p = shutil.which("adb")
    if p:
        return p
    # common Windows SDK path
    localapp = os.environ.get("LOCALAPPDATA", "")
    cand = Path(localapp) / "Android" / "Sdk" / "platform-tools" / "adb.exe"
    if cand.exists():
        return str(cand)
    for k in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        root = os.environ.get(k, "").strip()
        if root:
            cand2 = Path(root) / "platform-tools" / "adb.exe"
            if cand2.exists():
                return str(cand2)
    raise RuntimeError("adb not found. Put adb in PATH or set ADB_PATH.")


def _pick_device_serial(adb_path: str) -> Optional[str]:
    rc, out = _run([adb_path, "devices"], timeout=15, check=False)
    if rc != 0:
        return None
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    # prefer real device (not emulator-)
    serials = []
    for ln in lines:
        if ln.startswith("List of devices"):
            continue
        if "\tdevice" in ln:
            s = ln.split("\t", 1)[0].strip()
            serials.append(s)
    for s in serials:
        if not s.startswith("emulator-"):
            return s
    return serials[0] if serials else None


def _wait_boot_completed(adb: Adb, timeout_sec: int = 120) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout_sec:
        rc, out = adb.shell("getprop", "sys.boot_completed", timeout=10, check=False)
        if rc == 0 and out.strip() == "1":
            return True
        time.sleep(2)
    return False


# ============================================================
# Network evidence (REAL device): /proc/net/tcp* by UID
# ============================================================

def _get_uid_for_package(adb: Adb, pkg: str) -> Optional[int]:
    """Best-effort package -> UID resolver (works without root on most devices)."""
    # 1) cmd package list packages -U
    rc, out = adb.shell("cmd", "package", "list", "packages", "-U", timeout=20, check=False)
    if rc == 0 and out:
        for ln in out.splitlines():
            ln = ln.strip()
            # format: package:com.x uid:10123
            if ln.startswith("package:") and (" uid:" in ln) and (pkg in ln):
                m = re.search(r"\buid:(\d+)\b", ln)
                if m:
                    try:
                        return int(m.group(1))
                    except Exception:
                        pass

    # 2) dumpsys package
    rc, out = adb.shell("dumpsys", "package", pkg, timeout=30, check=False)
    if rc == 0 and out:
        m = re.search(r"\buserId=(\d+)\b", out)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                pass
        m = re.search(r"\buid=(\d+)\b", out)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                pass

    return None


def _hex_to_ipv4(hex_le: str) -> str:
    # /proc/net/tcp stores addr as 8 hex chars in little-endian per byte (e.g. 0100007F = 127.0.0.1)
    hex_le = (hex_le or "").strip()
    if len(hex_le) != 8:
        return ""
    try:
        b = [hex_le[i:i+2] for i in range(0, 8, 2)]
        b = list(reversed(b))
        return ".".join(str(int(x, 16)) for x in b)
    except Exception:
        return ""


def _hex_to_ipv6(hex_be_32: str) -> str:
    # /proc/net/tcp6 stores 32 hex chars (network order).
    s = (hex_be_32 or "").strip()
    if len(s) != 32:
        return ""
    try:
        raw = bytes.fromhex(s)
        ip = ipaddress.IPv6Address(raw)
        return str(ip)
    except Exception:
        return ""


def _is_external_ip(ip: str) -> bool:
    """External = public-routable (not private/loopback/link-local/multicast/unspecified/reserved)."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            return False
        if getattr(addr, "is_reserved", False):
            return False
        return True
    except Exception:
        return False


def _read_proc_net(adb: Adb, path: str) -> str:
    rc, out = adb.shell("cat", path, timeout=15, check=False)
    if rc != 0:
        return ""
    return out or ""


def _parse_proc_net_tcp(text: str, *, ipv6: bool) -> List[Dict[str, Any]]:
    """Parse /proc/net/tcp or /proc/net/tcp6 into records including UID + remote ip:port."""
    out: List[Dict[str, Any]] = []
    if not text:
        return out
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("sl"):
            continue
        parts = ln.split()
        # expected minimal columns. We rely on: local_address, rem_address, st, uid
        if len(parts) < 8:
            continue
        local = parts[1]
        remote = parts[2]
        st = parts[3]
        uid_s = parts[7]
        try:
            uid = int(uid_s)
        except Exception:
            continue

        def split_addr(x: str) -> Tuple[str, int]:
            try:
                a, p = x.split(":")
                port = int(p, 16)
                ip = _hex_to_ipv6(a) if ipv6 else _hex_to_ipv4(a)
                return ip, port
            except Exception:
                return "", 0

        lip, lport = split_addr(local)
        rip, rport = split_addr(remote)
        out.append({
            "uid": uid,
            "state": st,
            "local_ip": lip,
            "local_port": lport,
            "remote_ip": rip,
            "remote_port": rport,
            "ipv6": bool(ipv6),
        })
    return out


def _collect_external_connections_for_uid(adb: Adb, uid: int) -> Dict[str, Any]:
    """Return socket counts + unique external remote endpoints for a UID (best-effort)."""
    res: Dict[str, Any] = {
        "uid": int(uid),
        "capture_ok": False,
        "total_sockets": 0,
        "external_connections": 0,
        "external_remotes": [],
        "error": "",
    }
    try:
        tcp4 = _parse_proc_net_tcp(_read_proc_net(adb, "/proc/net/tcp"), ipv6=False)
        tcp6 = _parse_proc_net_tcp(_read_proc_net(adb, "/proc/net/tcp6"), ipv6=True)
        allr = [r for r in (tcp4 + tcp6) if r.get("uid") == uid]
        res["total_sockets"] = len(allr)

        # Keep only outbound-ish: remote_port != 0, remote_ip not empty, state not LISTEN (0A)
        remotes = set()
        for r in allr:
            rip = (r.get("remote_ip") or "").strip()
            rport = int(r.get("remote_port") or 0)
            st = (r.get("state") or "").strip().upper()
            if not rip or rport <= 0:
                continue
            if st == "0A":  # LISTEN
                continue
            if _is_external_ip(rip):
                remotes.add(f"{rip}:{rport}")

        ext = sorted(remotes)
        res["external_remotes"] = ext[:200]
        res["external_connections"] = len(ext)
        res["capture_ok"] = True
        return res
    except Exception as e:
        res["error"] = str(e)
        return res


# ============================================================
# Robust package/app name extraction
# ============================================================

PKG_RX = re.compile(r"package:\s+name='([^']+)'", re.IGNORECASE)

def _find_aapt() -> Optional[str]:
    for exe in ("aapt", "aapt2"):
        p = shutil.which(exe)
        if p:
            return p
    return None

def read_package_from_apk(apk_path: str) -> str:
    apk_path = str(apk_path)

    # 1) androguard
    try:
        from androguard.core.apk import APK
        a = APK(apk_path)
        pkg = (a.get_package() or "").strip()
        if pkg:
            return pkg
    except Exception:
        pass

    # 2) aapt/aapt2
    aapt = _find_aapt()
    if aapt:
        rc, out = _run([aapt, "dump", "badging", apk_path], timeout=30, check=False)
        if rc == 0 and out:
            m = PKG_RX.search(out)
            if m:
                return m.group(1).strip()

    raise RuntimeError("Could not determine package name (androguard/aapt both failed).")


def read_app_label_from_apk(apk_path: str) -> str:
    try:
        from androguard.core.apk import APK
        a = APK(apk_path)
        label = (a.get_app_name() or "").strip()
        if label:
            return label
    except Exception:
        pass
    return ""


def read_permissions_from_apk(apk_path: str) -> List[str]:
    try:
        from androguard.core.apk import APK
        a = APK(apk_path)
        perms = a.get_permissions() or []
        return sorted({str(p) for p in perms if p})
    except Exception:
        return []


# ============================================================
# IOC extraction from APK/logcat
# ============================================================

URL_RX = re.compile(r"https?://[^\s\"'<>()[\]]{6,}", re.IGNORECASE)
EMAIL_RX = re.compile(r"[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}", re.IGNORECASE)
IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DEX_CLASS_RX = re.compile(r"\bL([A-Za-z0-9_/]{3,})\;\b")

def _valid_ip(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for p in parts:
            n = int(p)
            if n < 0 or n > 255:
                return False
        return True
    except Exception:
        return False


def _extract_text_blobs_from_apk(apk_path: str, max_file_bytes: int = 2_500_000) -> bytes:
    blobs = bytearray()
    with zipfile.ZipFile(apk_path, "r") as z:
        names = z.namelist()

        priority = []
        for n in names:
            nl = n.lower()
            if nl.startswith("classes") and nl.endswith(".dex"):
                priority.append(n)
            elif nl in ("resources.arsc", "androidmanifest.xml"):
                priority.append(n)
            elif nl.startswith("assets/") or nl.startswith("res/"):
                priority.append(n)

        priority = sorted(priority, key=lambda n: (0 if n.lower().endswith(".dex") else 1, n.lower()))

        for n in priority:
            try:
                info = z.getinfo(n)
                if info.file_size <= 0 or info.file_size > max_file_bytes:
                    continue
                data = z.read(n)
                blobs += b"\n" + data + b"\n"
                if len(blobs) > 8_000_000:
                    break
            except Exception:
                continue
    return bytes(blobs)


def _extract_classes_from_apk(apk_path: str) -> List[str]:
    # 1) androguard AnalyzeAPK
    try:
        from androguard.misc import AnalyzeAPK  # type: ignore
        _a, _d, dx = AnalyzeAPK(apk_path)
        classes = []
        for c in dx.get_classes():
            name = str(getattr(c, "name", "") or "")
            if name.startswith("L") and name.endswith(";"):
                name = name[1:-1].replace("/", ".")
            if name:
                classes.append(name)
        if classes:
            return sorted(set(classes))
    except Exception:
        pass

    # 2) fallback: regex over dex bytes
    try:
        blob = _extract_text_blobs_from_apk(apk_path)
        s = blob.decode("latin-1", errors="ignore")
        found = []
        for m in DEX_CLASS_RX.finditer(s):
            raw = m.group(1).replace("/", ".")
            if raw and len(raw) >= 3:
                found.append(raw)
        return sorted(set(found))
    except Exception:
        return []


def _extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    if not text:
        return {"urls": [], "domains": [], "ips": [], "emails": []}

    urls = sorted(set(URL_RX.findall(text)))
    emails = sorted(set(EMAIL_RX.findall(text)))
    ips = sorted({ip for ip in IP_RX.findall(text) if _valid_ip(ip)})

    # domains from URLs
    domains = []
    for u in urls:
        try:
            m = re.search(r"https?://([^/]+)/?", u, re.IGNORECASE)
            if m:
                d = m.group(1).strip().lower()
                if d:
                    domains.append(d)
        except Exception:
            pass

    return {
        "urls": urls[:200],
        "domains": sorted(set(domains))[:300],
        "ips": ips[:200],
        "emails": emails[:200],
    }


def _extract_iocs_from_apk(apk_path: str) -> Dict[str, List[str]]:
    try:
        blob = _extract_text_blobs_from_apk(apk_path)
        text = blob.decode("latin-1", errors="ignore")
        return _extract_iocs_from_text(text)
    except Exception:
        return {"urls": [], "domains": [], "ips": [], "emails": []}


def _merge_iocs(a: Dict[str, List[str]], b: Dict[str, List[str]]) -> Dict[str, List[str]]:
    out = {}
    for k in ("urls", "domains", "ips", "emails"):
        out[k] = sorted(set((a.get(k) or []) + (b.get(k) or [])))
    return out


# ============================================================
# Risky permissions (dynamic capability hints)
# ============================================================

DANGEROUS_PERMS = set([
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.READ_PHONE_STATE",
])


# ============================================================
# Scoring (conservative, benign-first)
# ============================================================

def _score_dynamic(
    *,
    install_ok: bool,
    launched_ok: bool,
    crashed: bool,
    suspicious_domains: List[str],
    suspicious_emails: List[str],
    ips: List[str],
    permissions: List[str],
    net_has_external_traffic: bool,
    net_external_connections_count: int,
    log_text: str,
) -> Tuple[int, str, List[str], bool, bool]:

    score = 0
    reasons: List[str] = []

    if not install_ok:
        score += 2
        reasons.append("Install failed (+2) [reliability]")


    if not launched_ok:
        score += 1
        reasons.append("Launch/monkey failed (+1) [reliability]")


    if crashed:
        score += 6
        reasons.append("App crash detected in logcat (+6)")

    dom_n = len(suspicious_domains)
    if not net_has_external_traffic:
        # Avoid scoring APK-string IOCs when there is no evidence of external network sockets for this UID.
        dom_n = 0
        em_n = 0
        ip_n = 0

    if dom_n:
        add = min(10, dom_n) * 1
        score += add
        reasons.append(f"Suspicious domain(s) observed: {dom_n} (+{add})")

    em_n = len(suspicious_emails) if net_has_external_traffic else 0
    if em_n:
        add = min(5, em_n) * 1
        score += add
        reasons.append(f"Suspicious email(s) observed: {em_n} (+{add})")

    ip_n = len(ips or []) if net_has_external_traffic else 0
    if ip_n:
        add = min(5, ip_n) * 1
        score += add
        reasons.append(f"IP literal(s) observed: {ip_n} (+{add})")

    perms_set = set(permissions or [])
    risky = sorted([p for p in perms_set if p in DANGEROUS_PERMS])
    if risky:
        add = min(10, len(risky)) * 1
        score += add
        reasons.append(f"Risky permission capability indicators: {len(risky)} (+{add})")

    lt = (log_text or "").lower()
    low_keywords = [
        "dexclassloader", "loadlibrary", "magisk", "root",
        "payload", "command and control", "keylogger",
        "exfil", "rat ", "banking",
    ]
    hits = [k for k in low_keywords if k in lt]
    if hits:
        kw = min(10, len(hits) * 2)
        score += kw
        reasons.append(f"Suspicious runtime keyword hits (+{kw})")

    malicious_unlock = False
    if net_has_external_traffic and dom_n >= 3 and any(p in perms_set for p in ("android.permission.SEND_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE")):
        malicious_unlock = True
        reasons.append("Strong combo: multiple suspicious domains + high-risk permission (unlock)")
    if net_has_external_traffic and "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms_set and dom_n >= 1:
        malicious_unlock = True
        reasons.append("Strong combo: accessibility service + external domains (unlock)")

    # Optional: minor hint in reasons (no points) to show net evidence exists
    if net_has_external_traffic and int(net_external_connections_count or 0) > 0:
        reasons.append(f"External sockets observed (uid-scope): {int(net_external_connections_count)} (evidence)")

    benign_cap_applied = False
    if not malicious_unlock:
        score = int(round(score * 0.60))
        benign_cap_applied = True
        reasons.append("Benign cap/dampening applied (no strong malicious combo)")
            # hard cap for observational (ADB-only) runs to avoid false positives
        score = min(score, 15)


    score = _clamp(score, 0, 100)
    sev = _severity_from_score(score)

    if not reasons:
        reasons = ["No major dynamic risk indicators detected."]

    return score, sev, reasons, malicious_unlock, benign_cap_applied


# ============================================================
# Dynamic runner
# ============================================================

def _ensure_pkg_dir(case_dir: str) -> None:
    Path(case_dir).mkdir(parents=True, exist_ok=True)
    (Path(case_dir) / "evidence").mkdir(parents=True, exist_ok=True)
    (Path(case_dir) / "artifacts").mkdir(parents=True, exist_ok=True)
    (Path(case_dir) / "reports").mkdir(parents=True, exist_ok=True)

def _uninstall_pkg(adb: Adb, pkg: str) -> Tuple[bool, str]:
    rc, out = adb.run("uninstall", pkg, timeout=60, check=False)
    if rc == 0 and ("Success" in out or "success" in out):
        return True, out
    return False, out

def _install_apk(adb: Adb, apk_path: str) -> Tuple[bool, str]:
    rc, out = adb.run("install", "-r", "-g", apk_path, timeout=180, check=False)
    ok = (rc == 0) and ("Success" in out or "success" in out)
    return ok, out

def _logcat_clear(adb: Adb) -> None:
    adb.run("logcat", "-c", timeout=25, check=False)

def _logcat_dump(adb: Adb, max_lines: int = 2500) -> str:
    rc, out = adb.run("logcat", "-d", "-v", "threadtime", timeout=45, check=False)
    if rc != 0:
        return ""
    lines = out.splitlines()[-max_lines:]
    return "\n".join(lines)

def _launch_monkey(adb: Adb, pkg: str, events: int = 1) -> Tuple[bool, str]:
    rc, out = adb.shell("monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", str(int(events)), timeout=60, check=False)
    ok = (rc == 0)
    if "No activities found" in out or "Exception" in out:
        ok = False
    return ok, out

def _pidof(adb: Adb, pkg: str) -> List[str]:
    rc, out = adb.shell("pidof", pkg, timeout=10, check=False)
    if rc != 0:
        return []
    return [x for x in out.strip().split() if x.strip()]

def _is_pkg_installed(adb: Adb, pkg: str) -> bool:
    rc, out = adb.shell("pm", "path", pkg, timeout=15, check=False)
    return (rc == 0) and ("package:" in (out or ""))


def _detect_crash(log_text: str, pkg: str) -> bool:
    if "FATAL EXCEPTION" in (log_text or "") and pkg in (log_text or ""):
        return True
    if "ANR in" in (log_text or "") and pkg in (log_text or ""):
        return True
    return False


def run_dynamic(
    *,
    case_dir: str,
    apk_path: str,
    tag: str,
    device_serial: Optional[str] = None,
    duration_sec: int = 25,
    monkey_events: int = 1,
    clear_logcat: bool = True,
    keep_installed: bool = True,
) -> Dict[str, Any]:
    adb_path = _find_adb()
    serial = device_serial or _pick_device_serial(adb_path)
    if not serial:
        raise RuntimeError("No ADB device/emulator detected. Start an emulator or connect a device.")

    adb = Adb(adb_path=adb_path, serial=serial)

    if not _wait_boot_completed(adb, timeout_sec=120):
        raise RuntimeError("Device boot not completed. Wait for emulator/device to fully boot.")

    pkg = read_package_from_apk(apk_path)
    was_installed_before = _is_pkg_installed(adb, pkg)
    installed_by_us = not was_installed_before
    app_name = read_app_label_from_apk(apk_path)
    perms = read_permissions_from_apk(apk_path)

    if not keep_installed and installed_by_us:
        _uninstall_pkg(adb, pkg)


    install_ok, install_out = _install_apk(adb, apk_path)

    # ---- Network evidence baseline (/proc/net by UID) ----
    uid = _get_uid_for_package(adb, pkg) if install_ok else None
    _net_baseline: Dict[str, Any] = {
        "uid": uid,
        "capture_ok": False,
        "external_remotes": [],
        "error": "",
    }
    if isinstance(uid, int) and uid > 0:
        _net_baseline = _collect_external_connections_for_uid(adb, uid)
    else:
        _net_baseline["error"] = "UID not resolved (package not installed / command blocked)"

    if clear_logcat:
        _logcat_clear(adb)

    launched_ok, monkey_out = _launch_monkey(adb, pkg, events=monkey_events)

    t0 = time.time()
    seen_pids: List[str] = []
    while time.time() - t0 < max(5, int(duration_sec)):
        pids = _pidof(adb, pkg)
        for p in pids:
            if p not in seen_pids:
                seen_pids.append(p)
        time.sleep(2)

    log_text = _logcat_dump(adb, max_lines=3500)
    log_iocs = _extract_iocs_from_text(log_text)
    crashed = _detect_crash(log_text, pkg)

    # ---- Network evidence snapshot (post-observation) ----
    net_info: Dict[str, Any] = {
        "uid": uid,
        "capture_ok": False,
        "total_sockets": 0,
        "external_connections": 0,
        "external_remotes_sample": [],
        "has_external_traffic": False,
        "error": "",
    }
    if isinstance(uid, int) and uid > 0:
        after = _collect_external_connections_for_uid(adb, uid)
        before_set = set((_net_baseline.get("external_remotes", []) or []))
        after_set = set((after.get("external_remotes", []) or []))
        delta = sorted(list(after_set - before_set))
        net_info["capture_ok"] = bool(after.get("capture_ok", False))
        net_info["total_sockets"] = int(after.get("total_sockets", 0) or 0)
        net_info["external_connections"] = len(after_set)
        net_info["external_remotes_sample"] = (delta[:25] if delta else sorted(list(after_set))[:25])
        net_info["has_external_traffic"] = bool(len(after_set) > 0)
        net_info["error"] = str(after.get("error", "") or "")
    else:
        net_info["error"] = str(_net_baseline.get("error", "") or "UID not resolved")

    classes = _extract_classes_from_apk(apk_path)
    apk_iocs = _extract_iocs_from_apk(apk_path)
    combined_iocs = _merge_iocs(apk_iocs, log_iocs)

    # ---- Noise filtering & splits (single source of truth: src/dyn_noise_rules.py) ----
    rules = DynNoiseRules() if DynNoiseRules is not None else None

    classes_total = classes[:]
    classes_kept = classes_total[:]
    classes_removed_count = 0
    benign_libs = []
    if rules is not None:
        classes_kept = [c for c in classes_total if not rules.is_noise_class(c)]
        classes_removed_count = max(0, len(classes_total) - len(classes_kept))
        benign_libs = rules.infer_benign_libs_from_classes(classes_total)

    derived_domains = extract_domains_from_urls(combined_iocs.get("urls", []) or [])
    all_domains = sorted(set((combined_iocs.get("domains", []) or []) + derived_domains))

    if rules is not None:
        benign_domains = [d for d in all_domains if rules.is_benign_domain(d)]
        suspicious_domains = [d for d in all_domains if not rules.is_benign_domain(d)]
        benign_emails = [e for e in (combined_iocs.get("emails", []) or []) if rules.is_benign_email(e)]
        suspicious_emails = [e for e in (combined_iocs.get("emails", []) or []) if not rules.is_benign_email(e)]
    else:
        benign_domains = []
        suspicious_domains = all_domains
        benign_emails = []
        suspicious_emails = combined_iocs.get("emails", []) or []

    iocs_scoring = {
        "urls": combined_iocs.get("urls", []) or [],
        "domains": suspicious_domains,
        "ips": combined_iocs.get("ips", []) or [],
        "emails": suspicious_emails,
    }

    iocs_split = {
        "benign": {"domains": benign_domains, "emails": benign_emails},
        "suspicious": {"domains": suspicious_domains, "emails": suspicious_emails},
    }

    score, severity, reasons, malicious_unlock, benign_cap_applied = _score_dynamic(
        install_ok=install_ok,
        launched_ok=launched_ok,
        crashed=crashed,
        suspicious_domains=suspicious_domains,
        suspicious_emails=suspicious_emails,
        ips=(combined_iocs.get("ips", []) or []),
        permissions=perms,
        net_has_external_traffic=bool(net_info.get("has_external_traffic", False)),
        net_external_connections_count=int(net_info.get("external_connections", 0) or 0),
        log_text=log_text,
    )

    result: Dict[str, Any] = {
        "module": "apk_dynamic",
        "timestamp_utc": _utc_now_iso(),
        "device": {"serial": serial, "adb": adb_path},
        "app_name": app_name,
        "package": pkg,
        "apk_source_path": str(apk_path),
        "malicious_unlock": bool(malicious_unlock),
        "benign_cap_applied": bool(benign_cap_applied),
        "features": {
            "duration_sec": int(duration_sec),
            "monkey_events": int(monkey_events),
            "install_ok": bool(install_ok),
            "launch_ok": bool(launched_ok),
            "crash_detected": bool(crashed),
            "pids_seen": seen_pids,
            "classes_total": len(classes_total),
            "classes_kept": len(classes_kept),
            "classes_removed": classes_removed_count,
            "benign_libs_observed": benign_libs,
            "permissions_count": len(perms),
            "risky_permissions": sorted([p for p in perms if p in DANGEROUS_PERMS]),
            "net_uid": net_info.get("uid", None),
            "net_capture_ok": bool(net_info.get("capture_ok", False)),
            "net_total_sockets": int(net_info.get("total_sockets", 0) or 0),
            "net_external_connections": int(net_info.get("external_connections", 0) or 0),
            "net_has_external_traffic": bool(net_info.get("has_external_traffic", False)),
            "net_external_remotes_sample": net_info.get("external_remotes_sample", []) or [],
            "net_error": str(net_info.get("error", "") or ""),
        },
        "iocs": combined_iocs,
        "iocs_split": iocs_split,
        "iocs_scoring": iocs_scoring,
        "classes_filtered": classes_kept[:500],
        "logcat_excerpt": "\n".join((log_text.splitlines()[-900:])) + "\n" if log_text else "",
        "raw": {"install_out": install_out, "monkey_out": monkey_out},
        "scoring": {
            "score": int(score),
            "severity": severity,
            "reasons": reasons,
            "malicious_unlock": bool(malicious_unlock),
            "benign_cap_applied": bool(benign_cap_applied),
        },
    }

    return result


# ============================================================
# CLI entry
# ============================================================

def main():
    ap = argparse.ArgumentParser(prog="apk-dynamic")
    ap.add_argument("--case", required=True, help="Case directory, e.g. cases/CASE_005")
    ap.add_argument("--apk", required=True, help="Path to APK file")
    ap.add_argument("--tag", required=True, help="Short tag for artifact naming (e.g. cat_dyn)")
    ap.add_argument("--device", default=None, help="ADB serial (optional). If omitted, first 'device' is used.")
    ap.add_argument("--duration", type=int, default=25, help="Observation duration seconds (default: 25)")
    ap.add_argument("--monkey", type=int, default=1, help="Monkey launch events (default: 1)")
    ap.add_argument("--keep-installed", action="store_true", help="Do NOT uninstall app at end (debug).")
    ap.add_argument("--no-logcat-clear", action="store_true", help="Do NOT clear logcat before run.")
    args = ap.parse_args()

    case_dir = args.case
    apk_path = args.apk
    tag = args.tag

    if not os.path.exists(apk_path):
        raise SystemExit(f"[ERROR] APK not found: {apk_path}")

    _ensure_case_exists(case_dir)

    ev = add_evidence(case_dir, apk_path, "apk")
    copied_apk = ev.get("path") or str(Path(case_dir) / "evidence" / Path(apk_path).name)

    info = run_dynamic(
        case_dir=case_dir,
        apk_path=copied_apk,
        tag=tag,
        device_serial=args.device,
        duration_sec=int(args.duration),
        monkey_events=int(args.monkey),
        clear_logcat=not bool(args.no_logcat_clear),
        keep_installed=bool(args.keep_installed),
    )

    stamp = _utc_stamp_for_filename()
    artifact_name = f"apk_dynamic__{tag}__{stamp}.json"
    artifact_path = save_artifact(case_dir, artifact_name, info)

    scoring = info.get("scoring", {}) or {}
    sev = (scoring.get("severity") or "UNKNOWN")
    score = scoring.get("score", 0)

    print("\n== PIPELINE SUMMARY ==")
    print(f"Case: {case_dir}")
    print(f"APK: {info.get('package','')}")
    print(f"Severity: {sev}")
    print(f"Score: {score} / 100")
    print(f"Artifact: {artifact_path}")


if __name__ == "__main__":
    main()
