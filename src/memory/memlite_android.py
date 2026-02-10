from __future__ import annotations

import re
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple


def _now() -> float:
    return time.time()


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _clamp(x: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, int(x)))


def _adb(serial: str, args: List[str], timeout_s: int = 15, retries: int = 2) -> Tuple[int, str, str]:
    base = ["adb"]
    if serial:
        base += ["-s", serial]

    last_err = ""
    for i in range(retries + 1):
        try:
            p = subprocess.run(
                base + args,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                errors="replace",
            )
            out = (p.stdout or "").strip()
            err = (p.stderr or "").strip()
            rc = int(p.returncode)

            transient = ("device offline", "no devices/emulators", "closed", "timeout", "cannot connect")
            if rc != 0 and any(t in (out + " " + err).lower() for t in transient) and i < retries:
                last_err = err or out
                time.sleep(0.8 * (i + 1))
                try:
                    subprocess.run(base + ["wait-for-device"], timeout=10)
                except Exception:
                    pass
                continue

            return rc, out, err

        except subprocess.TimeoutExpired:
            last_err = "timeout"
            if i < retries:
                time.sleep(0.8 * (i + 1))
                continue
            return 124, "", "timeout"

        except Exception as e:
            last_err = str(e)
            if i < retries:
                time.sleep(0.8 * (i + 1))
                continue
            return 1, "", last_err

    return 1, "", last_err


def _adb_shell(serial: str, cmd: str, timeout_s: int = 15, retries: int = 2) -> Dict[str, Any]:
    rc, out, err = _adb(serial, ["shell", cmd], timeout_s=timeout_s, retries=retries)
    return {"cmd": cmd, "rc": rc, "stdout": out, "stderr": err}


def _get_model(serial: str) -> str:
    r = _adb_shell(serial, "getprop ro.product.model", timeout_s=8)
    return (r.get("stdout") or "").strip()


def _pidof(serial: str, pkg: str) -> Optional[int]:
    r = _adb_shell(serial, f"pidof {pkg}", timeout_s=8)
    s = (r.get("stdout") or "").strip()
    if s:
        return _safe_int(s.split()[0], 0) or None

    # fallback: grep in ps
    r2 = _adb_shell(serial, f"ps -A | grep {pkg} | head -n 1", timeout_s=10)
    line = (r2.get("stdout") or "").strip()
    if not line:
        return None

    toks = line.split()
    for t in toks:
        if t.isdigit():
            pid = int(t)
            if pid > 0:
                return pid
    return None


def _parse_uid_from_status(status_text: str) -> Optional[int]:
    m = re.search(r"^Uid:\s+(\d+)", status_text, flags=re.MULTILINE)
    return _safe_int(m.group(1), 0) or None if m else None


def _read_proc(serial: str, pid: int, what: str, timeout_s: int = 12) -> Dict[str, Any]:
    path = f"/proc/{pid}/{what}"
    r = _adb_shell(serial, f"cat {path}", timeout_s=timeout_s)
    return {"path": path, "rc": r["rc"], "stderr": r["stderr"], "data": r["stdout"] if r["rc"] == 0 else ""}


def _ls_proc(serial: str, pid: int, what: str, timeout_s: int = 12) -> Dict[str, Any]:
    path = f"/proc/{pid}/{what}"
    r = _adb_shell(serial, f"ls -la {path}", timeout_s=timeout_s)
    return {"path": path, "rc": r["rc"], "stderr": r["stderr"], "data": r["stdout"] if r["rc"] == 0 else ""}


def _logcat_tail(serial: str, pid: int, lines: int = 250, timeout_s: int = 18) -> Dict[str, Any]:
    r = _adb_shell(serial, f"logcat -d --pid={pid} -v time | tail -n {lines}", timeout_s=timeout_s)
    if r["rc"] == 0 and r["stdout"]:
        tail = [ln.rstrip("\n") for ln in r["stdout"].splitlines() if ln.strip()]
        return {"rc": 0, "tail": tail, "mode": "--pid"}

    r2 = _adb_shell(serial, f"logcat -d -v time | tail -n {lines}", timeout_s=timeout_s)
    tail2 = [ln.rstrip("\n") for ln in (r2["stdout"] or "").splitlines() if ln.strip()]
    return {"rc": r2["rc"], "tail": tail2, "mode": "global"}


def _parse_proc_net_table(text: str) -> Tuple[int, List[Dict[str, Any]]]:
    lines = (text or "").splitlines()
    if not lines:
        return 0, []
    rows: List[Dict[str, Any]] = []
    for ln in lines[1:]:
        parts = ln.split()
        if len(parts) < 10:
            continue
        rows.append(
            {
                "sl": parts[0].rstrip(":"),
                "local": parts[1],
                "remote": parts[2],
                "state": parts[3],
                "uid": _safe_int(parts[7], -1),
                "inode": parts[9],
                "raw": ln[:240],
            }
        )
    return max(0, len(lines) - 1), rows


def _net_snapshot_once(serial: str, uid: int, name: str) -> Dict[str, Any]:
    p = f"/proc/net/{name}"
    r = _adb_shell(serial, f"cat {p}", timeout_s=10)
    rows_total, rows = _parse_proc_net_table(r["stdout"] if r["rc"] == 0 else "")
    rows_uid = [x for x in rows if x.get("uid") == uid]
    return {"path": p, "rc": r["rc"], "stderr": r["stderr"], "rows_total": rows_total, "rows_uid": len(rows_uid), "rows": rows_uid}


def _net_snapshot(serial: str, uid: int, samples: int = 6, interval_ms: int = 250) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for name in ["tcp", "tcp6", "udp", "udp6"]:
        union: Dict[str, Dict[str, Any]] = {}
        rc, stderr, rows_total_last = 0, "", 0
        for i in range(max(1, samples)):
            snap = _net_snapshot_once(serial, uid, name)
            rc = snap.get("rc", 0)
            stderr = snap.get("stderr", "")
            rows_total_last = _safe_int(snap.get("rows_total"), 0)
            for row in snap.get("rows", []) or []:
                key = f"{row.get('inode','')}|{row.get('raw','')}"
                union[key] = row
            if i < samples - 1:
                time.sleep(max(0.05, interval_ms / 1000.0))
        rows_uid = list(union.values())
        out[name] = {
            "path": f"/proc/net/{name}",
            "rc": rc,
            "stderr": stderr,
            "rows_total": rows_total_last,
            "rows_uid": len(rows_uid),
            "rows": rows_uid[:50],
            "samples": samples,
            "interval_ms": interval_ms,
        }
    return out


def _dumpsys(serial: str, cmd: str, timeout_s: int = 25) -> Dict[str, Any]:
    r = _adb_shell(serial, f"dumpsys {cmd}", timeout_s=timeout_s)
    return {"cmd": f"dumpsys {cmd}", "rc": r["rc"], "stderr": r["stderr"], "data": r["stdout"] if r["rc"] == 0 else ""}


def _extract_netstats_bytes(netstats_text: str, target_uid: int) -> Dict[str, int]:
    rx = 0
    tx = 0
    text = netstats_text or ""
    uid_token = f"uid={int(target_uid)}"
    in_uid_block = False

    for line in text.splitlines():
        ln = line.strip()
        if not ln:
            continue

        if "uid=" in ln and "ident=" in ln:
            in_uid_block = (uid_token in ln)
            if in_uid_block:
                for m in re.finditer(r"rxBytes=(\d+)", ln):
                    rx += _safe_int(m.group(1), 0)
                for m in re.finditer(r"txBytes=(\d+)", ln):
                    tx += _safe_int(m.group(1), 0)
            continue

        if ln.startswith("uid="):
            in_uid_block = ln.startswith(uid_token)
            continue

        if not in_uid_block:
            continue

        for m in re.finditer(r"rxBytes=(\d+)", ln):
            rx += _safe_int(m.group(1), 0)
        for m in re.finditer(r"txBytes=(\d+)", ln):
            tx += _safe_int(m.group(1), 0)

        mrb = re.search(r"\brb=(\d+)", ln)
        mtb = re.search(r"\btb=(\d+)", ln)
        if mrb:
            rx += _safe_int(mrb.group(1), 0)
        if mtb:
            tx += _safe_int(mtb.group(1), 0)

        if ln.startswith("Stats Providers:") or ln.startswith("Stats Observers:"):
            in_uid_block = False

    return {"rx_bytes": int(rx), "tx_bytes": int(tx), "total_bytes": int(rx + tx)}


def _extract_qtaguid_bytes(qtag_text: str, target_uid: int) -> Dict[str, int]:
    rx = 0
    tx = 0
    uid = int(target_uid)

    for line in (qtag_text or "").splitlines():
        ln = line.strip()
        if not ln or ln.startswith("idx"):
            continue
        parts = ln.split()
        if len(parts) < 8:
            continue

        uid_field = None
        for j in range(2, min(6, len(parts))):
            if parts[j].isdigit() and int(parts[j]) == uid:
                uid_field = j
                break
        if uid_field is None:
            continue

        nums = []
        for tok in parts[uid_field + 1 :]:
            if tok.isdigit():
                nums.append(int(tok))
        if len(nums) >= 4:
            rx += max(nums[0], nums[1])
            tx += max(nums[2], nums[3])
        elif len(nums) >= 2:
            rx += nums[0]
            tx += nums[1]

    return {"rx_bytes": int(rx), "tx_bytes": int(tx), "total_bytes": int(rx + tx)}


def _detect_foreground_package(serial: str) -> Optional[str]:
    """
    Best-effort detection of the currently focused app package on Android.
    Works on most builds via dumpsys window or activity.
    """
    # Try window focus
    r = _adb_shell(serial, "dumpsys window | grep -E 'mCurrentFocus|mFocusedApp' | head -n 2", timeout_s=18)
    txt = (r.get("stdout") or "")
    m = re.search(r"([a-zA-Z0-9_.]+)\/[a-zA-Z0-9_.\$]+", txt)
    if m:
        return m.group(1)

    # Fallback: activity
    r2 = _adb_shell(serial, "dumpsys activity activities | grep -E 'mResumedActivity|topResumedActivity' | head -n 2", timeout_s=22)
    txt2 = (r2.get("stdout") or "")
    m2 = re.search(r"([a-zA-Z0-9_.]+)\/[a-zA-Z0-9_.\$]+", txt2)
    if m2:
        return m2.group(1)

    return None


def _maybe_autostart(serial: str, pkg: str) -> None:
    # Best-effort start; no hard-fail
    _adb_shell(serial, f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1", timeout_s=18, retries=0)


def _score_memlite(obj: Dict[str, Any]) -> Dict[str, Any]:
    reasons: List[str] = []
    score = 0
    malicious_unlock = False

    pid = _safe_int(obj.get("proc", {}).get("pid"), 0)
    uid = _safe_int(obj.get("proc", {}).get("uid"), -1)
    if pid <= 0 or uid < 0:
        return {
            "score": 0,
            "severity": "LOW",
            "reasons": ["App not running / pid not found (no MemLite signals)."],
            "malicious_unlock": False,
        }

    net = obj.get("network", {})
    net_uid_rows = sum(_safe_int(net.get(k, {}).get("rows_uid"), 0) for k in ["tcp", "tcp6", "udp", "udp6"])
    if net_uid_rows > 0:
        add = min(12, 2 + (net_uid_rows * 2))
        score += add
        reasons.append(f"Network sockets for UID (sampled): {net_uid_rows} (+{add})")

    ns = obj.get("extras", {}).get("netstats_uid", {}).get("parsed", {})
    ns_bytes = _safe_int(ns.get("total_bytes"), 0)

    qt = obj.get("extras", {}).get("qtaguid", {}).get("parsed", {})
    qt_bytes = _safe_int(qt.get("total_bytes"), 0)

    total_bytes = max(ns_bytes, qt_bytes)
    if total_bytes > 0:
        if total_bytes >= 10_000_000:
            add = 18
        elif total_bytes >= 2_000_000:
            add = 10
        elif total_bytes >= 200_000:
            add = 7
        elif total_bytes >= 20_000:
            add = 3
        else:
            add = 1
        score += add
        reasons.append(f"UID traffic observed: {total_bytes} bytes (+{add})")

    snaps = obj.get("proc", {}).get("snapshots", {})
    if snaps.get("maps", {}).get("rc") != 0:
        reasons.append("Note: /proc/<pid>/maps restricted (non-root device)")

    score = _clamp(score, 0, 100)
    severity = "LOW" if score < 30 else ("MEDIUM" if score < 60 else "HIGH")
    if score == 0 and not reasons:
        reasons = ["No MemLite indicators."]

    return {"score": int(score), "severity": severity, "reasons": reasons, "malicious_unlock": bool(malicious_unlock)}


def collect_memlite(
    pkg: str,
    serial: str = "",
    log_lines: int = 250,
    allow_auto_package: bool = True,
    autostart_if_missing: bool = False,
    pid_retries: int = 4,
    pid_retry_sleep_s: float = 0.6,
) -> Dict[str, Any]:
    t0 = _now()
    pkg = (pkg or "").strip()

    _adb(serial, ["wait-for-device"], timeout_s=12, retries=1)

    model = _get_model(serial)

    fg_pkg = _detect_foreground_package(serial)
    resolved_pkg = pkg

    if allow_auto_package and (pkg.lower() in ("auto", "@fg", "foreground", "focused")):
        if fg_pkg:
            resolved_pkg = fg_pkg
        else:
            resolved_pkg = ""  # will error below

    if not resolved_pkg:
        raise ValueError("Package name is required for MemLite (or use pkg='auto' to pick foreground app).")

    warnings: List[str] = []
    if fg_pkg and resolved_pkg != fg_pkg:
        warnings.append(f"Package mismatch: requested '{resolved_pkg}' but foreground app is '{fg_pkg}'.")

    # find PID with retries (real-device jitter)
    pid: Optional[int] = None
    for i in range(max(1, pid_retries)):
        pid = _pidof(serial, resolved_pkg)
        if pid:
            break
        if autostart_if_missing and i == 0:
            _maybe_autostart(serial, resolved_pkg)
        time.sleep(max(0.15, pid_retry_sleep_s))

    if not pid:
        out = {
            "module": "memlite",
            "package": resolved_pkg,
            "requested_package": pkg,
            "foreground_package": fg_pkg,
            "warnings": warnings,
            "device": {"serial": serial, "model": model},
            "collected_at": _now(),
            "proc": {"pid": None, "uid": None, "snapshots": {}},
            "logcat": {"rc": 0, "tail": [], "mode": "none"},
            "network": {},
            "extras": {},
            "scoring": {
                "score": 0,
                "severity": "LOW",
                "reasons": ["App not running / pid not found (no MemLite signals)."],
                "malicious_unlock": False,
            },
            "timing": {"elapsed_s": round(_now() - t0, 3)},
        }
        return out

    cmdline = _read_proc(serial, int(pid), "cmdline", timeout_s=10)
    status = _read_proc(serial, int(pid), "status", timeout_s=10)

    uid = _parse_uid_from_status(status.get("data", "") or "")
    if uid is None:
        ds = _dumpsys(serial, f"package {resolved_pkg}", timeout_s=25)
        m = re.search(r"userId=(\d+)", ds.get("data", ""))
        if m:
            uid = _safe_int(m.group(1), 0) or None

    snaps = {
        "cmdline": cmdline,
        "status": status,
        "maps": _read_proc(serial, int(pid), "maps", timeout_s=12),
        "smaps_rollup": _read_proc(serial, int(pid), "smaps_rollup", timeout_s=12),
        "fd": _ls_proc(serial, int(pid), "fd", timeout_s=12),
    }

    logcat = _logcat_tail(serial, int(pid), lines=log_lines, timeout_s=18)

    network: Dict[str, Any] = {}
    extras: Dict[str, Any] = {
        "meminfo": _dumpsys(serial, f"meminfo {resolved_pkg}", timeout_s=25),
        "pkg": _dumpsys(serial, f"package {resolved_pkg}", timeout_s=25),
    }

    if uid is not None:
        network = _net_snapshot(serial, int(uid), samples=6, interval_ms=250)

        _adb_shell(serial, "dumpsys netstats --poll", timeout_s=12, retries=0)

        ns = _dumpsys(serial, f"netstats --uid {int(uid)}", timeout_s=25)
        data = ns.get("data", "") or ""
        extras["netstats_uid"] = {
            "rc": ns.get("rc", 1),
            "stderr": ns.get("stderr", ""),
            "data_head": data[:12000],
            "parsed": _extract_netstats_bytes(data, int(uid)),
        }

        qt = _adb_shell(serial, "cat /proc/net/xt_qtaguid/stats 2>/dev/null", timeout_s=20, retries=0)
        qt_data = qt.get("stdout") or ""
        extras["qtaguid"] = {
            "rc": qt.get("rc", 1),
            "stderr": qt.get("stderr", ""),
            "data_head": qt_data[:12000],
            "parsed": _extract_qtaguid_bytes(qt_data, int(uid)) if qt.get("rc", 1) == 0 else {"rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0},
        }

    out = {
        "module": "memlite",
        "package": resolved_pkg,
        "requested_package": pkg,
        "foreground_package": fg_pkg,
        "warnings": warnings,
        "device": {"serial": serial, "model": model},
        "collected_at": _now(),
        "proc": {"pid": int(pid), "uid": int(uid) if uid is not None else None, "snapshots": snaps},
        "logcat": logcat,
        "network": network,
        "extras": extras,
        "timing": {"elapsed_s": round(_now() - t0, 3)},
    }

    out["scoring"] = _score_memlite(out)
    return out


def save_memlite_artifact(case_dir: str, tag: str, obj: Dict[str, Any]) -> str:
    from src.case_manager import save_artifact

    suffix = (tag or "mem").strip()
    name = f"memlite__{suffix}.json"
    return save_artifact(case_dir, name, obj)
