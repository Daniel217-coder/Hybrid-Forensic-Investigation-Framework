# src/memory/memlite_android.py
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
    """
    OneUI / AOSP variants:
      - Some include rxBytes=/txBytes=.
      - Many include NetworkStatsHistory lines with rb=/tb=, BUT uid is on the "ident= ... uid=XXXX ..." line,
        and rb/tb appear on following indented "st=... rb=... tb=..." lines.

    Strategy:
      - Track when we enter a block whose header contains uid=<target_uid>.
      - While inside that block, sum rb/tb from subsequent lines until we hit another header that contains 'uid='
        for a different uid (or we leave the history section).
      - Also sum any rxBytes/txBytes if present anywhere inside the block.
    """
    rx = 0
    tx = 0
    text = netstats_text or ""
    uid_token = f"uid={int(target_uid)}"

    in_uid_block = False

    for line in text.splitlines():
        ln = line.strip()
        if not ln:
            continue

        # Detect start of a new uid block header (common formats include: "ident=[...] uid=10364 set=... tag=0x0")
        if "uid=" in ln and "ident=" in ln:
            in_uid_block = (uid_token in ln)
            # even on header line, some builds might include rxBytes/txBytes; parse if present
            if in_uid_block:
                for m in re.finditer(r"rxBytes=(\d+)", ln):
                    rx += _safe_int(m.group(1), 0)
                for m in re.finditer(r"txBytes=(\d+)", ln):
                    tx += _safe_int(m.group(1), 0)
            continue

        # Some builds may emit "uid=10364 set=..." without ident= prefix
        if ln.startswith("uid="):
            in_uid_block = ln.startswith(uid_token)
            continue

        if not in_uid_block:
            continue

        # Inside the target UID block: parse traffic lines
        # Variant A
        for m in re.finditer(r"rxBytes=(\d+)", ln):
            rx += _safe_int(m.group(1), 0)
        for m in re.finditer(r"txBytes=(\d+)", ln):
            tx += _safe_int(m.group(1), 0)

        # Variant B: NetworkStatsHistory lines
        mrb = re.search(r"\brb=(\d+)", ln)
        mtb = re.search(r"\btb=(\d+)", ln)
        if mrb:
            rx += _safe_int(mrb.group(1), 0)
        if mtb:
            tx += _safe_int(mtb.group(1), 0)

        # End heuristics: if we hit a new section that clearly exits history, we can stop capturing.
        # (keep it permissive; not mandatory)
        if ln.startswith("Stats Providers:") or ln.startswith("Stats Observers:"):
            in_uid_block = False

    return {"rx_bytes": int(rx), "tx_bytes": int(tx), "total_bytes": int(rx + tx)}


def _score_memlite(obj: Dict[str, Any]) -> Dict[str, Any]:
    reasons: List[str] = []
    score = 0
    malicious_unlock = False

    pid = _safe_int(obj.get("proc", {}).get("pid"), 0)
    uid = _safe_int(obj.get("proc", {}).get("uid"), -1)
    if pid <= 0 or uid < 0:
        return {"score": 0, "severity": "LOW", "reasons": ["App not running / pid not found (no MemLite signals)."], "malicious_unlock": False}

        # sockets (weak signal on non-root; keep low to avoid FP)
    net = obj.get("network", {})
    net_uid_rows = sum(_safe_int(net.get(k, {}).get("rows_uid"), 0) for k in ["tcp", "tcp6", "udp", "udp6"])
    if net_uid_rows > 0:
        # 2..12 points max (instead of 40)
        add = min(12, 2 + (net_uid_rows * 2))
        score += add
        reasons.append(f"Network sockets for UID (sampled): {net_uid_rows} (+{add})")


    ns = obj.get("extras", {}).get("netstats_uid", {}).get("parsed", {})
    ns_bytes = _safe_int(ns.get("total_bytes"), 0)
    if ns_bytes > 0:
        # keep very low for small traffic
        if ns_bytes >= 5_000_000:
            add = 20
        elif ns_bytes >= 500_000:
            add = 12
        elif ns_bytes >= 50_000:
            add = 8
        else:
            add = 4
        score += add
        reasons.append(f"UID traffic via netstats: {ns_bytes} bytes (+{add})")


    # procfs restriction note (0 points)
    snaps = obj.get("proc", {}).get("snapshots", {})
    if snaps.get("maps", {}).get("rc") != 0:
        reasons.append("Note: /proc/<pid>/maps restricted (non-root device)")

    score = _clamp(score, 0, 100)
    severity = "LOW" if score < 30 else ("MEDIUM" if score < 60 else "HIGH")
    if score == 0 and not reasons:
        reasons = ["No MemLite indicators."]
    return {"score": int(score), "severity": severity, "reasons": reasons, "malicious_unlock": bool(malicious_unlock)}


def collect_memlite(pkg: str, serial: str = "", log_lines: int = 250) -> Dict[str, Any]:
    t0 = _now()
    pkg = (pkg or "").strip()
    if not pkg:
        raise ValueError("Package name is required for MemLite.")

    _adb(serial, ["wait-for-device"], timeout_s=12, retries=1)

    model = _get_model(serial)
    pid = _pidof(serial, pkg)

    if not pid:
        out = {
            "module": "memlite",
            "package": pkg,
            "device": {"serial": serial, "model": model},
            "collected_at": _now(),
            "proc": {"pid": None, "uid": None, "snapshots": {}},
            "logcat": {"rc": 0, "tail": [], "mode": "none"},
            "network": {},
            "extras": {},
            "scoring": {"score": 0, "severity": "LOW", "reasons": ["App not running / pid not found (no MemLite signals)."], "malicious_unlock": False},
            "timing": {"elapsed_s": round(_now() - t0, 3)},
        }
        return out

    cmdline = _read_proc(serial, pid, "cmdline", timeout_s=10)
    status = _read_proc(serial, pid, "status", timeout_s=10)

    uid = _parse_uid_from_status(status.get("data", "") or "")
    if uid is None:
        ds = _dumpsys(serial, f"package {pkg}", timeout_s=25)
        m = re.search(r"userId=(\d+)", ds.get("data", ""))
        if m:
            uid = _safe_int(m.group(1), 0) or None

    snaps = {
        "cmdline": cmdline,
        "status": status,
        "maps": _read_proc(serial, pid, "maps", timeout_s=12),
        "smaps_rollup": _read_proc(serial, pid, "smaps_rollup", timeout_s=12),
        "fd": _ls_proc(serial, pid, "fd", timeout_s=12),
    }

    logcat = _logcat_tail(serial, pid, lines=log_lines, timeout_s=18)

    network = {}
    extras = {
        "meminfo": _dumpsys(serial, f"meminfo {pkg}", timeout_s=25),
        "pkg": _dumpsys(serial, f"package {pkg}", timeout_s=25),
    }

    if uid is not None:
        network = _net_snapshot(serial, int(uid), samples=6, interval_ms=250)

        ns = _dumpsys(serial, f"netstats --uid {int(uid)}", timeout_s=25)
        data = ns.get("data", "") or ""
        extras["netstats_uid"] = {
            "rc": ns.get("rc", 1),
            "stderr": ns.get("stderr", ""),
            "data_head": data[:12000],
            "parsed": _extract_netstats_bytes(data, int(uid)),
        }

    out = {
        "module": "memlite",
        "package": pkg,
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
