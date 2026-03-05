# src/frida_auto.py
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any

try:
    import frida  # type: ignore
except Exception:
    frida = None  # type: ignore


def utc_now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def ensure_parent(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)


def save_json(p: Path, obj: dict) -> None:
    ensure_parent(p)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def which_or_guess_adb() -> str:
    adb = shutil.which("adb")
    if adb:
        return adb
    local = os.environ.get("LOCALAPPDATA", "")
    guess = Path(local) / "Android" / "Sdk" / "platform-tools" / "adb.exe"
    if guess.exists():
        return str(guess)
    raise SystemExit("[ERROR] adb not found. Add platform-tools to PATH.")


@dataclass
class DeviceInfo:
    serial: str
    release: str
    sdk: str
    abi: str


class Adb:
    def __init__(self, adb_path: str, serial: str, retries: int = 8, retry_sleep: float = 0.8):
        self.adb = adb_path
        self.serial = serial
        self.retries = max(0, int(retries))
        self.retry_sleep = max(0.2, float(retry_sleep))

    def base(self) -> List[str]:
        return [self.adb, "-s", self.serial]

    def _run(self, args: List[str], timeout: int = 25) -> str:
        last = ""
        for _ in range(self.retries + 1):
            try:
                cp = subprocess.run(
                    self.base() + args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=timeout,
                )
                out = (cp.stdout or "").strip()
                last = out
                low = out.lower()
                if "device offline" in low or "device not found" in low or "no devices" in low:
                    time.sleep(self.retry_sleep)
                    continue
                return out
            except subprocess.TimeoutExpired:
                last = "TIMEOUT"
                time.sleep(self.retry_sleep)
            except Exception as e:
                last = f"ERROR: {e}"
                time.sleep(self.retry_sleep)
        return last

    def shell(self, cmd: str, timeout: int = 25) -> str:
        return self._run(["shell", cmd], timeout=timeout)

    def logcat_clear(self) -> None:
        self._run(["logcat", "-c"], timeout=20)

    def logcat_proc(self) -> subprocess.Popen:
        return subprocess.Popen(
            self.base() + ["logcat", "-v", "threadtime"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )

    def forward_remove(self, port: int) -> None:
        self._run(["forward", "--remove", f"tcp:{port}"], timeout=10)

    def forward(self, host_port: int, device_port: int) -> None:
        self._run(["forward", f"tcp:{host_port}", f"tcp:{device_port}"], timeout=10)

    def resolve_main_activity(self, pkg: str) -> Optional[str]:
        out = self.shell(f"cmd package resolve-activity --brief {pkg} 2>/dev/null || true", timeout=25)
        for line in out.splitlines():
            line = line.strip()
            if "/" in line and line.startswith(pkg + "/"):
                return line
        return None

    def resolve_view_activity(self, pkg: str, url: str) -> Optional[str]:
        u = (url or "").replace("'", "%27")
        out = self.shell(
            f"cmd package resolve-activity --brief -a android.intent.action.VIEW -d '{u}' -p {pkg} 2>/dev/null || true",
            timeout=25,
        )
        for line in out.splitlines():
            line = line.strip()
            if "/" in line and line.startswith(pkg + "/"):
                return line
        return None

    def start_component(self, component: str) -> str:
        return self.shell(f"am start -n {component}", timeout=25)

    def monkey_launch(self, pkg: str) -> str:
        return self.shell(f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1", timeout=25)

    def start_view_url(self, pkg: str, url: str) -> str:
        u = (url or "").replace("'", "%27")
        comp = self.resolve_view_activity(pkg, url)
        if comp:
            return self.shell(
                f"am start -n {comp} -a android.intent.action.VIEW -d '{u}' --activity-new-task --activity-clear-top",
                timeout=25,
            )
        return self.shell(
            f"am start -a android.intent.action.VIEW -d '{u}' -p {pkg} --activity-new-task --activity-clear-top",
            timeout=25,
        )

    def force_stop(self, pkg: str) -> None:
        self.shell(f"am force-stop {pkg}", timeout=20)

    def has_listener_27042(self) -> bool:
        out = self.shell("cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep -i 69A2 | head -n 1 || true", timeout=10).lower()
        return ":69a2" in out

    def pidof_all(self, pkg: str) -> List[int]:
        out = self.shell(f"pidof {pkg} 2>/dev/null || true", timeout=10).strip()
        pids: List[int] = []
        for tok in (out.split() if out else []):
            if tok.isdigit():
                pids.append(int(tok))
        return pids

    def ps_processes(self) -> List[Tuple[int, str]]:
        out = self.shell("ps -A 2>/dev/null || ps 2>/dev/null || true", timeout=20)
        rows: List[Tuple[int, str]] = []
        for ln in out.splitlines():
            ln = ln.strip()
            if not ln or ln.lower().startswith("user") or ln.lower().startswith("uid"):
                continue
            parts = ln.split()
            pid = None
            for p in parts[:8]:
                if p.isdigit():
                    pid = int(p)
                    break
            name = parts[-1] if parts else ""
            if pid is not None and name:
                rows.append((pid, name))
        return rows

    def all_package_pids(self, pkg: str) -> List[int]:
        pids = set(self.pidof_all(pkg))
        for pid, name in self.ps_processes():
            if name == pkg or name.startswith(pkg + ":"):
                pids.add(pid)
        return sorted(pids)

    def get_app_uid(self, pkg: str) -> Optional[int]:
        out = self.shell(f"dumpsys package {pkg} 2>/dev/null | grep -m 1 -E 'userId=|uid=' || true", timeout=20)
        m = re.search(r"userId=(\d+)", out)
        if m:
            return int(m.group(1))
        m = re.search(r"\buid=(\d+)\b", out)
        if m:
            return int(m.group(1))
        return None

    def wm_size(self) -> Tuple[int, int]:
        out = self.shell("wm size", timeout=15)
        m = re.search(r"(\d+)\s*x\s*(\d+)", out)
        if not m:
            return (1080, 1920)
        return (int(m.group(1)), int(m.group(2)))

    def keyevent(self, code: int) -> None:
        self.shell(f"input keyevent {code}", timeout=10)

    def tap(self, x: int, y: int) -> None:
        self.shell(f"input tap {x} {y}", timeout=10)

    def monkey_run(self, pkg: str, events: int, throttle_ms: int, seed: int) -> None:
        cmd = (
            f"monkey -p {pkg} "
            f"--seed {seed} "
            f"--throttle {throttle_ms} "
            f"--pct-syskeys 0 --pct-appswitch 0 "
            f"--ignore-crashes --ignore-timeouts --ignore-security-exceptions "
            f"{events}"
        )
        timeout = max(40, int(events * throttle_ms / 1000) + 40)
        self.shell(cmd, timeout=timeout)


def detect_device(adb_path: str, preferred_serial: Optional[str]) -> str:
    cp = subprocess.run([adb_path, "devices"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = cp.stdout or ""
    serials: List[str] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            serials.append(parts[0])

    if preferred_serial:
        if preferred_serial in serials:
            return preferred_serial
        raise SystemExit(f"[ERROR] Device '{preferred_serial}' not found. Connected: {serials}")

    if not serials:
        raise SystemExit("[ERROR] No adb devices found. Enable USB debugging / reconnect device.")

    for s in serials:
        if not s.startswith("emulator-"):
            return s
    return serials[0]


def get_device_info(adb: Adb) -> DeviceInfo:
    rel = adb.shell("getprop ro.build.version.release") or "unknown"
    sdk = adb.shell("getprop ro.build.version.sdk") or "unknown"
    abi = adb.shell("getprop ro.product.cpu.abi") or "unknown"
    return DeviceInfo(serial=adb.serial, release=rel, sdk=sdk, abi=abi)


FRIDA_TAG_RE = re.compile(r"\]\[([A-Z0-9_]+)\]\s*(.*)$")


def split_frida_events(lines: List[str]) -> Tuple[List[Dict[str, str]], Dict[str, int]]:
    events: List[Dict[str, str]] = []
    counts: Dict[str, int] = {}
    for ln in lines:
        m = FRIDA_TAG_RE.search(ln or "")
        if not m:
            continue
        tag = m.group(1).strip()
        msg = m.group(2).strip()
        events.append({"tag": tag, "msg": msg, "raw": ln})
        counts[tag] = counts.get(tag, 0) + 1
    return events, counts


def _filter_logcat_by_pid(log_lines: List[str], pid: Optional[int]) -> str:
    if not pid:
        return "\n".join(log_lines or [])
    needle = f" {pid} "
    out = []
    for ln in (log_lines or []):
        if needle in ln:
            out.append(ln)
    return "\n".join(out)


def _clamp(x: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(x)))


def _severity_from_score(score: int) -> str:
    s = _clamp(score, 0, 100)
    if s >= 80:
        return "CRITICAL"
    if s >= 60:
        return "HIGH"
    if s >= 35:
        return "MEDIUM"
    return "LOW"


def _dynamic_interval_decision(score: int) -> Tuple[str, str, str]:
    """
    Interval policy for dynamic score 0..100:
      - 0..34   BENIGN
      - 35..59  SUSPICIOUS
      - 60..100 MALWARE_LIKELY
    Returns: (band, interval_text, malware_decision_binary)
    """
    s = _clamp(score, 0, 100)
    if s <= 34:
        return "BENIGN", "0-34", "BENIGN"
    if s <= 59:
        return "SUSPICIOUS", "35-59", "MALWARE_SUSPECTED"
    return "MALWARE_LIKELY", "60-100", "MALWARE_SUSPECTED"


def score_dynamic(event_counts: Dict[str, int], net_events: List[dict], logcat_app_text: str) -> Tuple[int, str, List[str], bool, bool, List[str], Dict[str, int]]:
    """
    Strict scoring goals:
      - benign apps < 20 (even with lots of TCP)
      - malware > 60 when hard signals appear
    Strategy:
      - TCP is "presence" only (0..2 pts max), never a hard trigger
      - Hard triggers (unlock): SMS/PROC/DLOAD/INTENT-danger/anti-analysis
      - Combos boost score significantly (TCP + PROC/DLOAD/FILE, SMS + TCP etc.)
      - If no unlock => benign cap at 18
    """
    reasons: List[str] = []
    unlock_triggers: List[str] = []

    tcp_count = len(net_events or [])
    sms = event_counts.get("SMS", 0)
    proc = event_counts.get("PROC", 0)
    dload = event_counts.get("DLOAD", 0)
    fileio = event_counts.get("FILE", 0)
    intent = event_counts.get("INTENT", 0)
    act = event_counts.get("ACT", 0)
    crypto = event_counts.get("CRYPTO", 0)
    selftest = event_counts.get("SELFTEST", 0)

    net = event_counts.get("OKHTTP", 0) + event_counts.get("HTTPURL", 0) + event_counts.get("WEBVIEW", 0)
    sock = event_counts.get("DNS", 0) + event_counts.get("SOCKET", 0)

    key_counts = {
        "SELFTEST": selftest,
        "ACT": act,
        "PROC": proc,
        "FILE": fileio,
        "DLOAD": dload,
        "SMS": sms,
        "CRYPTO": crypto,
        "NET": net,
        "SOCK": sock,
        "TCP": tcp_count,
        "NATIVE": event_counts.get("NATIVE", 0),
    }

    score = 0

    def add(pts: int, why: str):
        nonlocal score
        if pts <= 0:
            return
        score += pts
        reasons.append(f"{why} (+{pts})")

    if tcp_count > 0 or net > 0 or sock > 0:
        add(1, f"Network presence observed (TCP={tcp_count}, NET={net}, SOCK={sock})")
        if tcp_count >= 50:
            add(1, "High volume TCP observations (still benign-weighted)")

    la = (logcat_app_text or "").lower()
    anti_app = ("frida" in la) and (("detected" in la) or ("kill" in la) or ("terminate" in la))
    if anti_app:
        add(18, "Anti-instrumentation reaction detected in APP logcat")
        unlock_triggers.append("ANTI:app-logcat")

    if sms > 0:
        add(50, f"SMS/content provider access observed (SMS={sms})")
        unlock_triggers.append("HARD:sms")

    if proc > 0:
        add(25, f"Process execution observed (PROC={proc})")
        unlock_triggers.append("HARD:proc")

    if dload > 0:
        add(30, f"Dynamic code loading observed (DLOAD={dload})")
        unlock_triggers.append("HARD:dload")

    if intent > 0:
        add(18, f"Dangerous intent usage observed (INTENT={intent})")
        unlock_triggers.append("HARD:intent")

    if fileio > 0:
        add(8, f"File write/delete activity observed (FILE={fileio})")

    if (proc > 0 or dload > 0) and (tcp_count > 0 or net > 0 or sock > 0):
        add(20, "Suspicious combo: network + exec/dynamic-load")
        if "HARD:combo_net_exec" not in unlock_triggers:
            unlock_triggers.append("HARD:combo_net_exec")

    if fileio > 0 and (tcp_count > 0 or net > 0 or sock > 0) and (proc > 0 or dload > 0):
        add(12, "Suspicious combo: network + exec/dload + file tampering")
        if "HARD:combo_net_exec_file" not in unlock_triggers:
            unlock_triggers.append("HARD:combo_net_exec_file")

    if sms > 0 and (tcp_count > 0 or net > 0 or sock > 0):
        add(30, "Critical combo: network + SMS access")
        if "HARD:combo_net_sms" not in unlock_triggers:
            unlock_triggers.append("HARD:combo_net_sms")

    score = _clamp(score, 0, 100)
    malicious_unlock = len(unlock_triggers) > 0

    benign_cap_applied = False
    if not malicious_unlock and score > 18:
        score = 18
        benign_cap_applied = True
        reasons.append("Benign cap applied (no hard triggers).")

    sev = _severity_from_score(score)
    class_band, class_interval, malware_decision = _dynamic_interval_decision(score)
    reasons.append(
        f"Dynamic interval decision: {class_interval} -> {class_band} ({malware_decision})"
    )
    return score, sev, reasons, malicious_unlock, benign_cap_applied, unlock_triggers, key_counts


def read_stream_lines(proc: subprocess.Popen, sink: List[str], stop_event: threading.Event, max_lines: int = 25000):
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if stop_event.is_set():
                break
            sink.append(line.rstrip("\n"))
            if len(sink) >= max_lines:
                break
    except Exception:
        pass


def _frida_is_retryable(err: str) -> bool:
    e = (err or "").lower()
    needles = [
        "connection closed",
        "unable to connect",
        "timed out",
        "timeout",
        "not found",
        "transport error",
        "closed by peer",
    ]
    return any(n in e for n in needles)


def _get_remote_device(endpoint: str):
    if frida is None:
        raise RuntimeError("frida module missing")
    mgr = frida.get_device_manager()
    try:
        return mgr.add_remote_device(endpoint)
    except Exception:
        for d in mgr.enumerate_devices():
            if getattr(d, "id", "") == endpoint:
                return d
        raise


def frida_api_capture_gadget(
    endpoint: str,
    gadget_name: str,
    script_source: str,
    capture_s: int,
    attach_timeout_s: int,
    attached_evt: Optional[threading.Event] = None,
) -> Tuple[List[str], str]:
    if frida is None:
        return [], "frida python module not installed (pip install frida)"

    lines: List[str] = []
    last_err = ""

    def on_message(message: Dict[str, Any], data: Any):
        try:
            if message.get("type") != "send":
                return
            payload = message.get("payload", {})
            if isinstance(payload, dict) and "ts" in payload and "tag" in payload and "msg" in payload:
                lines.append(f"[{payload.get('ts')}][{payload.get('tag')}] {payload.get('msg')}")
            else:
                lines.append(f"[{utc_iso()}][SEND] {json.dumps(payload, ensure_ascii=False)}")
        except Exception:
            pass

    try:
        dev = _get_remote_device(endpoint)
    except Exception as e:
        return [], f"Could not create/get remote device for endpoint {endpoint}: {e}"

    deadline = time.time() + max(5, int(attach_timeout_s))
    while time.time() < deadline:
        session = None
        script = None
        try:
            session = dev.attach(gadget_name)
            script = session.create_script(script_source)
            script.on("message", on_message)
            script.load()
            if attached_evt is not None:
                attached_evt.set()
            time.sleep(max(3, int(capture_s)))
            try:
                script.unload()
            except Exception:
                pass
            try:
                session.detach()
            except Exception:
                pass
            return lines, ""
        except Exception as e:
            last_err = str(e)
            try:
                if script is not None:
                    script.unload()
            except Exception:
                pass
            try:
                if session is not None:
                    session.detach()
            except Exception:
                pass
            if _frida_is_retryable(last_err):
                time.sleep(0.8)
                continue
            break

    return lines, last_err or "attach timeout"


def _hex_to_ipv4(hex_ip: str) -> str:
    try:
        raw = bytes.fromhex(hex_ip)
        if len(raw) != 4:
            return hex_ip
        return ".".join(str(b) for b in raw[::-1])
    except Exception:
        return hex_ip


def _parse_proc_net_tcp(text: str, want_uid: int) -> List[dict]:
    out: List[dict] = []
    for ln in (text or "").splitlines():
        ln = ln.strip()
        if not ln or ln.lower().startswith("sl"):
            continue
        parts = ln.split()
        if len(parts) < 10:
            continue
        remote = parts[2]
        st = parts[3]
        uid_s = parts[7] if len(parts) > 7 else ""
        if not uid_s.isdigit():
            continue
        uid = int(uid_s)
        if uid != want_uid:
            continue

        try:
            r_ip_hex, r_port_hex = remote.split(":")
            r_port = int(r_port_hex, 16)
            if r_ip_hex == "00000000" and r_port == 0:
                continue
            r_ip = _hex_to_ipv4(r_ip_hex) if len(r_ip_hex) == 8 else r_ip_hex
            out.append({"remote_ip": r_ip, "remote_port": r_port, "state": st})
        except Exception:
            continue
    return out


def net_monitor_loop(adb: Adb, app_uid: int, stop_evt: threading.Event, sink: List[dict], interval_s: float = 1.0):
    seen = set()
    while not stop_evt.is_set():
        try:
            tcp = adb.shell("cat /proc/net/tcp 2>/dev/null || true", timeout=10)
            tcp6 = adb.shell("cat /proc/net/tcp6 2>/dev/null || true", timeout=10)
            conns = _parse_proc_net_tcp(tcp, app_uid) + _parse_proc_net_tcp(tcp6, app_uid)
            for c in conns:
                key = f"{c.get('remote_ip')}:{c.get('remote_port')}:{c.get('state')}"
                if key in seen:
                    continue
                seen.add(key)
                c["ts"] = utc_iso()
                sink.append(c)
        except Exception:
            pass
        time.sleep(max(0.5, float(interval_s)))


def driver_allow_clicks(adb: Adb, duration_s: int, stop_evt: threading.Event):
    w, h = adb.wm_size()
    x = int(w * 0.88)
    y = int(h * 0.92)
    end = time.time() + max(5, int(duration_s))
    while time.time() < end and not stop_evt.is_set():
        adb.keyevent(82)
        adb.keyevent(66)
        adb.tap(x, y)
        time.sleep(1.0)


def driver_monkey(adb: Adb, pkg: str, events: int, throttle_ms: int, seed: int, stop_evt: threading.Event):
    if stop_evt.is_set():
        return
    adb.monkey_run(pkg, events=events, throttle_ms=throttle_ms, seed=seed)


def post_attach_seed_driver(adb: Adb, pkg: str, seed_url: str, repeat: int, interval_s: float,
                           attached_evt: threading.Event, sink: List[str]):
    attached_evt.wait(timeout=25.0)
    if not attached_evt.is_set():
        sink.append("seed: attach wait timeout")
        return
    time.sleep(1.2)
    for i in range(max(1, int(repeat))):
        out = adb.start_view_url(pkg, seed_url)
        sink.append(f"seed[{i+1}]: {out[:450]}")
        time.sleep(max(1.0, float(interval_s)))


# -----------------------------
# API-friendly args + runner
# -----------------------------

@dataclass
class RunArgs:
    case_dir: str
    package: str
    tag: str = "dyn"
    serial: str = ""
    endpoint: str = "127.0.0.1:27042"
    gadget_name: str = "Gadget"
    launch: str = "am"  # am|monkey|none
    seed_url: str = ""
    seed_repeat: int = 2
    seed_interval: float = 3.0
    drive: str = "none"  # none|allow|monkey|monkey+allow
    monkey_events: int = 900
    throttle_ms: int = 100
    monkey_seed: int = 1337
    preflight: int = 30
    capture: int = 60
    script_path: str = str(Path("src/cybershadow_dyn.js"))
    force_stop_after: bool = True


def _run_with_args(args: RunArgs) -> Dict[str, Any]:
    adb_path = which_or_guess_adb()
    serial = detect_device(adb_path, args.serial or None)
    adb = Adb(adb_path, serial)
    devinfo = get_device_info(adb)

    script_path = Path(args.script_path)
    if not script_path.exists():
        raise RuntimeError(f"Script not found: {script_path}")
    script_source = script_path.read_text(encoding="utf-8", errors="replace")

    case_path = Path(args.case_dir)
    artifacts_dir = case_path / "artifacts"
    reports_dir = case_path / "reports"
    case_id = case_path.name

    adb.forward_remove(27042)
    adb.forward_remove(27043)
    adb.forward(27042, 27042)
    adb.forward(27043, 27043)

    adb.logcat_clear()
    logcat = adb.logcat_proc()
    stop_log = threading.Event()
    logcat_lines: List[str] = []
    t_log = threading.Thread(target=read_stream_lines, args=(logcat, logcat_lines, stop_log, 25000), daemon=True)
    t_log.start()

    launch_out = ""
    if args.launch != "none":
        comp = adb.resolve_main_activity(args.package)
        if args.launch == "am" and comp:
            launch_out = adb.start_component(comp)
        else:
            launch_out = adb.monkey_launch(args.package)

    time.sleep(1.2)

    pids = adb.all_package_pids(args.package)
    app_pid = pids[0] if pids else None
    app_uid = adb.get_app_uid(args.package)

    gadget_ready = False
    deadline = time.time() + max(5, int(args.preflight))
    while time.time() < deadline:
        if adb.has_listener_27042():
            gadget_ready = True
            break
        time.sleep(0.5)

    attached_evt = threading.Event()
    seed_results: List[str] = []

    seed_thread = None
    if args.seed_url:
        seed_thread = threading.Thread(
            target=post_attach_seed_driver,
            args=(adb, args.package, args.seed_url, int(args.seed_repeat), float(args.seed_interval), attached_evt, seed_results),
            daemon=True,
        )
        seed_thread.start()

    driver_stop = threading.Event()
    driver_threads: List[threading.Thread] = []
    if args.drive != "none":
        if "allow" in args.drive:
            t_allow = threading.Thread(target=driver_allow_clicks, args=(adb, args.capture, driver_stop), daemon=True)
            t_allow.start()
            driver_threads.append(t_allow)
        if "monkey" in args.drive:
            t_m = threading.Thread(
                target=driver_monkey,
                args=(adb, args.package, int(args.monkey_events), int(args.throttle_ms), int(args.monkey_seed), driver_stop),
                daemon=True,
            )
            t_m.start()
            driver_threads.append(t_m)

    net_stop = threading.Event()
    net_events: List[dict] = []
    t_net = None
    if app_uid is not None:
        t_net = threading.Thread(target=net_monitor_loop, args=(adb, app_uid, net_stop, net_events, 1.0), daemon=True)
        t_net.start()

    frida_lines: List[str] = []
    frida_err = ""
    attached_pids: List[int] = []

    if gadget_ready:
        frida_lines, frida_err = frida_api_capture_gadget(
            endpoint=args.endpoint,
            gadget_name=args.gadget_name,
            script_source=script_source,
            capture_s=args.capture,
            attach_timeout_s=args.preflight,
            attached_evt=attached_evt,
        )
        attached_pids = [app_pid] if app_pid is not None else []
    else:
        frida_err = "Gadget not ready (listener 27042 not detected)."

    driver_stop.set()
    for t in driver_threads:
        try:
            t.join(timeout=1.0)
        except Exception:
            pass

    net_stop.set()
    if t_net is not None:
        try:
            t_net.join(timeout=1.0)
        except Exception:
            pass

    stop_log.set()
    try:
        if logcat.poll() is None:
            logcat.terminate()
    except Exception:
        pass
    try:
        t_log.join(timeout=1.0)
    except Exception:
        pass

    if seed_thread is not None:
        try:
            seed_thread.join(timeout=0.2)
        except Exception:
            pass

    if args.force_stop_after:
        adb.force_stop(args.package)

    events, counts = split_frida_events(frida_lines)
    logcat_app_text = _filter_logcat_by_pid(logcat_lines[-2000:], app_pid)

    score, severity, reasons, malicious_unlock, benign_cap_applied, unlock_triggers, key_counts = score_dynamic(
        counts, net_events=net_events, logcat_app_text=logcat_app_text
    )
    class_band, class_interval, malware_decision = _dynamic_interval_decision(score)

    if key_counts.get("SELFTEST", 0) == 0:
        reasons.append("WARNING: SELFTEST not seen (wrong script path or old script).")

    artifact_name = f"apk_dynamic__{args.tag}__{utc_now_stamp()}.json"
    artifact_path = artifacts_dir / artifact_name

    artifact = {
        "kind": "apk_dynamic",
        "case_id": case_id,
        "package": args.package,
        "tag": args.tag,
        "device": f"{devinfo.serial} (Android {devinfo.release}, sdk {devinfo.sdk}, abi {devinfo.abi})",
        "created_at_utc": utc_iso(),
        "runtime": {
            "transport": "gadget",
            "endpoint": args.endpoint,
            "gadget_ready": bool(gadget_ready),
            "frida_api": "python",
            "frida_attach_error": frida_err,
            "launch_out": launch_out[:800],
            "seed_results": seed_results[:100],
            "package_pids": pids,
            "app_pid": app_pid,
            "app_uid": app_uid,
            "attached_pids": attached_pids,
            "event_counts": counts,
            "frida_output_lines": int(len(frida_lines)),
            "frida_output_tail": frida_lines[-2000:],
            "logcat_tail": logcat_lines[-2000:],
            "net_observed": net_events[:2000],
            "net_observed_count": len(net_events),
            "capture_seconds": int(args.capture),
            "launch": args.launch,
            "seed_url": args.seed_url,
            "seed_repeat": int(args.seed_repeat),
            "seed_interval": float(args.seed_interval),
            "drive": args.drive,
            "monkey_events": int(args.monkey_events),
            "throttle_ms": int(args.throttle_ms),
            "monkey_seed": int(args.monkey_seed),
        },
        "scoring": {
            "score": int(score),
            "score_max": 100,
            "risk_scale": "0-100",
            "severity": severity,
            "classification_band": class_band,
            "classification_interval": class_interval,
            "malware_decision": malware_decision,
            "reasons": reasons,
            "malicious_unlock": bool(malicious_unlock),
            "benign_cap_applied": bool(benign_cap_applied),
            "unlock_triggers": unlock_triggers,
            "key_counts": key_counts,
        },
        "events": events[:3000],
    }

    save_json(artifact_path, artifact)

    report_name = f"apk_dynamic_report__{Path(artifact_name).stem}.html"
    report_path = reports_dir / report_name
    ensure_parent(report_path)
    report_path.write_text(
        "<html><body><pre>" + json.dumps(artifact, indent=2, ensure_ascii=False) + "</pre></body></html>",
        encoding="utf-8"
    )

    return {
        "artifact": str(artifact_path),
        "report": str(report_path),
        "scoring": artifact.get("scoring", {}),
        "package": args.package,
        "device": {
            "serial": devinfo.serial,
            "release": devinfo.release,
            "sdk": devinfo.sdk,
            "abi": devinfo.abi,
            "adb": adb_path,
        },
        "runtime": {
            "gadget_ready": bool(gadget_ready),
            "frida_attach_error": frida_err,
            "frida_lines": len(frida_lines),
            "net_observed_count": len(net_events),
            "app_pid": app_pid,
            "app_uid": app_uid,
        },
    }


# -----------------------------
# API entrypoint expected by api_local.py
# -----------------------------
def run_dynamic_analysis(
    case_dir: str,
    package: str,
    tag: str = "dyn",
    serial: str = "",
    endpoint: str = "127.0.0.1:27042",
    gadget_name: str = "Gadget",
    script: str = "src/cybershadow_dyn.js",
    launch: str = "am",
    drive: str = "none",
    monkey_events: int = 900,
    throttle_ms: int = 100,
    monkey_seed: int = 1337,
    preflight: int = 30,
    capture: int = 60,
    force_stop_after: bool = True,
) -> Dict[str, Any]:
    """
    Wrapper used by Local API.
    Keeps CLI behavior intact; just runs the same pipeline programmatically.
    """
    args = RunArgs(
        case_dir=case_dir,
        package=package,
        tag=tag,
        serial=serial or "",
        endpoint=endpoint,
        gadget_name=gadget_name,
        script_path=script,
        launch=launch,
        drive=drive,
        monkey_events=int(monkey_events),
        throttle_ms=int(throttle_ms),
        monkey_seed=int(monkey_seed),
        preflight=int(preflight),
        capture=int(capture),
        force_stop_after=bool(force_stop_after),
    )
    return _run_with_args(args)


def main():
    ap = argparse.ArgumentParser(description="CyberShadow • Dynamic (Gadget + UID net monitor + strict scoring).")
    ap.add_argument("--case", dest="case_dir", required=True)
    ap.add_argument("--package", dest="package", required=True)
    ap.add_argument("--tag", dest="tag", default="dyn")
    ap.add_argument("--serial", dest="serial", default="")

    ap.add_argument("--endpoint", dest="endpoint", default="127.0.0.1:27042")
    ap.add_argument("--gadget-name", dest="gadget_name", default="Gadget")

    ap.add_argument("--launch", dest="launch", choices=["am", "monkey", "none"], default="am")

    ap.add_argument("--seed-url", dest="seed_url", default="")
    ap.add_argument("--seed-repeat", dest="seed_repeat", type=int, default=2)
    ap.add_argument("--seed-interval", dest="seed_interval", type=float, default=3.0)

    ap.add_argument("--drive", dest="drive", choices=["none", "allow", "monkey", "monkey+allow"], default="none")
    ap.add_argument("--monkey-events", dest="monkey_events", type=int, default=900)
    ap.add_argument("--throttle-ms", dest="throttle_ms", type=int, default=100)
    ap.add_argument("--monkey-seed", dest="monkey_seed", type=int, default=1337)

    ap.add_argument("--preflight", dest="preflight", type=int, default=30)
    ap.add_argument("--capture", dest="capture", type=int, default=60)
    ap.add_argument("--script", dest="script_path", default=str(Path("src/cybershadow_dyn.js")))

    ap.add_argument("--force-stop-after", dest="force_stop_after", action="store_true")
    ap.set_defaults(force_stop_after=True)

    a = ap.parse_args()

    args = RunArgs(
        case_dir=a.case_dir,
        package=a.package,
        tag=a.tag,
        serial=a.serial or "",
        endpoint=a.endpoint,
        gadget_name=a.gadget_name,
        launch=a.launch,
        seed_url=a.seed_url,
        seed_repeat=int(a.seed_repeat),
        seed_interval=float(a.seed_interval),
        drive=a.drive,
        monkey_events=int(a.monkey_events),
        throttle_ms=int(a.throttle_ms),
        monkey_seed=int(a.monkey_seed),
        preflight=int(a.preflight),
        capture=int(a.capture),
        script_path=a.script_path,
        force_stop_after=bool(a.force_stop_after),
    )

    res = _run_with_args(args)

    # Preserve your CLI summary output style
    print("== PIPELINE SUMMARY ==")
    print(f"Case: {args.case_dir}")
    print(f"APK: {args.package}")
    print("Transport: gadget")
    print(f"Gadget ready: {res.get('runtime', {}).get('gadget_ready')} | Endpoint: {args.endpoint}")
    print(f"AppPID: {res.get('runtime', {}).get('app_pid')}")
    print(f"Severity: {res.get('scoring', {}).get('severity')}")
    print(f"Score: {res.get('scoring', {}).get('score')} / 100")
    print(f"Artifact: {res.get('artifact')}")
    print(f"APK Report: {res.get('report')}")
    print("[DONE] return code: 0")


if __name__ == "__main__":
    main()
