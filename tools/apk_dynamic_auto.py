import argparse
import json
import os
import shutil
import subprocess
import socket
import time
from pathlib import Path
from datetime import datetime, timezone

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from frida_auto import run_gadget_script


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _adb_path() -> str:
    adb = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk", "platform-tools", "adb.exe")
    if os.path.exists(adb):
        return adb
    adb2 = shutil.which("adb")
    if adb2:
        return adb2
    raise FileNotFoundError(f"adb.exe not found at: {adb} and not found in PATH.")


def _run(cmd, check=True, capture=False):
    if capture:
        return subprocess.run(cmd, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return subprocess.run(cmd, check=check)


def adb(serial: str, *args, check=True, capture=False):
    cmd = [_adb_path(), "-s", serial, *args]
    return _run(cmd, check=check, capture=capture)


def adb_shell(serial: str, sh: str, check=True, capture=False):
    return adb(serial, "shell", sh, check=check, capture=capture)


def _wait_tcp_open(host: str, port: int, timeout_sec: int = 20, poll_ms: int = 200) -> bool:
    """
    Wait until we can connect to host:port (e.g., 127.0.0.1:27042 after adb forward).
    """
    t0 = time.time()
    while (time.time() - t0) < timeout_sec:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except Exception:
            time.sleep(poll_ms / 1000.0)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial", required=True, help="device serial, e.g. RF8N92WCTPP")
    ap.add_argument("--pkg", required=True, help="package name, e.g. me.hackerchick.catima")
    ap.add_argument("--tag", default="t1")
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--monkey", type=int, default=0)
    ap.add_argument("--throttle", type=int, default=100)

    # Gadget connection (ADB forward -> local)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=27042)
    ap.add_argument("--port2", type=int, default=27043)
    ap.add_argument("--wait_port_sec", type=int, default=20)

    ap.add_argument("--outdir", default="artifacts/dynamic")
    ap.add_argument("--js", default="src/cybershadow_dyn.js")
    args = ap.parse_args()

    serial = args.serial
    pkg = args.pkg

    js_path = Path(args.js)
    if not js_path.exists():
        raise FileNotFoundError(f"JS not found: {js_path}")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    out_json = outdir / f"apk_dynamic__{args.tag}__{pkg}__{_utc_stamp()}.json"

    # Setup ADB forwards for Gadget
    print("[*] adb forward tcp:27042/27043 -> device (best-effort)")
    adb(serial, "forward", "--remove", f"tcp:{args.port}", check=False)
    adb(serial, "forward", "--remove", f"tcp:{args.port2}", check=False)
    adb(serial, "forward", f"tcp:{args.port}", f"tcp:{args.port}", check=False)
    adb(serial, "forward", f"tcp:{args.port2}", f"tcp:{args.port2}", check=False)

    print("[*] force-stop + start app (launcher)")
    adb_shell(serial, f"am force-stop {pkg}", check=False)
    adb_shell(serial, f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1", check=False)

    # Wait for gadget port to open (after app starts)
    print(f"[*] waiting gadget port {args.host}:{args.port} up to {args.wait_port_sec}s ...")
    if not _wait_tcp_open(args.host, args.port, timeout_sec=args.wait_port_sec, poll_ms=200):
        print("[ERR] Gadget port did not open. This usually means:")
        print("  - APK not repacked with Frida Gadget OR")
        print("  - Gadget not configured to listen on tcp:27042 OR")
        print("  - App died early / anti-tamper")
        raise SystemExit(3)

    if args.monkey and args.monkey > 0:
        print(f"[*] running monkey events={args.monkey} throttle={args.throttle}ms")
        adb_shell(
            serial,
            f"monkey -p {pkg} --pct-syskeys 0 --pct-rotation 0 --throttle {args.throttle} {args.monkey}",
            check=False
        )

    print(f"[*] connecting to Frida Gadget at {args.host}:{args.port}")

    def log(line: str):
        print(line)

    dyn = run_gadget_script(
        host=args.host,
        port=args.port,
        js_path=js_path,
        duration_sec=args.duration,
        on_log=log
    )

    doc = {
        "schema": "cybershadow.apk_dynamic.v1",
        "created_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "package": pkg,
        "tag": args.tag,
        "device_serial": serial,
        "gadget_host": args.host,
        "gadget_port": args.port,
        "duration_sec": args.duration,
        "runtime_sec": dyn.runtime_sec,
        "events": dyn.events,
        "counts": dyn.counts,
        "iocs": dyn.iocs,
        "warnings": dyn.warnings,
        "errors": dyn.errors,
        "frida_output_tail": dyn.output_tail,
        "runtime": {
            "mode": "frida_gadget_tcp",
            "adb_forward": [args.port, args.port2],
        }
    }

    out_json.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[OK] Wrote: {out_json}")
    print(f"[OK] counts: {doc.get('counts')}")
    i = doc.get("iocs") or {}
    print(f"[OK] iocs: urls={len(i.get('urls') or [])} domains={len(i.get('domains') or [])} ips={len(i.get('ips') or [])}")
    if doc.get("warnings"):
        print(f"[WARN] warnings: {doc['warnings']}")
    if doc.get("errors"):
        print(f"[ERR] errors: {doc['errors']}")


if __name__ == "__main__":
    main()
