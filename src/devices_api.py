# src/devices_api.py
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import APIRouter

router = APIRouter(tags=["devices"])


def _run(cmd: List[str], timeout: int = 15) -> tuple[int, str]:
    try:
        cp = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        return int(cp.returncode), (cp.stdout or "")
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"
    except Exception as e:
        return 1, f"ERROR: {e}"


def _find_adb() -> str:
    adb = os.environ.get("ADB_PATH", "").strip()
    if adb and Path(adb).exists():
        return adb
    p = shutil.which("adb")
    if p:
        return p
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


def _adb_shell(adb: str, serial: str, *args: str, timeout: int = 10) -> str:
    rc, out = _run([adb, "-s", serial, "shell", *args], timeout=timeout)
    return (out or "").strip()


@dataclass
class DeviceItem:
    serial: str
    state: str
    is_emulator: bool
    model: str = ""
    manufacturer: str = ""
    android_release: str = ""
    sdk: str = ""
    abi: str = ""


def _parse_adb_devices_l(text: str) -> List[DeviceItem]:
    devices: List[DeviceItem] = []
    for ln in (text or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("List of devices"):
            continue
        parts = ln.split()
        if len(parts) < 2:
            continue
        serial = parts[0].strip()
        state = parts[1].strip()
        devices.append(DeviceItem(
            serial=serial,
            state=state,
            is_emulator=serial.startswith("emulator-"),
        ))
    return devices


def _enrich_device(adb: str, d: DeviceItem) -> DeviceItem:
    # only enrich if device is reachable
    if d.state != "device":
        return d
    d.model = _adb_shell(adb, d.serial, "getprop", "ro.product.model")
    d.manufacturer = _adb_shell(adb, d.serial, "getprop", "ro.product.manufacturer")
    d.android_release = _adb_shell(adb, d.serial, "getprop", "ro.build.version.release")
    d.sdk = _adb_shell(adb, d.serial, "getprop", "ro.build.version.sdk")
    d.abi = _adb_shell(adb, d.serial, "getprop", "ro.product.cpu.abi")
    return d


def _pick_default_serial(devs: List[DeviceItem]) -> Optional[str]:
    ok = [d for d in devs if d.state == "device"]
    if not ok:
        return None
    # prefer real device (non-emulator)
    for d in ok:
        if not d.is_emulator:
            return d.serial
    return ok[0].serial


@router.get("/devices")
def list_devices() -> Dict[str, Any]:
    """
    Returns connected ADB devices and a recommended default serial.
    UI uses this to auto-select; user doesn't need to know serial.
    """
    adb = _find_adb()
    rc, out = _run([adb, "devices", "-l"], timeout=15)
    devs = _parse_adb_devices_l(out if rc == 0 else "")

    # enrich (best-effort)
    enriched: List[DeviceItem] = []
    for d in devs:
        try:
            enriched.append(_enrich_device(adb, d))
        except Exception:
            enriched.append(d)

    return {
        "adb": adb,
        "default_serial": _pick_default_serial(enriched),
        "devices": [asdict(d) for d in enriched],
    }
