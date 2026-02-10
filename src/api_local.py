# src/api_local.py
from __future__ import annotations

import sys
import json
import threading
import time
import uuid
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Optional, List
import re
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field, field_validator
from src.vt_routes import router as vt_router
from src.case_manager import new_case, add_evidence, save_artifact
from src.apk_static import analyze_apk, set_verbose
from src.report_html import generate_apk_html_report
from src.case_report import write_case_html
from src.env_report import get_versions
from src.vt_routes import router as vt_router

# ADB-only dynamic (NO FRIDA REQUIRED)
from src.apk_dynamic import run_dynamic as run_dynamic_adb  # <- important

# optional frida (fallback to subprocess if missing)
_run_dynamic_analysis = None
try:
    from src.frida_auto import run_dynamic_analysis as _run_dynamic_analysis  # type: ignore
except Exception:
    _run_dynamic_analysis = None

import os
from pathlib import Path
from dotenv import load_dotenv

# Load env from repo-root OR inputs/api_key/.env
ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")
load_dotenv(ROOT / "inputs" / "api_keys" / ".env")

# -------------------------
# Models (API)
# -------------------------

class CreateCaseReq(BaseModel):
    case_id: str = Field(..., description="Case ID, ex: CASE_001")
    base_dir: str = Field("cases", description="Base cases directory")

    @field_validator("case_id")
    @classmethod
    def validate_case_id(cls, v: str) -> str:
        vv = (v or "").strip()
        if not vv or vv.lower() == "string":
            raise ValueError("case_id_invalid")
        return vv


class RunStaticReq(BaseModel):
    case_dir: str = Field(..., description="Path to case directory, ex: cases/CASE_001")
    apk_path: str = Field(..., description="Local path to APK evidence")
    tag: Optional[str] = Field(None, description="Artifact suffix tag (optional)")
    verbose: bool = False


# ADB-only dynamic: takes an APK file (installs + launches + observes)
class RunDynamicAdbReq(BaseModel):
    case_dir: str
    apk_path: str
    tag: str = "dyn_adb"
    serial: str = ""
    duration_sec: int = 25
    monkey_events: int = 1
    keep_installed: bool = False
    clear_logcat: bool = True


# FRIDA dynamic (will remain, but it needs gadget on non-root)
class RunDynamicFridaReq(BaseModel):
    case_dir: str
    package: str
    tag: str = "dyn"
    serial: str = ""
    endpoint: str = "127.0.0.1:27042"
    gadget_name: str = "Gadget"
    script: str = "src/cybershadow_dyn.js"
    launch: str = "am"
    drive: str = "none"
    monkey_events: int = 900
    throttle_ms: int = 100
    monkey_seed: int = 1337
    preflight: int = 10
    capture: int = 45
    force_stop_after: bool = True


@dataclass
class Job:
    job_id: str
    kind: str
    status: str  # QUEUED|RUNNING|DONE|ERROR
    created_ts: float
    updated_ts: float
    case_dir: str
    detail: str = ""
    result: Dict[str, Any] = None
    error: str = ""


JOBS: Dict[str, Job] = {}
JOBS_LOCK = threading.Lock()


def _now() -> float:
    return time.time()


def _put_job(job: Job) -> None:
    with JOBS_LOCK:
        JOBS[job.job_id] = job


def _get_job(job_id: str) -> Job:
    with JOBS_LOCK:
        j = JOBS.get(job_id)
    if not j:
        raise HTTPException(status_code=404, detail="job_not_found")
    return j


def _update_job(job_id: str, **kwargs) -> None:
    with JOBS_LOCK:
        j = JOBS.get(job_id)
        if not j:
            return
        for k, v in kwargs.items():
            setattr(j, k, v)
        j.updated_ts = _now()


def _ensure_case(case_dir: str) -> None:
    p = Path(case_dir)
    if p.exists() and (p / "case.json").exists():
        return
    base = str(p.parent) if str(p.parent) not in ("", ".") else "cases"
    cid = p.name
    new_case(base, cid)


def _sanitize_stem(path_str: str) -> str:
    stem = Path(path_str).stem
    safe = []
    for ch in stem:
        safe.append(ch if ch.isalnum() else "_")
    return "".join(safe)


def _start_job(kind: str, case_dir: str) -> str:
    job_id = uuid.uuid4().hex
    job = Job(
        job_id=job_id,
        kind=kind,
        status="QUEUED",
        created_ts=_now(),
        updated_ts=_now(),
        case_dir=case_dir,
        detail="queued",
        result={},
        error="",
    )
    _put_job(job)
    return job_id


# -------------------------
# FastAPI app
# -------------------------

app = FastAPI(title="CyberShadow Local API", version="0.2.0")
from src.devices_api import router as devices_router
app.include_router(devices_router)
app.include_router(vt_router)

@app.get("/")
def root():
    return RedirectResponse(url="/docs")


@app.get("/health")
def health():
    return {"ok": True, "ts": _now()}


@app.get("/env")
def env():
    return {"versions": get_versions()}


@app.post("/cases")
def create_case(req: CreateCaseReq):
    path = new_case(req.base_dir, req.case_id)
    return {"case_dir": str(path)}


@app.get("/jobs/{job_id}")
def job_status(job_id: str):
    j = _get_job(job_id)
    d = asdict(j)
    if d.get("result") is None:
        d["result"] = {}
    return d


@app.get("/jobs")
def list_jobs(limit: int = 50):
    with JOBS_LOCK:
        items = list(JOBS.values())
    items.sort(key=lambda x: x.created_ts, reverse=True)
    return {"jobs": [asdict(j) for j in items[: max(1, min(limit, 200))]]}


# -------------------------
# Job runners
# -------------------------

def _job_run_static(job_id: str, req: RunStaticReq) -> None:
    _update_job(job_id, status="RUNNING", detail="static_analysis_started", error="")
    try:
        set_verbose(bool(req.verbose))
        _ensure_case(req.case_dir)

        add_evidence(req.case_dir, req.apk_path, "apk")
        copied_apk = str(Path(req.case_dir) / "evidence" / Path(req.apk_path).name)

        info = analyze_apk(copied_apk)
        suffix = req.tag if req.tag else _sanitize_stem(req.apk_path)
        artifact_name = f"apk_static__{suffix}.json"
        out_path = save_artifact(req.case_dir, artifact_name, info)

        _update_job(
            job_id,
            status="DONE",
            detail="static_analysis_done",
            result={
                "artifact": str(out_path),
                "scoring": info.get("scoring", {}),
            },
        )
    except Exception as e:
        _update_job(job_id, status="ERROR", detail="static_analysis_failed", error=str(e))


def _job_run_dynamic_adb(job_id: str, req: RunDynamicAdbReq) -> None:
    _update_job(job_id, status="RUNNING", detail="dynamic_adb_started", error="")
    try:
        _ensure_case(req.case_dir)

        add_evidence(req.case_dir, req.apk_path, "apk")
        copied_apk = str(Path(req.case_dir) / "evidence" / Path(req.apk_path).name)

        info = run_dynamic_adb(
            case_dir=req.case_dir,
            apk_path=copied_apk,
            tag=req.tag,
            device_serial=req.serial or None,
            duration_sec=int(req.duration_sec),
            monkey_events=int(req.monkey_events),
            clear_logcat=bool(req.clear_logcat),
            keep_installed=bool(req.keep_installed),
        )

        stamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        artifact_name = f"apk_dynamic__{req.tag}__{stamp}.json"
        out_path = save_artifact(req.case_dir, artifact_name, info)

        _update_job(
            job_id,
            status="DONE",
            detail="dynamic_adb_done",
            result={
                "artifact": str(out_path),
                "scoring": (info.get("scoring") or {}),
                "package": info.get("package", ""),
                "device": info.get("device", {}),
            },
        )
    except Exception as e:
        _update_job(job_id, status="ERROR", detail="dynamic_adb_failed", error=str(e))


# (Optional) FRIDA runner – îl lăsăm pe mai târziu, după ce ADB-only e stabil
def _job_run_dynamic_frida(job_id: str, req: RunDynamicFridaReq) -> None:
    _update_job(job_id, status="RUNNING", detail="dynamic_frida_started", error="")
    try:
        _ensure_case(req.case_dir)
        if _run_dynamic_analysis is None:
            raise RuntimeError("frida_run_dynamic_analysis_not_implemented")

        res = _run_dynamic_analysis(
            case_dir=req.case_dir,
            package=req.package,
            tag=req.tag,
            serial=req.serial,
            endpoint=req.endpoint,
            gadget_name=req.gadget_name,
            script=req.script,
            launch=req.launch,
            drive=req.drive,
            monkey_events=req.monkey_events,
            throttle_ms=req.throttle_ms,
            monkey_seed=req.monkey_seed,
            preflight=req.preflight,
            capture=req.capture,
            force_stop_after=req.force_stop_after,
        )

        _update_job(job_id, status="DONE", detail="dynamic_frida_done", result=(res or {}))
    except Exception as e:
        _update_job(job_id, status="ERROR", detail="dynamic_frida_failed", error=str(e))


# -------------------------
# Endpoints (start jobs)
# -------------------------

@app.post("/run/static")
def run_static(req: RunStaticReq):
    job_id = _start_job("static", req.case_dir)
    threading.Thread(target=_job_run_static, args=(job_id, req), daemon=True).start()
    return {"job_id": job_id}


@app.post("/run/dynamic_adb")
def run_dynamic_adb_endpoint(req: RunDynamicAdbReq):
    job_id = _start_job("dynamic_adb", req.case_dir)
    threading.Thread(target=_job_run_dynamic_adb, args=(job_id, req), daemon=True).start()
    return {"job_id": job_id}


@app.post("/run/dynamic_frida")
def run_dynamic_frida_endpoint(req: RunDynamicFridaReq):
    job_id = _start_job("dynamic_frida", req.case_dir)
    threading.Thread(target=_job_run_dynamic_frida, args=(job_id, req), daemon=True).start()
    return {"job_id": job_id}

from src.devices_api import router as devices_router
app.include_router(devices_router)
app.include_router(vt_router)


# ==========================================================
# EXTRA: Repack + Install workflow (Frida Gadget) + Uninstall
# ==========================================================
# Goal (user-friendly):
# - You drop a new APK (untested, not installed)
# - API checks if it is already Gadget-repacked
# - If not: repack with frida-gadget
# - Install (KEEP installed by default)
# - Uninstall is a separate explicit endpoint/button

import os
import zipfile

class RepackInstallReq(BaseModel):
    case_dir: str
    apk_path: str
    tag: str = "gadget"
    serial: str = ""
    gadget_so: str = "inputs/frida-gadget.so.xz"
    abi: str = "auto"
    port: int = 27042
    keep_installed: bool = True

class InstallReq(BaseModel):
    apk_path: str
    serial: str = ""
    reinstall: bool = True

class UninstallReq(BaseModel):
    package: str
    serial: str = ""
    keep_data: bool = True  # True -> adb uninstall -k

def _api_project_root() -> str:
    # api_local.py is typically in <root>/src/api_local.py
    try:
        return str(Path(__file__).resolve().parents[1])
    except Exception:
        return str(Path.cwd())

def _adb_base(serial: str) -> List[str]:
    # rely on PATH; UI already augments PATH with platform-tools when launching subprocess
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    return cmd

def _run_cmd_capture(cmd: List[str], timeout: int = 600) -> str:
    env = os.environ.copy()
    root = str(Path(__file__).resolve().parents[1])  # <root>/src/api_local.py -> parents[1] = root
    bt_root = os.path.join(root, "inputs", "build-tools")
    if os.path.isdir(bt_root):
        vers = sorted([d for d in os.listdir(bt_root) if os.path.isdir(os.path.join(bt_root, d))], reverse=True)
        if vers:
            bt = os.path.join(bt_root, vers[0])
            env["PATH"] = bt + os.pathsep + env.get("PATH", "")

    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    return p.stdout or ""

def _apk_has_gadget(apk_path: str) -> bool:
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            names = z.namelist()
        for n in names:
            nn = n.lower()
            # common gadget libs
            if "frida-gadget" in nn:
                return True
            if nn.endswith(".so") and ("gadget" in nn and "frida" in nn):
                return True
        return False
    except Exception:
        # if we can't read it, assume no
        return False

def _find_repack_tool() -> str:
    # Try a few common locations; you can keep the tool in tools/ or alongside api_local.py
    root = _api_project_root()
    cands = [
        str(Path(__file__).resolve().parent / "repack_with_gadget.py"),
        str(Path(root) / "tools" / "repack_with_gadget.py"),
        str(Path(root) / "src" / "tools" / "repack_with_gadget.py"),
    ]
    for p in cands:
        if os.path.exists(p):
            return p
    # last resort: just call the first candidate (will error clearly if missing)
    return cands[0]

def _repack_with_gadget(apk_path: str, gadget_so: str, abi: str, port: int) -> str:
    # Uses your existing tool. It prints: OUTPUT_APK=<path>
    py = sys.executable
    tool = _find_repack_tool()

    cmd = [py, tool, "--apk", apk_path, "--gadget_so", gadget_so, "--abi", abi, "--port", str(int(port))]
    out = _run_cmd_capture(cmd, timeout=1800)

    # parse OUTPUT_APK line
    m = re.search(r"OUTPUT_APK=(.+)", out)
    if not m:
        raise RuntimeError("repack_failed_no_output_apk\n" + out[-1500:])
    p = m.group(1).strip()
    if not os.path.isabs(p):
        p = os.path.abspath(p)
    if not os.path.exists(p):
        raise RuntimeError("repack_failed_output_missing\n" + p + "\n" + out[-1500:])
    return p

def _adb_install(apk_path: str, serial: str, reinstall: bool = True) -> str:
    cmd = _adb_base(serial) + ["install"]
    if reinstall:
        cmd += ["-r"]
    cmd += [apk_path]
    return _run_cmd_capture(cmd, timeout=600)

def _adb_uninstall(package: str, serial: str, keep_data: bool = True) -> str:
    cmd = _adb_base(serial) + ["uninstall"]
    if keep_data:
        cmd += ["-k"]
    cmd += [package]
    return _run_cmd_capture(cmd, timeout=300)

def _job_repack_install(job_id: str, req: RepackInstallReq) -> None:
    _update_job(job_id, status="RUNNING", detail="repack_install_started", error="")
    try:
        _ensure_case(req.case_dir)

        add_evidence(req.case_dir, req.apk_path, "apk")
        copied_apk = str(Path(req.case_dir) / "evidence" / Path(req.apk_path).name)

        used_apk = copied_apk
        already = _apk_has_gadget(copied_apk)

        if not already:
            repacked = _repack_with_gadget(copied_apk, req.gadget_so, req.abi, int(req.port))
            used_apk = repacked

        install_out = _adb_install(used_apk, req.serial, reinstall=True)

        _update_job(
            job_id,
            status="DONE",
            detail="repack_install_done" if not already else "install_done_already_repacked",
            result={
                "input_apk": copied_apk,
                "used_apk": used_apk,
                "already_repacked": bool(already),
                "install_output": install_out,
                "keep_installed": bool(req.keep_installed),
            },
        )
    except Exception as e:
        _update_job(job_id, status="ERROR", detail="repack_install_failed", error=str(e))

@app.post("/apk/check_repack")
def check_repack(req: InstallReq):
    if not req.apk_path or not os.path.exists(req.apk_path):
        raise HTTPException(status_code=400, detail="apk_not_found")
    return {"apk_path": req.apk_path, "has_gadget": _apk_has_gadget(req.apk_path)}

@app.post("/apk/install")
def apk_install(req: InstallReq):
    if not req.apk_path or not os.path.exists(req.apk_path):
        raise HTTPException(status_code=400, detail="apk_not_found")
    out = _adb_install(req.apk_path, req.serial, reinstall=bool(req.reinstall))
    return {"ok": True, "output": out}

@app.post("/apk/uninstall")
def apk_uninstall(req: UninstallReq):
    if not req.package:
        raise HTTPException(status_code=400, detail="package_missing")
    out = _adb_uninstall(req.package, req.serial, keep_data=bool(req.keep_data))
    return {"ok": True, "output": out}

@app.post("/run/repack_install")
def run_repack_install(req: RepackInstallReq):
    job_id = _start_job("repack_install", req.case_dir)
    threading.Thread(target=_job_repack_install, args=(job_id, req), daemon=True).start()
    return {"job_id": job_id}
