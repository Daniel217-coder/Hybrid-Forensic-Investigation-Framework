#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r"""
Repack APK with Frida Gadget (stable approach for non-root devices):
- Injects libfrida-gadget.so into lib/<abi>/
- Writes Gadget config in MULTIPLE locations to be robust:
    * assets/frida-gadget.config
    * lib/<abi>/libfrida-gadget.config
- Avoids breaking apps:
    * If manifest has a custom Application and we can find its smali, we patch attachBaseContext() to load gadget.
    * Otherwise, we fall back to our own Application class and set android:name safely.

Windows-friendly:
- prefers repo-bundled tools/apktool/apktool.cmd if present.
- copies gadget .so into work dir first to avoid PermissionError from Downloads/AV.

Outputs a line:
    OUTPUT_APK=<full_path>
"""

import argparse
import lzma
import os
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, List


# ---------------- utils ----------------

def force_extract_native_libs_true(manifest_path: str) -> None:
    import re

    xml = Path(manifest_path).read_text(encoding="utf-8", errors="replace")

    # If attribute exists, flip to true
    if "android:extractNativeLibs" in xml:
        xml2 = re.sub(
            r'android:extractNativeLibs\s*=\s*"false"',
            'android:extractNativeLibs="true"',
            xml,
            flags=re.IGNORECASE,
        )
        xml = xml2
    else:
        # Add attribute into <application ...>
        xml = re.sub(
            r"(<application\b)([^>]*)(>)",
            r'\1\2 android:extractNativeLibs="true"\3',
            xml,
            count=1,
            flags=re.IGNORECASE,
        )

    Path(manifest_path).write_text(xml, encoding="utf-8")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def must_exist(p: Path, what: str):
    if not p.exists():
        raise FileNotFoundError(f"{what} not found: {p}")


def run(cmd, check=True, cwd: Optional[Path] = None, capture=False):
    if capture:
        return subprocess.run(cmd, check=check, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return subprocess.run(cmd, check=check, cwd=cwd)


def which(exe: str) -> Optional[str]:
    return shutil.which(exe)


def find_tool_candidates(project_root: Path) -> Tuple[str, ...]:
    return (
        str(project_root / "tools" / "apktool" / "apktool.cmd"),
        str(project_root / "tools" / "apktool" / "apktool.bat"),
        "apktool",
        "apktool.bat",
        "apktool.cmd",
    )


def find_apktool(project_root: Path) -> str:
    for c in find_tool_candidates(project_root):
        if c in ("apktool", "apktool.bat", "apktool.cmd"):
            w = which(c)
            if w:
                return w
        else:
            if Path(c).exists():
                return c
    raise FileNotFoundError("Tool 'apktool' not found. Put tools/apktool/apktool.cmd in repo or add apktool to PATH.")


def _infer_sdk_root_from_adb(adb_path: str) -> Optional[Path]:
    try:
        p = Path(adb_path).resolve()
        # .../platform-tools/adb(.exe) -> SDK root is parent of platform-tools
        if p.parent.name == "platform-tools":
            return p.parent.parent
    except Exception:
        pass
    return None


def find_android_sdk_tool(name: str) -> str:
    """
    Finds adb/zipalign/apksigner etc.
    Supports:
      - ANDROID_SDK_ROOT / ANDROID_HOME
      - repo-local portable tools: <repo>/inputs/build-tools/<ver>/
    On Windows, apksigner is usually apksigner.bat (NOT .exe).
    """
    # allow explicit overrides
    if name.lower() == "adb":
        env_adb = os.environ.get("ADB_PATH")
        if env_adb and Path(env_adb).exists():
            return str(Path(env_adb))

    candidates: List[Path] = []

    def add_build_tools_folder(bt: Path):
        if not bt.exists():
            return
        vers = sorted([p for p in bt.iterdir() if p.is_dir()], reverse=True)
        for v in vers[:12]:
            if os.name == "nt":
                candidates.extend([
                    v / (name + ".exe"),
                    v / (name + ".bat"),
                    v / (name + ".cmd"),
                    v / name,
                ])
            else:
                candidates.extend([v / name, v / (name + ".sh")])

    # 1) Android SDK env
    sdk = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if sdk:
        sdkp = Path(sdk)
        if name.lower() == "adb":
            candidates += [sdkp / "platform-tools" / "adb.exe", sdkp / "platform-tools" / "adb"]
        else:
            add_build_tools_folder(sdkp / "build-tools")

    # 2) repo-local portable build-tools: <repo>/inputs/build-tools
    # repack_with_gadget.py is in <repo>/tools/, so repo = parents[1]
    try:
        repo_root = Path(__file__).resolve().parents[1]
        add_build_tools_folder(repo_root / "inputs" / "build-tools")
    except Exception:
        pass

    for c in candidates:
        if c.exists():
            return str(c)

    # 3) fallback PATH
    w = which(name) or which(name + ".exe") or which(name + ".bat") or which(name + ".cmd")
    if w:
        return w

    raise FileNotFoundError(
        f"Android SDK tool not found: {name}. "
        f"Install Android SDK Build-Tools (for zipalign/apksigner) and set ANDROID_SDK_ROOT, "
        f"or place tools under inputs/build-tools/<ver>/, or put tools in PATH.")

    # allow explicit overrides
    if name.lower() == "adb":
        env_adb = os.environ.get("ADB_PATH")
        if env_adb and Path(env_adb).exists():
            return str(Path(env_adb))

    sdk = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    candidates = []

    if sdk:
        sdkp = Path(sdk)
        if name == "adb":
            candidates += [sdkp / "platform-tools" / "adb.exe", sdkp / "platform-tools" / "adb"]
        else:
            bt = sdkp / "build-tools"
            if bt.exists():
                vers = sorted([p for p in bt.iterdir() if p.is_dir()], reverse=True)
                for v in vers[:8]:
                    candidates += [v / (name + ".exe"), v / name]

    for c in candidates:
        if c.exists():
            return str(c)

        # --- NEW: allow vendored build-tools inside repo: inputs/build-tools/<ver> ---
    try:
        repo_root = Path(__file__).resolve().parents[1]  # tools/ -> repo root
        local_bt = repo_root / "inputs" / "build-tools"

        if name == "adb":
            # optional: inputs/platform-tools/adb(.exe)
            pt = repo_root / "inputs" / "platform-tools"
            for cc in [v / (name + ".exe"), v / (name + ".bat"), v / (name + ".cmd"), v / name]:
                if cc.exists():
                    return str(cc)


        if local_bt.exists() and local_bt.is_dir() and name != "adb":
            vers = sorted([p for p in local_bt.iterdir() if p.is_dir()], reverse=True)
            for v in vers[:8]:
                for cc in [v / (name + ".exe"), v / name]:
                    if cc.exists():
                        return str(cc)
    except Exception:
        pass


    # fallback PATH
    w = which(name) or which(name + ".exe") or which(name + ".bat") or which(name + ".cmd")
    if w:
        return w

    raise FileNotFoundError(
        f"Android SDK tool not found: {name}. "
        f"Install Android SDK Build-Tools (for zipalign/apksigner) and set ANDROID_SDK_ROOT, "
        f"or put tools in PATH."
    )


# ---------------- adb helpers ----------------

def adb_cmd(adb_path: str, serial: Optional[str], *args: str):
    cmd = [adb_path]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    return cmd


def adb_shell(adb_path: str, serial: str, sh: str, capture=False, check=True):
    return run(adb_cmd(adb_path, serial, "shell", sh), capture=capture, check=check)


def resolve_apk_from_device(adb_path: str, serial: str, pkg: str) -> str:
    cp = adb_shell(adb_path, serial, f"pm path --user 0 {pkg}", capture=True, check=True)
    out = (cp.stdout or "").strip()
    m = re.search(r"package:(\S+)", out)
    if not m:
        raise RuntimeError(f"Could not resolve apk path for {pkg}. pm output:\n{out}")
    return m.group(1)


# ---------------- APK parsing / patching ----------------

def detect_abi_from_apk(apk_path: Path) -> Optional[str]:
    with zipfile.ZipFile(apk_path, "r") as z:
        abis = set()
        for n in z.namelist():
            if n.startswith("lib/") and n.count("/") >= 2:
                parts = n.split("/")
                if len(parts) >= 3:
                    abis.add(parts[1])
        for pref in ("arm64-v8a", "armeabi-v7a", "x86_64", "x86"):
            if pref in abis:
                return pref
        return sorted(abis)[0] if abis else None


def read_manifest_application_name(decoded_dir: Path) -> Optional[str]:
    mf = decoded_dir / "AndroidManifest.xml"
    if not mf.exists():
        return None
    txt = mf.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r"<application\b[^>]*\bandroid:name\s*=\s*(['\"])(.+?)\1", txt)
    if not m:
        return None
    name = (m.group(2) or "").strip()
    return name or None


def read_manifest_package(decoded_dir: Path) -> Optional[str]:
    mf = decoded_dir / "AndroidManifest.xml"
    if not mf.exists():
        return None
    txt = mf.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r"<manifest\b[^>]*\bpackage\s*=\s*(['\"])(.+?)\1", txt)
    if not m:
        return None
    return (m.group(2) or "").strip() or None


def set_manifest_application_name(decoded_dir: Path, new_name: str):
    """
    Safer regex patch:
    - If android:name exists with ' or " -> replace value.
    - Else inject android:name="..." right after <application
    """
    mf = decoded_dir / "AndroidManifest.xml"
    txt = mf.read_text(encoding="utf-8", errors="ignore")

    # replace if present
    if re.search(r"<application\b[^>]*\bandroid:name\s*=", txt):
        txt2 = re.sub(
            r"(<application\b[^>]*\bandroid:name\s*=\s*)(['\"])(.+?)(\2)",
            r"\1" + '"' + new_name + '"' ,
            txt,
            count=1
        )
    else:
        txt2 = re.sub(
            r"<application\b",
            r'<application android:name="' + new_name + r'"',
            txt,
            count=1
        )

    mf.write_text(txt2, encoding="utf-8")


def class_name_to_smali_relpath(cls: str) -> str:
    cls = cls.lstrip(".")
    return cls.replace(".", "/") + ".smali"


def find_smali_file(decoded_dir: Path, fqcn: str) -> Optional[Path]:
    rel = class_name_to_smali_relpath(fqcn)
    for smali_root in decoded_dir.glob("smali*"):
        cand = smali_root / rel
        if cand.exists():
            return cand
    return None


def parse_super_class(smali_text: str) -> Optional[str]:
    m = re.search(r"^\s*\.super\s+(L[^;]+;)\s*$", smali_text, re.MULTILINE)
    return m.group(1) if m else None


def ensure_attachbasecontext_injection(smali_path: Path) -> bool:
    s = smali_path.read_text(encoding="utf-8", errors="ignore")

    gadget_snip = (
        '    const-string v0, "frida-gadget"\n'
        '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
    )

    m = re.search(
        r"(^\.method[^\n]*\battachBaseContext\(Landroid/content/Context;\)V[^\n]*\n)(.*?)(^\s*\.end method\s*$)",
        s,
        flags=re.MULTILINE | re.DOTALL
    )

    if m:
        head, body, endm = m.group(1), m.group(2), m.group(3)

        # ensure locals/registers
        if re.search(r"^\s*\.locals\s+\d+\s*$", body, re.MULTILINE):
            body = re.sub(r"^\s*\.locals\s+0\s*$", "    .locals 1", body, flags=re.MULTILINE)
        elif re.search(r"^\s*\.registers\s+\d+\s*$", body, re.MULTILINE):
            # need at least 2 registers (p0,p1) plus v0 => 3 is safe, but keep minimal if already >=3
            mr = re.search(r"^\s*\.registers\s+(\d+)\s*$", body, re.MULTILINE)
            if mr and int(mr.group(1)) < 3:
                body = re.sub(r"^\s*\.registers\s+\d+\s*$", "    .registers 3", body, flags=re.MULTILINE)
        else:
            body = "    .locals 1\n" + body

        lines = body.splitlines(True)
        out = []
        inserted = False
        i = 0
        while i < len(lines):
            out.append(lines[i])
            if re.match(r"^\s*\.(locals|registers)\b", lines[i]):
                i += 1
                while i < len(lines) and re.match(r"^\s*\.(param|prologue|line)\b", lines[i]):
                    out.append(lines[i])
                    i += 1
                if not inserted:
                    out.append(gadget_snip)
                    inserted = True
                continue
            i += 1

        if not inserted:
            out = [gadget_snip] + out

        new_body = "".join(out)
        s2 = s[:m.start()] + head + new_body + endm + s[m.end():]
        smali_path.write_text(s2, encoding="utf-8")
        return True

    # Method missing: create it
    super_cls = parse_super_class(s) or "Landroid/app/Application;"
    method_block = (
        "\n.method protected attachBaseContext(Landroid/content/Context;)V\n"
        "    .locals 1\n"
        f"    invoke-super {{p0, p1}}, {super_cls}->attachBaseContext(Landroid/content/Context;)V\n"
        '    const-string v0, "frida-gadget"\n'
        '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
        "    return-void\n"
        ".end method\n"
    )

    s2 = re.sub(r"^\s*\.end class\s*$", method_block + "\n.end class", s, flags=re.MULTILINE)
    if s2 == s:
        s2 = s + "\n" + method_block + "\n"
    smali_path.write_text(s2, encoding="utf-8")
    return True


def write_gadget_config_assets(decoded_dir: Path, port: int):
    assets = decoded_dir / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    (assets / "frida-gadget.config").write_text(
        "{\n"
        '  "interaction": {\n'
        '    "type": "listen",\n'
        '    "address": "0.0.0.0",\n'
        f'    "port": {port},\n'
        '    "on_load": "resume"\n'
        "  }\n"
        "}\n",
        encoding="utf-8"
    )


def write_gadget_config_lib(decoded_dir: Path, abi: str, port: int):
    libdir = decoded_dir / "lib" / abi
    libdir.mkdir(parents=True, exist_ok=True)
    (libdir / "libfrida-gadget.config").write_text(
        "{\n"
        '  "interaction": {\n'
        '    "type": "listen",\n'
        '    "address": "0.0.0.0",\n'
        f'    "port": {port},\n'
        '    "on_load": "resume"\n'
        "  }\n"
        "}\n",
        encoding="utf-8"
    )


def inject_gadget_so(decoded_dir: Path, gadget_so: Path, abi: str):
    libdir = decoded_dir / "lib" / abi
    libdir.mkdir(parents=True, exist_ok=True)
    target = libdir / "libfrida-gadget.so"
    shutil.copyfile(gadget_so, target)


def materialize_gadget_local(gadget_in: Path, work_dir: Path) -> Path:
    """
    Always produce a readable .so inside work_dir, even if input is a .so locked by AV/Downloads.
    Supports .xz input too.
    """
    work_dir.mkdir(parents=True, exist_ok=True)

    if gadget_in.suffix.lower() == ".xz":
        out = work_dir / gadget_in.name[:-3]
        data = lzma.open(gadget_in, "rb").read()
        out.write_bytes(data)
        return out

    # plain .so => copy into work dir
    out = work_dir / gadget_in.name
    shutil.copyfile(gadget_in, out)
    return out


# ---------------- signing ----------------

def ensure_debug_keystore(project_root: Path) -> Path:
    ks = project_root / "tools" / "debug.keystore"
    if ks.exists():
        return ks
    ks.parent.mkdir(parents=True, exist_ok=True)
    keytool = which("keytool") or which("keytool.exe")
    if not keytool:
        raise FileNotFoundError("keytool not found (need JDK). Install a JDK and ensure keytool is in PATH.")
    run([
        keytool, "-genkeypair",
        "-keystore", str(ks),
        "-storepass", "android",
        "-keypass", "android",
        "-alias", "androiddebugkey",
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-dname", "CN=Android Debug,O=Android,C=US"
    ], check=True)
    return ks


# ---------------- main ----------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial", help="adb serial (device id)")
    ap.add_argument("--pkg", help="package name on device (to pull base.apk)")
    ap.add_argument("--apk", help="local APK path (skip pulling from device)")
    ap.add_argument("--gadget_so", required=True, help="frida-gadget-...so OR .so.xz")
    ap.add_argument("--abi", default="auto", help="arm64-v8a / armeabi-v7a / x86_64 / x86 / auto")
    ap.add_argument("--port", type=int, default=27042)

    args = ap.parse_args()

    project_root = Path(__file__).resolve().parents[1]
    artifacts_root = project_root / "artifacts" / "repack_work" / f"work_{utc_stamp()}"
    artifacts_root.mkdir(parents=True, exist_ok=True)

    gadget_in = Path(args.gadget_so).expanduser()
    must_exist(gadget_in, "Gadget .so/.xz")

    # Make gadget readable locally (avoid PermissionError from Downloads)
    gadget_so = materialize_gadget_local(gadget_in, artifacts_root)
    must_exist(gadget_so, "Materialized gadget .so")

    adb = find_android_sdk_tool("adb")

    # Resolve APK input
    if args.apk:
        apk = Path(args.apk).expanduser()
        must_exist(apk, "APK")
    else:
        if not args.serial or not args.pkg:
            raise ValueError("Provide --apk OR (--serial and --pkg).")
        remote_apk = resolve_apk_from_device(adb, args.serial, args.pkg)
        inputs_dir = project_root / "inputs"
        inputs_dir.mkdir(parents=True, exist_ok=True)
        apk = inputs_dir / f"{args.pkg}__base.apk"
        run(adb_cmd(adb, args.serial, "pull", remote_apk, str(apk)), check=True)

    apktool = find_apktool(project_root)

    # Decode
    dec = artifacts_root / "dec"
    if dec.exists():
        shutil.rmtree(dec, ignore_errors=True)
    run([apktool, "d", "-f", str(apk), "-o", str(dec)], check=True)
    # FIX: avoid INSTALL_FAILED_INVALID_APK (native libs extraction issues)
    force_extract_native_libs_true(str(dec / "AndroidManifest.xml"))

    # Determine ABI
    abi = args.abi
    if abi == "auto":
        abi = detect_abi_from_apk(apk) or "arm64-v8a"

    # Inject gadget .so + config (both locations)
    inject_gadget_so(dec, gadget_so, abi)
    write_gadget_config_assets(dec, args.port)
    write_gadget_config_lib(dec, abi, args.port)

    # Patch existing Application if possible
    app_name = read_manifest_application_name(dec)
    manifest_pkg = read_manifest_package(dec)
    patched = False

    if app_name and app_name not in ("android.app.Application", ".android.app.Application"):
        fqcn = app_name
        if fqcn.startswith(".") and manifest_pkg:
            fqcn = manifest_pkg + fqcn

        smali_path = find_smali_file(dec, fqcn)
        if smali_path and smali_path.exists():
            patched = ensure_attachbasecontext_injection(smali_path)

    # Fallback: create our own Application and set manifest safely
    if not patched:
        new_app = "com.cybershadow.GadgetAppProxy"
        pkg_path = dec / "smali" / "com" / "cybershadow"
        pkg_path.mkdir(parents=True, exist_ok=True)
        out_smali = pkg_path / "GadgetAppProxy.smali"

        smali = (
            ".class public Lcom/cybershadow/GadgetAppProxy;\n"
            ".super Landroid/app/Application;\n"
            "\n"
            ".method public constructor <init>()V\n"
            "    .locals 0\n"
            "    invoke-direct {p0}, Landroid/app/Application;-><init>()V\n"
            "    return-void\n"
            ".end method\n"
            "\n"
            ".method protected attachBaseContext(Landroid/content/Context;)V\n"
            "    .locals 1\n"
            "    invoke-super {p0, p1}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V\n"
            "    const-string v0, \"frida-gadget\"\n"
            "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
            "    return-void\n"
            ".end method\n"
        )
        out_smali.write_text(smali, encoding="utf-8")
        set_manifest_application_name(dec, new_app)

    # Build
    unsigned_apk = artifacts_root / "rebuilt-unsigned.apk"
    run([apktool, "b", str(dec), "-o", str(unsigned_apk)], check=True)

    zipalign = find_android_sdk_tool("zipalign")
    apksigner = find_android_sdk_tool("apksigner")
    ks = ensure_debug_keystore(project_root)

    aligned_apk = artifacts_root / "aligned.apk"
    run([zipalign, "-f", "4", str(unsigned_apk), str(aligned_apk)], check=True)

    out_dir = project_root / "inputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_name = (apk.stem + f"__gadget_{utc_stamp()}.apk").replace("__base", "__base")
    out_apk = out_dir / out_name

    run([
        apksigner, "sign",
        "--ks", str(ks),
        "--ks-key-alias", "androiddebugkey",
        "--ks-pass", "pass:android",
        "--key-pass", "pass:android",
        "--out", str(out_apk),
        str(aligned_apk)
    ], check=True)

    run([apksigner, "verify", "--verbose", str(out_apk)], check=True)

    print(f"OUTPUT_APK={out_apk}")


if __name__ == "__main__":
    main()
