# src/dyn_smoke_test.py
import os
import shutil
import subprocess
from pathlib import Path


def find_adb() -> str:
    r"""
    Find adb.exe reliably on Windows.
    Priority:
      1) ADB_PATH env var (if you set it)
      2) adb in PATH
      3) default Android SDK location: %LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe
      4) ANDROID_SDK_ROOT / ANDROID_HOME
    """
    adb = os.environ.get("ADB_PATH", "").strip()
    if adb and Path(adb).exists():
        return adb

    adb = shutil.which("adb")
    if adb:
        return adb

    localapp = os.environ.get("LOCALAPPDATA", "")
    candidate = Path(localapp) / "Android" / "Sdk" / "platform-tools" / "adb.exe"
    if candidate.exists():
        return str(candidate)

    for k in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        root = os.environ.get(k, "").strip()
        if root:
            c = Path(root) / "platform-tools" / "adb.exe"
            if c.exists():
                return str(c)

    raise FileNotFoundError("adb.exe not found. Put adb in PATH or set ADB_PATH env var.")


def run(cmd: list[str], timeout: int = 25) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    out = (p.stdout or "") + (p.stderr or "")
    return out.strip()


def pick_device(adb: str) -> str:
    out = run([adb, "devices"])
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    devs = []
    for l in lines[1:]:
        parts = l.split()
        if len(parts) >= 2 and parts[1] == "device":
            devs.append(parts[0])
    if not devs:
        raise RuntimeError(f"No device found.\n\n{out}")
    # prefer emulator if present
    for d in devs:
        if d.startswith("emulator-"):
            return d
    return devs[0]


def _safe_int(s: str, default: int = 0) -> int:
    try:
        return int(str(s).strip())
    except Exception:
        return default


def get_current_user(adb: str, device: str) -> int:
    """
    Android 10+ supports:
      - am get-current-user
      - cmd activity get-current-user
    We'll try both; fallback to 0 (owner).
    """
    out = run([adb, "-s", device, "shell", "am", "get-current-user"])
    uid = _safe_int(out, -1)
    if uid >= 0:
        return uid

    out = run([adb, "-s", device, "shell", "cmd", "activity", "get-current-user"])
    uid = _safe_int(out, -1)
    if uid >= 0:
        return uid

    return 0


def list_packages(adb: str, device: str, user_id: int) -> str:
    """
    On some Android 13 builds, `pm list packages` may try to resolve other users/profiles
    and fail with SecurityException. Force a specific user to avoid false errors.
    """
    out = run([adb, "-s", device, "shell", "pm", "list", "packages", "--user", str(user_id)])
    if "SecurityException" in out or "does not have permission to access user" in out:
        # fallback to owner (user 0)
        out = run([adb, "-s", device, "shell", "pm", "list", "packages", "--user", "0"])
    return out


def main():
    adb = find_adb()
    device = pick_device(adb)

    print(f"[OK] adb: {adb}")
    print(f"[OK] device: {device}")
    print("\n--- adb devices ---")
    print(run([adb, "devices"]))

    print("\n--- Android version ---")
    print(run([adb, "-s", device, "shell", "getprop", "ro.build.version.release"]))

    print("\n--- Model ---")
    print(run([adb, "-s", device, "shell", "getprop", "ro.product.model"]))

    print("\n--- Boot completed? (1 = yes) ---")
    print(run([adb, "-s", device, "shell", "getprop", "sys.boot_completed"]))

    user_id = get_current_user(adb, device)
    print("\n--- Current Android user ---")
    print(user_id)

    print("\n--- Sample packages (first ~25) ---")
    pkgs = list_packages(adb, device, user_id=user_id)
    lines = [l for l in pkgs.splitlines() if l.strip()]
    print("\n".join(lines[:25]))
    print(f"\n[OK] packages count (approx): {len(lines)}")


if __name__ == "__main__":
    main()
