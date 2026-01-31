# tools/inject_gadget_config.py
import json
import zipfile
from pathlib import Path

INP = Path(r"C:\Users\Ionut\Downloads\catima_fixed.apk")
OUT = Path(r"C:\Users\Ionut\Downloads\catima_fixed_cfg_unsigned.apk")

CONFIG = {
    "interaction": {
        "type": "listen",
        "address": "127.0.0.1",
        "port": 27042,
        "on_port_conflict": "pick-next",
        "on_load": "resume",
    }
}

def main():
    if not INP.exists():
        raise FileNotFoundError(f"IN not found: {INP}")

    cfg_bytes = (json.dumps(CONFIG, indent=2) + "\n").encode("utf-8")

    with zipfile.ZipFile(INP, "r") as zin, zipfile.ZipFile(OUT, "w") as zout:
        names = zin.namelist()

        # copiem tot, dar forțăm resources.arsc necomprimat
        for info in zin.infolist():
            data = zin.read(info.filename)

            zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            zi.external_attr = info.external_attr
            zi.comment = info.comment
            zi.extra = info.extra
            zi.create_system = info.create_system

            if info.filename == "resources.arsc":
                zi.compress_type = zipfile.ZIP_STORED
            else:
                zi.compress_type = zipfile.ZIP_DEFLATED

            zout.writestr(zi, data)

        # adăugăm config lângă libfrida-gadget.so (arm64-v8a și armeabi-v7a dacă există)
        targets = []
        for abi in ("arm64-v8a", "armeabi-v7a", "x86_64", "x86"):
            so_path = f"lib/{abi}/libfrida-gadget.so"
            if so_path in names:
                targets.append(f"lib/{abi}/libfrida-gadget.config.so")

        if not targets:
            print("[WARN] No lib/*/libfrida-gadget.so found. Nothing to inject.")
        else:
            for t in targets:
                zout.writestr(t, cfg_bytes)
            print("[OK] Injected config:", *targets, sep="\n- ")

    print("[OK] OUT =", OUT)

if __name__ == "__main__":
    main()
