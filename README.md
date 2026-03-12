# HFIF — Hybrid Forensic Investigation Framework

**Android APK (Static + Real-Device Dynamic) • Runtime Artifacts • Explainable Risk Scoring • (Optional) VT/YARA/Deepfake**

HFIF is a **case-oriented** forensic framework that organizes evidence and derived artifacts into a reproducible pipeline:

* **APK static triage** (manifest/package signals + explainable reasons)
* **Real-device dynamic analysis (non-root friendly)** using **Frida Gadget + ADB port forwarding**
* **Per-case artifacts + HTML reports** (analyst-friendly)
* **Integrity & traceability**: SHA-256 hashes 
* **Risk scoring**: weights + synergy + benign-aware cap + “malicious-unlock”

> **⚠️ Disclaimer:** Use only on apps/media you own or have explicit permission to analyze. Prefer a dedicated test phone.

---

## Table of Contents
- [Quick Start](#quick-start)
- [Requirements](#requirements)
- [Install](#install)
- [Core Commands](#core-commands)
- [Real-Device Dynamic (Frida Gadget + ADB)](#real-device-dynamic-frida-gadget--adb)
- [Artifacts & Reports](#artifacts--reports)
- [Risk Scoring Model](#risk-scoring-model)
- [GUI](#gui)
- [Troubleshooting](#troubleshooting)
- [Tools & References](#tools--references)

---

## Quick Start

1.  **Create a case**
    ```bash
    python -m src.main new-case --id CASE_001 --base cases
    ```

2.  **Run static analysis on an APK**
    ```bash
    python -m src.main apk-static --case cases/CASE_001 --apk path/to/app.apk --tag run1 --verbose
    ```

3.  **(Optional) Run real-device dynamic analysis** (package name required)
    ```bash
    python -m src.main apk-dynamic --case cases/CASE_001 --package com.example.app --tag dyn1 --serial <DEVICE_SERIAL>
    ```

4.  **Generate the consolidated case report**
    ```bash
    python -m src.main case-report --case cases/CASE_001 --risk-mode latest
    ```

---

## Requirements

### Core
* **Python 3.10+**
* **ADB (Android SDK Platform-Tools)** in PATH (or set `ADB_PATH`)
* **Frida Python packages** (runner uses Frida tooling)
* **Real Android device** with:
    * Developer options enabled
    * USB debugging enabled

### Optional (only if you use them)
* **GUI:** `customtkinter`, `tkinterweb`
* **Deepfake inference:** `torch`, `torchvision`, `opencv-python`, `pillow`
* **Integrations:** YARA / VirusTotal / MemLite (if present in your build)

---

## Install

### 1) Create venv
```bash
python -m venv .venv

```

### 2) Activate

* **Windows (PowerShell):**
```powershell
.\.venv\Scripts\Activate.ps1

```

* **Linux/macOS:**
```bash
source .venv/bin/activate

```

### 3) Install deps

If you have a `requirements.txt`:

```bash
pip install -r requirements.txt

```

**Minimal baseline for the Android pipeline:**

```bash
pip install frida frida-tools

```

**GUI (optional):**

```bash
pip install customtkinter tkinterweb

```

**Deepfake (optional, heavy):**

```bash
pip install torch torchvision opencv-python pillow

```

---

## Core Commands

HFIF exposes the CLI via `src.main`. List all commands with:

```bash
python -m src.main --help

```

### Case Management

```bash
python -m src.main new-case --id CASE_001 --base cases
python -m src.main add-evidence --case cases/CASE_001 --file path/to/file --type apk

```

### Static APK

```bash
python -m src.main apk-static --case cases/CASE_001 --apk path/to/app.apk --tag run1 --verbose

```

### Dynamic APK (Real Device)

```bash
python -m src.main apk-dynamic \
  --case cases/CASE_001 \
  --package com.example.app \
  --tag dyn1 \
  --serial <DEVICE_SERIAL> \
  --capture 90 \
  --preflight 30 \
  --drive monkey \
  --monkey-events 1200 \
  --throttle-ms 90 \
  --endpoint 127.0.0.1:27042 \
  --gadget-name Gadget \
  --script src/cybershadow_dyn.js

```

### One-shot Pipeline (Static + Optional Dynamic + Reports + Ledger)

```bash
python -m src.main run-apk \
  --case cases/CASE_001 \
  --apk path/to/app.apk \
  --tag run1 \
  --dynamic \
  --serial <DEVICE_SERIAL> \
  --capture 90 \
  --drive monkey

```

### Reports

```bash
python -m src.main report-html --case cases/CASE_001
python -m src.main case-report --case cases/CASE_001 --risk-mode latest

```

### Utilities

```bash
# Environment info
python -m src.main env

# ADB smoke test (useful on real phones)
python -m src.dyn_smoke_test

```

---

## Real-Device Dynamic (Frida Gadget + ADB)

HFIF is optimized for **non-root real devices**, where `frida-server` attach/spawn can be unreliable.
**Recommended approach:** Embed Frida Gadget in the APK and connect through ADB forwarding.

### 1) Verify device connectivity

```bash
adb devices

```

### 2) Patch APK with Frida Gadget

Many workflows use **Objection**:

```bash
pip install objection
objection patchapk --source path/to/app.apk --architecture arm64-v8a
adb install -r <patched.apk>

```

*Note: Pick the correct architecture for your device (often `arm64-v8a`).*

### 3) Run HFIF dynamic capture

```bash
python -m src.main apk-dynamic --case cases/CASE_001 --package com.example.app --tag dyn1 --serial <DEVICE_SERIAL>

```

### Manual fallback (if needed)

```bash
adb -s <DEVICE_SERIAL> forward --remove-all
adb -s <DEVICE_SERIAL> forward tcp:27042 tcp:27042
adb -s <DEVICE_SERIAL> forward tcp:27043 tcp:27043

adb -s <DEVICE_SERIAL> shell "monkey -p com.example.app -c android.intent.category.LAUNCHER 1"
frida -H 127.0.0.1:27042 -n Gadget -l src/cybershadow_dyn.js

```

---

## Artifacts & Reports

Everything is stored per case in the `cases/` directory:

```text
cases/CASE_001/
  ├── case.json
  ├── evidence/
  ├── artifacts/
  │    ├── apk_static__<tag>.json
  │    └── apk_dynamic__<tag>.json (produced by Frida runner)
  └── reports/
       ├── *.html (module reports)
       └── case__CASE_001.html (final consolidated report)

```
---

## Risk Scoring Model

HFIF computes a normalized risk score **R ∈ [0,100]** from:

* Signals  (observed or not)
* Weights  (importance of each signal)
* Synergy conditions  with boosts  (e.g., Network ∧ SMS)

### Math

A boolean **malicious-unlock** flag  becomes **1** for high-confidence triggers (e.g., .onion, direct IP contact, YARA hit, strong synergy).

**Final Score:**

### Fallback (Text)

```
R_raw = min(100, R0 + Σ(w_i * s_i) + Σ(b_j * c_j))

if U == 0:
  R = min(R_raw, 19)   # benign-aware cap (keeps benign apps < 20)
else:
  R = R_raw            # allow malware to reach high-risk bands

```

---

## GUI

If you use the GUI module:

```bash
python -m src.ui.app

```

*Requires `customtkinter` and `tkinterweb`.*

---

## Troubleshooting

### `adb` not found

Install Platform-Tools and add to PATH, or set `ADB_PATH`.
**Windows (PowerShell):**

```powershell
$env:ADB_PATH="C:\Users\<YOU>\AppData\Local\Android\Sdk\platform-tools\adb.exe"

```

**Verify:**

```bash
adb version

```

### Device shows offline

```bash
adb kill-server
adb start-server
adb devices

```

*Reconnect USB and accept the RSA prompt on the phone.*

### Frida/Gadget not reachable

1. Confirm you installed the patched APK (with Gadget).
2. Launch app once manually.
3. Re-apply forwarding:
```bash
adb -s <DEVICE_SERIAL> forward --remove-all
adb -s <DEVICE_SERIAL> forward tcp:27042 tcp:27042
adb -s <DEVICE_SERIAL> forward tcp:27043 tcp:27043

```



---

## Tools & References

* **ADB:** [Android Platform-Tools]()
* **Frida:** [frida.re]() • [Gadget Docs]() • [GitHub]()
* **Objection (Patching):** [GitHub]()
* **Apktool:** [iBotPeaches/Apktool]()
* **JADX:** [skylot/jadx]()
* **Androguard:** [androguard/androguard]()
* **YARA:** [VirusTotal/yara]()
* **VirusTotal API:** [Documentation]()
* **Volatility3:** [volatilityfoundation/volatility3]()

```


```

