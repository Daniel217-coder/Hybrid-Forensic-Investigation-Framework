# HFIF — Hybrid Forensic Investigation Framework

**Android APK (Static + Real-Device Dynamic) • Runtime Artifacts • Explainable Risk Scoring • Optional VT/YARA/Deepfake**

HFIF is a **case-oriented** forensic framework that analyzes Android applications and related evidence in a reproducible workflow. The project is organized around **per-case evidence**, **derived JSON artifacts** and **HTML reports**.

The current build focuses on:

- **Static APK triage** using Androguard

- **Real-device dynamic analysis** on a **physical Android phone** using **Frida Gadget + ADB forwarding**

- **Analyst-friendly HTML reporting**

- **Risk scoring** based on weighted signals, synergy conditions, and a benign-aware cap

> **Disclaimer:** Use this framework only on software or media you own or are explicitly authorized to analyze. For dynamic analysis, use a dedicated test phone whenever possible.

---

## Table of Contents

- [1. Project Scope](#1-project-scope)

- [2. Repository Structure](#2-repository-structure)

- [3. Environment Used in Development](#3-environment-used-in-development)

- [4. Tools Installed](#4-tools-installed)

- [5. Python Dependencies](#5-python-dependencies)

- [6. Installation](#6-installation)

- [7. Core Commands](#7-core-commands) 

- [8. Real-Device Dynamic Analysis Workflow](#8-real-device-dynamic-analysis-workflow)

- [9. How We Tested the Framework](#9-how-we-tested-the-framework)

- [10. Example Test Commands Used in Practice](#10-example-test-commands-used-in-practice)

- [11. Artifacts and Reports](#11-artifacts-and-reports)

- [12. Scoring Model](#12-scoring-model)

- [13. GUI — Testing the Application](#13-gui--testing-the-application) 

- [14. Troubleshooting](#14-troubleshooting)

- [15. Notes for Dissertation Reproducibility](#15-notes-for-dissertation-reproducibility)

- [16. References / Tools](#16-references--tools)

---

## 1. Project Scope

HFIF was designed for a hybrid forensic workflow where multiple evidence sources can be analyzed inside the same case:

1. **APK Static Analysis** — manifest, permissions, components, strings, code hints, certificates, and explainable static risk.

2. **APK Dynamic Analysis** — runtime behavior captured on a **real Android device**, not on an emulator, using **Frida Gadget** and **ADB**.

3. **Case Reporting** — module-specific HTML reports and a final consolidated case report.

4. **Optional Extensions** — YARA, VirusTotal enrichment, memory-adjacent artifacts (MemLite), and deepfake/media analysis.

The design goal of the current dynamic pipeline is conservative scoring:

- **Benign applications should remain below 20** unless strong high-confidence evidence exists.

- **Malicious applications should exceed 60–70** when hard runtime indicators or strong combinations are present.

---

## 2. Repository Structure

The project is modular and case-oriented:

```text
src/

  apk_static.py           # static APK analysis

  apk_dynamic.py          # lightweight dynamic path (ADB-based)

  frida_auto.py           # real-device Frida Gadget runner

  dyn_smoke_test.py       # ADB sanity check for real device

  case_manager.py         # case creation / evidence / artifact helpers

  report_html.py          # module report generation

  case_report.py          # consolidated case report

  env_report.py           # environment/version summary

  cybershadow_dyn.js      # Frida JavaScript hooks

  ui/app.py               # desktop GUI

  ui/deepfake_ui.py       # optional deepfake UI
```

---

## 3. Environment Used in Development

The framework was developed and tested primarily in the following setup:

- **Host OS:** Windows 11

- **Python:** 3.10+

- **Dynamic target:** **real Android phone connected over USB via ADB**

- **Dynamic model:** **Frida Gadget embedded in the APK**, then attached through **ADB port forwarding**

- **Why real device:** this avoids many emulator-only artifacts and better reflects realistic behavior for modern Android apps

Important practical note: the current dynamic workflow is intentionally built around **physical-device analysis**, because `frida-server` attach/spawn is often unreliable on non-root production phones. The codebase reflects this by launching `frida_auto.py` as the dynamic runner and exposing `apk-dynamic` and `run-apk --dynamic` directly from `src.main`.

---

## 4. Tools Installed

This section explains **what was installed outside Python**, **why**, and **where to download each tool**.

### 4.1 Required external tools

#### ADB / Android SDK Platform-Tools

**What it does:** device detection, USB debugging, launching apps, logcat capture, port forwarding for Frida Gadget.

**Where to download:**
- **Option A (standalone — recommended):** Download *SDK Platform-Tools* from Google:
  https://developer.android.com/tools/releases/platform-tools —
  extract the ZIP anywhere (e.g. `C:\platform-tools`) and add that folder to your system `PATH`.
- **Option B (via Android Studio):** If Android Studio is already installed, the tools are at:
  `C:\Users\<YOU>\AppData\Local\Android\Sdk\platform-tools\`

**Verification:**

```bash
adb version
adb devices
```

#### Frida

**What it does:** runtime instrumentation from Python and manual attach/debug commands.

**How to install:** Frida is a Python package — no separate download needed:

```bash
pip install frida frida-tools
```

> **Important:** `frida` (the Python library) and `frida-tools` (the CLI — `frida`, `frida-ps`, etc.) are **two separate pip packages** — install both.
> If `frida --version` does not work after install, make sure the Python `Scripts` folder is in your `PATH` (e.g. `C:\Users\<YOU>\AppData\Local\Programs\Python\Python312\Scripts`).

**Verification:**

```bash
frida --version
python -c "import frida; print('frida', frida.__version__)"
```

#### Objection

**What it does:** patches an APK with Frida Gadget before installation on a real phone.

**How to install:**

```bash
pip install objection
```

**Verification:**

```bash
objection version
```

#### Apktool

**What it does:** APK patching/rebuilding (used internally by Objection during repackaging).

**Where to download:** https://apktool.org/ (or https://github.com/iBotPeaches/Apktool/releases).
On Windows: place `apktool.bat` and `apktool.jar` in a folder that is in your `PATH`.

**Verification:**

```bash
apktool --version
```

### 4.2 Optional helper tools

#### JADX
Useful for inspecting APK contents manually during validation/debug.
Download from: https://github.com/skylot/jadx/releases

#### YARA
Optional signature scanning for artifacts or extracted content.
The Python binding is installed via `pip install yara-python`.

#### VirusTotal API
Optional enrichment only. Not required for offline operation.
If you want VT enrichment, create a free API key at https://www.virustotal.com/ and place it in `inputs/api_keys/.env` as:
```
VT_API_KEY=your_key_here
```

#### Volatility 3
Planned / optional for future memory forensics integration.

---

## 5. Python Dependencies

The current code snapshot directly uses the following Python packages:

### Core Python packages

- `androguard` — static APK parsing and manifest/code extraction

- `frida` and `frida-tools` — runtime instrumentation support

- `rich` — CLI output / console friendliness

The `env` command reports versions for packages such as `androguard`, `customtkinter`, `tkinterweb`, and `rich`, via `src/env_report.py`.

### GUI packages

- `customtkinter`

- `tkinterweb`

### Optional deepfake/media packages

- `torch`

- `torchvision`

- `opencv-python`

- `pillow`

- `numpy`

### Notes

- Static analysis imports `APK` from `androguard.core.apk`.

- Dynamic Frida analysis imports `frida` in `src/frida_auto.py`.

- The GUI imports `customtkinter` and `tkinterweb`.

- The deepfake UI optionally imports `cv2`, `torch`, `torchvision`, and `PIL`.

---

## 6. Installation

### What is already included in the repository

Before installing, it is useful to know what you **already have** after cloning:

| Item | Path | Notes |
|------|------|-------|
| Sample test APK | `cases/CASE_001/evidence/com.neumorphic.calculator_2.apk` | Firefox F-Droid (benign app for calibration) |
| YARA demo rules | `rules/yara/cybershadow_demo.yar` | Ready to use — the GUI defaults to this folder |
| Frida JS hooks | `src/cybershadow_dyn.js` | The Frida script used during dynamic analysis |
| Repack tool | `tools/repack_with_gadget.py` | Used by Repack+Install button |
| VT API key template | `inputs/api_keys/.env.example` | Copy to `.env` and add your key if you want VirusTotal enrichment |

**What you need to provide yourself:**
- Your own APK files for analysis (or use the included sample)
- A VirusTotal API key (optional — only for VT enrichment)
- Frida Gadget `.so` file (only if you want to repack APKs — see [Section 14.12](#1412-repack-fails--gadget-soxz-not-found-inputsfrida-gadgetso.xz))
- A physical Android phone or emulator (only for dynamic/MemLite analysis)

### 6.1 Clone the repository and create a virtual environment (recommended)

```bash
git clone https://github.com/Daniel217-coder/Hybrid-Forensic-Investigation-Framework.git
cd Hybrid-Forensic-Investigation-Framework
python -m venv .venv
```

### 6.2 Activate the environment

**Windows (PowerShell):**

```powershell
.\.venv\Scripts\Activate.ps1
```

> If PowerShell blocks the script, run `Set-ExecutionPolicy -Scope Process Bypass` first.

**Windows (CMD):**

```cmd
.venv\Scripts\activate.bat
```

**Linux/macOS:**

```bash
source .venv/bin/activate
```

### 6.3 Install all Python dependencies at once

The easiest way — installs everything (static, dynamic, GUI, deepfake, YARA):

```bash
pip install -r requirements.txt
```

This single command installs: `androguard`, `frida`, `yara-python`, `customtkinter`, `tkinterweb`, `torch`, `torchvision`, `opencv-python`, `pillow`, `numpy`, `rich`, `fastapi`, `uvicorn`, `pydantic`, `python-dotenv`.

> **Note:** `torch` + `torchvision` are large packages (~2 GB). If you do not need deepfake detection, you can skip them and install only what you need manually (see steps 6.4–6.6 below).

### 6.4 (Alternative) Install only the core packages manually

```bash
pip install androguard rich frida frida-tools fastapi uvicorn pydantic python-dotenv
```

### 6.5 (Alternative) Install GUI packages separately

```bash
pip install customtkinter tkinterweb
```

### 6.6 (Alternative) Install deepfake/media packages separately

```bash
pip install torch torchvision opencv-python pillow numpy
```

### 6.7 Install Objection for APK patching (needed for dynamic analysis)

```bash
pip install objection
```

### 6.8 Install/prepare Android platform tools (needed for dynamic analysis)

Make sure `adb` works either from PATH or through `ADB_PATH`.

**Windows PowerShell example:**

```powershell
$env:ADB_PATH="C:\Users\<YOU>\AppData\Local\Android\Sdk\platform-tools\adb.exe"
$env:PATH += ";C:\Users\<YOU>\AppData\Local\Android\Sdk\platform-tools"
```

> **Where to get ADB:** see [Section 4.1](#41-required-external-tools) above for download links.

### 6.9 Verify the environment

After installation, run these two commands to confirm everything works:

```bash
python -m src.main env
python -m src.dyn_smoke_test
```

Expected output from `env`:
```json
{
  "python": "3.12.x ...",
  "packages": {
    "androguard": "4.x.x",
    "customtkinter": "5.x.x",
    "tkinterweb": "4.x.x",
    "rich": "14.x.x"
  }
}
```

---

## 7. Core Commands

The command-line entry point is `src.main`. The current CLI exposes case management, static analysis, dynamic analysis, report generation and an environment report.

Show all commands:

```bash
python -m src.main --help
```

### 7.1 Case management

Create a new case:

```bash
python -m src.main new-case --id CASE_001 --base cases
```

Add evidence manually:

```bash
python -m src.main add-evidence --case cases/CASE_001 --file path/to/app.apk --type apk
```

### 7.2 Static APK analysis

```bash
python -m src.main apk-static --case cases/CASE_001 --apk path/to/app.apk --tag run1 --verbose
```

### 7.3 Dynamic APK analysis (real device)

> **How to find `<DEVICE_SERIAL>`:** run `adb devices` — the serial is the first column (e.g. `emulator-5554` or `R5CR1234567`). See [Step 1 in Section 8](#step-1--connect-the-device) for details.

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

### 7.4 One-shot pipeline

This runs static analysis, optional dynamic analysis, generates the case report.

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

### 7.5 Reports

```bash
python -m src.main report-html --case cases/CASE_001

python -m src.main case-report --case cases/CASE_001 --risk-mode latest
```

### 7.6 Compute Final Risk (aggregate all modules)

This aggregates all artifacts in the case (static, dynamic, YARA, MemLite, VT) into a single risk score:

```bash
python -m src.main risk --case cases/CASE_001 --tag run1
```

> **Important:** `--tag` is **required** — it must match the tag you used when running static/YARA/MemLite. The command looks for artifacts like `apk_static__run1.json`, `yara__run1.json`, etc.

In the GUI, the **Compute Final Risk** button sends the tag automatically from the Tag field.

### 7.7 Environment / smoke checks

```bash
python -m src.main env

python -m src.dyn_smoke_test
```

### 7.8 Local API (for GUI / device orchestration)

The GUI and several features (VT enrichment, device discovery, repack/install workflow) communicate with a **local FastAPI backend**. The GUI and the API are **two separate processes** — both must be running at the same time.

**Start the API server (Terminal 1):**

```bash
python -m uvicorn src.api_local:app --host 127.0.0.1 --port 8000
```

After starting, the API is available at:
- **Swagger UI (interactive docs):** http://127.0.0.1:8000/docs
- **Health check:** http://127.0.0.1:8000/health

**Available API endpoints:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Server health check |
| GET | `/env` | Python environment/versions |
| GET | `/devices` | List connected ADB devices |
| POST | `/cases` | Create a new case |
| POST | `/run/static` | Run static APK analysis (async job) |
| POST | `/run/dynamic_adb` | Run ADB-only dynamic analysis (async job) |
| POST | `/run/dynamic_frida` | Run Frida dynamic analysis (async job) |
| POST | `/run/repack_install` | Repack APK with Gadget + install (async job) |
| POST | `/apk/check_repack` | Check if an APK already contains Frida Gadget |
| POST | `/apk/install` | Install an APK via ADB |
| POST | `/apk/uninstall` | Uninstall a package via ADB |
| GET | `/jobs` | List all jobs |
| GET | `/jobs/{job_id}` | Get status of a specific job |
| POST | `/vt/enrich` | VirusTotal enrichment (requires VT_API_KEY) |

> **Important:** If you see `WinError 10061` or "Connection refused" in the GUI, it means the API server is not running. Start it first, then use the GUI.

**Start the GUI (Terminal 2):**

```bash
python -m src.ui.app
```

## 8. Real-Device Dynamic Analysis Workflow

This is the **recommended workflow** for the current project.

### Step 1 — Connect the device

Enable:

- Developer Options
- USB Debugging

Then verify:

```bash
adb devices
```

Output example:

```
List of devices attached
emulator-5554   device        ← this is an emulator
R5CR1234567     device        ← this is a physical phone (Samsung, Pixel, etc.)
```

**The first column is the `<DEVICE_SERIAL>`** — this is the value you copy and use in all commands that ask for `--serial`.

For example, if `adb devices` shows `emulator-5554`, then your commands become:

```bash
python -m src.main apk-dynamic --serial emulator-5554 ...
```

> **Tip:** If you only have one device/emulator connected, you can often omit `--serial` entirely — ADB will auto-detect it.

### Step 2 — Patch the APK with Frida Gadget

Example using Objection:

```bash
objection patchapk --source path/to/app.apk --architecture arm64-v8a
```

Then install the patched APK:

```bash
adb install -r path/to/patched.apk
```

> Choose the correct ABI for your phone. For most recent physical phones, `arm64-v8a` is the correct target.

### Step 3 — Run dynamic analysis through HFIF

```bash
python -m src.main apk-dynamic --case cases/CASE_001 --package com.example.app --tag dyn1 --serial <DEVICE_SERIAL>
```

### Step 4 — Manual fallback when debugging

If you want to test the Gadget path manually:

```bash
adb -s <DEVICE_SERIAL> forward --remove-all

adb -s <DEVICE_SERIAL> forward tcp:27042 tcp:27042

adb -s <DEVICE_SERIAL> forward tcp:27043 tcp:27043

adb -s <DEVICE_SERIAL> shell "monkey -p com.example.app -c android.intent.category.LAUNCHER 1"

frida -H 127.0.0.1:27042 -n Gadget -l src/cybershadow_dyn.js
```

### What the dynamic runner actually does

The current real-device dynamic runner:

- re-applies ADB forwarding for ports `27042` and `27043`

- clears and captures `logcat`

- launches the app

- waits for the Gadget listener to become available

- attaches to Gadget through Frida

- optionally drives the app with `monkey`

- monitors runtime/network events

- scores the observed behavior

- saves a JSON artifact and updates the case report

---

## 9. How We Tested the Framework

This section is intended for dissertation reproducibility.

### 9.1 Static module validation

The static module was validated by running `apk-static` on APK samples and verifying:

- manifest parsing

- permission extraction

- suspicious component export detection

- code-hint extraction

- scoring explanations

- artifact/report generation

### 9.2 Real-device dynamic validation

Dynamic analysis was tested on a **physical Android device connected over ADB**, not on an emulator. This matters because the dissertation intentionally moved away from emulator-based execution to reduce anti-analysis artifacts and improve realism.

The dynamic validation process consisted of:

1. connecting the phone through ADB,

2. verifying connectivity with a smoke test,

3. patching the APK with Frida Gadget,

4. installing the patched APK,

5. launching the app,

6. attaching through forwarded local ports,

7. stimulating the UI with controlled `monkey` events,

8. collecting Frida events, logcat output, and lightweight network observations,

9. saving JSON artifacts and consolidated HTML reports.

### 9.3 Scoring calibration experiments

The most important dynamic experiments focused on **false-positive reduction**.

The scoring policy under calibration is:

- **benign apps should remain under 20** when only weak/normal behavior is observed,

- **malware/adware should exceed 60–70** when strong indicators or suspicious combinations appear,

- **network activity alone must not inflate benign scores**.

### 9.4 Dissertation evaluation datasets

In the dissertation experiments, the framework was evaluated on an Android application set composed of:

- **1100 benign apps**, and

- **1100 adware/malicious apps**

For dynamic testing, the dataset was executed under **time-bounded stimulation** on the physical device.

Examples of benign baseline applications discussed during calibration included common everyday apps such as:

- Calculator

- Facebook

- WhatsApp (official)

These baseline apps were important because the scoring goal was explicitly to keep benign samples below the high-risk range.

### 9.5 Optional external baseline used in experiments

For comparison, VirusTotal majority-vote style lookup was also used as an **external baseline**, not as the primary offline detector.

---

## 10. Example Test Commands Used in Practice

Below are representative commands used during validation and dissertation experiments.

### 10.1 Environment sanity check

```bash
python -m src.main env

python -m src.dyn_smoke_test

adb devices
```

### 10.2 Static-only test

```bash
python -m src.main new-case --id CASE_STATIC_001 --base cases

python -m src.main apk-static --case cases/CASE_STATIC_001 --apk datasets/benign/app1.apk --tag benign_001 --verbose

python -m src.main case-report --case cases/CASE_STATIC_001 --risk-mode latest
```

### 10.3 Dynamic test on a real device

```bash
python -m src.main new-case --id CASE_DYN_001 --base cases

python -m src.main apk-dynamic --case cases/CASE_DYN_001 --package com.example.target --tag dyn1 --serial <DEVICE_SERIAL> --capture 90 --preflight 30 --drive monkey --monkey-events 1200 --throttle-ms 90

python -m src.main case-report --case cases/CASE_DYN_001 --risk-mode latest
```

### 10.4 Full pipeline test

```bash
python -m src.main run-apk --case cases/CASE_PIPE_001 --apk datasets/adware/sample1.apk --tag adware_001 --dynamic --serial <DEVICE_SERIAL> --capture 90 --drive monkey
```

### 10.5 Manual Frida Gadget check

```bash
adb -s <DEVICE_SERIAL> forward --remove-all

adb -s <DEVICE_SERIAL> forward tcp:27042 tcp:27042

adb -s <DEVICE_SERIAL> forward tcp:27043 tcp:27043

frida -H 127.0.0.1:27042 -n Gadget -l src/cybershadow_dyn.js
```

### 10.6 Batch-style dissertation runs

In the broader dissertation workflow, repeated dataset runs were automated from PowerShell. A typical pattern was:

```powershell
python -m src.main run-apk --case cases/CASE_xxx --apk <sample.apk> --tag <sample_tag> --dynamic --serial <DEVICE_SERIAL>
```

If you maintained a separate batch runner such as `run_dataset.ps1`, document it here as the wrapper that iterated through the benign and adware folders and called the core HFIF commands above.

---

## 11. Artifacts and Reports

HFIF stores everything per case:

```text
cases/CASE_001/

  ├── case.json

  ├── evidence/

  ├── artifacts/

  │    ├── apk_static__<tag>.json

  │    ├── apk_dynamic__<tag>__<timestamp>.json

  │    └── other optional artifacts

  ├── reports/

      ├── module HTML reports

      └── case__CASE_001.html
```

### What is stored

- **evidence/** — original added files

- **artifacts/** — JSON outputs from analysis modules

- **reports/** — HTML reports for analysts

---

## 12. Scoring Model

HFIF uses explainable weighted scoring with synergy and a benign-aware cap.

Conceptually:

```text
R_raw = min(100, R0 + Σ(w_i * s_i) + Σ(b_j * c_j))

if malicious_unlock == 0:

    R = min(R_raw, 19)

else:

    R = R_raw
```

### Practical interpretation

- **Soft signals** receive low weight.

- **Hard signals** receive strong weights.

- **Suspicious combinations** receive additional boosts.

- If no hard unlock trigger exists, the final score is capped below 20 to protect benign applications from false positives.

### Dynamic scoring intent

Examples of policy logic used during calibration:

- network presence alone: very low weight

- SMS access: hard trigger

- process execution: hard trigger

- dynamic code loading: hard trigger

- network + SMS: critical combination

- network + exec/dynamic-load: suspicious combination

### Severity bands

- **0–34:** LOW

- **35–59:** MEDIUM

- **60–79:** HIGH

- **80–100:** CRITICAL

### GUI/UI bands

- **<20:** green

- **<50:** yellow

- **<75:** orange

- **>=75:** red

---

## 13. GUI — Testing the Application

The primary way to test HFIF is through the **desktop GUI** (`src/ui/app.py`), with the **local API server** (`src/api_local.py`) running in parallel. Most analysis commands are triggered from GUI buttons, and results are viewed in the built-in report viewer.

### 13.1 Prerequisites

```bash
pip install customtkinter tkinterweb
```

(Already included in `requirements.txt`.)

### 13.2 How to launch (two terminals)

You always need **two terminals open side by side**:

**Terminal 1 — Start the local API server:**

```bash
python -m uvicorn src.api_local:app --host 127.0.0.1 --port 8000
```

Wait until you see `Uvicorn running on http://127.0.0.1:8000`.

**Terminal 2 — Start the GUI:**

```bash
python -m src.ui.app
```

> The GUI calls the API server on `http://127.0.0.1:8000` for device discovery, VT enrichment, repack/install, and more. If you see `WinError 10061` in the GUI, it means Terminal 1 is not running.

### 13.3 GUI layout overview

The window is titled **CYBERSHADOW - Forensic Analysis Hub** (dark theme). It has two panels:

**Left panel — 4 control tabs:**

| Tab | Purpose |
|-----|---------|
| **APK Analyzer** | Static analysis, YARA, MemLite, full pipeline, VT enrich, final risk, reports |
| **Dynamic (Frida)** | Frida Gadget dynamic analysis on a real device or emulator |
| **Deepfake - Image** | Single image deepfake detection |
| **Deepfake - Video** | Video frame-by-frame deepfake analysis |

**Right panel — 3 output tabs:**

| Tab | What it shows |
|-----|-------------|
| **Console Log** | Live CLI output (green text on dark background) |
| **Quick Summary** | Parsed score, severity, artifact paths, key findings |
| **Report Viewer** | Built-in HTML viewer with buttons: Load Case Report, Load Selected Artifact Report, Load Latest APK Report, Open Reports Folder, Open Artifacts Folder |

**Top bar:** Progress bar + **Score** badge + **Severity** badge (update in real time as analysis runs).

### 13.4 APK Analyzer tab — all buttons explained

This is the main tab. The fields at the top are:

| Field | What to fill in | Example |
|-------|----------------|---------|
| **Case Folder** | Path to case directory (auto-created if missing) | `.\cases\CASE_001` |
| **Case Verdict Mode** | How to aggregate risk across multiple runs | `latest` / `max` / `mean` |
| **APK File** | Path to the `.apk` file to analyze | `C:\Downloads\app.apk` |
| **Tag** | Short label for this analysis run | `run1` |
| **YARA Rules** | Folder with `.yar` rule files (default: `.\rules\yara`) | `.\rules\yara` |
| **ADB Serial (MemLite)** | Device serial for memory-adjacent capture | `emulator-5554` |
| **Package override (MemLite)** | Override package name for MemLite | `com.example.app` |

Checkboxes:
- **Include YARA (full pipeline)** — checked by default
- **Include MemLite (full pipeline)** — checked by default

**Row 1 — Main action buttons:**

| Button | What it does |
|--------|-------------|
| **RUN FULL PIPELINE** | Runs everything in sequence: static analysis → YARA scan (if checked) → MemLite (if checked) → generates APK report → generates case report → computes final risk. This is the **one-click complete analysis**. |
| **STOP** | Stops a running analysis. |

**Row 2 — Individual module buttons (run one at a time):**

| Button | What it does |
|--------|-------------|
| **Run Static Only** | Runs only static APK analysis (permissions, manifest, code hints, scoring). |
| **Run YARA Only** | Runs only YARA signature scan on the case artifacts. |
| **Run MemLite Only** | Runs only MemLite (memory-adjacent artifact capture from device via ADB). |
| **Compute Final Risk** | Aggregates all existing artifacts (static, dynamic, YARA, MemLite) into a single risk score and generates the final case report. |

**Row 3 — APK management + VT:**

| Button | What it does |
|--------|-------------|
| **Repack + Install (keep)** | Repacks the APK with Frida Gadget and installs it on the device (via API). |
| **Uninstall** | Uninstalls the target package from the device (via API). |
| **VirusTotal Enrich** | Sends the APK hash to VirusTotal and saves detection results (requires `VT_API_KEY` in `.env`). |

**Bottom:**

| Button | What it does |
|--------|-------------|
| **LOAD REPORT INTO VIEWER** | Opens the generated HTML report in the built-in Report Viewer tab. |

Below the buttons there is an **Artifacts (generated)** section that lists all JSON artifacts in the case. You can select one to preview it in Quick Summary or load its associated report.

### 13.5 Dynamic (Frida) tab — all fields and buttons

| Field | What to fill in | Default |
|-------|----------------|---------|
| **Package Name** | Android package of the target app | (empty) |
| **Dynamic Tag** | Label for this dynamic run | `dyn` |
| **Preflight (sec)** | Seconds to wait after app launch before attaching Frida | `30` |
| **Capture (sec)** | How long to monitor runtime behavior | `90` |
| **Drive** | How to stimulate the app during capture | `monkey+allow` |
| **Monkey events** | Number of random UI events | `2500` |
| **Throttle (ms)** | Delay between monkey events | `80` |
| **Seed URL** | Optional URL to open in the app during analysis | `https://example.com` |
| **Target device** | Dropdown populated from `adb devices` via the API | (auto-detected) |
| **Frida JS Script** | Path to the Frida hooks script | `src\cybershadow_dyn.js` |

**Buttons:**

| Button | What it does |
|--------|-------------|
| **RUN DYNAMIC (FRIDA)** | Runs full Frida Gadget dynamic analysis: ADB forward → launch app → attach Frida → monkey stimulation → collect events → score → generate report. |
| **STOP** | Stops a running dynamic analysis. |
| **Refresh devices** | Queries the API (`/devices`) and refreshes the device dropdown. |

### 13.6 How to test the application — recommended workflow

This is the step-by-step process for testing HFIF through the GUI:

#### Step 1 — Start API + GUI

Open two terminals. In Terminal 1:
```bash
python -m uvicorn src.api_local:app --host 127.0.0.1 --port 8000
```
In Terminal 2:
```bash
python -m src.ui.app
```

#### Step 2 — Run Static Only (APK Analyzer tab)

1. Set **Case Folder** to `.\cases\CASE_001` (or any name).
2. Click **Browse APK** and select your `.apk` file.
   > **No APK to test with?** The repo includes a sample APK for testing at:
   > `cases\CASE_001\evidence\com.neumorphic.calculator_2.apk`
   > (This is Firefox for Android from F-Droid — a known benign app, useful for calibration.)
3. Set **Tag** to something like `static_run1`.
4. Click **Run Static Only**.
5. Watch the **Console Log** tab — when it finishes, the **Score** and **Severity** badges update at the top.
6. The artifact `apk_static__static_run1.json` appears in the Artifacts list.

#### Step 3 — Run YARA Only

1. The **YARA Rules** field defaults to `.\rules\yara` — this folder already exists in the repo and contains `cybershadow_demo.yar` (demo rules for testing).
2. Click **Run YARA Only**.
3. A `yara__*.json` artifact is created in the case.

#### Step 4 — Run MemLite Only

1. If you have a device/emulator connected, enter its serial in **ADB Serial (MemLite)**.
   > **How to find the serial:** run `adb devices` — the first column is the serial (e.g., `emulator-5554`).
2. Optionally enter a **Package override** if the APK package name differs from what was detected.
3. Click **Run MemLite Only**.
4. A `memlite__*.json` artifact is created.

#### Step 5 — Run Dynamic separately (Dynamic tab)

1. Switch to the **Dynamic (Frida)** tab.
2. Click **Refresh devices** — your device/emulator should appear in the dropdown.
3. Enter the **Package Name** (e.g., `com.example.app`).
4. Make sure the APK is already patched with Frida Gadget and installed on the device (use **Repack + Install** in the APK Analyzer tab if needed).
5. Click **RUN DYNAMIC (FRIDA)**.
6. The runner will: forward ADB ports → launch the app → wait for Gadget → attach Frida → stimulate with monkey → collect events → score → save artifact.
7. A `apk_dynamic__dyn__*.json` artifact is created.

#### Step 6 — Run Full Pipeline (all at once)

Instead of steps 2–5 individually, you can click **RUN FULL PIPELINE** in the APK Analyzer tab. This runs everything in sequence:
1. Static analysis
2. YARA scan (if checkbox is checked)
3. MemLite (if checkbox is checked)
4. APK HTML report generation
5. Case HTML report generation
6. Final risk computation

#### Step 7 — Compute Final Risk

After all modules have run (static, dynamic, YARA, MemLite), click **Compute Final Risk**. This:
- Reads all artifacts in the case
- Aggregates them using the selected **Case Verdict Mode** (`latest` / `max` / `mean`)
- Produces a `risk_aggregate__*.json` artifact
- Generates the final consolidated case report HTML

#### Step 8 — View the reports

1. In the **Report Viewer** tab (right panel), click **Load Case Report** to see the consolidated report.
2. Or click **Load Latest APK Report** to see the most recent module report.
3. Or select a specific artifact in the Artifacts list, then click **Load Selected Artifact Report**.
4. Use **Open Reports Folder** or **Open Artifacts Folder** to browse the generated files directly in Explorer.

The final case report shows:
- Overall risk score and severity band
- Per-module scores (static, dynamic, YARA, MemLite)
- Detailed findings with explanations and weights
- Synergy conditions that triggered or not

#### Typical full test session

```
Terminal 1:  python -m uvicorn src.api_local:app --host 127.0.0.1 --port 8000
Terminal 2:  python -m src.ui.app

In GUI (APK Analyzer tab):
  1. Case Folder:  .\cases\TEST_APP
  2. Browse APK:   select your test APK
  3. Tag:          v1
  4. Click "Run Static Only"         → wait for Score badge to update
  5. Click "Run YARA Only"           → yara artifact created
  6. Click "Run MemLite Only"        → memlite artifact created
  7. Click "Compute Final Risk"      → risk_aggregate artifact + case report

In GUI (Dynamic tab):
  8. Refresh devices                 → select emulator or phone
  9. Package Name:  com.example.app
 10. Click "RUN DYNAMIC (FRIDA)"     → dynamic artifact created

Back in APK Analyzer tab:
 11. Click "Compute Final Risk"      → now includes dynamic results too

In GUI (Report Viewer tab):
 12. Click "Load Case Report"        → view the final consolidated report
```

### 13.7 Swagger UI — testing the API without the GUI

If you prefer testing the API endpoints directly, open http://127.0.0.1:8000/docs in a browser after starting the API server. Swagger provides an interactive interface where you can:

- Create cases (`POST /cases`)
- Run static/dynamic analysis (`POST /run/static`, `POST /run/dynamic_adb`, `POST /run/dynamic_frida`)
- Check job status (`GET /jobs/{job_id}`)
- List connected devices (`GET /devices`)
- Repack + install APKs (`POST /run/repack_install`)
- VT enrichment (`POST /vt/enrich`)

> **Windows path tip:** When entering file paths in Swagger JSON bodies, either double the backslashes (`C:\\Users\\...`) or use forward slashes (`C:/Users/...`).

---

## 14. Troubleshooting

This is the most important practical section for real-device analysis.

### 14.1 `adb` not found

**Symptoms:**

- `adb: command not found`

- smoke test fails immediately

- dynamic analysis exits before device detection

**Fix:**

- install Android Platform-Tools

- add `adb` to PATH

- or set `ADB_PATH`

**PowerShell example:**

```powershell
$env:ADB_PATH="C:\Users\<YOU>\AppData\Local\Android\Sdk\platform-tools\adb.exe"

$env:PATH += ";C:\Users\<YOU>\AppData\Local\Android\Sdk\platform-tools"
```

Verify:

```bash
adb version

python -m src.dyn_smoke_test
```

### 14.2 Device not visible in `adb devices`

**Symptoms:**

- no devices listed

- dynamic run says device not found

**Fix:**

1. reconnect the USB cable,

2. enable USB debugging,

3. accept the RSA prompt on the phone,

4. restart the server:

```bash
adb kill-server

adb start-server

adb devices
```

### 14.3 Device shows `offline`

**Symptoms:**

- `adb devices` lists the phone as `offline`

- dynamic runner retries but does not progress

**Fix:**

```bash
adb kill-server

adb start-server

adb devices
```

Then reconnect the phone and unlock the screen.

### 14.4 PowerShell execution policy blocks venv activation

**Symptoms:**

- `Activate.ps1` cannot be loaded

**Fix:**

```powershell
Set-ExecutionPolicy -Scope Process Bypass

.\.venv\Scripts\Activate.ps1
```

### 14.5 `frida module missing`

**Symptoms:**

- dynamic runner reports that the `frida` Python module is missing

**Fix:**

```bash
pip install frida frida-tools
```

Verify:

```bash
python -c "import frida; print('frida ok')"

frida --version
```

### 14.6 Gadget not reachable / listener not detected

**Symptoms:**

- dynamic analysis reports Gadget not ready

- port `27042` is not listening

- Frida attach fails

**Fix:**

1. confirm that the APK was patched with Gadget,

2. install the patched APK, not the original one,

3. launch the app manually once,

4. reapply port forwarding:

```bash
adb -s <DEVICE_SERIAL> forward --remove-all

adb -s <DEVICE_SERIAL> forward tcp:27042 tcp:27042

adb -s <DEVICE_SERIAL> forward tcp:27043 tcp:27043
```

5. test manually:

```bash
frida -H 127.0.0.1:27042 -n Gadget -l src/cybershadow_dyn.js
```

### 14.7 `objection patchapk` fails

**Common causes:**

- outdated Objection version

- missing Apktool

- unsupported APK packaging/protection

**Fixes:**

```bash
pip install -U objection

apktool --version
```

If patching still fails:

- confirm the APK is not corrupted,

- check ABI selection (`arm64-v8a` for most modern phones),

- inspect the console output for signing/rebuild errors.

### 14.8 `SecurityException` when listing packages on Android 13+

Some builds restrict package listing across users/profiles. The included smoke test already handles this by trying the current user and then falling back to user `0`.

If you debug manually, prefer:

```bash
adb shell am get-current-user

adb shell pm list packages --user 0
```

### 14.9 App launches but dynamic capture remains empty

**Possible causes:**

- wrong package name

- wrong Frida script path

- the patched app was not installed

- Gadget never started

- app crashed immediately

**Checks:**

```bash
adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1

adb logcat

frida -H 127.0.0.1:27042 -n Gadget -l src/cybershadow_dyn.js
```

Also verify that `src/cybershadow_dyn.js` is the script passed to the runner.

### 14.10 App crashes on launch after patching

**Possible causes:**

- incompatibility introduced by repackaging,

- signature mismatch,

- anti-tamper or packer protection,

- native library/runtime mismatch.

**Fixes:**

- uninstall the previous version before reinstalling,

- patch again with the correct architecture,

- inspect `adb logcat` for the real exception,

- validate the app without HFIF first to confirm it starts.

### 14.11 VT enrich fails — "No connection could be made" (WinError 10061)

**Symptoms:**

```
[ERROR] VirusTotal enrich failed: <urlopen error [WinError 10061] No connection could be made because the target machine actively refused it>
```

**Cause:**

The GUI sends `POST /vt/enrich` to `http://127.0.0.1:8000`, but the local FastAPI backend is not running. The GUI and the API server are **two separate processes** — both must be running at the same time.

**Fix:**

Start the API server in a separate terminal before using any GUI feature that calls the backend:

```bash
python -m uvicorn src.api_local:app --host 127.0.0.1 --port 8000
```

Then relaunch the GUI or retry the operation.

---

### 14.12 Repack fails — "Gadget .so/.xz not found: inputs\frida-gadget.so.xz"

**Symptoms:**

```
FileNotFoundError: Gadget .so/.xz not found: inputs\frida-gadget.so.xz
```

**Cause:**

The Frida Gadget shared library is not included in the repository and must be downloaded separately. The repack tool expects it at `inputs/frida-gadget.so.xz`.

**Fix:**

1. Check your device/emulator ABI:

```bash
adb shell getprop ro.product.cpu.abi
```

2. Download the matching gadget from the Frida GitHub releases page (`https://github.com/frida/frida/releases`):

| ABI | File |

|-----|------|

| `arm64-v8a` | `frida-gadget-<version>-android-arm64.so.xz` |

| `armeabi-v7a` | `frida-gadget-<version>-android-arm.so.xz` |

| `x86_64` | `frida-gadget-<version>-android-x86_64.so.xz` |

| `x86` | `frida-gadget-<version>-android-x86.so.xz` |

3. Rename and place the file:

```
inputs\frida-gadget.so.xz
```

The repack tool accepts both `.so` and `.so.xz` — it decompresses `.xz` automatically.

---

### 14.13 Repack fails — "zipalign not found"

**Symptoms:**

```
FileNotFoundError: Android SDK tool not found: zipalign. Install Android SDK Build-Tools and set ANDROID_SDK_ROOT...
```

**Cause:**

`ANDROID_SDK_ROOT` is not set in the shell environment, or the SDK is installed but **Build-Tools** (the component that contains `zipalign` and `apksigner`) has not been installed. Note that `platform-tools` (which contains `adb`) is a separate SDK component from `build-tools`.

**Fix — Option A:** Set the path in `.env` (loaded automatically by the API):

```
ANDROID_SDK_ROOT=D:\Android\Sdk
```

The repack tool scans `$ANDROID_SDK_ROOT/build-tools/<version>/` automatically.

**Fix — Option B:** Install Build-Tools via Android Studio SDK Manager:

Android Studio → SDK Manager → SDK Tools tab → check **Android SDK Build-Tools** → Apply.

**Fix — Option C:** Install via command-line tools only (no Android Studio):

```bash
sdkmanager "build-tools;35.0.0"
```

Verify after installing:

```bash
where zipalign   # Windows

which zipalign   # Linux/macOS
```

---

### 14.14 App crashes on launch after repack — ABI mismatch on emulator

**Symptoms:**

```
dlopen failed: library "libfrida-gadget.so" not found

java.lang.UnsatisfiedLinkError: dlopen failed: library "libfrida-gadget.so" not found
```

**Cause:**

The Frida Gadget was injected into `lib/arm64-v8a/` (because the original APK's native libs were arm64), but the Android emulator's **primary ABI is x86_64**. Android starts the process as x86_64, looks for `lib/x86_64/libfrida-gadget.so`, and cannot find it.

> **Why this happens on emulators:** Emulators typically advertise `abilist=x86_64,arm64-v8a`. The `auto` ABI detection in the repack tool reads the original APK's native libraries (arm64) and injects the gadget there — but the emulator runs the process as x86_64, making the arm64 gadget invisible to the dynamic linker.

**Fix:**

1. Confirm the emulator ABI:

```bash
adb shell getprop ro.product.cpu.abi        # primary ABI (e.g. x86_64)

adb shell getprop ro.product.cpu.abilist    # full list
```

2. Download the matching gadget (e.g. `frida-gadget-<version>-android-x86_64.so.xz`) and place it at `inputs/frida-gadget.so.xz`.

3. When repacking via the API or GUI, set `abi` explicitly to match the emulator's primary ABI:

```json
{ "abi": "x86_64" }
```

The default in `src/api_local.py` has been updated to `"x86_64"` for emulator-friendly operation. For **physical phones** (which are almost always `arm64-v8a`), override this to `arm64-v8a` when repacking.

---

### 14.15 Swagger UI returns 422 with Windows file paths

**Symptoms:**

```json
{ "type": "json_invalid", "msg": "JSON decode error", "ctx": { "error": "Invalid \\escape" } }
```

**Cause:**

Windows paths use backslashes (`\`), which are escape characters in JSON. Pasting a raw Windows path into Swagger's request body causes a JSON parse failure.

**Fix:**

Double every backslash in the path when entering it in Swagger UI:

```json
{ "apk_path": "C:\\Users\\Administrator\\Downloads\\app.apk" }
```

Or use forward slashes, which Windows also accepts:

```json
{ "apk_path": "C:/Users/Administrator/Downloads/app.apk" }
```

---

### 14.16 Deepfake UI errors

**Symptoms:**

- missing `torch`, `cv2`, or `PIL`

**Fix:**

```bash
pip install torch torchvision opencv-python pillow numpy
```

---

## 15. Notes for Dissertation Reproducibility

For the dissertation/report version of this project:

1. **State clearly that dynamic analysis was executed on a physical Android device**, not only on an emulator.

2. **Document the exact host environment**: OS, Python version, and major tools.

3. **List the installed tools explicitly**: ADB, Frida, Objection, Apktool, Androguard, optional GUI/deepfake packages.

4. **Describe the test workflow**: patch APK → install → forward ports → attach → stimulate → collect → score → report.

5. **Record the dataset composition**: benign vs adware/malware samples.

6. **Mention that benign apps were used as calibration baselines** to reduce false positives.

7. **Keep the risk-scoring rule explicit**: benign <20 unless hard evidence unlocks the score.

8. **Preserve generated JSON artifacts and HTML reports** for reproducibility.

---

## 16. References / Tools

We used these references in the README or dissertation as needed:

- Android SDK Platform-Tools (ADB)

- Frida

- Frida Gadget

- Objection

- Apktool

- JADX

- Androguard

- YARA

- VirusTotal API

- Volatility 3

If you want a stricter academic appendix, add:

- tool name,

- purpose in the framework,

- whether it is required or optional,

- installation method,

- verification command.

---

## Final Practical Note

For this project, the most stable path is:

1. **Static analysis directly from HFIF**

2. **Dynamic analysis on a real phone**

3. **Frida Gadget embedded in the target APK**

4. **ADB forwarding to local ports 27042/27043**

5. **Case report generation after every run**

