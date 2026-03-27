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
- [13. GUI](#13-gui)
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

This section explains **what was installed outside Python**, and **why**.

### 4.1 Required external tools

#### ADB / Android SDK Platform-Tools
Used for:
- device detection
- USB debugging
- launching the target app
- logcat capture
- port forwarding for Frida Gadget
- smoke tests and troubleshooting

Typical verification command:

```bash
adb version
adb devices
```

#### Frida
Used for runtime instrumentation from Python and for manual attach/debug commands.

Typical verification command:

```bash
frida --version
```

#### Objection
Used to **patch an APK with Frida Gadget** before installation on a real phone.

Typical verification command:

```bash
objection version
```

#### Apktool
Needed by many APK patching/rebuilding workflows and often required by Objection during repackaging.

Typical verification command:

```bash
apktool --version
```

### 4.2 Optional helper tools

#### JADX
Useful for inspecting APK contents manually during validation/debug.

#### YARA
Optional signature scanning for artifacts or extracted content.

#### VirusTotal API
Optional enrichment only. Not required for offline operation.

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

### 6.1 Clone and create virtual environment

```bash
python -m venv .venv
```

### 6.2 Activate the environment

**Windows (PowerShell):**

```powershell
.\.venv\Scripts\Activate.ps1
```

**Linux/macOS:**

```bash
source .venv/bin/activate
```

### 6.3 Install baseline Python dependencies

If you maintain a `requirements.txt` file:

```bash
pip install -r requirements.txt
```

If you install manually, a safe baseline is:

```bash
pip install androguard rich frida frida-tools
```

### 6.4 Install GUI dependencies (optional)

```bash
pip install customtkinter tkinterweb
```

### 6.5 Install deepfake/media dependencies (optional, heavier)

```bash
pip install torch torchvision opencv-python pillow numpy
```

### 6.6 Install Objection for APK patching

```bash
pip install objection
```

### 6.7 Install/prepare Android platform tools

Make sure `adb` works either from PATH or through `ADB_PATH`.

**Windows PowerShell example:**

```powershell
$env:ADB_PATH="C:\Users\<YOU>\AppData\Local\Android\Sdk\platform-tools\adb.exe"
$env:PATH += ";C:\Users\<YOU>\AppData\Local\Android\Sdk\platform-tools"
```

### 6.8 Verify the environment

```bash
python -m src.main env
python -m src.dyn_smoke_test
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

### 7.6 Environment / smoke checks

```bash
python -m src.main env
python -m src.dyn_smoke_test
```
### 7.7 Local API (for GUI / device orchestration)

If you use the local API layer (for device discovery, job orchestration, or GUI integration), start it with:

```bash
python -m uvicorn src.api_local:app --host 127.0.0.1 --port 8000

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

## 13. GUI

If the GUI is enabled in your local build:

```bash
python -m src.ui.app
```

The GUI can help with:
- case selection
- running static analysis
- running dynamic analysis through the Frida Gadget workflow
- loading generated reports
- optional deepfake/media workflows

Required packages:

```bash
pip install customtkinter tkinterweb
```

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


### 14.12 Deepfake UI errors

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
