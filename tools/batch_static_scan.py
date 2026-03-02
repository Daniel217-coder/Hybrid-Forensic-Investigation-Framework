from __future__ import annotations

import argparse
import csv
import hashlib
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Iterable, Optional, Tuple


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def looks_like_apk(path: Path) -> Tuple[bool, str]:
    """
    Accept:
      - *.apk
      - OR any file that is a ZIP and contains AndroidManifest.xml (binary AXML) and/or classes.dex
    Returns (ok, reason)
    """
    if not path.is_file():
        return False, "not_file"

    # quick magic: ZIP local file header
    try:
        with path.open("rb") as f:
            magic = f.read(4)
        if magic != b"PK\x03\x04":
            # allow .apk even if header differs (rare)
            if path.suffix.lower() == ".apk":
                return True, "apk_ext_no_zip_magic"
            return False, "not_zip"
    except Exception:
        return False, "read_error"

    # verify zip structure + android markers
    try:
        with zipfile.ZipFile(path, "r") as z:
            names = set(z.namelist())
            if "AndroidManifest.xml" in names:
                return True, "has_manifest"
            if "classes.dex" in names:
                return True, "has_classes"
            # some split APKs: base.apk-like layouts still have manifest
            return False, "zip_no_android_markers"
    except Exception:
        # some corrupted zips
        return False, "bad_zip"


def iter_candidate_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if p.is_file():
            yield p


def run_cmd(cmd: list[str]) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True)
        out = (p.stdout or "") + ("\n" + (p.stderr or "") if p.stderr else "")
        return int(p.returncode), out.strip()
    except Exception as e:
        return 999, f"exception: {e}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Folderul cu fișierele (recursiv). Ex: D:\\Adware\\Adware")
    ap.add_argument("--cases-base", default="cases", help="Unde să creeze cazurile (default: cases)")
    ap.add_argument("--prefix", default="BULK", help="Prefix pentru case id (default: BULK)")
    ap.add_argument("--limit", type=int, default=0, help="0 = fără limită; altfel oprește după N APK-uri")
    ap.add_argument("--resume", action="store_true", help="Sari peste cazurile deja procesate (dacă există artifact static)")
    ap.add_argument("--with-reports", action="store_true", help="Generează și report-html + case-report (mai lent)")
    ap.add_argument("--risk-mode", default="latest", choices=["latest", "max", "mean"])
    args = ap.parse_args()

    root = Path(args.input).expanduser().resolve()
    cases_base = Path(args.cases_base).expanduser().resolve()
    cases_base.mkdir(parents=True, exist_ok=True)

    summary_path = cases_base / f"{args.prefix.lower()}_summary.csv"
    print(f"[i] Input: {root}")
    print(f"[i] Cases base: {cases_base}")
    print(f"[i] Summary: {summary_path}")

    # IMPORTANT: rulează cu python din venv (sys.executable)
    py = sys.executable

    rows = []
    seen = 0
    processed = 0
    skipped = 0

    start = time.time()

    with summary_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "idx", "case_id", "file_path", "sha256", "apk_detect_reason",
            "rc", "package_guess", "static_score", "static_severity", "note"
        ])

        for file_path in iter_candidate_files(root):
            seen += 1

            ok, reason = looks_like_apk(file_path)
            if not ok:
                continue

            if args.limit and processed >= args.limit:
                break

            # stable id from sha256 (short)
            try:
                h = sha256_file(file_path)
            except Exception:
                h = "sha256_error"

            idx = processed + 1
            case_id = f"{args.prefix}_{idx:05d}_{h[:8]}"
            case_dir = cases_base / case_id

            tag = f"{args.prefix.lower()}_{idx:05d}"

            # resume check: already has a static artifact
            if args.resume and (case_dir / "artifacts").exists():
                if list((case_dir / "artifacts").glob("apk_static__*.json")):
                    skipped += 1
                    w.writerow([idx, case_id, str(file_path), h, reason, 0, "", "", "", "resume_skip"])
                    f.flush()
                    continue

            # run apk-static
            cmd = [
                py, "-m", "src.main",
                "apk-static",
                "--case", str(case_dir),
                "--apk", str(file_path),
                "--tag", tag,
            ]
            rc, out = run_cmd(cmd)

            # try to parse score/severity from stdout (it prints scoring json)
            pkg_guess = ""
            score = ""
            sev = ""
            note = ""

            if rc != 0:
                note = (out[:4000] if out else "error")
            else:
                # lightweight parse: search for '"score":' and '"severity":'
                # not perfect, but enough for CSV
                text = out
                # package is printed as JSON in artifact, not always in stdout; leave blank
                import re
                m1 = re.search(r'"score"\s*:\s*([0-9]+)', text)
                m2 = re.search(r'"severity"\s*:\s*"([^"]+)"', text)
                if m1:
                    score = m1.group(1)
                if m2:
                    sev = m2.group(1)

                if args.with_reports:
                    # report-html (APK report)
                    rc2, out2 = run_cmd([py, "-m", "src.main", "report-html", "--case", str(case_dir)])
                    # case-report (final)
                    rc3, out3 = run_cmd([py, "-m", "src.main", "case-report", "--case", str(case_dir), "--risk-mode", args.risk_mode])
                    if rc2 != 0 or rc3 != 0:
                        note = f"report_err rc2={rc2} rc3={rc3}"

            w.writerow([idx, case_id, str(file_path), h, reason, rc, pkg_guess, score, sev, note])
            f.flush()

            processed += 1
            if processed % 25 == 0:
                elapsed = time.time() - start
                print(f"[i] processed={processed} (seen={seen}, skipped={skipped}) elapsed={elapsed:.1f}s")

    elapsed = time.time() - start
    print(f"[OK] Done. seen={seen} processed={processed} skipped={skipped} elapsed={elapsed:.1f}s")
    print(f"[OK] Summary CSV: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())