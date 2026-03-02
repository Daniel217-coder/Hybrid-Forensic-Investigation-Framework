# src/main.py
from __future__ import annotations

import argparse
import json
import sys
import subprocess
import traceback
from pathlib import Path
from typing import Optional

from src.case_manager import new_case, add_evidence, save_artifact
from src.apk_static import analyze_apk, set_verbose
from src.env_report import get_versions
from src.report_html import generate_apk_html_report
from src.case_report import write_case_html
from src.ledger import ledger_update, ledger_verify
from src.memory.yara_runner import scan_apk_with_yara, save_yara_artifact
from src.memory.memlite_android import collect_memlite, save_memlite_artifact

# Final risk aggregation
from src.risk_aggregator import aggregate_case_risk, save_risk_artifact


def _sanitize_stem(path_str: str) -> str:
    stem = Path(path_str).stem
    safe = []
    for ch in stem:
        safe.append(ch if ch.isalnum() else "_")
    return "".join(safe)


def _ensure_case_exists(case_dir: str):
    case_path = Path(case_dir)
    if case_path.exists() and (case_path / "case.json").exists():
        return
    base = str(case_path.parent) if str(case_path.parent) not in ("", ".") else "cases"
    cid = case_path.name
    new_case(base, cid)


def _run_frida_auto(
    case_dir: str,
    package: str,
    tag: str,
    serial: str = "",
    capture: int = 90,
    preflight: int = 30,
    drive: str = "monkey",
    monkey_events: int = 1200,
    throttle_ms: int = 90,
    monkey_seed: int = 1337,
    endpoint: str = "127.0.0.1:27042",
    gadget_name: str = "Gadget",
    script: str = "src/cybershadow_dyn.js",
    seed_url: Optional[str] = None,
    seed_repeat: int = 0,
    seed_interval: int = 3,
) -> int:
    """Run src/frida_auto.py as a child process (Windows-safe, no shell)."""
    here = Path(__file__).resolve().parent
    frida_auto = here / "frida_auto.py"
    cmd = [
        sys.executable,
        str(frida_auto),
        "--case",
        str(case_dir),
        "--package",
        str(package),
        "--tag",
        str(tag),
        "--capture",
        str(int(capture)),
        "--preflight",
        str(int(preflight)),
        "--drive",
        str(drive),
        "--monkey-events",
        str(int(monkey_events)),
        "--throttle-ms",
        str(int(throttle_ms)),
        "--monkey-seed",
        str(int(monkey_seed)),
        "--endpoint",
        str(endpoint),
        "--gadget-name",
        str(gadget_name),
        "--script",
        str(script),
    ]
    if serial:
        cmd += ["--serial", str(serial)]

    if seed_url:
        cmd += ["--seed-url", str(seed_url)]
        cmd += ["--seed-repeat", str(int(seed_repeat))]
        cmd += ["--seed-interval", str(int(seed_interval))]

    p = subprocess.run(cmd, stdout=sys.stdout, stderr=sys.stderr)
    return int(getattr(p, "returncode", 1) or 0)


def main():
    p = argparse.ArgumentParser(prog="hybrid-forensic")
    sub = p.add_subparsers(dest="cmd", required=True)

    # ---------- CASE MANAGEMENT ----------
    c1 = sub.add_parser("new-case")
    c1.add_argument("--id", required=True)
    c1.add_argument("--base", default="cases")

    c2 = sub.add_parser("add-evidence")
    c2.add_argument("--case", required=True)
    c2.add_argument("--file", required=True)
    c2.add_argument("--type", default="apk")

    # ---------- APK STATIC ----------
    c3 = sub.add_parser("apk-static")
    c3.add_argument("--case", required=True)
    c3.add_argument("--apk", required=True)
    c3.add_argument("--tag", default=None)
    c3.add_argument("--verbose", action="store_true")

    # ---------- APK DYNAMIC (FRIDA AUTO) ----------
    c3d = sub.add_parser("apk-dynamic")
    c3d.add_argument("--case", required=True)
    c3d.add_argument("--package", required=True)
    c3d.add_argument("--tag", default="dyn")
    c3d.add_argument("--serial", default="")
    c3d.add_argument("--capture", type=int, default=90)
    c3d.add_argument("--preflight", type=int, default=30)
    c3d.add_argument("--drive", default="monkey", choices=["none", "monkey", "monkey+allow"])
    c3d.add_argument("--monkey-events", type=int, default=1200)
    c3d.add_argument("--throttle-ms", type=int, default=90)
    c3d.add_argument("--monkey-seed", type=int, default=1337)
    c3d.add_argument("--endpoint", default="127.0.0.1:27042")
    c3d.add_argument("--gadget-name", default="Gadget")
    c3d.add_argument("--script", default=str(Path("src/cybershadow_dyn.js")))
    c3d.add_argument("--seed-url", default=None)
    c3d.add_argument("--seed-repeat", type=int, default=0)
    c3d.add_argument("--seed-interval", type=int, default=3)

    # ---------- REPORTS ----------
    c4 = sub.add_parser("report-html")
    c4.add_argument("--case", required=True)
    c4.add_argument("--apk-artifact", default=None)

    c5 = sub.add_parser("case-report")
    c5.add_argument("--case", required=True)
    c5.add_argument("--risk-mode", default="latest", choices=["latest", "max", "mean"])

    # ---------- LEDGER ----------
    c6 = sub.add_parser("ledger-update")
    c6.add_argument("--case", required=True)

    c7 = sub.add_parser("ledger-verify")
    c7.add_argument("--case", required=True)

    # ---------- ONE-SHOT PIPELINE ----------
    c8 = sub.add_parser("run-apk")
    c8.add_argument("--case", required=True)
    c8.add_argument("--apk", required=True)
    c8.add_argument("--tag", default=None)
    c8.add_argument("--risk-mode", default="latest", choices=["latest", "max", "mean"])
    c8.add_argument("--no-ledger", action="store_true")
    c8.add_argument("--verbose", action="store_true")

    c8.add_argument("--dynamic", action="store_true")
    c8.add_argument("--serial", default="")
    c8.add_argument("--capture", type=int, default=90)
    c8.add_argument("--preflight", type=int, default=30)
    c8.add_argument("--drive", default="monkey", choices=["none", "monkey", "monkey+allow"])
    c8.add_argument("--monkey-events", type=int, default=1200)
    c8.add_argument("--throttle-ms", type=int, default=90)
    c8.add_argument("--monkey-seed", type=int, default=1337)
    c8.add_argument("--endpoint", default="127.0.0.1:27042")
    c8.add_argument("--gadget-name", default="Gadget")
    c8.add_argument("--script", default=str(Path("src/cybershadow_dyn.js")))
    c8.add_argument("--seed-url", default=None)
    c8.add_argument("--seed-repeat", type=int, default=0)
    c8.add_argument("--seed-interval", type=int, default=3)

    # optional extras
    c8.add_argument("--yara", action="store_true", help="Run YARA scan on APK and include in case artifacts")
    c8.add_argument("--yara-rules", default=None, help="Path to YARA rules file or directory")
    c8.add_argument("--memlite", action="store_true", help="Collect non-root procfs/logcat/network snapshots for the package")
    c8.add_argument("--memlite-after-dynamic", action="store_true", help="Run memlite after dynamic (default: before/without)")

    # NEW: final risk artifact
    c8.add_argument("--final-risk", action="store_true", help="Compute and save risk__<tag>.json at end of pipeline")

    # ---------- ENV ----------
    c9 = sub.add_parser("env")

    # ---------- YARA ----------
    cy = sub.add_parser("yara-scan")
    cy.add_argument("--case", required=True)
    cy.add_argument("--apk", required=True)
    cy.add_argument("--tag", default="yara")
    cy.add_argument("--rules", default=None)
    cy.add_argument("--timeout", type=int, default=30)

    # ---------- MEMLITE (ANDROID) ----------
    cm = sub.add_parser("memlite")
    cm.add_argument("--case", required=True)
    cm.add_argument("--package", required=True)
    cm.add_argument("--tag", default="mem")
    cm.add_argument("--serial", default="")
    cm.add_argument("--endpoint", default="127.0.0.1:27042")

    # ---------- FINAL RISK ----------
    cr = sub.add_parser("risk")
    cr.add_argument("--case", required=True)
    cr.add_argument("--tag", required=True)
    cr.add_argument("--no-save", action="store_true", help="Only print JSON; don't save risk__<tag>.json")

    args = p.parse_args()
    rc = 0

    try:
        if args.cmd == "new-case":
            path = new_case(args.base, args.id)
            print(f"Created: {path}")

        elif args.cmd == "add-evidence":
            entry = add_evidence(args.case, args.file, args.type)
            print(json.dumps(entry, indent=2))

        elif args.cmd == "apk-static":
            set_verbose(args.verbose)
            _ensure_case_exists(args.case)
            add_evidence(args.case, args.apk, "apk")

            copied_apk = str(Path(args.case) / "evidence" / Path(args.apk).name)
            info = analyze_apk(copied_apk)

            suffix = args.tag if args.tag else _sanitize_stem(args.apk)
            artifact_name = f"apk_static__{suffix}.json"
            out_path = save_artifact(args.case, artifact_name, info)
            print(f"Saved: {out_path}")
            print(json.dumps(info.get("scoring", {}), indent=2))

        elif args.cmd == "apk-dynamic":
            _ensure_case_exists(args.case)
            rc = _run_frida_auto(
                case_dir=args.case,
                package=args.package,
                tag=args.tag,
                serial=args.serial,
                capture=args.capture,
                preflight=args.preflight,
                drive=args.drive,
                monkey_events=args.monkey_events,
                throttle_ms=args.throttle_ms,
                monkey_seed=args.monkey_seed,
                endpoint=args.endpoint,
                gadget_name=args.gadget_name,
                script=args.script,
                seed_url=args.seed_url,
                seed_repeat=args.seed_repeat,
                seed_interval=args.seed_interval,
            )
            out_case = write_case_html(args.case, risk_mode="latest")
            print(f"Case report saved: {out_case}")

        elif args.cmd == "report-html":
            out = generate_apk_html_report(args.case, apk_artifact=args.apk_artifact)
            print(f"HTML report saved: {out}")

        elif args.cmd == "case-report":
            out = write_case_html(args.case, risk_mode=args.risk_mode)
            print(f"Case report saved: {out}")

        elif args.cmd == "ledger-update":
            out = ledger_update(args.case)
            print(f"Ledger saved: {out}")

        elif args.cmd == "ledger-verify":
            result = ledger_verify(args.case)
            print(json.dumps(result, indent=2))
            rc = 0 if result.get("ok") else 2

        elif args.cmd == "env":
            print(json.dumps(get_versions(), indent=2))

        elif args.cmd == "yara-scan":
            _ensure_case_exists(args.case)
            add_evidence(args.case, args.apk, "apk")
            copied_apk = str(Path(args.case) / "evidence" / Path(args.apk).name)
            obj = scan_apk_with_yara(apk_path=copied_apk, rules_path=args.rules, timeout_s=int(args.timeout))
            out_path = save_yara_artifact(args.case, tag=str(args.tag), yara_obj=obj)
            print(f"Saved: {out_path}")
            print(json.dumps(obj.get("scoring", {}), indent=2))

        elif args.cmd == "memlite":
            _ensure_case_exists(args.case)
            obj = collect_memlite(pkg=args.package, serial=args.serial)
            out_path = save_memlite_artifact(args.case, tag=str(args.tag), obj=obj)
            print(f"Saved: {out_path}")
            print(json.dumps(obj.get("scoring", {}), indent=2))

        elif args.cmd == "risk":
            _ensure_case_exists(args.case)
            tag = str(args.tag)
            obj = aggregate_case_risk(str(args.case), tag=tag)
            if not bool(getattr(args, "no_save", False)):
                out_path = save_risk_artifact(str(args.case), tag=tag, obj=obj)
                print(f"Saved: {out_path}")
            print(json.dumps(obj, indent=2))

        elif args.cmd == "run-apk":
            set_verbose(args.verbose)
            case_dir = args.case
            apk_path = args.apk
            tag = args.tag if args.tag else _sanitize_stem(apk_path)
            dyn_tag = f"{tag}_dyn"

            _ensure_case_exists(case_dir)

            ev = add_evidence(case_dir, apk_path, "apk")

            copied_apk = str(Path(case_dir) / "evidence" / Path(apk_path).name)
            info = analyze_apk(copied_apk)

            artifact_name = f"apk_static__{tag}.json"
            artifact_path = save_artifact(case_dir, artifact_name, info)

            apk_report_path = generate_apk_html_report(case_dir, apk_artifact=artifact_name)

            yara_path = None
            if bool(getattr(args, "yara", False)):
                yara_obj = scan_apk_with_yara(
                    apk_path=copied_apk,
                    rules_path=getattr(args, "yara_rules", None),
                )
                yara_path = save_yara_artifact(case_dir, tag=tag, yara_obj=yara_obj)

            memlite_path = None
            pkg_for_memlite = str(info.get("package") or "")

            def _do_memlite():
                nonlocal memlite_path
                if not pkg_for_memlite:
                    return
                objm = collect_memlite(
                    pkg=pkg_for_memlite,
                    serial=str(getattr(args, "serial", "") or ""),
                )
                memlite_path = save_memlite_artifact(case_dir, tag=tag, obj=objm)

            if bool(getattr(args, "memlite", False)) and not bool(getattr(args, "memlite_after_dynamic", False)):
                _do_memlite()

            dyn_rc = None
            pkg = str(info.get("package") or "")
            if args.dynamic:
                if not pkg:
                    raise RuntimeError("Static analysis did not return a package name; cannot run dynamic.")
                dyn_rc = _run_frida_auto(
                    case_dir=case_dir,
                    package=pkg,
                    tag=dyn_tag,
                    serial=args.serial,
                    capture=args.capture,
                    preflight=args.preflight,
                    drive=args.drive,
                    monkey_events=args.monkey_events,
                    throttle_ms=args.throttle_ms,
                    monkey_seed=args.monkey_seed,
                    endpoint=args.endpoint,
                    gadget_name=args.gadget_name,
                    script=args.script,
                    seed_url=args.seed_url,
                    seed_repeat=args.seed_repeat,
                    seed_interval=args.seed_interval,
                )

            if bool(getattr(args, "memlite", False)) and bool(getattr(args, "memlite_after_dynamic", False)):
                _do_memlite()

            case_report_path = write_case_html(case_dir, risk_mode=args.risk_mode)

            risk_path = None
            risk_obj = None
            if bool(getattr(args, "final_risk", False)):
                risk_obj = aggregate_case_risk(
                    case_dir,
                    tag=tag,
                    module_tags={
                        "static": tag,
                        "dynamic": dyn_tag,
                        "yara": tag,
                        "memlite": tag,
                    },
                )
                risk_path = save_risk_artifact(case_dir, tag=tag, obj=risk_obj)

            ledger_path = None
            ledger_ok = None
            ledger_details = None
            if not args.no_ledger:
                ledger_path = ledger_update(case_dir)
                ledger_details = ledger_verify(case_dir)
                ledger_ok = bool(ledger_details.get("ok", False))

            scoring = info.get("scoring", {}) or {}
            score = scoring.get("score", 0)
            score_max = scoring.get("score_max", 100)
            sev = scoring.get("severity", "UNKNOWN")

            print("\n== PIPELINE SUMMARY ==")
            print(f"Case: {case_dir}")
            print(f"Evidence: {ev.get('name')} | SHA-256: {ev.get('sha256')}")
            print(f"APK: {info.get('app_name')} | {info.get('package')}")
            print(f"Static severity: {sev}")
            print(f"Static score: {score} / {score_max}")
            if dyn_rc is not None:
                print(f"Dynamic run return code: {dyn_rc}")
            print(f"Risk mode: {args.risk_mode}")
            print(f"Static Artifact: {artifact_path}")
            print(f"APK Report: {apk_report_path}")
            print(f"Case Report: {case_report_path}")
            if yara_path:
                print(f"YARA Artifact: {yara_path}")
            if memlite_path:
                print(f"MemLite Artifact: {memlite_path}")
            if risk_path:
                print(f"Final Risk Artifact: {risk_path}")
                print(f"Final Risk: {risk_obj.get('score')} / 100 | {risk_obj.get('severity')}")
            if ledger_path:
                print(f"Ledger: {ledger_path} | Verified: {ledger_ok}")
                if ledger_details and not ledger_ok:
                    print(json.dumps(ledger_details, indent=2))

    except Exception as e:
        rc = 1
        print(f"[ERROR] {type(e).__name__}: {e}")
        traceback.print_exc()

    print(f"[DONE] return code: {rc}")
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
