# src/main.py
import argparse
import json
from pathlib import Path

from src.case_manager import new_case, add_evidence, save_artifact
from src.apk_static import analyze_apk, set_verbose
from src.env_report import get_versions
from src.report_html import generate_apk_html_report
from src.case_report import write_case_html
from src.ledger import ledger_update, ledger_verify


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

    # ---------- APK STATIC ANALYSIS ----------
    c3 = sub.add_parser("apk-static")
    c3.add_argument("--case", required=True)
    c3.add_argument("--apk", required=True)
    c3.add_argument("--tag", default=None)
    c3.add_argument("--verbose", action="store_true", help="Show noisy parser logs (debug).")

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
    c8.add_argument("--case", required=True, help="Case directory, e.g. .\\cases\\CASE_002")
    c8.add_argument("--apk", required=True, help="Path to APK file")
    c8.add_argument("--tag", default=None, help="Short tag name (optional)")
    c8.add_argument("--risk-mode", default="latest", choices=["latest", "max", "mean"])
    c8.add_argument("--no-ledger", action="store_true", help="Skip ledger update/verify (not recommended)")
    c8.add_argument("--verbose", action="store_true", help="Show noisy parser logs (debug).")

    # ---------- ENV ----------
    c9 = sub.add_parser("env")

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
            ev = add_evidence(args.case, args.apk, "apk")

            copied_apk = str(Path(args.case) / "evidence" / Path(args.apk).name)
            info = analyze_apk(copied_apk)

            suffix = args.tag if args.tag else _sanitize_stem(args.apk)
            artifact_name = f"apk_static__{suffix}.json"
            out_path = save_artifact(args.case, artifact_name, info)
            print(f"Saved: {out_path}")
            print(json.dumps(info.get("scoring", {}), indent=2))

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

        elif args.cmd == "run-apk":
            set_verbose(args.verbose)

            case_dir = args.case
            apk_path = args.apk
            tag = args.tag if args.tag else _sanitize_stem(apk_path)

            _ensure_case_exists(case_dir)

            # 1) add evidence (copies file into case/evidence/)
            ev = add_evidence(case_dir, apk_path, "apk")

            # 2) analyze copied evidence
            copied_apk = str(Path(case_dir) / "evidence" / Path(apk_path).name)
            info = analyze_apk(copied_apk)

            artifact_name = f"apk_static__{tag}.json"
            artifact_path = save_artifact(case_dir, artifact_name, info)

            # 3) per-APK report
            apk_report_path = generate_apk_html_report(case_dir, apk_artifact=artifact_name)

            # 4) case report (dynamic aggregation)
            case_report_path = write_case_html(case_dir, risk_mode=args.risk_mode)

            # 5) ledger update + verify
            ledger_path = None
            ledger_ok = None
            ledger_details = None
            if not args.no_ledger:
                ledger_path = ledger_update(case_dir)
                ledger_details = ledger_verify(case_dir)
                ledger_ok = bool(ledger_details.get("ok", False))

            scoring = info.get("scoring", {}) or {}
            sev = (scoring.get("severity") or "UNKNOWN")
            score = scoring.get("score", 0)

            print("\n== PIPELINE SUMMARY ==")
            print(f"Case: {case_dir}")
            print(f"Evidence: {ev.get('name')} | SHA-256: {ev.get('sha256')}")
            print(f"APK: {info.get('app_name')} | {info.get('package')}")
            print(f"Severity: {sev}")
            print(f"Score: {score} / 100")
            print(f"Risk mode: {args.risk_mode}")
            print(f"Artifact: {artifact_path}")
            print(f"APK Report: {apk_report_path}")
            print(f"Case Report: {case_report_path}")
            if ledger_path:
                print(f"Ledger: {ledger_path} | Verified: {ledger_ok}")
                if ledger_details and not ledger_ok:
                    print(json.dumps(ledger_details, indent=2))

        elif args.cmd == "env":
            print(json.dumps(get_versions(), indent=2))

    except Exception as e:
        rc = 1
        print(f"[ERROR] {e}")

    print(f"[DONE] return code: {rc}")
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
