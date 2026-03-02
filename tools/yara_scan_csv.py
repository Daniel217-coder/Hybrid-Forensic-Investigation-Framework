from __future__ import annotations

import argparse
import csv
from pathlib import Path

import yara


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", required=True, help="Path to .yar/.yara file")
    ap.add_argument("--in", dest="inp", required=True, help="Input CSV with file_path column")
    ap.add_argument("--out", required=True, help="Output CSV")
    ap.add_argument("--max-rules", type=int, default=5, help="How many rule names to keep")
    ap.add_argument("--timeout", type=int, default=10, help="YARA timeout per file (seconds)")
    args = ap.parse_args()

    rules_path = Path(args.rules).resolve()
    in_csv = Path(args.inp).resolve()
    out_csv = Path(args.out).resolve()

    if not rules_path.exists():
        raise SystemExit(f"Rules file not found: {rules_path}")
    if not in_csv.exists():
        raise SystemExit(f"Input CSV not found: {in_csv}")

    rules = yara.compile(filepath=str(rules_path))

    out_csv.parent.mkdir(parents=True, exist_ok=True)

    with in_csv.open("r", encoding="utf-8-sig", newline="") as f_in, out_csv.open("w", encoding="utf-8", newline="") as f_out:
        r = csv.DictReader(f_in)
        fieldnames = [
            "case_id", "package", "static_score", "hits_count", "first_rules", "file_path", "error"
        ]
        w = csv.DictWriter(f_out, fieldnames=fieldnames)
        w.writeheader()

        for row in r:
            file_path = (row.get("file_path") or "").strip()
            case_id = (row.get("case_id") or "").strip()
            package = (row.get("package") or "").strip()
            static_score = (row.get("static_score") or "").strip()

            err = ""
            hits = []
            if not file_path:
                err = "missing_file_path"
            else:
                p = Path(file_path)
                if not p.exists():
                    err = "file_not_found"
                else:
                    try:
                        matches = rules.match(filepath=str(p), timeout=args.timeout)
                        hits = [m.rule for m in matches]
                    except Exception as e:
                        err = f"scan_error:{type(e).__name__}"

            first_rules = "|".join(hits[: args.max_rules])
            w.writerow({
                "case_id": case_id,
                "package": package,
                "static_score": static_score,
                "hits_count": str(len(hits)),
                "first_rules": first_rules,
                "file_path": file_path,
                "error": err,
            })

    print(f"[OK] Wrote: {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())