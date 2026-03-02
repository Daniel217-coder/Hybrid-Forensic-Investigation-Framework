from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path
from typing import List, Optional


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def find_by_name_contains(root: Path, token: str) -> List[Path]:
    token = token.lower()
    out: List[Path] = []
    for p in root.rglob("*"):
        if p.is_file() and token in p.name.lower():
            out.append(p)
    return out


def resolve_path(case_id: str, roots: List[Path]) -> Optional[Path]:
    sha8 = case_id.split("_")[-1].lower()

    # 1) try filename contains sha8
    for r in roots:
        cands = find_by_name_contains(r, sha8)
        if not cands:
            continue
        if len(cands) == 1:
            return cands[0]

        # 2) verify by sha256 prefix (best)
        for c in cands:
            try:
                if sha256_file(c).startswith(sha8):
                    return c
            except Exception:
                pass

    # 3) fallback: nothing found
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--roots", nargs="+", required=True, help="One or more folders to search (APK store roots)")
    args = ap.parse_args()

    in_csv = Path(args.inp).resolve()
    out_csv = Path(args.out).resolve()
    roots = [Path(x).resolve() for x in args.roots]

    for r in roots:
        if not r.exists():
            raise SystemExit(f"Root not found: {r}")

    with in_csv.open("r", encoding="utf-8-sig", newline="") as f_in:
        reader = csv.DictReader(f_in)
        rows = list(reader)

    out_csv.parent.mkdir(parents=True, exist_ok=True)

    with out_csv.open("w", encoding="utf-8", newline="") as f_out:
        fieldnames = list(rows[0].keys()) + ["resolve_status"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        ok = 0
        for row in rows:
            case_id = (row.get("case_id") or "").strip()
            fp = (row.get("file_path") or "").strip()

            # keep if exists
            if fp and Path(fp).exists():
                row["resolve_status"] = "kept_existing"
                ok += 1
                writer.writerow(row)
                continue

            rp = resolve_path(case_id, roots)
            if rp:
                row["file_path"] = str(rp)
                row["resolve_status"] = "resolved"
                ok += 1
            else:
                row["resolve_status"] = "unresolved"

            writer.writerow(row)

    print(f"[OK] Wrote: {out_csv} | resolved_or_kept={ok}/{len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())