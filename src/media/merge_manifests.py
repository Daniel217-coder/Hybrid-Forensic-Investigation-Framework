# src/media/merge_manifests.py
from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import List, Dict

SPLITS = ["train", "val", "test"]

def read_csv(p: Path) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    with p.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append(row)
    return rows

def write_csv(p: Path, rows: List[Dict[str, str]]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["path", "label", "source", "origin"])
        w.writeheader()
        for row in rows:
            w.writerow({
                "path": row["path"],
                "label": row["label"],
                "source": row.get("source", "image"),
                "origin": row.get("origin", row["path"]),
            })

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--inputs", nargs="+", required=True, help="Processed dataset dirs containing manifest_train/val/test.csv")
    args = ap.parse_args()

    out = Path(args.out_dir)
    inputs = [Path(x) for x in args.inputs]

    for split in SPLITS:
        merged: List[Dict[str, str]] = []
        for d in inputs:
            mf = d / f"manifest_{split}.csv"
            if not mf.exists():
                print(f"[WARN] Missing: {mf}")
                continue
            rows = read_csv(mf)
            merged.extend(rows)
            print(f"[OK] {split}: +{len(rows)} from {d}")
        write_csv(out / f"manifest_{split}.csv", merged)
        print(f"[DONE] Wrote {split}: {len(merged)} rows -> {out / f'manifest_{split}.csv'}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
