from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple


def _load_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


def _latest_artifact(case_dir: Path, glob_pat: str) -> Optional[Path]:
    files = sorted(case_dir.glob(f"artifacts/{glob_pat}"), key=lambda x: x.stat().st_mtime, reverse=True)
    return files[0] if files else None


def _extract_score(obj: Dict[str, Any]) -> Tuple[int, bool, bool]:
    scoring = obj.get("scoring", {}) or {}
    score = int(scoring.get("score", 0) or 0)
    unlock = bool(scoring.get("malicious_unlock", False))
    cap = bool(scoring.get("benign_cap_applied", False))
    return score, unlock, cap


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adw-base", required=True)
    ap.add_argument("--ben-base", required=True)
    ap.add_argument("--tag", default="dynlite", help="artifact tag used in apk_dynamic (default dynlite)")
    ap.add_argument("--out", default="dataset_dynlite_results.csv")
    ap.add_argument("--thr", type=int, default=35, help="decision threshold for 'malicious' (default 35)")
    args = ap.parse_args()

    adw = Path(args.adw_base).resolve()
    ben = Path(args.ben_base).resolve()
    out = Path(args.out).resolve()

    rows: List[Dict[str, Any]] = []

    def scan_group(base: Path, label: int, group: str):
        for case_dir in sorted([p for p in base.iterdir() if p.is_dir()]):
            art = _latest_artifact(case_dir, f"apk_dynamic__{args.tag}__*.json")
            if not art:
                continue
            obj = _load_json(art)
            score, unlock, cap = _extract_score(obj)
            pkg = str(obj.get("package") or "")
            rows.append({
                "group": group,
                "label": label,
                "case_id": case_dir.name,
                "package": pkg,
                "score": score,
                "unlock": int(unlock),
                "benign_cap": int(cap),
                "artifact": str(art),
            })

    scan_group(adw, 1, "ADWARE")
    scan_group(ben, 0, "BENIGN")

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [])
        if rows:
            w.writeheader()
            w.writerows(rows)

    # metrics
    thr = int(args.thr)
    tp = fp = tn = fn = 0
    for r in rows:
        y = int(r["label"])
        pred = 1 if int(r["score"]) >= thr or int(r["unlock"]) == 1 else 0
        if y == 1 and pred == 1: tp += 1
        elif y == 0 and pred == 1: fp += 1
        elif y == 0 and pred == 0: tn += 1
        elif y == 1 and pred == 0: fn += 1

    print(f"[OK] wrote {out} rows={len(rows)}")
    print(f"[METRICS] thr={thr}  TP={tp} FP={fp} TN={tn} FN={fn}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())