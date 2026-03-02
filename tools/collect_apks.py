from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import zipfile
from pathlib import Path
from typing import Tuple, Optional


def sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def apk_markers(names: list[str]) -> bool:
    s = set(names)
    if "AndroidManifest.xml" not in s:
        return False
    # accept multi-dex
    return any(n.startswith("classes") and n.endswith(".dex") for n in s)


def is_apk_zip_path(p: Path) -> bool:
    try:
        if not zipfile.is_zipfile(p):
            return False
        with zipfile.ZipFile(p, "r") as z:
            return apk_markers(z.namelist())
    except Exception:
        return False


def is_apk_zip_bytes(raw: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(raw), "r") as z:
            return apk_markers(z.namelist())
    except Exception:
        return False


def read_head(p: Path, n: int = 4) -> bytes:
    with p.open("rb") as f:
        return f.read(n)


def gunzip_limited(p: Path, max_bytes: int) -> Optional[bytes]:
    """
    Decompress gzip safely with an upper bound to avoid RAM blow-ups.
    Returns bytes or None on failure/oversize.
    """
    try:
        out = io.BytesIO()
        with gzip.open(p, "rb") as gz:
            total = 0
            while True:
                chunk = gz.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    return None
                out.write(chunk)
        return out.getvalue()
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Folder input (recursiv)")
    ap.add_argument("--out", required=True, help="Folder output (se vor scrie .apk normalizate)")
    ap.add_argument("--limit", type=int, default=0, help="0 = fara limita")
    ap.add_argument("--max-gzip-bytes", type=int, default=200_000_000, help="Max bytes dupa gunzip (default 200MB)")
    args = ap.parse_args()

    root = Path(args.input).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    total_files = 0
    kept_apk = 0
    kept_zip = 0
    kept_gzip = 0
    skipped = 0

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        total_files += 1
        if args.limit and kept_apk >= args.limit:
            break

        try:
            head = read_head(p, 4)
        except Exception:
            skipped += 1
            continue

        # Case 1: ZIP directly (many APKs are ZIP)
        if head == b"PK\x03\x04":
            if is_apk_zip_path(p):
                try:
                    h = sha256_file(p)
                    dest = out_dir / f"{h[:16]}.apk"
                    if not dest.exists():
                        dest.write_bytes(p.read_bytes())
                    kept_apk += 1
                    kept_zip += 1
                except Exception:
                    skipped += 1
            else:
                skipped += 1
            continue

        # Case 2: GZIP containing an APK ZIP
        if head[:2] == b"\x1f\x8b":
            raw = gunzip_limited(p, args.max_gzip_bytes)
            if raw is None:
                skipped += 1
                continue
            if is_apk_zip_bytes(raw):
                try:
                    h = sha256_bytes(raw)
                    dest = out_dir / f"{h[:16]}.apk"
                    if not dest.exists():
                        dest.write_bytes(raw)
                    kept_apk += 1
                    kept_gzip += 1
                except Exception:
                    skipped += 1
            else:
                skipped += 1
            continue

        # Other formats
        skipped += 1

    print(f"[OK] total_files={total_files} kept_apk={kept_apk} zip_apk={kept_zip} gzip_apk={kept_gzip} skipped={skipped}")
    print(f"[OK] out_dir={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
