# src/media/prepare_dataset.py
from __future__ import annotations

import argparse
import csv
import random
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple, Optional

import cv2
import numpy as np
from PIL import Image
from tqdm import tqdm


@dataclass
class SampleRow:
    path: str
    label: int  # 0 real, 1 fake
    source: str  # "video" or "image"
    origin: str  # original file path (video/image)


def _seed_all(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _read_image(path: Path) -> Optional[np.ndarray]:
    img = cv2.imread(str(path))
    return img


def _write_face(out_path: Path, bgr_face: np.ndarray, size: int) -> bool:
    try:
        rgb = cv2.cvtColor(bgr_face, cv2.COLOR_BGR2RGB)
        pil = Image.fromarray(rgb).resize((size, size), Image.BILINEAR)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        pil.save(out_path, format="JPEG", quality=92, optimize=True)
        return True
    except Exception:
        return False


def _clamp_box(x1, y1, x2, y2, w, h) -> Tuple[int, int, int, int]:
    x1 = max(0, min(w - 1, x1))
    y1 = max(0, min(h - 1, y1))
    x2 = max(0, min(w - 1, x2))
    y2 = max(0, min(h - 1, y2))
    if x2 <= x1:
        x2 = min(w - 1, x1 + 1)
    if y2 <= y1:
        y2 = min(h - 1, y1 + 1)
    return x1, y1, x2, y2


def _expand_box(x1, y1, x2, y2, w, h, expand: float) -> Tuple[int, int, int, int]:
    cx = (x1 + x2) / 2.0
    cy = (y1 + y2) / 2.0
    bw = (x2 - x1) * (1.0 + expand)
    bh = (y2 - y1) * (1.0 + expand)
    nx1 = int(cx - bw / 2.0)
    ny1 = int(cy - bh / 2.0)
    nx2 = int(cx + bw / 2.0)
    ny2 = int(cy + bh / 2.0)
    return _clamp_box(nx1, ny1, nx2, ny2, w, h)


# ---- Face detector: OpenCV Haar cascade (no extra deps) ----
def _haar_face_detector():
    cascade_path = Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml"
    det = cv2.CascadeClassifier(str(cascade_path))
    if det.empty():
        raise RuntimeError(f"Failed to load Haar cascade: {cascade_path}")
    return det


def _detect_face_box_haar(detector, bgr: np.ndarray, min_face: int = 48) -> Optional[Tuple[int, int, int, int, float]]:
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    faces = detector.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(min_face, min_face))
    if faces is None or len(faces) == 0:
        return None
    # pick largest face
    best = None
    h, w = bgr.shape[:2]
    for (x, y, fw, fh) in faces:
        x1, y1, x2, y2 = int(x), int(y), int(x + fw), int(y + fh)
        x1, y1, x2, y2 = _clamp_box(x1, y1, x2, y2, w, h)
        area = (x2 - x1) * (y2 - y1)
        if best is None or area > best[0]:
            # confidence is not provided by Haar; we set a proxy
            best = (area, x1, y1, x2, y2)
    _, x1, y1, x2, y2 = best
    return (x1, y1, x2, y2, 0.7)


def _iter_videos(dir_path: Path) -> List[Path]:
    exts = {".mp4", ".mov", ".mkv", ".avi", ".webm"}
    if not dir_path.exists():
        return []
    return sorted([p for p in dir_path.rglob("*") if p.suffix.lower() in exts])


def _iter_images(dir_path: Path) -> List[Path]:
    exts = {".jpg", ".jpeg", ".png", ".webp"}
    if not dir_path.exists():
        return []
    return sorted([p for p in dir_path.rglob("*") if p.suffix.lower() in exts])


def _split_paths(paths: List[Path], train: float, val: float, seed: int) -> Tuple[List[Path], List[Path], List[Path]]:
    _seed_all(seed)
    paths = paths[:]
    random.shuffle(paths)
    n = len(paths)
    n_train = int(n * train)
    n_val = int(n * val)
    train_set = paths[:n_train]
    val_set = paths[n_train:n_train + n_val]
    test_set = paths[n_train + n_val:]
    return train_set, val_set, test_set


def _write_manifest(csv_path: Path, rows: List[SampleRow]) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["path", "label", "source", "origin"])
        for r in rows:
            w.writerow([r.path, r.label, r.source, r.origin])


def _process_image(
    detector,
    img_path: Path,
    out_dir: Path,
    label: int,
    split: str,
    size: int,
    expand: float,
    allow_no_face: bool,
    min_face: int,
) -> Optional[SampleRow]:
    bgr = _read_image(img_path)
    if bgr is None:
        return None

    box = _detect_face_box_haar(detector, bgr, min_face=min_face)
    if box is None:
        if not allow_no_face:
            return None
        # fallback: use the whole image
        face = bgr
    else:
        x1, y1, x2, y2, _ = box
        h, w = bgr.shape[:2]
        x1, y1, x2, y2 = _expand_box(x1, y1, x2, y2, w, h, expand=expand)
        face = bgr[y1:y2, x1:x2]
        if face.size == 0:
            if not allow_no_face:
                return None
            face = bgr  # fallback

    cls = "fake" if label == 1 else "real"
    out_path = out_dir / "faces" / split / cls / f"{img_path.stem}__{abs(hash(str(img_path))) % 10_000_000}.jpg"
    ok = _write_face(out_path, face, size=size)
    if not ok:
        return None
    return SampleRow(path=str(out_path.as_posix()), label=label, source="image", origin=str(img_path.as_posix()))


def _process_video(
    detector,
    vid_path: Path,
    out_dir: Path,
    label: int,
    split: str,
    size: int,
    expand: float,
    sample_every_sec: float,
    max_frames: int,
    allow_no_face: bool,
    min_face: int,
) -> List[SampleRow]:
    cap = cv2.VideoCapture(str(vid_path))
    if not cap.isOpened():
        return []

    fps = cap.get(cv2.CAP_PROP_FPS)
    if fps is None or fps <= 0:
        fps = 25.0
    stride = max(1, int(round(fps * sample_every_sec)))

    rows: List[SampleRow] = []
    frame_idx = 0
    saved = 0
    cls = "fake" if label == 1 else "real"
    vid_tag = f"{vid_path.stem}__{abs(hash(str(vid_path))) % 10_000_000}"

    while True:
        ok, frame = cap.read()
        if not ok:
            break

        if frame_idx % stride != 0:
            frame_idx += 1
            continue

        box = _detect_face_box_haar(detector, frame, min_face=min_face)
        if box is None:
            if not allow_no_face:
                frame_idx += 1
                continue
            # fallback: whole frame
            face = frame
        else:
            x1, y1, x2, y2, _ = box
            h, w = frame.shape[:2]
            x1, y1, x2, y2 = _expand_box(x1, y1, x2, y2, w, h, expand=expand)
            face = frame[y1:y2, x1:x2]
            if face.size == 0:
                if not allow_no_face:
                    frame_idx += 1
                    continue
                face = frame  # fallback

        out_path = out_dir / "faces" / split / cls / f"{vid_tag}__f{frame_idx}.jpg"
        if _write_face(out_path, face, size=size):
            rows.append(SampleRow(path=str(out_path.as_posix()), label=label, source="video", origin=str(vid_path.as_posix())))
            saved += 1

        if saved >= max_frames:
            break
        frame_idx += 1

    cap.release()
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Prepare face-cropped dataset from raw real/fake videos+images.")
    ap.add_argument("--raw-dir", default="data/raw", help="Input raw directory containing real_videos, fake_videos, real_images, fake_images OR CIFAKE train/test.")
    ap.add_argument("--out-dir", default="data/processed", help="Output processed directory.")
    ap.add_argument("--img-size", type=int, default=224, help="Output face crop size.")
    ap.add_argument("--expand", type=float, default=0.25, help="Expand face bbox by this ratio.")
    ap.add_argument("--sample-every-sec", type=float, default=0.8, help="Sample one frame every N seconds.")
    ap.add_argument("--max-frames-per-video", type=int, default=25, help="Max saved face frames per video.")
    ap.add_argument("--train-ratio", type=float, default=0.8, help="Train split ratio (default layout).")
    ap.add_argument("--val-ratio", type=float, default=0.1, help="Val split ratio. Test = 1-train-val (default layout).")
    ap.add_argument("--seed", type=int, default=1337, help="Random seed.")

    # NEW (minimal additions)
    ap.add_argument("--allow-no-face", action="store_true", help="If no face detected, use whole image/frame instead of skipping.")
    ap.add_argument("--min-face", type=int, default=48, help="Min face size for Haar detector.")
    ap.add_argument("--cifake", action="store_true", help="Use CIFAKE folder layout: raw/train/REAL|FAKE and raw/test/REAL|FAKE (images only).")

    args = ap.parse_args()

    raw = Path(args.raw_dir)
    out = Path(args.out_dir)
    _ensure_dir(out)

    detector = _haar_face_detector()

    manifests = {"train": [], "val": [], "test": []}

    if args.cifake:
        # CIFAKE images-only layout:
        #   raw/train/REAL, raw/train/FAKE
        #   raw/test/REAL,  raw/test/FAKE
        train_real = _iter_images(raw / "train" / "REAL")
        train_fake = _iter_images(raw / "train" / "FAKE")
        test_real = _iter_images(raw / "test" / "REAL")
        test_fake = _iter_images(raw / "test" / "FAKE")

        # carve VAL from TRAIN (val_ratio), keep TEST as test
        tr_r, val_r, _ = _split_paths(train_real, train=1.0 - args.val_ratio, val=args.val_ratio, seed=args.seed)
        tr_f, val_f, _ = _split_paths(train_fake, train=1.0 - args.val_ratio, val=args.val_ratio, seed=args.seed + 1)

        for p in tqdm(tr_r, desc="train images real (CIFAKE)"):
            row = _process_image(detector, p, out, 0, "train", args.img_size, args.expand, args.allow_no_face, args.min_face)
            if row:
                manifests["train"].append(row)

        for p in tqdm(tr_f, desc="train images fake (CIFAKE)"):
            row = _process_image(detector, p, out, 1, "train", args.img_size, args.expand, args.allow_no_face, args.min_face)
            if row:
                manifests["train"].append(row)

        for p in tqdm(val_r, desc="val images real (CIFAKE)"):
            row = _process_image(detector, p, out, 0, "val", args.img_size, args.expand, args.allow_no_face, args.min_face)
            if row:
                manifests["val"].append(row)

        for p in tqdm(val_f, desc="val images fake (CIFAKE)"):
            row = _process_image(detector, p, out, 1, "val", args.img_size, args.expand, args.allow_no_face, args.min_face)
            if row:
                manifests["val"].append(row)

        for p in tqdm(test_real, desc="test images real (CIFAKE)"):
            row = _process_image(detector, p, out, 0, "test", args.img_size, args.expand, args.allow_no_face, args.min_face)
            if row:
                manifests["test"].append(row)

        for p in tqdm(test_fake, desc="test images fake (CIFAKE)"):
            row = _process_image(detector, p, out, 1, "test", args.img_size, args.expand, args.allow_no_face, args.min_face)
            if row:
                manifests["test"].append(row)

    else:
        # DEFAULT layout:
        real_videos = _iter_videos(raw / "real_videos")
        fake_videos = _iter_videos(raw / "fake_videos")
        real_images = _iter_images(raw / "real_images")
        fake_images = _iter_images(raw / "fake_images")

        rv_train, rv_val, rv_test = _split_paths(real_videos, args.train_ratio, args.val_ratio, args.seed)
        fv_train, fv_val, fv_test = _split_paths(fake_videos, args.train_ratio, args.val_ratio, args.seed + 1)
        ri_train, ri_val, ri_test = _split_paths(real_images, args.train_ratio, args.val_ratio, args.seed + 2)
        fi_train, fi_val, fi_test = _split_paths(fake_images, args.train_ratio, args.val_ratio, args.seed + 3)

        def proc_split(split: str, vids: List[Path], imgs: List[Path], label: int):
            for p in tqdm(imgs, desc=f"{split} images {'fake' if label else 'real'}"):
                row = _process_image(detector, p, out, label, split, args.img_size, args.expand, args.allow_no_face, args.min_face)
                if row:
                    manifests[split].append(row)
            for p in tqdm(vids, desc=f"{split} videos {'fake' if label else 'real'}"):
                rows = _process_video(
                    detector,
                    p,
                    out,
                    label,
                    split,
                    args.img_size,
                    args.expand,
                    args.sample_every_sec,
                    args.max_frames_per_video,
                    args.allow_no_face,
                    args.min_face,
                )
                manifests[split].extend(rows)

        proc_split("train", rv_train, ri_train, label=0)
        proc_split("train", fv_train, fi_train, label=1)
        proc_split("val", rv_val, ri_val, label=0)
        proc_split("val", fv_val, fi_val, label=1)
        proc_split("test", rv_test, ri_test, label=0)
        proc_split("test", fv_test, fi_test, label=1)

    _write_manifest(out / "manifest_train.csv", manifests["train"])
    _write_manifest(out / "manifest_val.csv", manifests["val"])
    _write_manifest(out / "manifest_test.csv", manifests["test"])

    print(f"[OK] Prepared dataset in: {out}")
    print(f"[OK] Train rows: {len(manifests['train'])} | Val: {len(manifests['val'])} | Test: {len(manifests['test'])}")
    if args.allow_no_face:
        print("[NOTE] allow-no-face enabled: samples without detected faces use whole image/frame.")
    else:
        print("[NOTE] Samples with 'no face detected' are skipped by design.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
