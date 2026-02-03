# src/media/infer_media.py
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional, List, Tuple

import cv2
import numpy as np
from PIL import Image

import torch
import torch.nn as nn
import torchvision.transforms as T
import torchvision.models as models


def _clamp_box(x1, y1, x2, y2, w, h):
    x1 = max(0, min(w - 1, x1))
    y1 = max(0, min(h - 1, y1))
    x2 = max(0, min(w - 1, x2))
    y2 = max(0, min(h - 1, y2))
    if x2 <= x1:
        x2 = min(w - 1, x1 + 1)
    if y2 <= y1:
        y2 = min(h - 1, y1 + 1)
    return x1, y1, x2, y2


def _expand_box(x1, y1, x2, y2, w, h, expand: float):
    cx = (x1 + x2) / 2.0
    cy = (y1 + y2) / 2.0
    bw = (x2 - x1) * (1.0 + expand)
    bh = (y2 - y1) * (1.0 + expand)
    nx1 = int(cx - bw / 2.0)
    ny1 = int(cy - bh / 2.0)
    nx2 = int(cx + bw / 2.0)
    ny2 = int(cy + bh / 2.0)
    return _clamp_box(nx1, ny1, nx2, ny2, w, h)


def _haar_face_detector():
    cascade_path = Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml"
    det = cv2.CascadeClassifier(str(cascade_path))
    if det.empty():
        raise RuntimeError(f"Failed to load Haar cascade: {cascade_path}")
    return det


def _detect_face_box_haar(detector, bgr: np.ndarray) -> Optional[Tuple[int, int, int, int, float]]:
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    faces = detector.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(48, 48))
    if faces is None or len(faces) == 0:
        return None
    best = None
    h, w = bgr.shape[:2]
    for (x, y, fw, fh) in faces:
        x1, y1, x2, y2 = int(x), int(y), int(x + fw), int(y + fh)
        x1, y1, x2, y2 = _clamp_box(x1, y1, x2, y2, w, h)
        area = (x2 - x1) * (y2 - y1)
        if best is None or area > best[0]:
            best = (area, x1, y1, x2, y2)
    _, x1, y1, x2, y2 = best
    return (x1, y1, x2, y2, 0.7)


def build_model() -> nn.Module:
    m = models.efficientnet_b0(weights=None)
    in_features = m.classifier[1].in_features
    m.classifier[1] = nn.Linear(in_features, 2)
    return m


def load_ckpt(model_path: str, device: torch.device) -> nn.Module:
    ckpt = torch.load(model_path, map_location=device)
    model = build_model().to(device)
    model.load_state_dict(ckpt["model_state"])
    model.eval()
    return model


def face_to_tensor(bgr_face: np.ndarray, size: int = 224) -> torch.Tensor:
    rgb = cv2.cvtColor(bgr_face, cv2.COLOR_BGR2RGB)
    pil = Image.fromarray(rgb).resize((size, size), Image.BILINEAR)
    tf = T.Compose([
        T.ToTensor(),
        T.Normalize(mean=[0.485, 0.456, 0.406],
                    std=[0.229, 0.224, 0.225])
    ])
    return tf(pil).unsqueeze(0)


@torch.no_grad()
def predict_face(model: nn.Module, x: torch.Tensor, device: torch.device) -> float:
    x = x.to(device)
    logits = model(x)
    prob_fake = torch.softmax(logits, dim=1)[:, 1].item()
    return float(prob_fake)


def infer_image(model, detector, path: Path, device: torch.device, expand: float, save_debug: Optional[Path]) -> dict:
    bgr = cv2.imread(str(path))
    if bgr is None:
        return {"status": "error", "error": "cannot_read_image"}

    box = _detect_face_box_haar(detector, bgr)
    if box is None:
        return {"status": "no_face"}

    x1, y1, x2, y2, det_score = box
    h, w = bgr.shape[:2]
    x1, y1, x2, y2 = _expand_box(x1, y1, x2, y2, w, h, expand=expand)
    face = bgr[y1:y2, x1:x2]
    if face.size == 0:
        return {"status": "no_face"}

    x = face_to_tensor(face)
    p = predict_face(model, x, device)

    if save_debug:
        save_debug.parent.mkdir(parents=True, exist_ok=True)
        cv2.imwrite(str(save_debug), face)

    return {
        "status": "ok",
        "prob_fake": p,
        "confidence": float(min(1.0, abs(p - 0.5) * 2.0)),
        "face_det_conf": float(det_score),
    }


def infer_video(model, detector, path: Path, device: torch.device, expand: float, sample_every_sec: float, max_frames: int, debug_dir: Optional[Path]) -> dict:
    cap = cv2.VideoCapture(str(path))
    if not cap.isOpened():
        return {"status": "error", "error": "cannot_open_video"}

    fps = cap.get(cv2.CAP_PROP_FPS)
    if fps is None or fps <= 0:
        fps = 25.0
    stride = max(1, int(round(fps * sample_every_sec)))

    frame_idx = 0
    scores: List[Tuple[int, float, float]] = []
    saved = 0

    while True:
        ok, frame = cap.read()
        if not ok:
            break

        if frame_idx % stride != 0:
            frame_idx += 1
            continue

        box = _detect_face_box_haar(detector, frame)
        if box is None:
            frame_idx += 1
            continue

        x1, y1, x2, y2, det_score = box
        h, w = frame.shape[:2]
        x1, y1, x2, y2 = _expand_box(x1, y1, x2, y2, w, h, expand=expand)
        face = frame[y1:y2, x1:x2]
        if face.size == 0:
            frame_idx += 1
            continue

        x = face_to_tensor(face)
        p = predict_face(model, x, device)
        scores.append((frame_idx, p, float(det_score)))

        saved += 1
        if debug_dir:
            debug_dir.mkdir(parents=True, exist_ok=True)
            if saved <= 8:
                cv2.imwrite(str(debug_dir / f"frame_{frame_idx}.jpg"), face)

        if saved >= max_frames:
            break

        frame_idx += 1

    cap.release()

    if not scores:
        return {"status": "no_face_frames"}

    probs = np.array([p for _, p, _ in scores], dtype=np.float32)
    video_prob = float(np.median(probs))
    conf = float(min(1.0, abs(video_prob - 0.5) * 2.0))

    top = sorted(scores, key=lambda t: t[1], reverse=True)[:5]
    top_frames = [{"frame_idx": int(fi), "prob_fake": float(p), "face_det_conf": float(ds)} for fi, p, ds in top]

    return {
        "status": "ok",
        "prob_fake": video_prob,
        "confidence": conf,
        "frames_analyzed": int(len(scores)),
        "top_frames": top_frames,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Infer deepfake probability for image/video using trained model.")
    ap.add_argument("--model", default="models/deepfake_effnetb0.pt")
    ap.add_argument("--input", required=True)
    ap.add_argument("--out-json", default="media_artifact.json")
    ap.add_argument("--expand", type=float, default=0.25)
    ap.add_argument("--sample-every-sec", type=float, default=0.8)
    ap.add_argument("--max-frames", type=int, default=25)
    ap.add_argument("--device", default="auto", help="auto|cpu|cuda")
    ap.add_argument("--debug-dir", default="")
    args = ap.parse_args()

    if args.device == "cpu":
        device = torch.device("cpu")
    elif args.device == "cuda":
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    else:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    model = load_ckpt(args.model, device)
    detector = _haar_face_detector()

    inp = Path(args.input)
    debug_dir = Path(args.debug_dir) if args.debug_dir else None

    is_video = inp.suffix.lower() in {".mp4", ".mov", ".mkv", ".avi", ".webm"}

    if is_video:
        res = infer_video(model, detector, inp, device, args.expand, args.sample_every_sec, args.max_frames, debug_dir)
        media_type = "video"
    else:
        dbg = (debug_dir / "face.jpg") if debug_dir else None
        res = infer_image(model, detector, inp, device, args.expand, dbg)
        media_type = "image"

    artifact = {
        "engine": "media_forensics",
        "model": {"arch": "efficientnet_b0", "checkpoint": str(Path(args.model).as_posix()), "device": str(device)},
        "input": {"path": str(inp.as_posix()), "type": media_type},
        "result": res,
    }

    out = Path(args.out_json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    print(f"[OK] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
