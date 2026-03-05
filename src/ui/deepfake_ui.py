from __future__ import annotations

import os
import json
import time
import threading
import html as html_lib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List, TYPE_CHECKING

import customtkinter as ctk
from tkinter import filedialog, messagebox

# ---- Inference deps (NO mediapipe) ----
import numpy as np

try:
    import cv2  # opencv-python
except Exception:
    cv2 = None

# --- PIL (runtime) ---
try:
    from PIL import Image as PIL
except Exception:
    PIL = None

try:
    from PIL import ExifTags as PILExifTags
except Exception:
    PILExifTags = None

# --- Torch (runtime) ---
try:
    import torch
    import torch.nn as nn
    from torchvision import models, transforms
except Exception:
    torch = None
    nn = None
    models = None
    transforms = None

# --- Typing aliases (NO Pylance errors) ---
if TYPE_CHECKING:
    from PIL.Image import Image as PILImageType
    from torch.nn import Module as TorchModuleType
    from torch import device as TorchDeviceType
else:
    PILImageType = Any
    TorchModuleType = Any
    TorchDeviceType = Any


# ============================================================
# Public API (import these in src/ui/app.py)
# ============================================================

def build_deepfake_image_tab(app: Any, parent: Any) -> None:
    """
    Populate the 'Deepfake • Image' tab.
    `app` is your existing CyberShadowHub instance.
    """
    ui = getattr(app, "_dfui", None)
    if ui is None:
        ui = _DFUI(app)
        app._dfui = ui
    ui.build_image(parent)


def build_deepfake_video_tab(app: Any, parent: Any) -> None:
    """Populate the 'Deepfake • Video' tab."""
    ui = getattr(app, "_dfui", None)
    if ui is None:
        ui = _DFUI(app)
        app._dfui = ui
    ui.build_video(parent)


# ============================================================
# Helpers
# ============================================================
def _latest_model_ckpt(models_dir: Optional[str] = None) -> Optional[str]:
    root = Path(_project_root_dir())
    mdir = Path(models_dir) if models_dir else (root / "models")
    if not mdir.exists():
        return None

    # priority: deepfake__*.pt then any *.pt/*.pth
    cands = list(mdir.glob("deepfake__*.pt")) + list(mdir.glob("deepfake__*.pth"))
    if not cands:
        cands = list(mdir.glob("*.pt")) + list(mdir.glob("*.pth"))

    if not cands:
        return None

    cands.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return str(cands[0])



def _project_root_dir() -> str:
    # src/ui/deepfake_ui.py -> root is two parents up from /src/ui
    here = Path(__file__).resolve()
    return str(here.parents[2])


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _now_tag() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def _safe_float(x: Any, default: float) -> float:
    try:
        return float(x)
    except Exception:
        return default


def _safe_int(x: Any, default: int) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _device_pick(pref: str) -> str:
    pref = (pref or "auto").lower().strip()
    if pref in ("cpu", "cuda"):
        return pref
    return "auto"


def _load_image_pil(path: str) -> PILImageType:
    if PIL is None:
        raise RuntimeError("Pillow (PIL) missing. Install: pip install pillow")
    return PIL.open(path).convert("RGB")


def _pil_to_ctk_image(pil_img: PILImageType, max_wh: int = 360) -> ctk.CTkImage:
    w, h = pil_img.size
    scale = min(max_wh / max(w, 1), max_wh / max(h, 1), 1.0)
    nw, nh = max(1, int(w * scale)), max(1, int(h * scale))
    pil_resized = pil_img.resize((nw, nh))
    return ctk.CTkImage(light_image=pil_resized, dark_image=pil_resized, size=(nw, nh))


def _read_video_frame(path: str, frame_idx: int) -> Optional[np.ndarray]:
    if cv2 is None:
        return None
    cap = cv2.VideoCapture(path)
    if not cap.isOpened():
        return None
    try:
        cap.set(cv2.CAP_PROP_POS_FRAMES, max(0, int(frame_idx)))
        ok, frame = cap.read()
        if not ok or frame is None:
            return None
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        return frame
    finally:
        cap.release()


def _np_to_pil(img_rgb: np.ndarray) -> PILImageType:
    if PIL is None:
        raise RuntimeError("Pillow (PIL) missing. Install: pip install pillow")
    return PIL.fromarray(img_rgb.astype(np.uint8), mode="RGB")


def _make_output_paths(kind: str) -> Tuple[Path, Path]:
    root = Path(_project_root_dir())
    out_dir = root / "reports" / "deepfake"
    _ensure_dir(out_dir)
    ts = _now_tag()
    base = f"deepfake_{kind}__{ts}"
    return out_dir / f"{base}.json", out_dir / f"{base}.html"


EXIF_TAGS: Dict[int, str] = dict(getattr(PILExifTags, "TAGS", {}) or {})

PAYLOAD_BIN_SIGNATURES: List[Tuple[bytes, str]] = [
    (b"PK\x03\x04", "ZIP archive header"),
    (b"\x7fELF", "ELF executable header"),
    (b"MZ", "PE executable header"),
    (b"\x1f\x8b\x08", "GZIP archive header"),
]

PAYLOAD_TEXT_SIGNATURES: List[Tuple[str, str]] = [
    ("<script", "Script tag text"),
    ("powershell", "PowerShell text"),
    ("cmd.exe", "Windows command text"),
    ("#!/bin/sh", "Shell script shebang"),
]

AI_METADATA_MARKERS = [
    "stable diffusion",
    "midjourney",
    "automatic1111",
    "comfyui",
    "sdxl",
    "generator",
    "negative prompt",
    "prompt",
    "sampler",
]

SUSPICIOUS_METADATA_MARKERS = [
    "powershell",
    "cmd.exe",
    "<script",
    "<?php",
    "base64,",
    "wget ",
    "curl ",
    "http://",
]


def _human_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    v = float(max(0, int(n)))
    for u in units:
        if v < 1024.0 or u == units[-1]:
            return f"{v:.2f} {u}" if u != "B" else f"{int(v)} {u}"
        v /= 1024.0
    return f"{int(n)} B"


def _guess_magic(head: bytes) -> str:
    h = head or b""
    if h.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if h.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF"
    if h.startswith(b"RIFF") and h[8:12] == b"WEBP":
        return "WEBP"
    if h.startswith(b"RIFF") and h[8:12] == b"AVI ":
        return "AVI"
    if len(h) >= 8 and h[4:8] == b"ftyp":
        return "MP4"
    if h.startswith(b"\x1A\x45\xDF\xA3"):
        return "MKV_WEBM"
    return "UNKNOWN"


def _extension_matches_magic(ext: str, magic: str) -> bool:
    ext_l = (ext or "").lower().strip()
    expected = {
        "JPEG": {".jpg", ".jpeg"},
        "PNG": {".png"},
        "GIF": {".gif"},
        "WEBP": {".webp"},
        "AVI": {".avi"},
        "MP4": {".mp4", ".mov", ".m4v", ".3gp"},
        "MKV_WEBM": {".mkv", ".webm"},
    }
    if magic not in expected:
        return True
    return ext_l in expected[magic]


def _mp4_end_offset(path: str, file_size: int) -> int:
    pos = 0
    boxes = 0
    try:
        with open(path, "rb") as f:
            while pos + 8 <= file_size and boxes < 100000:
                f.seek(pos)
                hdr = f.read(8)
                if len(hdr) < 8:
                    break
                box_size = int.from_bytes(hdr[:4], "big", signed=False)
                header_len = 8
                if box_size == 0:
                    return file_size
                if box_size == 1:
                    ext = f.read(8)
                    if len(ext) < 8:
                        break
                    box_size = int.from_bytes(ext, "big", signed=False)
                    header_len = 16
                if box_size < header_len:
                    break
                nxt = pos + box_size
                if nxt <= pos or nxt > file_size:
                    break
                pos = nxt
                boxes += 1
        return max(0, min(file_size, pos))
    except Exception:
        return 0


def _detect_trailing_payload(path: str, magic: str) -> Dict[str, Any]:
    size = int(os.path.getsize(path))
    if size <= 0:
        return {"trailing_bytes": 0, "end_offset": 0, "marker": "empty_file"}

    marker = "unknown"
    end_offset = size

    try:
        with open(path, "rb") as f:
            head = f.read(64)
            if magic == "WEBP" and head.startswith(b"RIFF") and len(head) >= 8:
                declared = int.from_bytes(head[4:8], "little", signed=False) + 8
                end_offset = min(size, max(0, declared))
                marker = "webp_riff_size"
            elif magic == "AVI" and head.startswith(b"RIFF") and len(head) >= 8:
                declared = int.from_bytes(head[4:8], "little", signed=False) + 8
                end_offset = min(size, max(0, declared))
                marker = "avi_riff_size"
            elif magic == "MP4":
                parsed = _mp4_end_offset(path, size)
                if parsed > 0:
                    end_offset = parsed
                    marker = "mp4_box_walk"
    except Exception:
        pass

    if magic in {"JPEG", "PNG", "GIF"}:
        try:
            window = min(size, 2 * 1024 * 1024)
            with open(path, "rb") as f:
                f.seek(max(0, size - window))
                tail = f.read(window)
            if magic == "JPEG":
                idx = tail.rfind(b"\xff\xd9")
                if idx >= 0:
                    end_offset = size - window + idx + 2
                    marker = "jpeg_eoi"
            elif magic == "PNG":
                idx = tail.rfind(b"IEND\xaeB`\x82")
                if idx >= 0:
                    end_offset = size - window + idx + 8
                    marker = "png_iend"
            elif magic == "GIF":
                idx = tail.rfind(b"\x3b")
                if idx >= 0:
                    end_offset = size - window + idx + 1
                    marker = "gif_trailer"
        except Exception:
            pass

    end_offset = max(0, min(size, int(end_offset)))
    trailing = max(0, int(size - end_offset))
    return {"trailing_bytes": trailing, "end_offset": end_offset, "marker": marker}


def _scan_tail_signatures(path: str, tail_limit: int = 1024 * 1024) -> List[Dict[str, Any]]:
    size = int(os.path.getsize(path))
    if size <= 0:
        return []

    with open(path, "rb") as f:
        read_n = min(size, int(tail_limit))
        f.seek(max(0, size - read_n))
        blob = f.read(read_n)

    hits: List[Dict[str, Any]] = []
    base_off = size - len(blob)

    for sig, label in PAYLOAD_BIN_SIGNATURES:
        idx = blob.find(sig)
        if idx >= 0:
            hits.append(
                {
                    "label": label,
                    "kind": "binary",
                    "signature": sig.hex(),
                    "offset": int(base_off + idx),
                }
            )

    blob_text = blob.decode("latin-1", errors="ignore").lower()
    for text_sig, label in PAYLOAD_TEXT_SIGNATURES:
        idx = blob_text.find(text_sig)
        if idx >= 0:
            hits.append(
                {
                    "label": label,
                    "kind": "text",
                    "signature": text_sig,
                    "offset": int(base_off + idx),
                }
            )

    return hits[:12]


def _collect_image_metadata(path: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if PIL is None:
        out["error"] = "Pillow not available"
        return out

    try:
        with PIL.open(path) as img:
            out["format"] = str(getattr(img, "format", "") or "")
            out["mode"] = str(getattr(img, "mode", "") or "")
            out["width"] = int(getattr(img, "width", 0) or 0)
            out["height"] = int(getattr(img, "height", 0) or 0)

            info = dict(getattr(img, "info", {}) or {})
            out["info_keys"] = sorted(str(k) for k in info.keys())[:40]
            info_preview: Dict[str, str] = {}
            for k, v in list(info.items())[:25]:
                sv = str(v)
                if len(sv) > 220:
                    sv = sv[:220] + "..."
                info_preview[str(k)] = sv
            out["info_preview"] = info_preview

            exif_preview: Dict[str, str] = {}
            exif_count = 0
            if hasattr(img, "getexif"):
                exif = img.getexif() or {}
                exif_count = len(exif)
                for tag_id, value in list(exif.items())[:25]:
                    tag = EXIF_TAGS.get(int(tag_id), str(tag_id))
                    sval = str(value)
                    if len(sval) > 220:
                        sval = sval[:220] + "..."
                    exif_preview[str(tag)] = sval
            out["exif_count"] = int(exif_count)
            out["exif_preview"] = exif_preview
    except Exception as e:
        out["error"] = str(e)

    return out


def _collect_video_metadata(path: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if cv2 is None:
        out["error"] = "OpenCV not available"
        return out

    try:
        cap = cv2.VideoCapture(path)
        if not cap.isOpened():
            out["error"] = "Cannot open video"
            return out
        try:
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
            fps = float(cap.get(cv2.CAP_PROP_FPS) or 0.0)
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
            fourcc = int(cap.get(cv2.CAP_PROP_FOURCC) or 0)
            codec = "".join(chr((fourcc >> (8 * i)) & 0xFF) for i in range(4)).strip("\x00")
            duration = float(frame_count / fps) if fps > 0 else 0.0
            out.update(
                {
                    "width": width,
                    "height": height,
                    "fps": round(fps, 4),
                    "frame_count": frame_count,
                    "duration_sec": round(duration, 3),
                    "codec_fourcc": codec,
                }
            )
        finally:
            cap.release()
    except Exception as e:
        out["error"] = str(e)

    return out


def _decide_payload_verdict(score: int) -> Tuple[str, str, str]:
    s = max(0, min(100, int(score)))
    if s >= 60:
        return "PAYLOAD_SUSPECTED", "60-100", "MALWARE_SUSPECTED"
    if s >= 25:
        return "SUSPICIOUS", "25-59", "MALWARE_SUSPECTED"
    return "CLEAN", "0-24", "BENIGN"


def _scan_media_payload(path: str, kind: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise RuntimeError(f"File not found: {path}")

    size = int(p.stat().st_size)
    with p.open("rb") as f:
        head = f.read(64)

    magic = _guess_magic(head)
    ext = p.suffix.lower()
    trailing = _detect_trailing_payload(path, magic=magic)
    tail_hits = _scan_tail_signatures(path)

    metadata = _collect_image_metadata(path) if kind == "image" else _collect_video_metadata(path)
    metadata_blob = json.dumps(metadata, ensure_ascii=False).lower()
    ai_metadata_hits = sorted({m for m in AI_METADATA_MARKERS if m in metadata_blob})
    suspicious_meta_hits = sorted({m for m in SUSPICIOUS_METADATA_MARKERS if m in metadata_blob})

    score = 0
    reasons: List[str] = []
    indicators: List[Dict[str, Any]] = []

    if not _extension_matches_magic(ext, magic):
        score += 12
        reasons.append(f"Extension/type mismatch: ext={ext or '(none)'} vs magic={magic} (+12)")

    trailing_bytes = int(trailing.get("trailing_bytes", 0) or 0)
    if trailing_bytes > 0:
        add = min(40, 10 + int(trailing_bytes / 2048))
        score += add
        reasons.append(
            f"Trailing bytes after media end marker: {trailing_bytes} bytes ({trailing.get('marker')}) (+{add})"
        )
        indicators.append(
            {
                "type": "trailing_data",
                "bytes": trailing_bytes,
                "marker": trailing.get("marker"),
                "end_offset": int(trailing.get("end_offset", 0) or 0),
            }
        )

    for hit in tail_hits:
        add = 20 if hit.get("kind") == "binary" else 12
        score += add
        reasons.append(f"Embedded payload signature in tail: {hit.get('label')} (+{add})")
        indicators.append({"type": "signature", **hit})

    if suspicious_meta_hits:
        add = min(30, 12 + 6 * len(suspicious_meta_hits))
        score += add
        reasons.append(
            f"Suspicious metadata/script markers: {', '.join(suspicious_meta_hits[:6])} (+{add})"
        )
        indicators.append(
            {
                "type": "metadata_markers",
                "markers": suspicious_meta_hits[:20],
            }
        )

    if ai_metadata_hits:
        reasons.append(
            f"AI-generation metadata markers present (informational): {', '.join(ai_metadata_hits[:6])}"
        )

    if not reasons:
        reasons = ["No suspicious embedded payload or metadata abuse indicators detected."]

    score = max(0, min(100, int(score)))
    verdict, interval, decision = _decide_payload_verdict(score)

    payload = {
        "engine": "media_payload_forensics",
        "input": {"path": str(p), "type": kind},
        "result": {
            "status": "ok",
            "verdict": verdict,
            "score": score,
            "score_max": 100,
            "classification_interval": interval,
            "malware_decision": decision,
            "file_meta": {
                "name": p.name,
                "extension": ext,
                "size_bytes": size,
                "size_human": _human_size(size),
                "magic": magic,
                "extension_matches_magic": bool(_extension_matches_magic(ext, magic)),
            },
            "metadata": metadata,
            "ai_metadata_markers": ai_metadata_hits,
            "payload_indicators": indicators[:40],
            "reasons": reasons[:25],
        },
    }
    return payload


def _render_payload_summary(payload: Dict[str, Any]) -> str:
    r = payload.get("result", {}) or {}
    inp = payload.get("input", {}) or {}
    path = str(inp.get("path", "") or "")
    kind = str(inp.get("type", "?") or "?").upper()

    lines: List[str] = []
    lines.append(f"Media metadata/payload scan ({kind}): {r.get('verdict', '?')}")
    lines.append(f"Input: {path}")
    lines.append(
        f"Score={int(r.get('score', 0) or 0)}/100 | Interval={r.get('classification_interval', '?')} | Decision={r.get('malware_decision', '?')}"
    )

    ai_hits = r.get("ai_metadata_markers") or []
    if ai_hits:
        lines.append(f"AI metadata markers: {', '.join([str(x) for x in ai_hits[:8]])}")

    indicators = r.get("payload_indicators") or []
    if indicators:
        lines.append("\nPayload indicators:")
        for it in indicators[:8]:
            lines.append(f"  - {it.get('type')}: {it.get('label') or it.get('marker') or it.get('signature')}")

    reasons = r.get("reasons") or []
    if reasons:
        lines.append("\nWhy this result:")
        for rr in reasons[:8]:
            lines.append(f"- {rr}")

    return "\n".join(lines) + "\n"


def _render_payload_html(payload: Dict[str, Any]) -> str:
    def _h(x: Any) -> str:
        return html_lib.escape(str(x), quote=True)

    r = payload.get("result", {}) or {}
    inp = payload.get("input", {}) or {}
    fm = r.get("file_meta", {}) or {}
    meta = r.get("metadata", {}) or {}
    indicators = r.get("payload_indicators", []) or []
    reasons = r.get("reasons", []) or []
    ai_hits = r.get("ai_metadata_markers", []) or []

    rows = [
        ("Type", inp.get("type", "?")),
        ("Input", inp.get("path", "")),
        ("Verdict", r.get("verdict", "?")),
        ("Score", f"{int(r.get('score', 0) or 0)}/100"),
        ("Interval", r.get("classification_interval", "?")),
        ("Decision", r.get("malware_decision", "?")),
        ("File size", fm.get("size_human", "?")),
        ("Magic", fm.get("magic", "UNKNOWN")),
        ("Extension", fm.get("extension", "")),
        ("Ext/Magic match", fm.get("extension_matches_magic", True)),
    ]

    rows_html = "".join(
        f"<tr><td>{_h(k)}</td><td><code>{_h(v)}</code></td></tr>" for k, v in rows
    )

    meta_block = _h(json.dumps(meta, indent=2, ensure_ascii=False))
    ind_block = _h(json.dumps(indicators, indent=2, ensure_ascii=False))
    reasons_html = "".join(f"<li>{_h(x)}</li>" for x in reasons)
    ai_html = ", ".join(_h(x) for x in ai_hits) if ai_hits else "(none)"

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>CYBERSHADOW Payload/Metadata Report</title>
<style>
body {{ font-family: Arial, sans-serif; background:#0b1220; color:#e5e7eb; padding:20px; }}
.card {{ background:#0f172a; border:1px solid #1f2a44; border-radius:16px; padding:18px; margin-bottom:12px; }}
table {{ width:100%; border-collapse:collapse; margin-top:8px; }}
td {{ padding:8px; border-bottom:1px solid #1f2a44; vertical-align:top; }}
code, pre {{ color:#93c5fd; white-space:pre-wrap; word-break:break-word; }}
</style>
</head>
<body>
<div class="card">
  <h2>Media Metadata/Payload Scan</h2>
  <table>{rows_html}</table>
  <p><b>AI metadata markers:</b> {ai_html}</p>
</div>
<div class="card">
  <h3>Reasons</h3>
  <ul>{reasons_html or "<li>(none)</li>"}</ul>
</div>
<div class="card">
  <h3>Payload indicators</h3>
  <pre>{ind_block}</pre>
</div>
<div class="card">
  <h3>Metadata snapshot</h3>
  <pre>{meta_block}</pre>
</div>
</body>
</html>
"""


def _verdict(prob_fake: float, thr: float, eps: float = 0.05) -> str:
    """
    Decision with uncertainty band:
      - FAKE if prob_fake >= thr + eps
      - REAL if prob_fake <= thr - eps
      - UNCERTAIN if near threshold
    """
    if prob_fake >= thr + eps:
        return "FAKE"
    if prob_fake <= thr - eps:
        return "REAL"
    return "UNCERTAIN"


def _render_summary(payload: Dict[str, Any]) -> str:
    r = payload.get("result", {})
    verdict = r.get("verdict", "?")
    prob = float(r.get("prob_fake", 0.5))
    conf = float(r.get("confidence", 0.0))
    face = float(r.get("face_det_conf", 0.0))
    kind = payload.get("input", {}).get("type", "?")
    path = payload.get("input", {}).get("path", "")

    lines: List[str] = []
    lines.append(f"Deepfake {kind.upper()} verdict: {verdict}")
    lines.append(f"Input: {path}")
    lines.append(f"prob_fake={prob:.6f} | confidence={conf:.4f} | face_det_conf={face:.2f}")
    if verdict == "UNCERTAIN":
        lines.append("NOTE: Prediction is near threshold; treat as inconclusive (try more frames / different sample).")

    if kind == "video":
        frames = int(r.get("frames_analyzed", 0) or 0)
        lines.append(f"frames_analyzed={frames}")
        top = r.get("top_frames") or []
        if top:
            lines.append("\nTop suspicious frames:")
            for t in top[:8]:
                lines.append(
                    f"  - frame {t.get('frame_idx')}: prob_fake={float(t.get('prob_fake',0.0)):.4f} | face={float(t.get('face_det_conf',0.0)):.2f}"
                )

    lines.append("\nWhy this result:")
    lines.append("- prob_fake is produced by the trained EfficientNet classifier on a face crop.")
    lines.append("- For video, frames are sampled and aggregated (median) to reduce noise.")
    lines.append("- The UI shows top suspicious frames for explainability.")
    return "\n".join(lines) + "\n"


def _render_html(payload: Dict[str, Any]) -> str:
    r = payload.get("result", {})
    kind = payload.get("input", {}).get("type", "?")
    path = payload.get("input", {}).get("path", "")
    prob = float(r.get("prob_fake", 0.5))
    verdict = r.get("verdict", "?")
    conf = float(r.get("confidence", 0.0))
    face = float(r.get("face_det_conf", 0.0))

    rows = []
    rows.append(f"<tr><td>Type</td><td>{kind}</td></tr>")
    rows.append(f"<tr><td>Input</td><td><code>{path}</code></td></tr>")
    rows.append(f"<tr><td>Verdict</td><td><b>{verdict}</b></td></tr>")
    rows.append(f"<tr><td>prob_fake</td><td>{prob:.6f}</td></tr>")
    rows.append(f"<tr><td>confidence</td><td>{conf:.4f}</td></tr>")
    rows.append(f"<tr><td>face_det_conf</td><td>{face:.2f}</td></tr>")

    extra = ""
    if kind == "video":
        top = r.get("top_frames") or []
        if top:
            extra += "<h3>Top suspicious frames</h3><ul>"
            for t in top[:10]:
                extra += f"<li>frame {t.get('frame_idx')}: prob_fake={float(t.get('prob_fake',0.0)):.4f} | face={float(t.get('face_det_conf',0.0)):.2f}</li>"
            extra += "</ul>"

    html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>CYBERSHADOW • Deepfake Report</title>
<style>
body {{ font-family: Arial, sans-serif; background:#0b1220; color:#e5e7eb; padding:20px; }}
.card {{ background:#0f172a; border:1px solid #1f2a44; border-radius:16px; padding:18px; }}
table {{ width:100%; border-collapse:collapse; margin-top:12px; }}
td {{ padding:8px; border-bottom:1px solid #1f2a44; vertical-align:top; }}
code {{ color:#93c5fd; }}
.badge {{ display:inline-block; padding:6px 10px; border-radius:999px; border:1px solid #1f2a44; }}
</style>
</head>
<body>
<div class="card">
  <h2>Deepfake Analysis</h2>
  <div class="badge">Verdict: <b>{verdict}</b> • prob_fake={prob:.4f}</div>
  <table>
    {''.join(rows)}
  </table>
  {extra}
  <h3>Why this result</h3>
  <ul>
    <li>The probability is produced by an EfficientNet classifier trained on real vs fake face crops.</li>
    <li>For videos, multiple frames are sampled and aggregated to reduce single-frame noise.</li>
    <li>Top suspicious frames provide explainability for the analyst.</li>
  </ul>
</div>
</body>
</html>
"""
    return html


# ============================================================
# Model + Face Crop + Inference
# ============================================================

FAKE_CLASS_INDEX = 1  # class 1 = FAKE in your 2-logit checkpoint


def _torch_check() -> None:
    if torch is None or nn is None or models is None or transforms is None:
        raise RuntimeError("PyTorch/torchvision missing. Install torch + torchvision.")
    if PIL is None:
        raise RuntimeError("Pillow missing. Install: pip install pillow")
    if cv2 is None:
        raise RuntimeError("OpenCV missing. Install: pip install opencv-python")


def _build_model(num_classes: int = 2) -> TorchModuleType:
    # IMPORTANT: your checkpoint has classifier with 2 outputs (shape [2,1280])
    m = models.efficientnet_b0(weights=None)
    in_features = m.classifier[1].in_features
    m.classifier[1] = nn.Linear(in_features, num_classes)  # 2-class logits (REAL/FAKE)
    return m


def _load_checkpoint(model: TorchModuleType, ckpt_path: str, device: TorchDeviceType) -> None:
    # Load checkpoint safely (support older/newer torch)
    try:
        ckpt = torch.load(ckpt_path, map_location=device, weights_only=True)
    except TypeError:
        ckpt = torch.load(ckpt_path, map_location=device)

    sd = None
    if isinstance(ckpt, dict):
        # common save layouts
        for key in ("model_state", "state_dict", "model_state_dict", "model", "net", "weights"):
            if key in ckpt and isinstance(ckpt[key], dict):
                sd = ckpt[key]
                break
        # sometimes dict itself is a state_dict
        if sd is None and all(isinstance(k, str) for k in ckpt.keys()):
            sd = ckpt

    if not isinstance(sd, dict):
        raise RuntimeError("Unsupported checkpoint format (no state_dict found).")

    # strip common prefixes
    cleaned = {}
    for k, v in sd.items():
        nk = k
        for pref in ("module.", "model.", "net.", "backbone."):
            if nk.startswith(pref):
                nk = nk[len(pref):]
        cleaned[nk] = v

    # load and verify
    try:
        res = model.load_state_dict(cleaned, strict=False)
    except RuntimeError as e:
        # crystal clear error (e.g., num_classes mismatch)
        raise RuntimeError(f"Checkpoint load failed: {e}")

    missing = list(getattr(res, "missing_keys", []))
    unexpected = list(getattr(res, "unexpected_keys", []))

    # If too many missing -> it didn't actually load correct weights
    if len(missing) > 50:
        raise RuntimeError(
            "Checkpoint did NOT load cleanly into the model.\n"
            f"Missing keys: {len(missing)} (sample: {missing[:10]})\n"
            f"Unexpected keys: {len(unexpected)} (sample: {unexpected[:10]})\n"
            "=> Model would behave like random weights (~0.5)."
        )


def _pick_device(pref: str) -> TorchDeviceType:
    pref = _device_pick(pref)
    if pref == "cpu":
        return torch.device("cpu")
    if pref == "cuda":
        return torch.device("cuda") if torch.cuda.is_available() else torch.device("cpu")
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def _prep_transform(img_size: int = 224):
    return transforms.Compose([
        transforms.Resize((img_size, img_size)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
    ])


def _predict_prob(model: TorchModuleType, device: TorchDeviceType, pil_img: PILImageType) -> float:
    tfm = _prep_transform(224)
    x = tfm(pil_img).unsqueeze(0).to(device)

    with torch.no_grad():
        out = model(x)

        # 2 logits -> softmax -> take class=1 as FAKE
        if hasattr(out, "ndim") and out.ndim == 2 and out.shape[1] == 2:
            probs = torch.softmax(out, dim=1)
            prob_fake = probs[0, FAKE_CLASS_INDEX].item()
            return float(prob_fake)

        # fallback: single logit -> sigmoid
        logit = out.view(-1)
        prob = torch.sigmoid(logit)[0].item()
        return float(prob)


def _haar_face_detector():
    if cv2 is None:
        return None
    haar = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    if not os.path.exists(haar):
        return None
    return cv2.CascadeClassifier(haar)


_FACE_DET = None


def _detect_face_bbox(rgb: np.ndarray) -> Tuple[Optional[Tuple[int, int, int, int]], float]:
    """
    Returns (x,y,w,h) and approximate confidence [0..1].
    Haar doesn't give real confidence; we approximate by relative face size.
    """
    global _FACE_DET
    if _FACE_DET is None:
        _FACE_DET = _haar_face_detector()
    if _FACE_DET is None:
        return None, 0.0

    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    faces = _FACE_DET.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(60, 60))
    if faces is None or len(faces) == 0:
        return None, 0.0

    x, y, w, h = max(faces, key=lambda b: b[2] * b[3])
    conf = float(min(1.0, (w * h) / float(rgb.shape[0] * rgb.shape[1] + 1e-9) * 8.0))
    return (int(x), int(y), int(w), int(h)), conf


def _expand_bbox(x: int, y: int, w: int, h: int, expand: float, W: int, H: int) -> Tuple[int, int, int, int]:
    ex = int(w * expand)
    ey = int(h * expand)
    nx = max(0, x - ex)
    ny = max(0, y - ey)
    nw = min(W - nx, w + 2 * ex)
    nh = min(H - ny, h + 2 * ey)
    return nx, ny, nw, nh


def _crop_face(rgb: np.ndarray, expand: float) -> Tuple[Optional[np.ndarray], float]:
    bbox, face_conf = _detect_face_bbox(rgb)
    if bbox is None:
        return None, 0.0
    x, y, w, h = bbox
    H, W = rgb.shape[:2]
    x, y, w, h = _expand_bbox(x, y, w, h, expand, W, H)
    crop = rgb[y:y + h, x:x + w].copy()
    return crop, face_conf


@dataclass
class _InferResult:
    kind: str
    payload: Dict[str, Any]
    best_frame_idx: Optional[int] = None


def _infer_image(path: str, model_path: str, device_pref: str, thr: float, expand: float) -> _InferResult:
    _torch_check()
    device = _pick_device(device_pref)

    model = _build_model(num_classes=2).to(device)
    model.eval()
    _load_checkpoint(model, model_path, device)

    rgb = np.array(_load_image_pil(path))
    crop, face_conf = _crop_face(rgb, expand=expand)

    if crop is None:
        payload = {
            "engine": "media_forensics",
            "model": {"arch": "efficientnet_b0", "checkpoint": model_path, "device": str(device)},
            "input": {"path": path, "type": "image"},
            "result": {"status": "ok", "verdict": "UNKNOWN_NO_FACE", "prob_fake": 0.5, "confidence": 0.0, "face_det_conf": 0.0},
        }
        return _InferResult(kind="image", payload=payload)

    pil_crop = _np_to_pil(crop)
    prob = _predict_prob(model, device, pil_crop)
    verdict = _verdict(prob, thr, eps=0.05)

    # confidence heuristic: distance from 0.5 plus face confidence
    conf = float(min(1.0, abs(prob - 0.5) * 2.0) * 0.75 + min(1.0, face_conf) * 0.25)

    payload = {
        "engine": "media_forensics",
        "model": {"arch": "efficientnet_b0", "checkpoint": model_path, "device": str(device)},
        "input": {"path": path, "type": "image"},
        "result": {
            "status": "ok",
            "verdict": verdict,
            "prob_fake": float(prob),
            "confidence": float(conf),
            "face_det_conf": float(face_conf),
        },
    }
    return _InferResult(kind="image", payload=payload)


def _sample_frame_indices(path: str, frames: int) -> List[int]:
    if cv2 is None:
        return [0]
    cap = cv2.VideoCapture(path)
    if not cap.isOpened():
        return [0]
    try:
        n = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        if n <= 0:
            return [0]
        frames = max(1, int(frames))
        idxs = np.linspace(0, max(0, n - 1), num=frames).astype(int).tolist()
        return sorted(set(int(x) for x in idxs))
    finally:
        cap.release()


def _infer_video(path: str, model_path: str, device_pref: str, thr: float, expand: float, frames: int) -> _InferResult:
    _torch_check()
    device = _pick_device(device_pref)

    model = _build_model(num_classes=2).to(device)
    model.eval()
    _load_checkpoint(model, model_path, device)

    idxs = _sample_frame_indices(path, frames=frames)

    per_frame: List[Dict[str, Any]] = []
    probs: List[float] = []
    best_prob = -1.0
    best_idx = None
    best_face_conf = 0.0

    for idx in idxs:
        rgb = _read_video_frame(path, idx)
        if rgb is None:
            continue
        crop, face_conf = _crop_face(rgb, expand=expand)
        if crop is None:
            continue
        pil_crop = _np_to_pil(crop)
        p = _predict_prob(model, device, pil_crop)

        probs.append(float(p))
        per_frame.append({"frame_idx": int(idx), "prob_fake": float(p), "face_det_conf": float(face_conf)})

        if p > best_prob:
            best_prob = float(p)
            best_idx = int(idx)
            best_face_conf = float(face_conf)

    if not probs:
        payload = {
            "engine": "media_forensics",
            "model": {"arch": "efficientnet_b0", "checkpoint": model_path, "device": str(device)},
            "input": {"path": path, "type": "video"},
            "result": {
                "status": "ok",
                "verdict": "UNKNOWN_NO_FACE",
                "prob_fake": 0.5,
                "confidence": 0.0,
                "face_det_conf": 0.0,
                "frames_analyzed": 0,
                "top_frames": [],
            },
        }
        return _InferResult(kind="video", payload=payload, best_frame_idx=None)

    # robust aggregation: median
    prob = float(np.median(np.array(probs, dtype=np.float32)))
    verdict = _verdict(prob, thr, eps=0.05)
    conf = float(min(1.0, abs(prob - 0.5) * 2.0))

    per_frame.sort(key=lambda d: float(d.get("prob_fake", 0.0)), reverse=True)

    payload = {
        "engine": "media_forensics",
        "model": {"arch": "efficientnet_b0", "checkpoint": model_path, "device": str(device)},
        "input": {"path": path, "type": "video"},
        "result": {
            "status": "ok",
            "verdict": verdict,
            "prob_fake": float(prob),
            "confidence": float(conf),
            "face_det_conf": float(best_face_conf),
            "frames_analyzed": int(len(probs)),
            "top_frames": per_frame[:10],
        },
    }
    return _InferResult(kind="video", payload=payload, best_frame_idx=best_idx)


# ============================================================
# UI Class
# ============================================================

class _DFUI:
    def __init__(self, app: Any):
        self.app = app

        self.img_path_var = ctk.StringVar(value="")
        self.vid_path_var = ctk.StringVar(value="")

        # default checkpoint path
        default_ckpt = _latest_model_ckpt() or str(Path(_project_root_dir()) / "models" / "deepfake_mixed.pt")
        self.img_model_var = ctk.StringVar(value=default_ckpt)
        self.vid_model_var = ctk.StringVar(value=default_ckpt)


        self.img_device_var = ctk.StringVar(value="auto")
        self.vid_device_var = ctk.StringVar(value="auto")

        self.img_expand_var = ctk.DoubleVar(value=0.25)
        self.vid_expand_var = ctk.DoubleVar(value=0.25)

        self.img_thr_var = ctk.DoubleVar(value=0.50)
        self.vid_thr_var = ctk.DoubleVar(value=0.50)

        self.vid_frames_var = ctk.IntVar(value=20)

        self._img_preview_ctk = None
        self._vid_preview_ctk = None

        self.img_preview_label = None
        self.vid_preview_label = None

        self.img_btn_analyze = None
        self.vid_btn_analyze = None
        self.img_btn_payload_scan = None
        self.vid_btn_payload_scan = None

    # -------------------- BUILDERS --------------------

    def build_image(self, parent: Any) -> None:
        for child in parent.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass

        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=12, pady=12)

        title = ctk.CTkLabel(
            wrap,
            text="Deepfake Detector (Image)",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#E5E7EB",
        )
        title.pack(anchor="w", pady=(0, 10))

        ctrl = ctk.CTkFrame(wrap, fg_color="#0B1220", corner_radius=14)
        ctrl.pack(fill="x", pady=(0, 10))
        ctrl.grid_columnconfigure(0, weight=1)

        row1 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row1.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 8))
        row1.grid_columnconfigure(0, weight=1)

        ent = ctk.CTkEntry(row1, textvariable=self.img_path_var, placeholder_text="Select image...", height=34)
        ent.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        btn_browse = ctk.CTkButton(row1, text="Browse", height=34, command=self._pick_image)
        btn_browse.grid(row=0, column=1)

        row2 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row2.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 8))
        row2.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(row2, text="Model", text_color="#94A3B8").grid(row=0, column=0, sticky="w")
        ent_model = ctk.CTkEntry(row2, textvariable=self.img_model_var, height=30)
        ent_model.grid(row=0, column=1, sticky="ew", padx=(8, 12))
        btn_model = ctk.CTkButton(row2, text="...", width=44, height=30, command=self._pick_model_image)
        btn_model.grid(row=0, column=2, padx=(0, 12))
        btn_latest = ctk.CTkButton(row2, text="Use latest", width=110, height=30, command=self._use_latest_model_image)
        btn_latest.grid(row=0, column=3, padx=(0, 12))


        ctk.CTkLabel(row2, text="Device", text_color="#94A3B8").grid(row=0, column=4, sticky="e")
        opt = ctk.CTkOptionMenu(row2, values=["auto", "cpu", "cuda"], variable=self.img_device_var, height=30)
        opt.grid(row=0, column=5, sticky="w")

        row3 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row3.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
        row3.grid_columnconfigure(1, weight=1)
        row3.grid_columnconfigure(3, weight=1)

        ctk.CTkLabel(row3, text="Face expand", text_color="#94A3B8").grid(row=0, column=0, sticky="w")
        s_expand = ctk.CTkSlider(row3, from_=0.0, to=0.6, number_of_steps=30, variable=self.img_expand_var)
        s_expand.grid(row=0, column=1, sticky="ew", padx=(10, 10))

        ctk.CTkLabel(row3, text="Threshold", text_color="#94A3B8").grid(row=0, column=2, sticky="e")
        s_thr = ctk.CTkSlider(row3, from_=0.1, to=0.9, number_of_steps=40, variable=self.img_thr_var)
        s_thr.grid(row=0, column=3, sticky="ew", padx=(10, 0))

        row4 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row4.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 10))
        row4.grid_columnconfigure(0, weight=1)
        row4.grid_columnconfigure(1, weight=1)

        self.img_btn_analyze = ctk.CTkButton(row4, text="Analyze Image", height=36, command=self._run_image)
        self.img_btn_analyze.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.img_btn_payload_scan = ctk.CTkButton(
            row4,
            text="Scan Metadata/Payload",
            height=36,
            command=self._scan_image_payload,
        )
        self.img_btn_payload_scan.grid(row=0, column=1, sticky="ew")

        prev = ctk.CTkFrame(wrap, fg_color="#0B1220", corner_radius=14)
        prev.pack(fill="both", expand=False, pady=(0, 10))
        prev.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(prev, text="Preview", text_color="#94A3B8").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 4))
        self.img_preview_label = ctk.CTkLabel(prev, text="(no image selected)", text_color="#64748B")
        self.img_preview_label.grid(row=1, column=0, sticky="w", padx=10, pady=(0, 10))

        self._refresh_image_preview()

    def build_video(self, parent: Any) -> None:
        for child in parent.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass

        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=12, pady=12)

        title = ctk.CTkLabel(
            wrap,
            text="Deepfake Detector (Video)",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#E5E7EB",
        )
        title.pack(anchor="w", pady=(0, 10))

        ctrl = ctk.CTkFrame(wrap, fg_color="#0B1220", corner_radius=14)
        ctrl.pack(fill="x", pady=(0, 10))
        ctrl.grid_columnconfigure(0, weight=1)

        row1 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row1.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 8))
        row1.grid_columnconfigure(0, weight=1)

        ent = ctk.CTkEntry(row1, textvariable=self.vid_path_var, placeholder_text="Select video...", height=34)
        ent.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        btn_browse = ctk.CTkButton(row1, text="Browse", height=34, command=self._pick_video)
        btn_browse.grid(row=0, column=1)

        row2 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row2.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 8))
        row2.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(row2, text="Model", text_color="#94A3B8").grid(row=0, column=0, sticky="w")
        ent_model = ctk.CTkEntry(row2, textvariable=self.vid_model_var, height=30)
        ent_model.grid(row=0, column=1, sticky="ew", padx=(8, 12))
        btn_model = ctk.CTkButton(row2, text="...", width=44, height=30, command=self._pick_model_video)
        btn_model.grid(row=0, column=2, padx=(0, 12))
        btn_latest = ctk.CTkButton(row2, text="Use latest", width=110, height=30, command=self._use_latest_model_video)
        btn_latest.grid(row=0, column=3, padx=(0, 12))


        ctk.CTkLabel(row2, text="Device", text_color="#94A3B8").grid(row=0, column=4, sticky="e")
        opt = ctk.CTkOptionMenu(row2, values=["auto", "cpu", "cuda"], variable=self.vid_device_var, height=30)
        opt.grid(row=0, column=5, sticky="w")

        row3 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row3.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
        row3.grid_columnconfigure(1, weight=1)
        row3.grid_columnconfigure(3, weight=1)

        ctk.CTkLabel(row3, text="Face expand", text_color="#94A3B8").grid(row=0, column=0, sticky="w")
        s_expand = ctk.CTkSlider(row3, from_=0.0, to=0.6, number_of_steps=30, variable=self.vid_expand_var)
        s_expand.grid(row=0, column=1, sticky="ew", padx=(10, 10))

        ctk.CTkLabel(row3, text="Threshold", text_color="#94A3B8").grid(row=0, column=2, sticky="e")
        s_thr = ctk.CTkSlider(row3, from_=0.1, to=0.9, number_of_steps=40, variable=self.vid_thr_var)
        s_thr.grid(row=0, column=3, sticky="ew", padx=(10, 10))

        ctk.CTkLabel(row3, text="Frames", text_color="#94A3B8").grid(row=0, column=4, sticky="e")
        ent_frames = ctk.CTkEntry(row3, textvariable=self.vid_frames_var, width=80, height=30)
        ent_frames.grid(row=0, column=5, sticky="w", padx=(10, 0))

        row4 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row4.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 10))
        row4.grid_columnconfigure(0, weight=1)
        row4.grid_columnconfigure(1, weight=1)

        self.vid_btn_analyze = ctk.CTkButton(row4, text="Analyze Video", height=36, command=self._run_video)
        self.vid_btn_analyze.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.vid_btn_payload_scan = ctk.CTkButton(
            row4,
            text="Scan Metadata/Payload",
            height=36,
            command=self._scan_video_payload,
        )
        self.vid_btn_payload_scan.grid(row=0, column=1, sticky="ew")

        prev = ctk.CTkFrame(wrap, fg_color="#0B1220", corner_radius=14)
        prev.pack(fill="both", expand=False, pady=(0, 10))
        prev.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(prev, text="Preview (thumbnail)", text_color="#94A3B8").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 4))
        self.vid_preview_label = ctk.CTkLabel(prev, text="(no video selected)", text_color="#64748B")
        self.vid_preview_label.grid(row=1, column=0, sticky="w", padx=10, pady=(0, 10))

        self._refresh_video_preview()

    # -------------------- PICKERS + PREVIEWS --------------------

    def _pick_image(self) -> None:
        p = filedialog.askopenfilename(
            title="Select image",
            filetypes=[("Images", "*.png;*.jpg;*.jpeg;*.bmp;*.webp"), ("All", "*.*")],
        )
        if p:
            self.img_path_var.set(p)
            self._refresh_image_preview()

    def _pick_video(self) -> None:
        p = filedialog.askopenfilename(
            title="Select video",
            filetypes=[("Videos", "*.mp4;*.avi;*.mov;*.mkv;*.webm"), ("All", "*.*")],
        )
        if p:
            self.vid_path_var.set(p)
            self._refresh_video_preview()

    def _pick_model_image(self) -> None:
        p = filedialog.askopenfilename(
            title="Select model checkpoint",
            filetypes=[("PyTorch", "*.pt;*.pth"), ("All", "*.*")],
        )
        if p:
            self.img_model_var.set(p)

    def _pick_model_video(self) -> None:
        p = filedialog.askopenfilename(
            title="Select model checkpoint",
            filetypes=[("PyTorch", "*.pt;*.pth"), ("All", "*.*")],
        )
        if p:
            self.vid_model_var.set(p)
    
    def _use_latest_model_image(self) -> None:
        p = _latest_model_ckpt()
        if not p:
            messagebox.showwarning("No models", "No .pt/.pth found in ./models")
            return
        self.img_model_var.set(p)

    def _use_latest_model_video(self) -> None:
        p = _latest_model_ckpt()
        if not p:
            messagebox.showwarning("No models", "No .pt/.pth found in ./models")
            return
        self.vid_model_var.set(p)


    def _refresh_image_preview(self) -> None:
        if self.img_preview_label is None:
            return
        path = (self.img_path_var.get() or "").strip()
        if not path or not os.path.exists(path):
            self.img_preview_label.configure(text="(no image selected)", image=None)
            self._img_preview_ctk = None
            return
        try:
            pil = _load_image_pil(path)
            self._img_preview_ctk = _pil_to_ctk_image(pil, max_wh=360)
            self.img_preview_label.configure(text="", image=self._img_preview_ctk)
        except Exception as e:
            self.img_preview_label.configure(text=f"(preview error: {e})", image=None)
            self._img_preview_ctk = None

    def _refresh_video_preview(self, frame_idx: int = 0) -> None:
        if self.vid_preview_label is None:
            return
        path = (self.vid_path_var.get() or "").strip()
        if not path or not os.path.exists(path):
            self.vid_preview_label.configure(text="(no video selected)", image=None)
            self._vid_preview_ctk = None
            return
        if cv2 is None:
            self.vid_preview_label.configure(text="(opencv missing: pip install opencv-python)", image=None)
            self._vid_preview_ctk = None
            return
        try:
            frame = _read_video_frame(path, frame_idx)
            if frame is None:
                self.vid_preview_label.configure(text="(cannot read video frame)", image=None)
                self._vid_preview_ctk = None
                return
            pil = _np_to_pil(frame)
            self._vid_preview_ctk = _pil_to_ctk_image(pil, max_wh=360)
            self.vid_preview_label.configure(text="", image=self._vid_preview_ctk)
        except Exception as e:
            self.vid_preview_label.configure(text=f"(preview error: {e})", image=None)
            self._vid_preview_ctk = None

    def _scan_image_payload(self) -> None:
        path = (self.img_path_var.get() or "").strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Missing input", "Select a valid image.")
            return

        def job():
            try:
                self.app._set_status("Deepfake image metadata/payload: running")
                self.app._progress_running(True)
                self.app._append_log(f"\n[DF][IMAGE][PAYLOAD] input={path}\n")

                payload = _scan_media_payload(path, kind="image")
                out_json, out_html = _make_output_paths("image_payload")
                out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
                out_html.write_text(_render_payload_html(payload), encoding="utf-8")

                summary = _render_payload_summary(payload)
                self.app._append_log(f"[DF][PAYLOAD] wrote: {str(out_json)}\n")
                self.app._append_log(f"[DF][PAYLOAD] report: {str(out_html)}\n")
                self.app._set_summary_text(summary)
                self.app._set_report(str(out_html))

                score = int((payload.get("result", {}) or {}).get("score", 0) or 0)
                self.app._set_badges(max(0, min(100, score)), None)
                self.app._scroll_end()

            except Exception as e:
                msg = str(e)
                self.app._append_log(f"[DF][PAYLOAD][ERR] {msg}\n")
                self.app._set_summary_text(f"Deepfake IMAGE metadata/payload scan error:\n{msg}\n")
            finally:
                self.app._progress_running(False)
                self.app._set_status("Idle")

        threading.Thread(target=job, daemon=True).start()

    def _scan_video_payload(self) -> None:
        path = (self.vid_path_var.get() or "").strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Missing input", "Select a valid video.")
            return

        def job():
            try:
                self.app._set_status("Deepfake video metadata/payload: running")
                self.app._progress_running(True)
                self.app._append_log(f"\n[DF][VIDEO][PAYLOAD] input={path}\n")

                payload = _scan_media_payload(path, kind="video")
                out_json, out_html = _make_output_paths("video_payload")
                out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
                out_html.write_text(_render_payload_html(payload), encoding="utf-8")

                summary = _render_payload_summary(payload)
                self.app._append_log(f"[DF][PAYLOAD] wrote: {str(out_json)}\n")
                self.app._append_log(f"[DF][PAYLOAD] report: {str(out_html)}\n")
                self.app._set_summary_text(summary)
                self.app._set_report(str(out_html))

                score = int((payload.get("result", {}) or {}).get("score", 0) or 0)
                self.app._set_badges(max(0, min(100, score)), None)
                self.app._scroll_end()

            except Exception as e:
                msg = str(e)
                self.app._append_log(f"[DF][PAYLOAD][ERR] {msg}\n")
                self.app._set_summary_text(f"Deepfake VIDEO metadata/payload scan error:\n{msg}\n")
            finally:
                self.app._progress_running(False)
                self.app._set_status("Idle")

        threading.Thread(target=job, daemon=True).start()

    # -------------------- RUNNERS --------------------

    def _run_image(self) -> None:
        path = (self.img_path_var.get() or "").strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Missing input", "Select a valid image.")
            return

        model_path = (self.img_model_var.get() or "").strip()
        if not model_path or not os.path.exists(model_path):
            messagebox.showerror("Missing model", "Select an valid checkpoint (.pt).")
            return

        thr = _safe_float(self.img_thr_var.get(), 0.5)
        expand = _safe_float(self.img_expand_var.get(), 0.25)
        device_pref = _device_pick(self.img_device_var.get())

        def job():
            try:
                self.app._set_status("Deepfake image: running")
                self.app._progress_running(True)
                self.app._append_log(f"\n[DF][IMAGE] input={path}\n")
                self.app._append_log(f"[DF][IMAGE] model={model_path} device={device_pref} thr={thr:.2f} expand={expand:.2f}\n")

                res = _infer_image(path, model_path, device_pref=device_pref, thr=thr, expand=expand)

                out_json, out_html = _make_output_paths("image")
                out_json.write_text(json.dumps(res.payload, indent=2), encoding="utf-8")
                out_html.write_text(_render_html(res.payload), encoding="utf-8")

                summary = _render_summary(res.payload)
                self.app._append_log(f"[DF] wrote: {str(out_json)}\n")
                self.app._append_log(f"[DF] report: {str(out_html)}\n")
                self.app._set_summary_text(summary)
                self.app._set_report(str(out_html))

                pf = float(res.payload["result"]["prob_fake"])
                self.app._set_badges(int(round(pf * 100.0)), None)
                self.app._scroll_end()

            except Exception as e:
                msg = str(e)
                self.app._append_log(f"[DF][ERR] {msg}\n")
                self.app._set_summary_text(f"Deepfake IMAGE error:\n{msg}\n")
            finally:
                self.app._progress_running(False)
                self.app._set_status("Idle")

        threading.Thread(target=job, daemon=True).start()

    def _run_video(self) -> None:
        path = (self.vid_path_var.get() or "").strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Missing input", "Select an valid video.")
            return

        model_path = (self.vid_model_var.get() or "").strip()
        if not model_path or not os.path.exists(model_path):
            messagebox.showerror("Missing model", "Select an valid checkpoint (.pt).")
            return

        thr = _safe_float(self.vid_thr_var.get(), 0.5)
        expand = _safe_float(self.vid_expand_var.get(), 0.25)
        device_pref = _device_pick(self.vid_device_var.get())
        frames = _safe_int(self.vid_frames_var.get(), 20)

        def job():
            try:
                self.app._set_status("Deepfake video: running")
                self.app._progress_running(True)
                self.app._append_log(f"\n[DF][VIDEO] input={path}\n")
                self.app._append_log(f"[DF][VIDEO] model={model_path} device={device_pref} thr={thr:.2f} expand={expand:.2f} frames={frames}\n")

                res = _infer_video(path, model_path, device_pref=device_pref, thr=thr, expand=expand, frames=frames)

                out_json, out_html = _make_output_paths("video")
                out_json.write_text(json.dumps(res.payload, indent=2), encoding="utf-8")
                out_html.write_text(_render_html(res.payload), encoding="utf-8")

                if res.best_frame_idx is not None:
                    self.app.after(0, lambda: self._refresh_video_preview(res.best_frame_idx))

                summary = _render_summary(res.payload)
                self.app._append_log(f"[DF] wrote: {str(out_json)}\n")
                self.app._append_log(f"[DF] report: {str(out_html)}\n")
                self.app._set_summary_text(summary)
                self.app._set_report(str(out_html))

                pf = float(res.payload["result"]["prob_fake"])
                self.app._set_badges(int(round(pf * 100.0)), None)
                self.app._scroll_end()

            except Exception as e:
                msg = str(e)
                self.app._append_log(f"[DF][ERR] {msg}\n")
                self.app._set_summary_text(f"Deepfake VIDEO error:\n{msg}\n")
            finally:
                self.app._progress_running(False)
                self.app._set_status("Idle")

        threading.Thread(target=job, daemon=True).start()
