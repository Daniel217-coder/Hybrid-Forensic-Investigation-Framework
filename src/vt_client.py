from __future__ import annotations

import json
import os
import time
import hashlib
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


VT_API_BASE = "https://www.virustotal.com/api/v3"


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _clamp_int(x: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, x))


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _now_utc_ts() -> float:
    return time.time()


def vt_gui_url_for_sha256(sha256: str) -> str:
    # link public (UI)
    return f"https://www.virustotal.com/gui/file/{sha256}"


@dataclass
class VTStats:
    harmless: int = 0
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    timeout: int = 0

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "VTStats":
        return cls(
            harmless=_safe_int(d.get("harmless"), 0),
            malicious=_safe_int(d.get("malicious"), 0),
            suspicious=_safe_int(d.get("suspicious"), 0),
            undetected=_safe_int(d.get("undetected"), 0),
            timeout=_safe_int(d.get("timeout"), 0),
        )

    def positives(self) -> int:
        return int(self.malicious + self.suspicious)

    def total(self) -> int:
        # ignore timeout in denominator (optional)
        return int(self.harmless + self.malicious + self.suspicious + self.undetected)

    def ratio(self) -> float:
        t = self.total()
        return (self.positives() / t) if t > 0 else 0.0


def vt_score_from_stats(stats: VTStats) -> int:
    """
    Simple and stable:
      vt_ratio = (malicious+suspicious) / total
      vt_score = round(100 * vt_ratio)
    """
    score = int(round(100.0 * stats.ratio()))
    return _clamp_int(score, 0, 100)


def vt_confidence(stats: VTStats, found: bool) -> float:
    """
    Confidence of trusting VT as a calibrator.
    Very conservative by default.
    """
    if not found:
        return 0.0

    total = stats.total()
    pos = stats.positives()

    if total <= 0:
        return 0.0

    # low coverage => low confidence
    if total < 10:
        base = 0.05
    elif total < 20:
        base = 0.10
    elif total < 30:
        base = 0.15
    else:
        base = 0.20

    # if multiple malicious hits, increase confidence a bit
    if stats.malicious >= 5:
        base += 0.15
    elif stats.malicious >= 2:
        base += 0.10
    elif stats.malicious == 1:
        base += 0.05

    # if only 1 suspicious and 0 malicious -> keep tiny
    if stats.malicious == 0 and stats.suspicious <= 1:
        base = min(base, 0.10)

    # cap
    return float(max(0.0, min(0.50, base)))


def blend_scores(our_score: int, vt_score: int, w: float) -> int:
    """
    final = (1-w)*our + w*vt
    """
    our_score = _clamp_int(_safe_int(our_score, 0), 0, 100)
    vt_score = _clamp_int(_safe_int(vt_score, 0), 0, 100)
    w = max(0.0, min(1.0, float(w)))
    out = int(round((1.0 - w) * our_score + w * vt_score))
    return _clamp_int(out, 0, 100)


class VirusTotalClient:
    def __init__(self, api_key: Optional[str] = None, base_url: str = VT_API_BASE, timeout: int = 20):
        self.api_key = api_key or os.environ.get("VT_API_KEY") or ""
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _req(self, method: str, path: str) -> Dict[str, Any]:
        if not self.api_key:
            raise RuntimeError("VT_API_KEY missing. Set env VT_API_KEY to your VirusTotal API key.")

        url = f"{self.base_url}{path}"
        req = urllib.request.Request(
            url,
            method=method.upper(),
            headers={
                "x-apikey": self.api_key,
                "accept": "application/json",
                "user-agent": "CyberShadow/1.0",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            # VT returns JSON body usually
            try:
                body = e.read().decode("utf-8", errors="replace")
                data = json.loads(body) if body else {}
            except Exception:
                data = {"error": str(e)}
            data["_http_status"] = getattr(e, "code", None)
            return data
        except Exception as e:
            return {"error": str(e), "_http_status": None}

    def get_file_report(self, sha256: str) -> Dict[str, Any]:
        sha256 = (sha256 or "").strip().lower()
        if not sha256 or len(sha256) < 32:
            raise ValueError("Invalid sha256.")
        return self._req("GET", f"/files/{sha256}")

    @staticmethod
    def normalize_file_report(resp: Dict[str, Any], sha256: str) -> Dict[str, Any]:
        """
        Returns a stable schema for your pipeline/UI.
        """
        sha256 = (sha256 or "").strip().lower()
        found = True

        http_status = resp.get("_http_status")
        if http_status in (404,):
            found = False
        if "error" in resp and not resp.get("data"):
            # could be network error too
            if http_status == 404:
                found = False

        attrs = (((resp.get("data") or {}).get("attributes")) or {}) if found else {}
        stats_dict = (attrs.get("last_analysis_stats") or {}) if isinstance(attrs, dict) else {}
        stats = VTStats.from_dict(stats_dict)

        vt_score = vt_score_from_stats(stats) if found else 0
        conf = vt_confidence(stats, found)

        out = {
            "provider": "virustotal",
            "found": bool(found),
            "sha256": sha256,
            "stats": {
                "harmless": stats.harmless,
                "malicious": stats.malicious,
                "suspicious": stats.suspicious,
                "undetected": stats.undetected,
                "timeout": stats.timeout,
                "total": stats.total(),
                "positives": stats.positives(),
            },
            "vt_score": vt_score,          # 0..100
            "confidence": conf,            # 0..0.5
            "gui_url": vt_gui_url_for_sha256(sha256),
            "ts_utc": _now_utc_ts(),
            "raw": resp,                   # keep for audit/debug
        }
        return out
