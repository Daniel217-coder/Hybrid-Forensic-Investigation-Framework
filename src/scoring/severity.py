# src/scoring/severity.py
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Severity:
    label: str
    band: str
    score_0_100: int


def _safe_int(x, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def severity_from_score(score_0_100: int) -> Severity:
    """
    Pragurile tale UI:
      green <20, yellow <50, orange <75, red >=75
    """
    s = _safe_int(score_0_100, 0)
    if s < 0:
        s = 0
    if s > 100:
        s = 100

    if s < 20:
        return Severity(label="Low", band="low", score_0_100=s)
    if s < 50:
        return Severity(label="Medium", band="medium", score_0_100=s)
    if s < 75:
        return Severity(label="High", band="high", score_0_100=s)
    return Severity(label="Critical", band="critical", score_0_100=s)


def score_badge_color(sev_band: str) -> str:
    band = (sev_band or "").strip().lower()
    return {
        "low": "#2e7d32",       # green
        "medium": "#f9a825",    # yellow
        "high": "#ef6c00",      # orange
        "critical": "#c62828",  # red
    }.get(band, "#546e7a")
