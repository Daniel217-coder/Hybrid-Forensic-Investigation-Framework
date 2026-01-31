# src/scoring/normalization.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class NormalizedScore:
    raw: float
    max_possible: float
    normalized_0_100: int


def _clamp(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x


def safe_float(x, default: float = 0.0) -> float:
    try:
        if x is None:
            return default
        return float(x)
    except Exception:
        return default


def normalize_raw_score(raw: float, max_possible: float) -> NormalizedScore:
    r = safe_float(raw, 0.0)
    m = safe_float(max_possible, 0.0)
    if m <= 0:
        return NormalizedScore(raw=r, max_possible=m, normalized_0_100=0)

    norm = (r / m) * 100.0
    norm = _clamp(norm, 0.0, 100.0)
    return NormalizedScore(raw=r, max_possible=m, normalized_0_100=int(round(norm)))


def max_possible_from_weights(weights: Iterable[float]) -> float:
    total = 0.0
    for w in weights:
        total += max(0.0, safe_float(w, 0.0))
    return total
