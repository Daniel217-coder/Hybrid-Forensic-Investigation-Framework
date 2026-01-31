# src/scoring/apk_static_scoring.py
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .normalization import normalize_raw_score, max_possible_from_weights, safe_float


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    title: str
    weight: float
    hit: bool
    evidence: str = ""


@dataclass(frozen=True)
class ApkStaticScore:
    raw: float
    max_possible: float
    normalized: int
    findings: list[RuleHit]


def _load_json(p: Path) -> dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


def _to_bool(x) -> bool:
    if isinstance(x, bool):
        return x
    if isinstance(x, (int, float)):
        return x != 0
    s = str(x).strip().lower()
    return s in {"1", "true", "yes", "y", "hit", "detected", "present", "triggered"}


def pick_latest_apk_artifact(artifacts_dir: Path) -> Path | None:
    files = sorted(artifacts_dir.glob("apk_static__*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def _read_findings_from_artifact(artifact: dict[str, Any]) -> list[RuleHit]:
    """
    Acceptă mai multe formate:
      - artifact["rules"] = [{id, title, weight, hit, evidence}, ...]
      - artifact["findings"] = [...]
      - artifact["checks"] = [...]
    """
    for key in ("rules", "findings", "checks"):
        items = artifact.get(key)
        if isinstance(items, list):
            out: list[RuleHit] = []
            for i, it in enumerate(items):
                if not isinstance(it, dict):
                    continue
                rid = str(it.get("id") or it.get("rule_id") or f"rule_{i}")
                title = str(it.get("title") or it.get("name") or rid)
                weight = safe_float(it.get("weight", 1.0), 1.0)
                hit = _to_bool(it.get("hit") or it.get("triggered") or it.get("detected") or False)
                evidence = str(it.get("evidence") or it.get("details") or it.get("note") or "")
                out.append(RuleHit(rule_id=rid, title=title, weight=weight, hit=hit, evidence=evidence))
            return out
    return []


def score_apk_static_artifact(artifact_path: Path) -> ApkStaticScore:
    data = _load_json(artifact_path)

    # Dacă artifactul tău are deja scoruri, le folosim (robust).
    existing_score = data.get("score") or data.get("risk_score") or data.get("apk_score")
    existing_max = data.get("max_score") or data.get("max_possible") or data.get("risk_max")

    if existing_score is not None and existing_max is not None:
        raw = safe_float(existing_score, 0.0)
        mx = safe_float(existing_max, 0.0)
        norm = normalize_raw_score(raw, mx)
        findings = _read_findings_from_artifact(data)
        return ApkStaticScore(raw=norm.raw, max_possible=norm.max_possible, normalized=norm.normalized_0_100, findings=findings)

    # Altfel calculăm din reguli/findings.
    findings = _read_findings_from_artifact(data)
    raw = 0.0
    weights: list[float] = []
    for f in findings:
        weights.append(f.weight)
        if f.hit:
            raw += max(0.0, safe_float(f.weight, 0.0))

    max_possible = max_possible_from_weights(weights)
    norm = normalize_raw_score(raw, max_possible)
    return ApkStaticScore(raw=norm.raw, max_possible=norm.max_possible, normalized=norm.normalized_0_100, findings=findings)
