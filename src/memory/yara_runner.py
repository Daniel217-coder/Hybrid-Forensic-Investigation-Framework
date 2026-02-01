# src/memory/yara_runner.py
from __future__ import annotations

import os
import re
import subprocess
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.hash_utils import sha256_file


def _now() -> float:
    return time.time()


def _safe_str(x: Any) -> str:
    try:
        return "" if x is None else str(x)
    except Exception:
        return ""


def _as_list(x: Any) -> list:
    return x if isinstance(x, list) else []


def _clamp_int(x: Any, lo: int, hi: int, default: int = 0) -> int:
    try:
        v = int(x)
    except Exception:
        v = int(default)
    return max(lo, min(hi, v))


def _read_text_if_exists(p: Path) -> str:
    # robust la BOM / encoding Windows
    try:
        return p.read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        try:
            return p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""


def _is_rules_path(p: Path) -> bool:
    if not p.exists():
        return False
    if p.is_dir():
        return any(x.suffix.lower() in {".yar", ".yara"} for x in p.rglob("*"))
    return p.suffix.lower() in {".yar", ".yara"}


def _default_rules_dir(project_root: Path) -> Optional[Path]:
    candidates = [
        project_root / "rules" / "yara",
        project_root / "rules",
        project_root / "yara",
    ]
    for c in candidates:
        if _is_rules_path(c):
            return c
    return None


@dataclass
class YaraTarget:
    kind: str  # apk|dex|so|manifest
    name: str
    file_path: Optional[Path] = None
    data: Optional[bytes] = None


def _enumerate_apk_targets(apk_path: Path) -> List[YaraTarget]:
    targets: List[YaraTarget] = [YaraTarget(kind="apk", name=apk_path.name, file_path=apk_path)]
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for n in z.namelist():
                nl = n.lower()
                if nl.startswith("classes") and nl.endswith(".dex"):
                    try:
                        targets.append(YaraTarget(kind="dex", name=n, data=z.read(n)))
                    except Exception:
                        pass
                elif nl.startswith("lib/") and nl.endswith(".so"):
                    try:
                        targets.append(YaraTarget(kind="so", name=n, data=z.read(n)))
                    except Exception:
                        pass
                elif nl == "androidmanifest.xml":
                    try:
                        targets.append(YaraTarget(kind="manifest", name=n, data=z.read(n)))
                    except Exception:
                        pass
    except Exception:
        pass
    return targets


# -------------------- YARA backend: yara-python --------------------

def _try_import_yara():
    try:
        import yara  # type: ignore
        return yara
    except Exception:
        return None


def _compile_rules_yara_python(yara_mod, rules_path: Path, externals: Optional[dict] = None):
    externals = externals or {}
    if rules_path.is_dir():
        sources: Dict[str, str] = {}
        for rp in sorted(rules_path.rglob("*")):
            if rp.suffix.lower() in {".yar", ".yara"}:
                sources[str(rp)] = _read_text_if_exists(rp)
        if not sources:
            raise RuntimeError(f"No .yar/.yara files under: {rules_path}")
        return yara_mod.compile(sources=sources, externals=externals)

    return yara_mod.compile(filepath=str(rules_path), externals=externals)


def _match_to_json_yara_python(matches, max_strings: int = 60) -> List[dict]:
    out: List[dict] = []
    for m in matches or []:
        try:
            rule = getattr(m, "rule", None)
            namespace = getattr(m, "namespace", None)
            tags = list(getattr(m, "tags", []) or [])
            meta = dict(getattr(m, "meta", {}) or {})

            strings_raw = getattr(m, "strings", []) or []
            strings: List[dict] = []
            for i, s in enumerate(strings_raw):
                if i >= max_strings:
                    break
                try:
                    off, ident, data = s
                    if isinstance(data, bytes):
                        preview = data[:64]
                        try:
                            preview_txt = preview.decode("utf-8", errors="replace")
                        except Exception:
                            preview_txt = repr(preview)
                    else:
                        preview_txt = _safe_str(data)[:64]
                    strings.append({"offset": int(off), "id": _safe_str(ident), "preview": preview_txt})
                except Exception:
                    continue

            out.append(
                {
                    "rule": _safe_str(rule),
                    "namespace": _safe_str(namespace),
                    "tags": [str(t) for t in tags],
                    "meta": {k: _safe_str(v) for k, v in meta.items()},
                    "strings": strings,
                }
            )
        except Exception:
            continue
    return out


# -------------------- YARA backend: yara CLI -----------------------

def _which(cmd: str) -> Optional[str]:
    exts = [""]
    if os.name == "nt":
        exts += [".exe", ".cmd", ".bat"]
    paths = os.environ.get("PATH", "").split(os.pathsep)
    for p in paths:
        p = p.strip('"')
        for e in exts:
            cand = Path(p) / (cmd + e)
            if cand.exists() and cand.is_file():
                return str(cand)
    return None


def _run_yara_cli(
    rules_path: Path,
    target_file: Path,
    timeout_s: int = 15,
    recursive: bool = True,
) -> Tuple[int, str, str]:
    yara_bin = _which("yara")
    if not yara_bin:
        raise RuntimeError(
            "yara CLI not found in PATH. Install YARA or install yara-python. "
            "For Windows, ensure yara.exe is in PATH."
        )

    cmd = [yara_bin]
    if recursive and rules_path.is_dir():
        cmd.append("-r")
    cmd += [str(rules_path), str(target_file)]

    p = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        errors="replace",
    )
    return int(p.returncode), p.stdout or "", p.stderr or ""


def _parse_yara_cli_stdout(stdout: str, max_lines: int = 3000) -> List[dict]:
    out: List[dict] = []
    lines = (stdout or "").splitlines()[:max_lines]
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        parts = ln.split()
        rule_part = parts[0]
        namespace = ""
        rule = rule_part
        if ":" in rule_part:
            namespace, rule = rule_part.split(":", 1)
        out.append({"rule": rule, "namespace": namespace, "tags": [], "meta": {}, "strings": []})
    return out


# ---------------------------- Scoring -----------------------------

def _match_severity_hint(m: dict) -> str:
    meta = m.get("meta") or {}
    sev = str(meta.get("severity") or meta.get("sev") or "").lower().strip()
    if sev in {"critical", "crit"}:
        return "critical"
    if sev in {"high", "h"}:
        return "high"
    if sev in {"medium", "med", "m"}:
        return "medium"
    if sev in {"low", "l"}:
        return "low"
    return "low"


def score_yara(matches_by_target: Dict[str, List[dict]]) -> Tuple[int, List[str], bool]:
    """
    Strict calibration:
    - benign apps stay <20 even with a few low hits
    - any high/critical hit triggers malicious_unlock
    - 1x HIGH hit should push malware-ish samples over 60 (your target)
    """
    total_hits = sum(len(v or []) for v in (matches_by_target or {}).values())
    if total_hits <= 0:
        return 0, [], False

    highcrit = 0
    medium = 0
    low = 0

    for _t, ms in (matches_by_target or {}).items():
        for m in ms or []:
            sev = _match_severity_hint(m)
            if sev in {"critical", "high"}:
                highcrit += 1
            elif sev == "medium":
                medium += 1
            else:
                low += 1

    # Base points only for “presence” (small, to avoid FP)
    base_pts = min(12, total_hits + 2)         # 2 hits -> 4, 3 hits -> 5 (matches output-ul tău)
    low_pts = min(20, low * 2)                 # 3 low -> 6
    med_pts = min(25, medium * 8)              # moderate but capped
    high_pts = min(90, highcrit * 60)          # IMPORTANT: 1 high/critical -> +60 (push >60)

    score = _clamp_int(base_pts + low_pts + med_pts + high_pts, 0, 100)
    malicious_unlock = highcrit > 0

    reasons: List[str] = []
    reasons.append(f"YARA matches: {total_hits} (+{base_pts})")
    if highcrit > 0:
        reasons.append(f"High/critical YARA hits: {highcrit} (+{high_pts})")
    if medium > 0:
        reasons.append(f"Medium-confidence hits: {medium} (+{med_pts})")
    if low > 0:
        reasons.append(f"Low-confidence hits: {low} (+{low_pts})")

    return score, reasons, malicious_unlock


# ----------------------------- Public API -----------------------------

def scan_apk_with_yara(
    apk_path: str,
    rules_path: Optional[str] = None,
    timeout_s: int = 15,
    max_strings: int = 60,
    include_kinds: Optional[List[str]] = None,
    project_root: Optional[str] = None,
) -> dict:
    t0 = _now()
    apk = Path(apk_path)
    if not apk.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    root = Path(project_root) if project_root else Path(__file__).resolve().parents[2]
    rp = Path(rules_path) if rules_path else (_default_rules_dir(root) or Path(""))
    if not rules_path and (not rp or not rp.exists()):
        raise RuntimeError(
            "No YARA rules provided and no default rules directory found. "
            "Create rules/yara/*.yar or pass --rules <file|dir>."
        )
    if rules_path and not _is_rules_path(rp):
        raise RuntimeError(f"Invalid YARA rules path: {rp}")

    include_kinds = include_kinds or ["apk", "dex", "so", "manifest"]
    include_set = {k.strip().lower() for k in include_kinds}

    targets = [t for t in _enumerate_apk_targets(apk) if t.kind in include_set]

    yara_mod = _try_import_yara()
    backend = "yara-python" if yara_mod else "yara-cli"

    matches_by_target: Dict[str, List[dict]] = {}
    backend_notes: List[str] = []

    if yara_mod:
        rules = _compile_rules_yara_python(yara_mod, rp)
        for tgt in targets:
            key = f"{tgt.kind}:{tgt.name}"
            try:
                if tgt.file_path:
                    ms = rules.match(filepath=str(tgt.file_path), timeout=timeout_s)
                else:
                    ms = rules.match(data=tgt.data or b"", timeout=timeout_s)
                matches_by_target[key] = _match_to_json_yara_python(ms, max_strings=max_strings)
            except Exception as e:
                backend_notes.append(f"match failed on {key}: {e}")
                matches_by_target[key] = []
    else:
        tmp_dir = Path(os.environ.get("TEMP", "/tmp")) / f"cybershadow_yara_{int(_now())}"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        try:
            for tgt in targets:
                key = f"{tgt.kind}:{tgt.name}"
                try:
                    if tgt.file_path:
                        scan_path = tgt.file_path
                    else:
                        safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", tgt.name)
                        scan_path = tmp_dir / safe_name
                        scan_path.write_bytes(tgt.data or b"")

                    rc, out, err = _run_yara_cli(rp, scan_path, timeout_s=timeout_s, recursive=True)
                    if err:
                        backend_notes.append(f"yara stderr for {key}: {err.strip()[:240]}")
                    if rc not in (0, 1):
                        backend_notes.append(f"yara rc={rc} for {key}")
                    matches_by_target[key] = _parse_yara_cli_stdout(out)
                except Exception as e:
                    backend_notes.append(f"CLI match failed on {key}: {e}")
                    matches_by_target[key] = []
        finally:
            try:
                for x in tmp_dir.glob("*"):
                    try:
                        x.unlink()
                    except Exception:
                        pass
                tmp_dir.rmdir()
            except Exception:
                pass

    flat_rules: List[str] = []
    for _k, ms in (matches_by_target or {}).items():
        for m in ms or []:
            rname = _safe_str(m.get("rule"))
            if rname:
                flat_rules.append(rname)
    flat_rules = sorted(list(dict.fromkeys(flat_rules)))

    score, reasons, malicious_unlock = score_yara(matches_by_target)

    out = {
        "type": "yara",
        "created_at": _now(),
        "apk": {
            "path": str(apk),
            "name": apk.name,
            "sha256": sha256_file(str(apk)),
            "size": int(apk.stat().st_size),
        },
        "rules": {
            "path": str(rp),
            "is_dir": bool(rp.is_dir()),
        },
        "engine": {
            "backend": backend,
            "notes": backend_notes[:50],
        },
        "matches": {
            "by_target": matches_by_target,
            "unique_rules": flat_rules,
            "unique_rules_count": len(flat_rules),
            "total_matches": sum(len(v or []) for v in (matches_by_target or {}).values()),
        },
        "scoring": {
            "score": int(_clamp_int(score, 0, 100)),
            "severity": "HIGH" if malicious_unlock and score >= 60 else ("MEDIUM" if score >= 30 else "LOW"),
            "reasons": reasons,
            "malicious_unlock": bool(malicious_unlock),
        },
        "timing": {
            "elapsed_s": round(_now() - t0, 3),
        },
    }
    return out


def save_yara_artifact(case_dir: str, tag: str, yara_obj: dict) -> str:
    from src.case_manager import save_artifact
    suffix = tag or "yara"
    name = f"yara__{suffix}.json"
    return save_artifact(case_dir, name, yara_obj)
