# src/ledger.py
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

LEDGER_NAME = "ledger.json"


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _collect_files(case_path: Path) -> list[Path]:
    files: list[Path] = []
    for folder in ["evidence", "artifacts", "reports"]:
        d = case_path / folder
        if d.exists():
            files.extend([p for p in d.rglob("*") if p.is_file()])

    # exclude ledger itself if present anywhere
    files = [p for p in files if p.name != LEDGER_NAME]
    return sorted(files, key=lambda p: str(p).lower())


def ledger_update(case_dir: str) -> str:
    case_path = Path(case_dir)
    ledger_path = case_path / LEDGER_NAME

    prev_chain_head = "GENESIS"
    if ledger_path.exists():
        old = json.loads(ledger_path.read_text(encoding="utf-8"))
        prev_chain_head = old.get("chain_head", "GENESIS")

    entries = []
    chain_prev = prev_chain_head

    for p in _collect_files(case_path):
        rel = str(p.relative_to(case_path)).replace("\\", "/")
        file_hash = _sha256_file(p)

        link_payload = (chain_prev + "|" + rel + "|" + file_hash).encode("utf-8")
        chain_hash = _sha256_bytes(link_payload)

        entries.append(
            {
                "path": rel,
                "sha256": file_hash,
                "chain_prev": chain_prev,
                "chain_hash": chain_hash,
            }
        )
        chain_prev = chain_hash

    out = {
        "case_dir": str(case_path),
        "updated_at_utc": _utc_now(),
        "prev_chain_head": prev_chain_head,
        "entries": entries,
        "chain_head": chain_prev,
    }

    ledger_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    return str(ledger_path)


def ledger_verify(case_dir: str) -> dict:
    case_path = Path(case_dir)
    ledger_path = case_path / LEDGER_NAME
    if not ledger_path.exists():
        return {"ok": False, "error": "ledger.json not found. Run ledger-update first."}

    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    entries = ledger.get("entries", [])
    expected_prev_head = ledger.get("prev_chain_head", "GENESIS")

    problems = []
    chain_prev = expected_prev_head

    for i, e in enumerate(entries):
        rel = e.get("path", "")
        if not rel:
            problems.append(f"[{i}] Missing path in ledger entry")
            continue

        p = case_path / Path(rel)
        if not p.exists():
            problems.append(f"[{i}] Missing file: {rel}")
            chain_prev = e.get("chain_hash", chain_prev)
            continue

        actual_hash = _sha256_file(p)
        if actual_hash != e.get("sha256"):
            problems.append(f"[{i}] Hash mismatch: {rel}")

        link_payload = (chain_prev + "|" + rel + "|" + actual_hash).encode("utf-8")
        actual_chain = _sha256_bytes(link_payload)

        if actual_chain != e.get("chain_hash"):
            problems.append(f"[{i}] Chain mismatch: {rel}")

        chain_prev = actual_chain

    ok = (len(problems) == 0) and (chain_prev == ledger.get("chain_head"))
    return {
        "ok": ok,
        "checked_files": len(entries),
        "problems": problems,
        "expected_chain_head": ledger.get("chain_head"),
        "computed_chain_head": chain_prev,
    }
