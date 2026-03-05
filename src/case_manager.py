# src/case_manager.py
import json
import time
from pathlib import Path

from src.hash_utils import sha256_file
from src.env_report import get_versions
#De modificat si aici
def new_case(base_dir: str, case_id: str) -> Path:
    case_path = Path(base_dir) / case_id
    (case_path / "evidence").mkdir(parents=True, exist_ok=True)
    (case_path / "artifacts").mkdir(parents=True, exist_ok=True)
    (case_path / "reports").mkdir(parents=True, exist_ok=True)

    meta = {
        "case_id": case_id,
        "created_at": time.time(),
        "evidence": [],
        "env": get_versions(),
    }
    (case_path / "case.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return case_path


def add_evidence(case_dir: str, file_path: str, evidence_type: str = "unknown") -> dict:
    case_path = Path(case_dir)
    evidence_dir = case_path / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    src = Path(file_path)
    if not src.exists():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    dst = evidence_dir / src.name
    dst.write_bytes(src.read_bytes())

    h = sha256_file(str(dst))
    entry = {"name": src.name, "path": str(dst), "sha256": h, "type": evidence_type}

    case_json = case_path / "case.json"
    if not case_json.exists():
        # auto-create minimal case if missing
        new_case(str(case_path.parent) if str(case_path.parent) not in ("", ".") else "cases", case_path.name)

    data = json.loads(case_json.read_text(encoding="utf-8"))
    data.setdefault("evidence", []).append(entry)
    # refresh env snapshot
    data["env"] = get_versions()
    case_json.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return entry


def save_artifact(case_dir: str, name: str, obj: dict) -> str:
    case_path = Path(case_dir)
    out = case_path / "artifacts" / name
    out.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    return str(out)
