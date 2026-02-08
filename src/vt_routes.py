from __future__ import annotations

import os
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from src.vt_client import VirusTotalClient
from src.vt_enrich import enrich_case_with_vt


router = APIRouter(prefix="/vt", tags=["virustotal"])


class VTEnrichRequest(BaseModel):
    case_dir: str
    apk_path: Optional[str] = None
    sha256: Optional[str] = None
    tag: str = "run1"


@router.get("/file/{sha256}")
def vt_lookup(sha256: str) -> Dict[str, Any]:
    """
    Lookup VT report by sha256 (no upload).
    """
    vt = VirusTotalClient()
    raw = vt.get_file_report(sha256)
    norm = vt.normalize_file_report(raw, sha256)
    return norm


@router.post("/enrich")
def vt_enrich(req: VTEnrichRequest) -> Dict[str, Any]:
    """
    Creates vt artifact in case/artifacts and returns artifact path + summary.
    """
    try:
        res = enrich_case_with_vt(
            case_dir=req.case_dir,
            apk_path=req.apk_path,
            sha256=req.sha256,
            tag=req.tag,
            api_key=os.environ.get("VT_API_KEY"),
        )
        return {"ok": True, "result": res}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
