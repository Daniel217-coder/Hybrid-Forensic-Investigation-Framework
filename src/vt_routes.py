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
        # 1) read key from env (support both names)
        vt_api_key = (os.getenv("VT_API_KEY") or os.getenv("VT_KEY") or "").strip()
        if not vt_api_key:
            raise HTTPException(status_code=500, detail="VT_API_KEY_missing")

        # 2) make sure client sees the key (keep it only in process env)
        os.environ["VT_API_KEY"] = vt_api_key

        # 3) call enrich WITHOUT passing unexpected kwargs
        res = enrich_case_with_vt(
            case_dir=req.case_dir,
            apk_path=req.apk_path,
            sha256=req.sha256,
            tag=req.tag,
        )

        return {"ok": True, "result": res}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

