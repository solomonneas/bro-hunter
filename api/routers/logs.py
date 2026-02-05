"""
Log ingestion and retrieval endpoints.
Handles uploading and querying Zeek and Suricata logs.
"""
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from typing import List, Annotated

from api.dependencies.auth import api_key_auth

router = APIRouter()


@router.post("/upload/zeek")
async def upload_zeek_logs(
    _: Annotated[str, Depends(api_key_auth)],
    file: UploadFile = File(...),
):
    """Upload Zeek JSON log file for analysis."""
    if not file.filename or not file.filename.endswith((".json", ".log")):
        raise HTTPException(status_code=400, detail="Only JSON/log files supported")

    return {
        "status": "success",
        "message": f"Zeek log file '{file.filename}' uploaded",
        "filename": file.filename,
    }


@router.post("/upload/suricata")
async def upload_suricata_logs(
    _: Annotated[str, Depends(api_key_auth)],
    file: UploadFile = File(...),
):
    """Upload Suricata eve.json file for analysis."""
    if not file.filename or not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="Only JSON files supported")

    return {
        "status": "success",
        "message": f"Suricata log file '{file.filename}' uploaded",
        "filename": file.filename,
    }


@router.get("/stats")
async def get_log_stats(
    _: Annotated[str, Depends(api_key_auth)],
):
    """Get statistics about ingested logs."""
    return {
        "zeek_logs": {"count": 0, "types": []},
        "suricata_logs": {"count": 0, "types": []},
    }
