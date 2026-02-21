from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies.auth import api_key_auth
from api.services.case_manager import CaseManager
from api.services.thehive_client import TheHiveClient, map_brohunter_case_to_thehive

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])

case_manager = CaseManager()


@router.get("/status")
async def integration_status():
    thehive = TheHiveClient()
    return {
        "thehive": {
            "configured": thehive.configured,
            "url": thehive.base_url or None,
        }
    }


@router.post("/thehive/cases/from-case/{case_id}")
async def create_thehive_case_from_case(
    case_id: str,
    _: Annotated[str, Depends(api_key_auth)] = "",
):
    try:
        case = case_manager.get_case(case_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e

    client = TheHiveClient()
    if not client.configured:
        raise HTTPException(
            status_code=400,
            detail="TheHive integration not configured. Set THEHIVE_URL and THEHIVE_API_KEY.",
        )

    payload = map_brohunter_case_to_thehive(case)

    try:
        result = client.create_case(payload)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e

    return {
        "status": "ok",
        "source_case_id": case_id,
        "thehive": result,
    }
