"""Packet inspector API endpoints."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.dependencies.auth import api_key_auth
from api.services.packet_inspector import packet_inspector

router = APIRouter()


@router.get("/{connection_uid}")
async def get_packet_details(
    connection_uid: str,
    _: Annotated[str, Depends(api_key_auth)],
):
    detail = packet_inspector.get_connection_detail(connection_uid)
    if not detail:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
    return detail


@router.get("/{connection_uid}/flow")
async def get_connection_flow(
    connection_uid: str,
    _: Annotated[str, Depends(api_key_auth)],
):
    flow = packet_inspector.get_flow(connection_uid)
    if flow is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
    return {"uid": connection_uid, "events": flow}


@router.get("/payload-preview/{connection_uid}")
async def get_payload_preview(
    connection_uid: str,
    _: Annotated[str, Depends(api_key_auth)],
):
    preview = packet_inspector.get_payload_preview(connection_uid)
    if not preview:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
    return preview
