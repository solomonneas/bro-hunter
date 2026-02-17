"""Annotations API router."""
from __future__ import annotations

from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.dependencies.auth import api_key_auth
from api.services.annotations import annotations_service

router = APIRouter()


@router.get("")
async def list_annotations(
    target_type: Optional[str] = Query(default=None),
    target_id: Optional[str] = Query(default=None),
):
    try:
        return annotations_service.list_all(target_type=target_type, target_id=target_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/target/{target_type}/{target_id}")
async def list_target_annotations(target_type: str, target_id: str):
    return annotations_service.list_by_target(target_type, target_id)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_annotation(payload: dict[str, Any], _: Annotated[str, Depends(api_key_auth)] = ""):
    try:
        return annotations_service.create(payload)
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"Missing required field: {exc}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.put("/{annotation_id}")
async def update_annotation(annotation_id: str, payload: dict[str, Any], _: Annotated[str, Depends(api_key_auth)] = ""):
    try:
        return annotations_service.update(annotation_id, payload)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/{annotation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_annotation(annotation_id: str, _: Annotated[str, Depends(api_key_auth)] = ""):
    try:
        annotations_service.delete(annotation_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
