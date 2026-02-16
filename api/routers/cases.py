"""Case management API router."""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, status

from api.services.case_manager import case_manager

router = APIRouter()


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_case(payload: dict[str, Any]):
    try:
        return case_manager.create_case(payload)
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"Missing required field: {exc}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("")
async def list_cases(
    status_filter: Optional[str] = Query(default=None, alias="status"),
    severity: Optional[str] = Query(default=None),
    tags: Optional[str] = Query(default=None, description="Comma-separated tags"),
):
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
    return case_manager.list_cases(status=status_filter, severity=severity, tags=tag_list)


@router.get("/{case_id}")
async def get_case(case_id: str):
    try:
        return case_manager.get_case(case_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.put("/{case_id}")
async def update_case(case_id: str, payload: dict[str, Any]):
    try:
        return case_manager.update_case(case_id, payload)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_case(case_id: str):
    try:
        case_manager.delete_case(case_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/{case_id}/findings", status_code=status.HTTP_201_CREATED)
async def add_finding(case_id: str, payload: dict[str, Any]):
    try:
        return case_manager.add_finding(case_id, payload)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"Missing required field: {exc}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/{case_id}/notes", status_code=status.HTTP_201_CREATED)
async def add_note(case_id: str, payload: dict[str, Any]):
    try:
        return case_manager.add_note(case_id, payload)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"Missing required field: {exc}")


@router.put("/{case_id}/notes/{note_id}")
async def update_note(case_id: str, note_id: str, payload: dict[str, Any]):
    try:
        return case_manager.update_note(case_id, note_id, payload)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/{case_id}/iocs", status_code=status.HTTP_201_CREATED)
async def add_ioc(case_id: str, payload: dict[str, Any]):
    try:
        return case_manager.add_ioc(case_id, payload)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"Missing required field: {exc}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/{case_id}/timeline")
async def get_timeline(case_id: str):
    try:
        return case_manager.get_timeline(case_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
