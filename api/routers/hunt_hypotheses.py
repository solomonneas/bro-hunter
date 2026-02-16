"""Hunt hypotheses API router."""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, status

from api.services.hunt_hypotheses import hunt_hypotheses_service

router = APIRouter()


@router.get("")
async def list_hypotheses(status_filter: Optional[str] = Query(default=None, alias="status")):
    try:
        return hunt_hypotheses_service.list_all(status=status_filter)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_hypothesis(payload: dict[str, Any]):
    try:
        return hunt_hypotheses_service.create(payload)
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"Missing required field: {exc}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/{hypothesis_id}")
async def get_hypothesis(hypothesis_id: str):
    try:
        return hunt_hypotheses_service.get(hypothesis_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.put("/{hypothesis_id}")
async def update_hypothesis(hypothesis_id: str, payload: dict[str, Any]):
    try:
        return hunt_hypotheses_service.update(hypothesis_id, payload)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/{hypothesis_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_hypothesis(hypothesis_id: str):
    try:
        hunt_hypotheses_service.delete(hypothesis_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/{hypothesis_id}/steps/{step_idx}/complete")
async def complete_hypothesis_step(hypothesis_id: str, step_idx: int, payload: dict[str, Any]):
    try:
        actual_result = payload.get("actual_result") if isinstance(payload, dict) else None
        return hunt_hypotheses_service.complete_step(hypothesis_id, step_idx, actual_result)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
