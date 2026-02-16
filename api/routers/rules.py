"""Rules router: CRUD + test/evaluate endpoints."""
import re
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException

from api.dependencies.auth import api_key_auth
from api.services.rule_engine import RuleCreate, RuleUpdate, rule_engine

router = APIRouter()

MAX_REGEX_LENGTH = 200


def _validate_regex_conditions(payload):
    """Validate regex patterns in rule conditions for length and correctness."""
    conditions = None
    if hasattr(payload, 'definition') and payload.definition and hasattr(payload.definition, 'conditions'):
        conditions = payload.definition.conditions
    elif hasattr(payload, 'conditions'):
        conditions = payload.conditions
    if not conditions:
        return
    for cond in conditions:
        if getattr(cond, 'operator', None) == 'regex':
            value = getattr(cond, 'value', '')
            if isinstance(value, str) and len(value) > MAX_REGEX_LENGTH:
                raise HTTPException(status_code=400, detail=f"Regex pattern exceeds {MAX_REGEX_LENGTH} character limit")
            try:
                re.compile(str(value))
            except re.error as e:
                raise HTTPException(status_code=400, detail=f"Invalid regex pattern: {e}")


@router.get("")
async def list_rules():
    return {"rules": [r.model_dump() for r in rule_engine.list_rules()]}


@router.post("")
async def create_rule(payload: RuleCreate, _: Annotated[str, Depends(api_key_auth)] = ""):
    _validate_regex_conditions(payload)
    try:
        rule = rule_engine.create_rule(payload)
        return rule.model_dump()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/{rule_id}")
async def update_rule(rule_id: str, payload: RuleUpdate, _: Annotated[str, Depends(api_key_auth)] = ""):
    _validate_regex_conditions(payload)
    try:
        rule = rule_engine.update_rule(rule_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule.model_dump()


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str, _: Annotated[str, Depends(api_key_auth)] = ""):
    if not rule_engine.delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"deleted": True}


@router.post("/{rule_id}/test")
async def test_rule(rule_id: str, _: Annotated[str, Depends(api_key_auth)] = ""):
    rule = rule_engine.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule_engine.test_rule(rule)


@router.post("/evaluate")
async def evaluate_enabled_rules(_: Annotated[str, Depends(api_key_auth)] = ""):
    return rule_engine.evaluate_enabled()
