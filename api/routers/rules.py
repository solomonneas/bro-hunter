"""Rules router: CRUD + test/evaluate endpoints."""
from fastapi import APIRouter, HTTPException

from api.services.rule_engine import RuleCreate, RuleUpdate, rule_engine

router = APIRouter()


@router.get("")
async def list_rules():
    return {"rules": [r.model_dump() for r in rule_engine.list_rules()]}


@router.post("")
async def create_rule(payload: RuleCreate):
    try:
        rule = rule_engine.create_rule(payload)
        return rule.model_dump()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/{rule_id}")
async def update_rule(rule_id: str, payload: RuleUpdate):
    try:
        rule = rule_engine.update_rule(rule_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule.model_dump()


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str):
    if not rule_engine.delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"deleted": True}


@router.post("/{rule_id}/test")
async def test_rule(rule_id: str):
    rule = rule_engine.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule_engine.test_rule(rule)


@router.post("/evaluate")
async def evaluate_enabled_rules():
    return rule_engine.evaluate_enabled()
