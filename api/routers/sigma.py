"""Sigma import router."""
from __future__ import annotations

import os
from typing import Annotated
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from api.dependencies.auth import api_key_auth

from api.services.rule_engine import rule_engine
from api.services.sigma_converter import convert_sigma_batch, convert_sigma_yaml

router = APIRouter()

SIGMA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "sigma"))


@router.post("/import")
async def import_sigma(file: UploadFile = File(...), _: Annotated[str, Depends(api_key_auth)] = ""):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")
    if not file.filename.endswith((".yml", ".yaml")):
        raise HTTPException(status_code=400, detail="Only .yml/.yaml files are supported")

    raw = await file.read()
    content = raw.decode("utf-8", errors="ignore")
    rule_payload = convert_sigma_yaml(content, source=f"sigma:{file.filename}")
    parsed = rule_engine.create_rule(rule_payload)
    return {"imported": True, "rule": parsed.model_dump()}


@router.post("/import-batch")
async def import_sigma_batch(files: list[UploadFile] = File(...), _: Annotated[str, Depends(api_key_auth)] = ""):
    sigma_files: list[tuple[str, str]] = []
    for item in files:
        if not item.filename or not item.filename.endswith((".yml", ".yaml")):
            continue
        body = await item.read()
        sigma_files.append((item.filename, body.decode("utf-8", errors="ignore")))

    converted = convert_sigma_batch(sigma_files)
    imported = [rule_engine.create_rule(rule).model_dump() for rule in converted]
    return {"imported_count": len(imported), "rules": imported}


@router.get("/templates")
async def sigma_templates():
    os.makedirs(SIGMA_DIR, exist_ok=True)
    templates = []
    for name in sorted(os.listdir(SIGMA_DIR)):
        if not name.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(SIGMA_DIR, name)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        preview = convert_sigma_yaml(content, source=f"sigma:{name}")
        templates.append({
            "filename": name,
            "name": preview.name,
            "description": preview.description,
            "severity": preview.severity,
            "logic": preview.logic,
            "conditions": [c.model_dump() for c in preview.conditions],
        })

    return {"templates": templates}
