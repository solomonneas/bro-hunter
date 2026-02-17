"""Webhook alert management router."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from api.services.webhook_manager import webhook_manager

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])


class WebhookCreate(BaseModel):
    name: str
    url: str
    webhook_type: str = "generic"
    enabled: bool = True
    severity_threshold: str = "medium"
    event_types: list[str] = ["new_threat", "score_change", "beacon_detected", "cert_anomaly"]


class WebhookUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    webhook_type: Optional[str] = None
    enabled: Optional[bool] = None
    severity_threshold: Optional[str] = None
    event_types: Optional[list[str]] = None


@router.get("")
async def list_webhooks():
    return {"webhooks": [c.to_dict() for c in webhook_manager.configs]}


@router.post("")
async def create_webhook(data: WebhookCreate):
    config = webhook_manager.add_config(data.model_dump())
    return config.to_dict()


@router.put("/{config_id}")
async def update_webhook(config_id: str, data: WebhookUpdate):
    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    config = webhook_manager.update_config(config_id, updates)
    if not config:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return config.to_dict()


@router.delete("/{config_id}")
async def delete_webhook(config_id: str):
    if not webhook_manager.delete_config(config_id):
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"status": "deleted"}


@router.post("/{config_id}/test")
async def test_webhook(config_id: str):
    record = await webhook_manager.test_webhook(config_id)
    if not record:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return record.to_dict()


@router.get("/history")
async def webhook_history():
    return {"history": [r.to_dict() for r in reversed(webhook_manager.history)]}
