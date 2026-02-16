"""Trend analysis API endpoints."""
from fastapi import APIRouter, HTTPException, Query

from api.services.log_store import log_store
from api.services.trend_tracker import TrendTracker

router = APIRouter()
tracker = TrendTracker()


@router.get("/summary")
async def trend_summary(days: int = Query(7, ge=1, le=90)):
    return tracker.get_trend_summary(days=days)


@router.get("/hosts")
async def hosts_trend(days: int = Query(7, ge=1, le=90)):
    return tracker.get_hosts_changes(days=days)


@router.get("/hosts/{ip}")
async def host_trend(ip: str, days: int = Query(7, ge=1, le=90)):
    return tracker.get_host_trends(ip=ip, days=days)


@router.get("/mitre")
async def mitre_trend(days: int = Query(7, ge=1, le=90)):
    return tracker.get_mitre_trends(days=days)


@router.post("/snapshot")
async def create_snapshot():
    return tracker.take_snapshot(log_store)


@router.get("/snapshots")
async def list_snapshots():
    return {"snapshots": tracker.list_snapshots()}


@router.delete("/snapshots/{snapshot_id}")
async def delete_snapshot(snapshot_id: str):
    deleted = tracker.delete_snapshot(snapshot_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return {"deleted": True, "id": snapshot_id}
