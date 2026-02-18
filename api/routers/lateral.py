"""Lateral movement detection router."""
from fastapi import APIRouter
from api.services.lateral_movement import lateral_detector

router = APIRouter(prefix="/api/v1/lateral", tags=["lateral"])


@router.get("/detections")
async def list_detections():
    return {"detections": [d.to_dict() for d in lateral_detector.detections]}


@router.get("/stats")
async def lateral_stats():
    return lateral_detector.get_stats()


@router.post("/analyze")
async def analyze():
    lateral_detector.generate_demo_data()
    return {"status": "ok", "count": len(lateral_detector.detections)}
