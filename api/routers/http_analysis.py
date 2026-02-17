"""HTTP anomaly detection router."""
from fastapi import APIRouter
from api.services.http_analyzer import http_analyzer

router = APIRouter(prefix="/api/v1/http", tags=["http"])


@router.get("/sessions")
async def list_sessions():
    return {"sessions": [s.to_dict() for s in http_analyzer.sessions]}


@router.get("/stats")
async def http_stats():
    return http_analyzer.get_stats()


@router.post("/analyze")
async def analyze():
    http_analyzer.generate_demo_data(80)
    return {"status": "ok", "count": len(http_analyzer.sessions)}
