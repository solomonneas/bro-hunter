"""TLS/JA3 fingerprinting router."""
from fastapi import APIRouter
from api.services.tls_analyzer import tls_analyzer, KNOWN_BAD_JA3

router = APIRouter(prefix="/api/v1/tls", tags=["tls"])


@router.get("/sessions")
async def list_sessions():
    return {"sessions": [s.to_dict() for s in tls_analyzer.sessions]}


@router.get("/ja3-database")
async def ja3_database():
    return {"entries": KNOWN_BAD_JA3, "count": len(KNOWN_BAD_JA3)}


@router.get("/stats")
async def tls_stats():
    return tls_analyzer.get_stats()


@router.post("/analyze")
async def analyze():
    tls_analyzer.generate_demo_data(50)
    return {"status": "ok", "count": len(tls_analyzer.sessions)}
