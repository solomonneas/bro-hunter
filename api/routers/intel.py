"""
Threat Intelligence Router - IP/domain reputation lookups.
"""
from typing import Optional, List
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel

from api.services.threat_intel import ThreatIntelService

router = APIRouter()

_intel_service: Optional[ThreatIntelService] = None


def _get_service() -> ThreatIntelService:
    global _intel_service
    if _intel_service is None:
        _intel_service = ThreatIntelService()
    return _intel_service


class BulkLookupRequest(BaseModel):
    indicators: List[dict]  # [{"value": "1.2.3.4", "type": "ip"}, ...]


@router.get("/status")
async def intel_status():
    """Get threat intel service configuration status."""
    return _get_service().get_status()


@router.get("/ip/{ip}")
async def lookup_ip(ip: str):
    """Look up an IP address across all configured threat intel sources."""
    service = _get_service()
    result = await service.lookup_ip(ip)
    return {
        "indicator": result.indicator,
        "type": result.indicator_type,
        "is_malicious": result.is_malicious,
        "max_confidence": round(result.max_confidence, 3),
        "sources_checked": result.sources_checked,
        "sources_flagged": result.sources_flagged,
        "categories": sorted(result.categories),
        "results": [
            {
                "source": r.source,
                "malicious": r.malicious,
                "confidence": round(r.confidence, 3),
                "description": r.description,
                "categories": r.categories,
                "references": r.references,
            }
            for r in result.results
        ],
    }


@router.get("/domain/{domain}")
async def lookup_domain(domain: str):
    """Look up a domain across all configured threat intel sources."""
    service = _get_service()
    result = await service.lookup_domain(domain)
    return {
        "indicator": result.indicator,
        "type": result.indicator_type,
        "is_malicious": result.is_malicious,
        "max_confidence": round(result.max_confidence, 3),
        "sources_checked": result.sources_checked,
        "sources_flagged": result.sources_flagged,
        "categories": sorted(result.categories),
        "results": [
            {
                "source": r.source,
                "malicious": r.malicious,
                "confidence": round(r.confidence, 3),
                "description": r.description,
                "categories": r.categories,
                "references": r.references,
            }
            for r in result.results
        ],
    }


@router.post("/bulk")
async def bulk_lookup(req: BulkLookupRequest):
    """Bulk lookup multiple indicators."""
    if len(req.indicators) > 100:
        raise HTTPException(status_code=400, detail="Max 100 indicators per request")

    service = _get_service()
    results = await service.bulk_lookup(req.indicators)

    return {
        "total": len(results),
        "malicious_count": sum(1 for r in results if r.is_malicious),
        "results": [
            {
                "indicator": r.indicator,
                "type": r.indicator_type,
                "is_malicious": r.is_malicious,
                "max_confidence": round(r.max_confidence, 3),
                "sources_checked": r.sources_checked,
                "sources_flagged": r.sources_flagged,
                "categories": sorted(r.categories),
            }
            for r in results
        ],
    }
