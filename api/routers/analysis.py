"""
Threat analysis and hunting endpoints.
Provides unified threat scoring, indicator detection, and MITRE ATT&CK mapping.
"""
from typing import Optional, List, Annotated
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
import ipaddress

from api.models.threat import ThreatLevel, ThreatScore, ThreatIndicator, MitreMapping
from api.services.unified_threat_engine import UnifiedThreatEngine
from api.services.log_store import LogStore
from api.dependencies.auth import api_key_auth

router = APIRouter()

# Dependency to get log store instance
_log_store_instance: Optional[LogStore] = None


def get_log_store() -> LogStore:
    """Get the shared log store instance."""
    global _log_store_instance
    if _log_store_instance is None:
        from api.main import log_store
        _log_store_instance = log_store
    return _log_store_instance


def get_threat_engine(log_store: LogStore = Depends(get_log_store)) -> UnifiedThreatEngine:
    """Get unified threat engine instance."""
    return UnifiedThreatEngine(log_store)


# Response models
class ThreatScoreResponse(BaseModel):
    """Threat score response."""
    entity: str
    score: float
    level: str
    confidence: float
    reasons: List[str]
    indicators_count: int
    mitre_techniques_count: int
    first_seen: float
    last_seen: float


class ThreatListResponse(BaseModel):
    """List of threats response."""
    threats: List[ThreatScoreResponse]
    total: int


class IndicatorListResponse(BaseModel):
    """List of indicators response."""
    indicators: List[ThreatIndicator]
    total: int


class MitreMappingResponse(BaseModel):
    """MITRE mapping response."""
    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    confidence: float
    detection_count: int
    affected_hosts: List[str]
    observed_behaviors: List[str]


class MitreListResponse(BaseModel):
    """List of MITRE mappings response."""
    mappings: List[MitreMappingResponse]
    total: int
    techniques_count: int
    tactics_count: int


class HostProfileResponse(BaseModel):
    """Host threat profile response."""
    ip: str
    score: float
    threat_level: str
    confidence: float
    beacon_count: int
    dns_threat_count: int
    alert_count: int
    long_connection_count: int
    reasons: List[str]
    indicators: List[ThreatIndicator]
    mitre_techniques: List[str]
    mitre_mappings: List[MitreMapping]
    attack_summary: str
    related_ips: List[str]
    related_domains: List[str]
    first_seen: float
    last_seen: float


class MitreOverviewResponse(BaseModel):
    """MITRE ATT&CK overview response."""
    techniques: dict
    tactics: dict
    affected_hosts: dict


@router.get("/threats", response_model=ThreatListResponse)
async def get_threat_scores(
    _: Annotated[str, Depends(api_key_auth)],
    threat_level: Optional[str] = Query(None, description="Filter by threat level (critical, high, medium, low, info)"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
    offset: int = Query(0, ge=0, le=100000, description="Number of results to skip"),
    engine: UnifiedThreatEngine = Depends(get_threat_engine),
):
    """
    Get unified threat scores for all hosts.

    Aggregates detections from:
    - Beaconing analysis
    - DNS threat detection
    - Suricata alerts
    - Long connection analysis

    Returns per-host threat scores with evidence chains.
    """
    # Get all profiles
    if threat_level:
        try:
            level = ThreatLevel(threat_level.lower())
            profiles = engine.get_threats_by_level(level)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid threat level. Must be one of: critical, high, medium, low, info"
            )
    else:
        profiles = engine.get_top_threats(limit=limit)

    # Convert to response format
    threats = []
    for profile in profiles[:limit]:
        threats.append(ThreatScoreResponse(
            entity=profile.ip,
            score=profile.score,
            level=profile.threat_level.value,
            confidence=profile.confidence,
            reasons=profile.all_reasons,
            indicators_count=len(profile.all_indicators),
            mitre_techniques_count=len(profile.mitre_techniques),
            first_seen=profile.first_seen,
            last_seen=profile.last_seen,
        ))

    return ThreatListResponse(
        threats=threats,
        total=len(threats),
    )


@router.get("/threats/{ip}", response_model=HostProfileResponse)
async def get_host_threat_profile(
    ip: str,
    _: Annotated[str, Depends(api_key_auth)],
    engine: UnifiedThreatEngine = Depends(get_threat_engine),
):
    """
    Get detailed threat profile for a specific host.

    Includes:
    - All detections (beacons, DNS threats, alerts, long connections)
    - Evidence chains
    - MITRE ATT&CK mappings
    - Attack timeline and narrative
    """
    # Validate IP address format
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid IP address format: {ip}"
        )

    profile = engine.get_host_profile(ip)
    if not profile:
        raise HTTPException(
            status_code=404,
            detail=f"No threat data found for host {ip}"
        )

    return HostProfileResponse(
        ip=profile.ip,
        score=profile.score,
        threat_level=profile.threat_level.value,
        confidence=profile.confidence,
        beacon_count=profile.beacon_count,
        dns_threat_count=profile.dns_threat_count,
        alert_count=profile.alert_count,
        long_connection_count=profile.long_connection_count,
        reasons=profile.all_reasons,
        indicators=profile.all_indicators,
        mitre_techniques=sorted(list(profile.mitre_techniques)),
        mitre_mappings=profile.mitre_mappings,
        attack_summary=profile.attack_summary,
        related_ips=sorted(list(profile.related_ips)),
        related_domains=sorted(list(profile.related_domains)),
        first_seen=profile.first_seen,
        last_seen=profile.last_seen,
    )


@router.get("/indicators", response_model=IndicatorListResponse)
async def get_threat_indicators(
    _: Annotated[str, Depends(api_key_auth)],
    severity: Optional[str] = Query(None, description="Filter by severity"),
    indicator_type: Optional[str] = Query(None, description="Filter by type (beacon, dns_tunneling, ids_alert, etc.)"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0, le=100000, description="Number of results to skip"),
    engine: UnifiedThreatEngine = Depends(get_threat_engine),
):
    """
    Get all detected threat indicators across all hosts.

    Indicators include:
    - Beaconing destinations
    - Malicious domains
    - IDS alert signatures
    - Long connection destinations
    """
    profiles = engine.analyze_all()

    # Collect all indicators
    all_indicators = []
    for profile in profiles.values():
        all_indicators.extend(profile.all_indicators)

    # Filter by severity
    if severity:
        try:
            level = ThreatLevel(severity.lower())
            all_indicators = [i for i in all_indicators if i.severity == level]
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid severity. Must be one of: critical, high, medium, low, info"
            )

    # Filter by type
    if indicator_type:
        all_indicators = [i for i in all_indicators if i.indicator_type == indicator_type]

    # Sort by severity and confidence
    severity_order = {
        ThreatLevel.CRITICAL: 4,
        ThreatLevel.HIGH: 3,
        ThreatLevel.MEDIUM: 2,
        ThreatLevel.LOW: 1,
        ThreatLevel.INFO: 0,
    }
    all_indicators.sort(
        key=lambda x: (severity_order.get(x.severity, 0), x.confidence),
        reverse=True
    )

    return IndicatorListResponse(
        indicators=all_indicators[:limit],
        total=len(all_indicators),
    )


@router.get("/mitre", response_model=MitreListResponse)
async def get_mitre_mappings(
    _: Annotated[str, Depends(api_key_auth)],
    technique_id: Optional[str] = Query(None, description="Filter by technique ID"),
    tactic_id: Optional[str] = Query(None, description="Filter by tactic ID"),
    min_detections: int = Query(1, ge=1, description="Minimum detection count"),
    engine: UnifiedThreatEngine = Depends(get_threat_engine),
):
    """
    Get MITRE ATT&CK technique mappings from all detections.

    Shows which techniques have been observed, with:
    - Detection counts
    - Affected hosts
    - Confidence scores
    - Evidence chains
    """
    profiles = engine.analyze_all()

    # Collect all MITRE mappings
    all_mappings = []
    for profile in profiles.values():
        all_mappings.extend(profile.mitre_mappings)

    # Filter by technique ID
    if technique_id:
        all_mappings = [m for m in all_mappings if m.technique_id == technique_id]

    # Filter by tactic ID
    if tactic_id:
        all_mappings = [m for m in all_mappings if m.tactic_id == tactic_id]

    # Filter by minimum detections
    all_mappings = [m for m in all_mappings if m.detection_count >= min_detections]

    # Sort by detection count
    all_mappings.sort(key=lambda x: x.detection_count, reverse=True)

    # Convert to response format
    mappings = [
        MitreMappingResponse(
            technique_id=m.technique_id,
            technique_name=m.technique_name,
            tactic=m.tactic,
            tactic_id=m.tactic_id,
            confidence=m.confidence,
            detection_count=m.detection_count,
            affected_hosts=m.affected_hosts,
            observed_behaviors=m.observed_behaviors,
        )
        for m in all_mappings
    ]

    # Count unique techniques and tactics
    unique_techniques = len(set(m.technique_id for m in all_mappings))
    unique_tactics = len(set(m.tactic_id for m in all_mappings))

    return MitreListResponse(
        mappings=mappings,
        total=len(mappings),
        techniques_count=unique_techniques,
        tactics_count=unique_tactics,
    )


@router.get("/mitre/overview", response_model=MitreOverviewResponse)
async def get_mitre_overview(
    _: Annotated[str, Depends(api_key_auth)],
    engine: UnifiedThreatEngine = Depends(get_threat_engine),
):
    """
    Get overview of all MITRE ATT&CK techniques and tactics observed.

    Provides aggregate statistics:
    - Technique usage counts
    - Tactic coverage
    - Affected hosts per technique
    """
    overview = engine.get_mitre_attack_overview()
    return MitreOverviewResponse(**overview)


@router.get("/stats")
async def get_analysis_stats(
    _: Annotated[str, Depends(api_key_auth)],
    engine: UnifiedThreatEngine = Depends(get_threat_engine),
):
    """
    Get aggregate statistics from all detection engines.

    Provides counts of:
    - Hosts with threats
    - Total detections by type
    - MITRE technique coverage
    - Threat level distribution
    """
    profiles = engine.analyze_all()

    # Count by threat level
    level_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for profile in profiles.values():
        level_counts[profile.threat_level.value] += 1

    # Total detections
    total_beacons = sum(p.beacon_count for p in profiles.values())
    total_dns_threats = sum(p.dns_threat_count for p in profiles.values())
    total_alerts = sum(p.alert_count for p in profiles.values())
    total_long_connections = sum(p.long_connection_count for p in profiles.values())

    # MITRE coverage
    overview = engine.get_mitre_attack_overview()

    return {
        "total_hosts": len(profiles),
        "threat_level_distribution": level_counts,
        "detections": {
            "beacons": total_beacons,
            "dns_threats": total_dns_threats,
            "ids_alerts": total_alerts,
            "long_connections": total_long_connections,
            "total": total_beacons + total_dns_threats + total_alerts + total_long_connections,
        },
        "mitre": {
            "techniques_observed": len(overview["techniques"]),
            "tactics_observed": len(overview["tactics"]),
        },
    }
