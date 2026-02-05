"""
Threat hunting endpoints for beacon detection and analysis.
"""
from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, Annotated
import logging
import ipaddress

from api.services.log_store import log_store
from api.services.beacon_analyzer import BeaconAnalyzer
from api.models.beacon import BeaconResult, BeaconDetailedResult
from api.dependencies.auth import api_key_auth

logger = logging.getLogger(__name__)

router = APIRouter()


def _validate_ip(ip: str, param_name: str) -> str:
    """
    Validate IP address format.

    Args:
        ip: IP address string
        param_name: Parameter name for error message

    Returns:
        Validated IP address string

    Raises:
        HTTPException: 422 if IP format is invalid
    """
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid IP address format for {param_name}: {ip}",
        )


@router.get("/beacons", response_model=dict)
async def get_beacons(
    _: Annotated[str, Depends(api_key_auth)],
    min_score: float = Query(70.0, description="Minimum beacon score", ge=0.0, le=100.0),
    min_connections: int = Query(10, description="Minimum connection count", ge=3),
    max_jitter_pct: float = Query(20.0, description="Maximum jitter percentage", ge=0.0),
    min_time_span_hours: float = Query(1.0, description="Minimum time span (hours)", ge=0.1),
    include_allowlisted: bool = Query(False, description="Include allowlisted destinations"),
    limit: int = Query(100, description="Maximum results to return", ge=1, le=1000),
    offset: int = Query(0, description="Results offset for pagination", ge=0),
) -> dict:
    """
    Get all detected beacons sorted by score.

    Analyzes connection patterns to identify hosts making periodic callbacks
    to external IPs, a hallmark of C2 (command and control) communication.

    Returns beacons with:
    - High interval regularity (low jitter)
    - Consistent data sizes
    - Multiple connections over time windows
    - Statistical confidence scores
    """
    if not log_store.connections:
        raise HTTPException(
            status_code=400,
            detail="No connection data loaded. Please ingest logs first."
        )

    logger.info(
        f"Running beacon detection with score_threshold={min_score}, "
        f"min_connections={min_connections}, max_jitter={max_jitter_pct}%"
    )

    # Initialize analyzer with parameters
    analyzer = BeaconAnalyzer(
        min_connections=min_connections,
        max_jitter_pct=max_jitter_pct,
        min_time_span_hours=min_time_span_hours,
        score_threshold=min_score,
    )

    # Analyze connections
    beacons = analyzer.analyze_connections(
        connections=log_store.connections,
        include_allowlisted=include_allowlisted,
    )

    # Apply pagination
    total = len(beacons)
    beacons = beacons[offset:offset + limit]

    logger.info(f"Detected {total} beacons, returning {len(beacons)} after pagination")

    return {
        "beacons": [b.model_dump() for b in beacons],
        "total": total,
        "returned": len(beacons),
        "offset": offset,
        "limit": limit,
        "parameters": {
            "min_score": min_score,
            "min_connections": min_connections,
            "max_jitter_pct": max_jitter_pct,
            "min_time_span_hours": min_time_span_hours,
            "include_allowlisted": include_allowlisted,
        },
        "analysis_summary": {
            "total_connections_analyzed": len(log_store.connections),
            "time_range": {
                "start": log_store.min_timestamp.isoformat() if log_store.min_timestamp else None,
                "end": log_store.max_timestamp.isoformat() if log_store.max_timestamp else None,
            },
        },
    }


@router.get("/beacons/{src_ip}/{dst_ip}", response_model=dict)
async def get_beacon_detail(
    src_ip: str,
    dst_ip: str,
    _: Annotated[str, Depends(api_key_auth)],
    min_connections: int = Query(10, description="Minimum connection count", ge=3),
) -> dict:
    """
    Get detailed beacon analysis for a specific src->dst pair.

    Returns comprehensive analysis including:
    - Full interval histogram for visualization
    - All observed intervals and timestamps
    - Data size distributions
    - Statistical metrics and confidence scores
    """
    # Validate IP address formats
    _validate_ip(src_ip, "src_ip")
    _validate_ip(dst_ip, "dst_ip")

    if not log_store.connections:
        raise HTTPException(
            status_code=400,
            detail="No connection data loaded. Please ingest logs first."
        )

    logger.info(f"Getting detailed beacon analysis for {src_ip} -> {dst_ip}")

    # Initialize analyzer
    analyzer = BeaconAnalyzer(
        min_connections=min_connections,
        max_jitter_pct=100.0,  # Don't filter by jitter for detail view
        min_time_span_hours=0.1,  # Lower threshold for detail view
        score_threshold=0.0,  # Show all scores in detail view
    )

    # Get detailed analysis
    detailed = analyzer.analyze_connection_pair_detailed(
        connections=log_store.connections,
        src_ip=src_ip,
        dst_ip=dst_ip,
    )

    if not detailed:
        raise HTTPException(
            status_code=404,
            detail=f"No beacon pattern found for {src_ip} -> {dst_ip} "
                   f"(need at least {min_connections} connections)"
        )

    logger.info(
        f"Found beacon pattern: {detailed.connection_count} connections, "
        f"score={detailed.beacon_score:.1f}, jitter={detailed.jitter_pct:.1f}%"
    )

    return {
        "beacon": detailed.model_dump(),
        "message": "Detailed beacon analysis",
    }


@router.get("/beacons/stats", response_model=dict)
async def get_beacon_stats(
    _: Annotated[str, Depends(api_key_auth)],
    min_score: float = Query(70.0, description="Minimum beacon score", ge=0.0, le=100.0),
) -> dict:
    """
    Get summary statistics about beacon detection.

    Returns aggregate statistics and top beacons without full detail.
    """
    if not log_store.connections:
        raise HTTPException(
            status_code=400,
            detail="No connection data loaded. Please ingest logs first."
        )

    # Run analysis with default parameters
    analyzer = BeaconAnalyzer(score_threshold=min_score)
    beacons = analyzer.analyze_connections(log_store.connections)

    # Calculate statistics
    if beacons:
        avg_score = sum(b.beacon_score for b in beacons) / len(beacons)
        max_score = max(b.beacon_score for b in beacons)
        avg_jitter = sum(b.jitter_pct for b in beacons) / len(beacons)
        avg_connections = sum(b.connection_count for b in beacons) / len(beacons)

        # Count by score ranges
        critical = len([b for b in beacons if b.beacon_score >= 90])
        high = len([b for b in beacons if 80 <= b.beacon_score < 90])
        medium = len([b for b in beacons if 70 <= b.beacon_score < 80])

        # Top 10 beacons
        top_beacons = [
            {
                "src_ip": b.src_ip,
                "dst_ip": b.dst_ip,
                "dst_port": b.dst_port,
                "score": round(b.beacon_score, 1),
                "jitter_pct": round(b.jitter_pct, 1),
                "connection_count": b.connection_count,
            }
            for b in beacons[:10]
        ]
    else:
        avg_score = 0.0
        max_score = 0.0
        avg_jitter = 0.0
        avg_connections = 0
        critical = 0
        high = 0
        medium = 0
        top_beacons = []

    return {
        "summary": {
            "total_beacons": len(beacons),
            "avg_score": round(avg_score, 1),
            "max_score": round(max_score, 1),
            "avg_jitter_pct": round(avg_jitter, 1),
            "avg_connections": round(avg_connections, 1),
        },
        "by_severity": {
            "critical": critical,  # >= 90
            "high": high,  # 80-89
            "medium": medium,  # 70-79
        },
        "top_beacons": top_beacons,
        "parameters": {
            "min_score": min_score,
        },
    }
