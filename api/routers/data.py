"""
Data router for querying loaded network logs.
Provides endpoints for connections, DNS queries, alerts, and summaries.
"""
from fastapi import APIRouter, Query, HTTPException, status, Depends
from pydantic import BaseModel, Field
from typing import Optional, Annotated
from datetime import datetime
from collections import Counter
import logging

from api.services.log_store import log_store
from api.parsers.unified import Connection, DnsQuery, Alert
from api.dependencies.auth import api_key_auth

logger = logging.getLogger(__name__)

router = APIRouter()


class ConnectionsResponse(BaseModel):
    """Response model for connections query."""

    total: int = Field(..., description="Total matching connections")
    limit: int = Field(..., description="Page size")
    offset: int = Field(..., description="Page offset")
    connections: list[Connection] = Field(..., description="Connection data")


class SummaryResponse(BaseModel):
    """Response model for summary statistics."""

    total_connections: int = Field(..., description="Total connections in store")
    unique_src_ips: int = Field(..., description="Unique source IP addresses")
    unique_dst_ips: int = Field(..., description="Unique destination IP addresses")
    time_range: dict = Field(..., description="Time range of data")
    protocol_breakdown: dict[str, int] = Field(..., description="Protocol distribution")
    service_breakdown: dict[str, int] = Field(..., description="Service distribution")
    top_sources: list[dict] = Field(..., description="Top source IPs by connection count")
    top_destinations: list[dict] = Field(..., description="Top destination IPs by connection count")


@router.get(
    "/connections",
    response_model=ConnectionsResponse,
    summary="Get connections",
    description="Query network connections with optional filters and pagination",
)
async def get_connections(
    _: Annotated[str, Depends(api_key_auth)],
    src_ip: Optional[str] = Query(None, description="Filter by source IP address"),
    dst_ip: Optional[str] = Query(None, description="Filter by destination IP address"),
    port: Optional[int] = Query(None, ge=1, le=65535, description="Filter by source or destination port"),
    proto: Optional[str] = Query(None, description="Filter by protocol (tcp/udp/icmp)"),
    service: Optional[str] = Query(None, description="Filter by detected service"),
    min_duration: Optional[float] = Query(None, ge=0, description="Filter by minimum duration (seconds)"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results per page"),
    offset: int = Query(0, ge=0, le=100000, description="Number of results to skip"),
) -> ConnectionsResponse:
    """
    Get network connections with optional filters.

    Supports filtering by:
    - Source/destination IP
    - Port (source or destination)
    - Protocol (tcp/udp/icmp)
    - Service name
    - Minimum duration

    Results are paginated with configurable limit and offset.

    Args:
        src_ip: Source IP address filter
        dst_ip: Destination IP address filter
        port: Port number filter
        proto: Protocol filter
        service: Service name filter
        min_duration: Minimum duration filter
        limit: Page size (1-1000)
        offset: Page offset

    Returns:
        Paginated list of connections
    """
    try:
        connections = log_store.get_connections(
            src_ip=src_ip,
            dst_ip=dst_ip,
            port=port,
            proto=proto,
            service=service,
            min_duration=min_duration,
            limit=limit,
            offset=offset,
        )

        # Get total count (without pagination)
        total = len(
            log_store.get_connections(
                src_ip=src_ip,
                dst_ip=dst_ip,
                port=port,
                proto=proto,
                service=service,
                min_duration=min_duration,
            )
        )

        return ConnectionsResponse(
            total=total,
            limit=limit,
            offset=offset,
            connections=connections,
        )

    except Exception as e:
        logger.error(f"Error querying connections: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Query failed: {str(e)}",
        )


@router.get(
    "/summary",
    response_model=SummaryResponse,
    summary="Get data summary",
    description="Get summary statistics for all loaded network data",
)
async def get_summary(
    _: Annotated[str, Depends(api_key_auth)],
) -> SummaryResponse:
    """
    Get summary statistics for loaded data.

    Returns aggregate statistics including:
    - Total connections
    - Unique source/destination IPs
    - Time range
    - Protocol breakdown
    - Service breakdown
    - Top talkers (sources and destinations)

    Returns:
        Summary statistics dictionary
    """
    try:
        time_range = log_store.get_time_range()
        unique_ips = log_store.get_unique_ips()

        # Calculate protocol breakdown
        proto_counter = Counter(conn.proto for conn in log_store.connections)
        protocol_breakdown = dict(proto_counter)

        # Calculate service breakdown
        service_counter = Counter(
            conn.service for conn in log_store.connections if conn.service
        )
        service_breakdown = dict(service_counter.most_common(10))

        # Calculate top sources
        src_counter = Counter(conn.src_ip for conn in log_store.connections)
        top_sources = [
            {"ip": ip, "count": count}
            for ip, count in src_counter.most_common(10)
        ]

        # Calculate top destinations
        dst_counter = Counter(conn.dst_ip for conn in log_store.connections)
        top_destinations = [
            {"ip": ip, "count": count}
            for ip, count in dst_counter.most_common(10)
        ]

        return SummaryResponse(
            total_connections=len(log_store.connections),
            unique_src_ips=len(unique_ips["sources"]),
            unique_dst_ips=len(unique_ips["destinations"]),
            time_range={
                "start": time_range[0].isoformat() if time_range[0] else None,
                "end": time_range[1].isoformat() if time_range[1] else None,
            },
            protocol_breakdown=protocol_breakdown,
            service_breakdown=service_breakdown,
            top_sources=top_sources,
            top_destinations=top_destinations,
        )

    except Exception as e:
        logger.error(f"Error generating summary: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Summary generation failed: {str(e)}",
        )


@router.get(
    "/dns",
    summary="Get DNS queries",
    description="Query DNS queries with optional filters",
)
async def get_dns_queries(
    _: Annotated[str, Depends(api_key_auth)],
    src_ip: Optional[str] = Query(None, description="Filter by source IP address"),
    query: Optional[str] = Query(None, description="Filter by domain name (substring)"),
    qtype: Optional[str] = Query(None, description="Filter by query type (A, AAAA, etc.)"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results per page"),
    offset: int = Query(0, ge=0, le=100000, description="Number of results to skip"),
) -> dict:
    """
    Get DNS queries with optional filters.

    Args:
        src_ip: Source IP address filter
        query: Domain name substring filter
        qtype: Query type filter
        limit: Page size
        offset: Page offset

    Returns:
        Paginated list of DNS queries
    """
    try:
        dns_queries = log_store.get_dns_queries(
            src_ip=src_ip,
            query=query,
            qtype=qtype,
            limit=limit,
            offset=offset,
        )

        # Get total count
        total = len(
            log_store.get_dns_queries(
                src_ip=src_ip,
                query=query,
                qtype=qtype,
            )
        )

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "queries": [q.dict() for q in dns_queries],
        }

    except Exception as e:
        logger.error(f"Error querying DNS: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Query failed: {str(e)}",
        )


@router.get(
    "/alerts",
    summary="Get security alerts",
    description="Query Suricata IDS alerts with optional filters",
)
async def get_alerts(
    _: Annotated[str, Depends(api_key_auth)],
    severity: Optional[int] = Query(None, ge=1, le=3, description="Filter by severity (1=high, 3=low)"),
    category: Optional[str] = Query(None, description="Filter by alert category"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results per page"),
    offset: int = Query(0, ge=0, le=100000, description="Number of results to skip"),
) -> dict:
    """
    Get IDS alerts with optional filters.

    Args:
        severity: Severity level filter (1=high, 2=medium, 3=low)
        category: Alert category filter
        limit: Page size
        offset: Page offset

    Returns:
        Paginated list of alerts
    """
    try:
        alerts = log_store.get_alerts(
            severity=severity,
            category=category,
            limit=limit,
            offset=offset,
        )

        # Get total count
        total = len(
            log_store.get_alerts(
                severity=severity,
                category=category,
            )
        )

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "alerts": [a.dict() for a in alerts],
        }

    except Exception as e:
        logger.error(f"Error querying alerts: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Query failed: {str(e)}",
        )


@router.get(
    "/timeline",
    summary="Get timeline data",
    description="Get connection timeline for visualization",
)
async def get_timeline(
    _: Annotated[str, Depends(api_key_auth)],
    interval: str = Query("hour", description="Time interval (hour, day)"),
    limit: int = Query(100, ge=1, le=500, description="Maximum data points"),
) -> dict:
    """
    Get connection timeline data for visualization.

    Aggregates connections into time buckets for timeline charts.

    Args:
        interval: Time bucket size (hour or day)
        limit: Maximum number of buckets

    Returns:
        Timeline data with timestamps and connection counts
    """
    try:
        # This is a simplified implementation
        # In production, you'd use proper time bucketing
        return {
            "interval": interval,
            "data": [],
            "message": "Timeline endpoint - implementation in progress",
        }

    except Exception as e:
        logger.error(f"Error generating timeline: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Timeline generation failed: {str(e)}",
        )
