"""
DNS threat detection endpoints for tunneling, DGA, and suspicious patterns.
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional
import logging

from api.services.log_store import log_store
from api.services.dns_analyzer import DnsAnalyzer
from api.models.dns_threat import (
    DnsThreatSummary,
    DnsTunnelingResult,
    DgaResult,
    DnsFastFluxResult,
    SuspiciousDnsPattern,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/dns/threats", response_model=dict)
async def get_dns_threats(
    tunneling_threshold: float = Query(60.0, description="Minimum tunneling score", ge=0.0, le=100.0),
    dga_threshold: float = Query(65.0, description="Minimum DGA score", ge=0.0, le=100.0),
    fast_flux_threshold: float = Query(70.0, description="Minimum fast-flux score", ge=0.0, le=100.0),
    min_queries_tunneling: int = Query(10, description="Minimum queries for tunneling detection", ge=3),
    min_queries_dga: int = Query(3, description="Minimum queries for DGA detection", ge=1),
    min_queries_fast_flux: int = Query(5, description="Minimum queries for fast-flux detection", ge=3),
) -> dict:
    """
    Get comprehensive DNS threat analysis.

    Analyzes DNS queries to detect:
    - DNS tunneling (data exfiltration via encoded subdomains)
    - DGA domains (algorithmically generated domains for C2)
    - Fast-flux DNS (rapidly changing IPs)
    - Other suspicious DNS patterns

    Returns summary with top threats in each category.
    """
    if not log_store.dns_queries:
        raise HTTPException(
            status_code=400,
            detail="No DNS query data loaded. Please ingest DNS logs first."
        )

    logger.info(
        f"Running DNS threat analysis on {len(log_store.dns_queries)} queries "
        f"with thresholds: tunneling={tunneling_threshold}, dga={dga_threshold}, "
        f"fast_flux={fast_flux_threshold}"
    )

    # Initialize analyzer with parameters
    analyzer = DnsAnalyzer(
        tunneling_threshold=tunneling_threshold,
        dga_threshold=dga_threshold,
        fast_flux_threshold=fast_flux_threshold,
        min_queries_tunneling=min_queries_tunneling,
        min_queries_dga=min_queries_dga,
        min_queries_fast_flux=min_queries_fast_flux,
    )

    # Analyze all DNS queries
    summary = analyzer.analyze_dns_threats(log_store.dns_queries)

    logger.info(
        f"DNS threat analysis complete: {summary.tunneling_detections} tunneling, "
        f"{summary.dga_detections} DGA, {summary.fast_flux_detections} fast-flux, "
        f"{summary.other_patterns} other patterns"
    )

    return {
        "summary": summary.model_dump(),
        "parameters": {
            "tunneling_threshold": tunneling_threshold,
            "dga_threshold": dga_threshold,
            "fast_flux_threshold": fast_flux_threshold,
            "min_queries_tunneling": min_queries_tunneling,
            "min_queries_dga": min_queries_dga,
            "min_queries_fast_flux": min_queries_fast_flux,
        },
    }


@router.get("/dns/tunneling", response_model=dict)
async def get_dns_tunneling(
    min_score: float = Query(60.0, description="Minimum tunneling score", ge=0.0, le=100.0),
    min_queries: int = Query(10, description="Minimum query count", ge=3),
    limit: int = Query(100, description="Maximum results to return", ge=1, le=1000),
    offset: int = Query(0, description="Results offset for pagination", ge=0),
) -> dict:
    """
    Detect DNS tunneling patterns.

    DNS tunneling uses DNS queries/responses to exfiltrate data or establish
    C2 channels by encoding data in subdomains or TXT records.

    Detection based on:
    - High subdomain entropy (random/encoded data)
    - Long subdomain lengths
    - High query volume with unique subdomains
    - TXT record abuse
    - Excessive NXDOMAIN responses
    """
    if not log_store.dns_queries:
        raise HTTPException(
            status_code=400,
            detail="No DNS query data loaded. Please ingest DNS logs first."
        )

    logger.info(f"Detecting DNS tunneling with score_threshold={min_score}")

    # Initialize analyzer
    analyzer = DnsAnalyzer(
        tunneling_threshold=min_score,
        min_queries_tunneling=min_queries,
    )

    # Detect tunneling
    results = analyzer.detect_dns_tunneling(log_store.dns_queries)

    # Apply pagination
    total = len(results)
    results = results[offset:offset + limit]

    logger.info(f"Detected {total} DNS tunneling patterns, returning {len(results)} after pagination")

    return {
        "tunneling_detections": [r.model_dump() for r in results],
        "total": total,
        "returned": len(results),
        "offset": offset,
        "limit": limit,
        "parameters": {
            "min_score": min_score,
            "min_queries": min_queries,
        },
        "analysis_summary": {
            "total_queries_analyzed": len(log_store.dns_queries),
            "time_range": {
                "start": log_store.min_timestamp.isoformat() if log_store.min_timestamp else None,
                "end": log_store.max_timestamp.isoformat() if log_store.max_timestamp else None,
            },
        },
    }


@router.get("/dns/dga", response_model=dict)
async def get_dga_domains(
    min_score: float = Query(65.0, description="Minimum DGA score", ge=0.0, le=100.0),
    min_queries: int = Query(3, description="Minimum query count", ge=1),
    limit: int = Query(100, description="Maximum results to return", ge=1, le=1000),
    offset: int = Query(0, description="Results offset for pagination", ge=0),
) -> dict:
    """
    Detect DGA (Domain Generation Algorithm) domains.

    DGA domains are algorithmically generated by malware to evade blocklists
    and establish C2 communication.

    Detection based on:
    - High entropy (randomness)
    - Low bigram frequency (not English-like)
    - High consonant-to-vowel ratio
    - Digit presence
    - Suspicious TLDs
    - High NXDOMAIN rates
    """
    if not log_store.dns_queries:
        raise HTTPException(
            status_code=400,
            detail="No DNS query data loaded. Please ingest DNS logs first."
        )

    logger.info(f"Detecting DGA domains with score_threshold={min_score}")

    # Initialize analyzer
    analyzer = DnsAnalyzer(
        dga_threshold=min_score,
        min_queries_dga=min_queries,
    )

    # Detect DGA
    results = analyzer.detect_dga_domains(log_store.dns_queries)

    # Apply pagination
    total = len(results)
    results = results[offset:offset + limit]

    logger.info(f"Detected {total} DGA domains, returning {len(results)} after pagination")

    return {
        "dga_detections": [r.model_dump() for r in results],
        "total": total,
        "returned": len(results),
        "offset": offset,
        "limit": limit,
        "parameters": {
            "min_score": min_score,
            "min_queries": min_queries,
        },
        "analysis_summary": {
            "total_queries_analyzed": len(log_store.dns_queries),
            "time_range": {
                "start": log_store.min_timestamp.isoformat() if log_store.min_timestamp else None,
                "end": log_store.max_timestamp.isoformat() if log_store.max_timestamp else None,
            },
        },
    }


@router.get("/dns/fast-flux", response_model=dict)
async def get_fast_flux(
    min_score: float = Query(70.0, description="Minimum fast-flux score", ge=0.0, le=100.0),
    min_queries: int = Query(5, description="Minimum query count", ge=3),
    limit: int = Query(100, description="Maximum results to return", ge=1, le=1000),
    offset: int = Query(0, description="Results offset for pagination", ge=0),
) -> dict:
    """
    Detect fast-flux DNS patterns.

    Fast-flux DNS uses rapidly changing IP addresses to evade detection and
    make takedowns difficult. Common in botnets and malware infrastructure.

    Detection based on:
    - High number of unique IPs
    - Rapid IP change rate
    - Low TTL values
    - Geographic/ASN diversity
    """
    if not log_store.dns_queries:
        raise HTTPException(
            status_code=400,
            detail="No DNS query data loaded. Please ingest DNS logs first."
        )

    logger.info(f"Detecting fast-flux DNS with score_threshold={min_score}")

    # Initialize analyzer
    analyzer = DnsAnalyzer(
        fast_flux_threshold=min_score,
        min_queries_fast_flux=min_queries,
    )

    # Detect fast-flux
    results = analyzer.detect_fast_flux(log_store.dns_queries)

    # Apply pagination
    total = len(results)
    results = results[offset:offset + limit]

    logger.info(f"Detected {total} fast-flux patterns, returning {len(results)} after pagination")

    return {
        "fast_flux_detections": [r.model_dump() for r in results],
        "total": total,
        "returned": len(results),
        "offset": offset,
        "limit": limit,
        "parameters": {
            "min_score": min_score,
            "min_queries": min_queries,
        },
        "analysis_summary": {
            "total_queries_analyzed": len(log_store.dns_queries),
            "time_range": {
                "start": log_store.min_timestamp.isoformat() if log_store.min_timestamp else None,
                "end": log_store.max_timestamp.isoformat() if log_store.max_timestamp else None,
            },
        },
    }


@router.get("/dns/suspicious-patterns", response_model=dict)
async def get_suspicious_patterns(
    min_score: float = Query(60.0, description="Minimum suspicion score", ge=0.0, le=100.0),
    pattern_type: Optional[str] = Query(
        None,
        description="Filter by pattern type (excessive_nxdomain, unusual_query_types, high_query_rate)"
    ),
    limit: int = Query(100, description="Maximum results to return", ge=1, le=1000),
    offset: int = Query(0, description="Results offset for pagination", ge=0),
) -> dict:
    """
    Detect other suspicious DNS patterns.

    Includes:
    - Excessive NXDOMAIN responses (scanning/probing)
    - Unusual query types (reconnaissance)
    - High query rates to single domain (potential C2)
    """
    if not log_store.dns_queries:
        raise HTTPException(
            status_code=400,
            detail="No DNS query data loaded. Please ingest DNS logs first."
        )

    logger.info(f"Detecting suspicious DNS patterns with score_threshold={min_score}")

    # Initialize analyzer
    analyzer = DnsAnalyzer()

    # Detect patterns
    results = analyzer.detect_suspicious_patterns(log_store.dns_queries)

    # Filter by score
    results = [r for r in results if r.suspicion_score >= min_score]

    # Filter by pattern type if specified
    if pattern_type:
        results = [r for r in results if r.pattern_type == pattern_type]

    # Apply pagination
    total = len(results)
    results = results[offset:offset + limit]

    logger.info(f"Detected {total} suspicious patterns, returning {len(results)} after pagination")

    return {
        "suspicious_patterns": [r.model_dump() for r in results],
        "total": total,
        "returned": len(results),
        "offset": offset,
        "limit": limit,
        "parameters": {
            "min_score": min_score,
            "pattern_type": pattern_type,
        },
        "analysis_summary": {
            "total_queries_analyzed": len(log_store.dns_queries),
            "time_range": {
                "start": log_store.min_timestamp.isoformat() if log_store.min_timestamp else None,
                "end": log_store.max_timestamp.isoformat() if log_store.max_timestamp else None,
            },
        },
    }


@router.get("/dns/stats", response_model=dict)
async def get_dns_threat_stats() -> dict:
    """
    Get summary statistics about DNS threats.

    Returns aggregate statistics across all DNS threat categories
    without full detail.
    """
    if not log_store.dns_queries:
        raise HTTPException(
            status_code=400,
            detail="No DNS query data loaded. Please ingest DNS logs first."
        )

    logger.info("Calculating DNS threat statistics")

    # Run full analysis with default parameters
    analyzer = DnsAnalyzer()
    summary = analyzer.analyze_dns_threats(log_store.dns_queries)

    # Calculate severity breakdown for each category
    def count_by_severity(results, score_attr='tunneling_score'):
        critical = len([r for r in results if getattr(r, score_attr) >= 90])
        high = len([r for r in results if 80 <= getattr(r, score_attr) < 90])
        medium = len([r for r in results if 70 <= getattr(r, score_attr) < 80])
        low = len([r for r in results if 60 <= getattr(r, score_attr) < 70])
        return {"critical": critical, "high": high, "medium": medium, "low": low}

    # Top threats by category (just counts and IPs, not full details)
    top_tunneling = [
        {
            "domain": t.domain,
            "src_ip": t.src_ip,
            "score": round(t.tunneling_score, 1),
            "query_count": t.query_count,
            "avg_entropy": round(t.avg_subdomain_entropy, 2),
        }
        for t in summary.top_tunneling[:5]
    ]

    top_dga = [
        {
            "domain": d.domain,
            "src_ip": d.src_ip,
            "score": round(d.dga_score, 1),
            "entropy": round(d.domain_entropy, 2),
            "bigram_score": round(d.bigram_score, 1),
        }
        for d in summary.top_dga[:5]
    ]

    top_fast_flux = [
        {
            "domain": f.domain,
            "score": round(f.fast_flux_score, 1),
            "unique_ips": f.unique_ips,
            "ip_changes_per_hour": round(f.ip_changes_per_hour, 1),
        }
        for f in summary.top_fast_flux[:5]
    ]

    return {
        "summary": {
            "total_queries_analyzed": summary.total_queries_analyzed,
            "total_threats_detected": (
                summary.tunneling_detections +
                summary.dga_detections +
                summary.fast_flux_detections +
                summary.other_patterns
            ),
            "tunneling_detections": summary.tunneling_detections,
            "dga_detections": summary.dga_detections,
            "fast_flux_detections": summary.fast_flux_detections,
            "other_patterns": summary.other_patterns,
        },
        "by_category": {
            "tunneling": count_by_severity(summary.top_tunneling, 'tunneling_score'),
            "dga": count_by_severity(summary.top_dga, 'dga_score'),
            "fast_flux": count_by_severity(summary.top_fast_flux, 'fast_flux_score'),
        },
        "top_threats": {
            "tunneling": top_tunneling,
            "dga": top_dga,
            "fast_flux": top_fast_flux,
        },
        "analysis_metadata": {
            "analysis_duration_seconds": round(
                summary.analysis_end - summary.analysis_start, 2
            ),
            "data_time_range": {
                "start": summary.data_time_range_start,
                "end": summary.data_time_range_end,
            },
        },
    }
