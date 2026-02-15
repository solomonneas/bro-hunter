"""
Dashboard Analytics Router - Trend charts, top talkers, protocol breakdown, attack heatmap.
"""
from typing import Optional
from collections import defaultdict
from datetime import datetime, timezone
from fastapi import APIRouter, Query

from api.services.log_store import LogStore
from api.services.unified_threat_engine import UnifiedThreatEngine

router = APIRouter()

_log_store: Optional[LogStore] = None


def set_log_store(store: LogStore):
    global _log_store
    _log_store = store


def _get_store() -> LogStore:
    if _log_store is None:
        return LogStore()
    return _log_store


@router.get("/top-talkers")
async def top_talkers(limit: int = Query(10, ge=1, le=50)):
    """Get top N hosts by total bytes transferred."""
    store = _get_store()
    host_bytes: dict = defaultdict(lambda: {"sent": 0, "recv": 0, "connections": 0})

    for conn in store.connections:
        host_bytes[conn.src_ip]["sent"] += conn.bytes_sent or 0
        host_bytes[conn.src_ip]["recv"] += conn.bytes_recv or 0
        host_bytes[conn.src_ip]["connections"] += 1

    sorted_hosts = sorted(
        host_bytes.items(),
        key=lambda x: x[1]["sent"] + x[1]["recv"],
        reverse=True,
    )[:limit]

    return {
        "top_talkers": [
            {
                "ip": ip,
                "bytes_sent": data["sent"],
                "bytes_recv": data["recv"],
                "total_bytes": data["sent"] + data["recv"],
                "connections": data["connections"],
            }
            for ip, data in sorted_hosts
        ]
    }


@router.get("/protocol-breakdown")
async def protocol_breakdown():
    """Get connection count and bytes by protocol."""
    store = _get_store()
    protos: dict = defaultdict(lambda: {"count": 0, "bytes": 0})

    for conn in store.connections:
        proto = conn.proto or "unknown"
        protos[proto]["count"] += 1
        protos[proto]["bytes"] += (conn.bytes_sent or 0) + (conn.bytes_recv or 0)

    return {
        "protocols": [
            {"protocol": p, "connections": d["count"], "total_bytes": d["bytes"]}
            for p, d in sorted(protos.items(), key=lambda x: x[1]["count"], reverse=True)
        ]
    }


@router.get("/service-breakdown")
async def service_breakdown():
    """Get connection count by detected service."""
    store = _get_store()
    services: dict = defaultdict(int)

    for conn in store.connections:
        svc = conn.service or "unknown"
        services[svc] += 1

    return {
        "services": [
            {"service": s, "count": c}
            for s, c in sorted(services.items(), key=lambda x: x[1], reverse=True)
        ]
    }


@router.get("/traffic-timeline")
async def traffic_timeline(bucket_minutes: int = Query(5, ge=1, le=60)):
    """Get traffic volume over time in buckets."""
    store = _get_store()
    bucket_seconds = bucket_minutes * 60
    buckets: dict = defaultdict(lambda: {"connections": 0, "bytes": 0, "alerts": 0})

    for conn in store.connections:
        if conn.timestamp:
            bucket_ts = int(conn.timestamp / bucket_seconds) * bucket_seconds
            buckets[bucket_ts]["connections"] += 1
            buckets[bucket_ts]["bytes"] += (conn.bytes_sent or 0) + (conn.bytes_recv or 0)

    for alert in store.alerts:
        ts = alert.timestamp or 0.0
        if ts:
            bucket_ts = int(ts / bucket_seconds) * bucket_seconds
            buckets[bucket_ts]["alerts"] += 1

    sorted_buckets = sorted(buckets.items())

    return {
        "bucket_minutes": bucket_minutes,
        "timeline": [
            {
                "timestamp": ts,
                "time": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                "connections": data["connections"],
                "bytes": data["bytes"],
                "alerts": data["alerts"],
            }
            for ts, data in sorted_buckets
        ],
    }


@router.get("/threat-heatmap")
async def threat_heatmap():
    """Get a src_ip x dst_ip heatmap of threat scores."""
    store = _get_store()
    engine = UnifiedThreatEngine(store)
    profiles = engine.analyze_all()

    # Build IP pair threat data
    pairs: dict = defaultdict(lambda: {"score": 0.0, "connections": 0, "alerts": 0})

    for conn in store.connections:
        key = f"{conn.src_ip}|{conn.dst_ip}"
        pairs[key]["connections"] += 1

    for alert in store.alerts:
        key = f"{alert.src_ip}|{alert.dest_ip}"
        pairs[key]["alerts"] += 1

    # Enhance with threat scores
    for key in pairs:
        src_ip = key.split("|")[0]
        if src_ip in profiles:
            pairs[key]["score"] = max(pairs[key]["score"], profiles[src_ip].score)

    # Return top 50 pairs by score
    sorted_pairs = sorted(pairs.items(), key=lambda x: x[1]["score"], reverse=True)[:50]

    return {
        "heatmap": [
            {
                "src_ip": pair.split("|")[0],
                "dst_ip": pair.split("|")[1],
                "threat_score": round(data["score"], 3),
                "connections": data["connections"],
                "alerts": data["alerts"],
            }
            for pair, data in sorted_pairs
        ]
    }


@router.get("/geo-summary")
async def geo_summary():
    """Get summary statistics for the loaded dataset."""
    store = _get_store()

    unique_src = set(c.src_ip for c in store.connections)
    unique_dst = set(c.dst_ip for c in store.connections)
    unique_domains = set(q.query for q in store.dns_queries if q.query)

    time_range = store.get_time_range() if hasattr(store, "get_time_range") else None

    return {
        "connections": len(store.connections),
        "dns_queries": len(store.dns_queries),
        "alerts": len(store.alerts),
        "unique_source_ips": len(unique_src),
        "unique_dest_ips": len(unique_dst),
        "unique_domains": len(unique_domains),
        "time_range": {
            "start": time_range[0] if time_range else None,
            "end": time_range[1] if time_range else None,
        } if time_range else None,
    }
