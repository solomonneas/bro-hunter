"""Host ranking and deep-dive analytics endpoints."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.encoders import jsonable_encoder

from api.services.log_store import log_store
from api.services.unified_threat_engine import UnifiedThreatEngine
from api.services.beacon_analyzer import BeaconAnalyzer
from api.services.long_connection_analyzer import LongConnectionAnalyzer
from api.services.session_reconstructor import SessionReconstructor

router = APIRouter()


def _to_epoch(ts: Any) -> Optional[float]:
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, datetime):
        return ts.timestamp()
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except Exception:
            return None
    if hasattr(ts, "timestamp"):
        try:
            return float(ts.timestamp())
        except Exception:
            return None
    return None


def _to_iso(ts: Any) -> Optional[str]:
    epoch = _to_epoch(ts)
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch).isoformat()


def _fmt_duration(seconds: Optional[float]) -> str:
    if not seconds or seconds <= 0:
        return "0s"
    total = int(seconds)
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


@router.get("/ranking")
async def host_ranking(
    severity: Optional[str] = Query(default=None, description="Filter by threat level"),
    limit: int = Query(default=50, ge=1, le=500),
):
    engine = UnifiedThreatEngine(log_store)
    profiles = list(engine.analyze_all().values())

    if severity:
        sev = severity.lower()
        profiles = [p for p in profiles if p.threat_level.value.lower() == sev]

    profiles.sort(key=lambda p: p.score, reverse=True)
    profiles = profiles[:limit]

    return {
        "hosts": [
            {
                "ip": p.ip,
                "score": round(float(p.score), 4),
                "threat_level": p.threat_level.value,
                "confidence": round(float(p.confidence), 4),
                "beacon_count": p.beacon_count,
                "dns_threat_count": p.dns_threat_count,
                "alert_count": p.alert_count,
                "long_connection_count": p.long_connection_count,
                "mitre_techniques": sorted(list(p.mitre_techniques)),
                "attack_summary": p.attack_summary,
            }
            for p in profiles
        ]
    }


@router.get("/{ip}/deep-dive")
async def host_deep_dive(ip: str):
    engine = UnifiedThreatEngine(log_store)
    profiles = engine.analyze_all()
    profile = profiles.get(ip)

    outbound = [c for c in log_store.connections if c.src_ip == ip]
    inbound = [c for c in log_store.connections if c.dst_ip == ip]
    dns_queries = [q for q in log_store.dns_queries if q.src_ip == ip]
    alerts = [a for a in log_store.alerts if a.src_ip == ip or a.dst_ip == ip]

    if not any([profile, outbound, inbound, dns_queries, alerts]):
        raise HTTPException(status_code=404, detail=f"Host not found: {ip}")

    beacons = BeaconAnalyzer().analyze_connections(log_store.connections)
    host_beacons = [b for b in beacons if b.src_ip == ip or b.dst_ip == ip]

    long_connections = LongConnectionAnalyzer().analyze_connections(log_store.connections)
    host_long_connections = [
        lc for lc in long_connections
        if lc.connection.src_ip == ip or lc.connection.dst_ip == ip
    ]

    sessions = SessionReconstructor(log_store).reconstruct_all()
    host_sessions = [s for s in sessions if s.src_ip == ip or s.dst_ip == ip]

    timeline: list[dict[str, Any]] = []

    for conn in outbound:
        timeline.append({
            "timestamp": _to_epoch(conn.timestamp),
            "type": "connection_outbound",
            "description": f"Outbound {conn.proto} to {conn.dst_ip}:{conn.dst_port}",
            "severity": "info",
        })
    for conn in inbound:
        timeline.append({
            "timestamp": _to_epoch(conn.timestamp),
            "type": "connection_inbound",
            "description": f"Inbound {conn.proto} from {conn.src_ip}:{conn.src_port}",
            "severity": "info",
        })

    for q in dns_queries:
        timeline.append({
            "timestamp": _to_epoch(q.timestamp),
            "type": "dns",
            "description": f"DNS {q.qtype or 'A'} query: {q.query}",
            "severity": "low",
        })

    for a in alerts:
        sev = "critical" if a.severity <= 1 else "high" if a.severity == 2 else "medium"
        timeline.append({
            "timestamp": _to_epoch(a.timestamp),
            "type": "alert",
            "description": f"{a.signature} ({a.category})",
            "severity": sev,
        })

    for b in host_beacons:
        sev = "critical" if b.beacon_score >= 90 else "high" if b.beacon_score >= 75 else "medium"
        timeline.append({
            "timestamp": _to_epoch(b.first_seen),
            "type": "beacon",
            "description": f"Beacon pattern to {b.dst_ip}:{b.dst_port} (score {b.beacon_score:.1f})",
            "severity": sev,
        })

    for lc in host_long_connections:
        sev = lc.threat_level.value if hasattr(lc.threat_level, "value") else str(lc.threat_level)
        timeline.append({
            "timestamp": _to_epoch(lc.connection.timestamp),
            "type": "long_connection",
            "description": f"Long connection {lc.connection.src_ip} → {lc.connection.dst_ip}:{lc.connection.dst_port} ({lc.duration_seconds:.0f}s)",
            "severity": sev,
        })

    if profile:
        for event in profile.attack_timeline:
            event_score = float(event.get("score", 0) or 0)
            sev = "critical" if event_score >= 0.8 else "high" if event_score >= 0.6 else "medium" if event_score >= 0.4 else "low"
            timeline.append({
                "timestamp": _to_epoch(event.get("timestamp")),
                "type": event.get("type", "threat"),
                "description": event.get("description", "Threat activity"),
                "severity": sev,
            })

    timeline = [t for t in timeline if t.get("timestamp") is not None]
    timeline.sort(key=lambda x: x["timestamp"])

    risk_timeline = [
        {
            "timestamp": _to_iso(item["timestamp"]),
            "type": item["type"],
            "description": item["description"],
            "severity": item["severity"],
        }
        for item in timeline
    ]

    host_connections = outbound + inbound
    total_bytes_sent = sum((c.bytes_sent or 0) for c in outbound)
    total_bytes_received = sum((c.bytes_recv or 0) for c in inbound)
    unique_destinations = len(set(c.dst_ip for c in outbound))
    unique_sources = len(set(c.src_ip for c in inbound))
    protocols = sorted(set((c.proto or "unknown") for c in host_connections))

    all_timestamps = [_to_epoch(c.timestamp) for c in host_connections]
    all_timestamps.extend(_to_epoch(q.timestamp) for q in dns_queries)
    all_timestamps.extend(_to_epoch(a.timestamp) for a in alerts)
    all_timestamps = [t for t in all_timestamps if t is not None]

    first_seen = min(all_timestamps) if all_timestamps else None
    last_seen = max(all_timestamps) if all_timestamps else None

    return {
        "ip": ip,
        "threat_profile": jsonable_encoder(profile) if profile else None,
        "connections": {
            "outbound": jsonable_encoder(outbound),
            "inbound": jsonable_encoder(inbound),
        },
        "dns_queries": jsonable_encoder(dns_queries),
        "alerts": jsonable_encoder(alerts),
        "beacons": jsonable_encoder(host_beacons),
        "long_connections": jsonable_encoder(host_long_connections),
        "sessions": jsonable_encoder(host_sessions),
        "risk_timeline": risk_timeline,
        "statistics": {
            "total_bytes_sent": total_bytes_sent,
            "total_bytes_received": total_bytes_received,
            "unique_destinations": unique_destinations,
            "unique_sources": unique_sources,
            "protocols": protocols,
            "first_seen": _to_iso(first_seen),
            "last_seen": _to_iso(last_seen),
            "active_duration": _fmt_duration((last_seen - first_seen) if first_seen and last_seen else 0),
        },
    }
