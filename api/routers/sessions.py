"""
Sessions Router - Reconstructed network session endpoints.
"""
from typing import Optional
from fastapi import APIRouter, Query, HTTPException

from api.services.log_store import LogStore
from api.services.session_reconstructor import SessionReconstructor

router = APIRouter()

_log_store: Optional[LogStore] = None


def set_log_store(store: LogStore):
    global _log_store
    _log_store = store


def _get_reconstructor() -> SessionReconstructor:
    if _log_store is None:
        from api.services.log_store import LogStore
        return SessionReconstructor(LogStore())
    return SessionReconstructor(_log_store)


@router.get("")
async def list_sessions(
    sort_by: str = Query("start_time", regex="^(start_time|duration|bytes|threat_score|connections)$"),
    order: str = Query("desc", regex="^(asc|desc)$"),
    min_threat: str = Query("info", regex="^(info|low|medium|high|critical)$"),
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List reconstructed network sessions."""
    reconstructor = _get_reconstructor()
    sessions = reconstructor.reconstruct_all()

    # Filter by minimum threat level
    threat_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_level = threat_order.get(min_threat, 0)
    sessions = [s for s in sessions if threat_order.get(s.threat_level, 0) >= min_level]

    # Filter by IP
    if src_ip:
        sessions = [s for s in sessions if s.src_ip == src_ip or s.dst_ip == src_ip]
    if dst_ip:
        sessions = [s for s in sessions if s.dst_ip == dst_ip or s.src_ip == dst_ip]

    # Sort
    sort_keys = {
        "start_time": lambda s: s.start_time,
        "duration": lambda s: s.duration_seconds,
        "bytes": lambda s: s.total_bytes_sent + s.total_bytes_recv,
        "threat_score": lambda s: s.threat_score,
        "connections": lambda s: s.connection_count,
    }
    sessions.sort(key=sort_keys.get(sort_by, sort_keys["start_time"]), reverse=(order == "desc"))

    total = len(sessions)
    page = sessions[offset:offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "sessions": [_serialize_session(s, include_events=False) for s in page],
    }


@router.get("/{session_id}")
async def get_session(session_id: str):
    """Get a specific session with full event timeline."""
    reconstructor = _get_reconstructor()
    session = reconstructor.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return _serialize_session(session, include_events=True)


def _serialize_session(session, include_events: bool = False) -> dict:
    """Serialize a session to JSON-safe dict."""
    result = {
        "session_id": session.session_id,
        "src_ip": session.src_ip,
        "dst_ip": session.dst_ip,
        "start_time": session.start_time,
        "end_time": session.end_time,
        "duration_seconds": round(session.duration_seconds, 1),
        "total_bytes_sent": session.total_bytes_sent,
        "total_bytes_recv": session.total_bytes_recv,
        "total_bytes": session.total_bytes_sent + session.total_bytes_recv,
        "connection_count": session.connection_count,
        "dns_query_count": session.dns_query_count,
        "alert_count": session.alert_count,
        "protocols": session.protocols,
        "services": session.services,
        "ports": session.ports,
        "threat_score": round(session.threat_score, 3),
        "threat_level": session.threat_level,
        "flags": session.flags,
    }

    if include_events:
        result["events"] = [
            {
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "summary": e.summary,
                "details": e.details,
                "severity": e.severity,
            }
            for e in session.events
        ]
        result["event_count"] = len(session.events)

    return result
