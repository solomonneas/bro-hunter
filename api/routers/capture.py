"""
Live Capture Router - Start/stop/manage packet capture sessions.
"""
import time
from typing import Optional
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel

from api.services.live_capture import LiveCaptureService

router = APIRouter()

_capture_service: Optional[LiveCaptureService] = None


def _get_service() -> LiveCaptureService:
    global _capture_service
    if _capture_service is None:
        _capture_service = LiveCaptureService()
    return _capture_service


class StartCaptureRequest(BaseModel):
    interface: str = "any"
    filter: str = ""
    max_packets: int = 10000
    max_seconds: int = 300


@router.get("/interfaces")
async def list_interfaces():
    """List available network interfaces for capture."""
    service = _get_service()
    return {"interfaces": service.get_interfaces()}


@router.post("/start")
async def start_capture(req: StartCaptureRequest):
    """Start a live packet capture session."""
    service = _get_service()

    # Limit concurrent captures
    active = [s for s in service.list_sessions() if s.status == "running"]
    if len(active) >= 3:
        raise HTTPException(status_code=429, detail="Max 3 concurrent captures. Stop one first.")

    session = service.start_capture(
        interface=req.interface,
        capture_filter=req.filter,
        max_packets=req.max_packets,
        max_seconds=req.max_seconds,
    )

    return _serialize_session(session)


@router.post("/stop/{session_id}")
async def stop_capture(session_id: str):
    """Stop a running capture session."""
    service = _get_service()
    session = service.stop_capture(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Capture session not found")
    return _serialize_session(session)


@router.get("/sessions")
async def list_captures():
    """List all capture sessions."""
    service = _get_service()
    sessions = service.list_sessions()
    return {
        "sessions": [_serialize_session(s) for s in sessions],
        "active_count": sum(1 for s in sessions if s.status == "running"),
    }


@router.get("/sessions/{session_id}")
async def get_capture(session_id: str):
    """Get details of a specific capture session."""
    service = _get_service()
    session = service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Capture session not found")
    return _serialize_session(session)


@router.post("/ingest/{session_id}")
async def ingest_capture(session_id: str):
    """Ingest a stopped capture into the analysis pipeline (uses existing PCAP ingest)."""
    service = _get_service()
    session = service.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Capture session not found")
    if session.status == "running":
        raise HTTPException(status_code=400, detail="Stop the capture first")

    pcap_path = service.get_pcap_path(session_id)
    if not pcap_path:
        raise HTTPException(status_code=404, detail="PCAP file not found")

    # Return the path for the frontend to call /api/ingest/pcap
    return {
        "session_id": session_id,
        "pcap_path": pcap_path,
        "file_size_bytes": session.file_size_bytes,
        "packet_count": session.packet_count,
        "message": "Use POST /api/v1/ingest/pcap with this file to analyze",
    }


@router.delete("/sessions/{session_id}")
async def delete_capture(session_id: str):
    """Delete a capture session and its files."""
    service = _get_service()
    session = service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Capture session not found")
    if session.status == "running":
        service.stop_capture(session_id)
    service.cleanup(session_id)
    return {"message": "Capture session deleted", "session_id": session_id}


def _serialize_session(session) -> dict:
    return {
        "session_id": session.session_id,
        "interface": session.interface,
        "capture_filter": session.capture_filter,
        "started_at": session.started_at,
        "stopped_at": session.stopped_at,
        "duration_seconds": round(
            (session.stopped_at or time.time()) - session.started_at, 1
        ) if session.started_at else 0,
        "pcap_path": session.pcap_path,
        "packet_count": session.packet_count,
        "file_size_bytes": session.file_size_bytes,
        "status": session.status,
        "pid": session.pid,
        "error": session.error,
    }


