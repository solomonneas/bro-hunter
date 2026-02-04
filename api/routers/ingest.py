"""
Ingest router for loading log files into Hunter.
Provides endpoints for loading directories of Zeek and Suricata logs.
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional
import logging

from api.services.log_store import log_store

logger = logging.getLogger(__name__)

router = APIRouter()


class IngestDirectoryRequest(BaseModel):
    """Request model for directory ingestion."""

    path: str = Field(..., description="Absolute path to directory containing log files")


class IngestDirectoryResponse(BaseModel):
    """Response model for directory ingestion."""

    success: bool = Field(..., description="Whether ingestion succeeded")
    message: str = Field(..., description="Status message")
    stats: dict = Field(..., description="Ingestion statistics")


class IngestStats(BaseModel):
    """Detailed ingestion statistics."""

    file_count: int = Field(..., description="Number of files processed")
    record_count: int = Field(..., description="Total records loaded")
    time_range: tuple[Optional[str], Optional[str]] = Field(
        ..., description="Time range of loaded logs (min, max)"
    )
    unique_src_ips: int = Field(..., description="Number of unique source IPs")
    unique_dst_ips: int = Field(..., description="Number of unique destination IPs")
    connections: int = Field(..., description="Number of connections loaded")
    dns_queries: int = Field(..., description="Number of DNS queries loaded")
    alerts: int = Field(..., description="Number of alerts loaded")


@router.post(
    "/directory",
    response_model=IngestDirectoryResponse,
    summary="Ingest log directory",
    description="Load all Zeek and Suricata log files from a directory into memory for analysis",
)
async def ingest_directory(request: IngestDirectoryRequest) -> IngestDirectoryResponse:
    """
    Load log files from a directory.

    This endpoint:
    1. Clears existing data
    2. Scans directory for Zeek (*.log.json) and Suricata (eve.json) files
    3. Parses and loads all supported log types
    4. Returns summary statistics

    Args:
        request: Directory path to ingest

    Returns:
        Ingestion summary with file count, record count, time range, and unique IPs

    Raises:
        HTTPException: If directory not found or ingestion fails
    """
    try:
        logger.info(f"Starting directory ingestion: {request.path}")

        # Load directory
        stats = log_store.load_directory(request.path)

        logger.info(f"Ingestion complete: {stats}")

        return IngestDirectoryResponse(
            success=True,
            message=f"Successfully loaded {stats['file_count']} files with {stats['record_count']} records",
            stats=stats,
        )

    except FileNotFoundError as e:
        logger.error(f"Directory not found: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    except ValueError as e:
        logger.error(f"Invalid directory path: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    except Exception as e:
        logger.error(f"Ingestion failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ingestion failed: {str(e)}",
        )


@router.post(
    "/clear",
    summary="Clear log store",
    description="Clear all loaded logs from memory",
)
async def clear_logs() -> dict:
    """
    Clear all loaded logs from the in-memory store.

    Returns:
        Success message
    """
    try:
        log_store.clear()
        logger.info("Log store cleared")

        return {
            "success": True,
            "message": "Log store cleared successfully",
        }

    except Exception as e:
        logger.error(f"Failed to clear log store: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clear logs: {str(e)}",
        )


@router.get(
    "/status",
    summary="Get ingestion status",
    description="Get current status of the log store (loaded data summary)",
)
async def get_status() -> dict:
    """
    Get current log store status.

    Returns:
        Dictionary with store statistics
    """
    time_range = log_store.get_time_range()

    return {
        "loaded": log_store.total_records > 0,
        "file_count": log_store.file_count,
        "total_records": log_store.total_records,
        "connections": len(log_store.connections),
        "dns_queries": len(log_store.dns_queries),
        "alerts": len(log_store.alerts),
        "time_range": {
            "start": time_range[0].isoformat() if time_range[0] else None,
            "end": time_range[1].isoformat() if time_range[1] else None,
        },
        "unique_ips": {
            "sources": len(log_store._src_ip_index),
            "destinations": len(log_store._dst_ip_index),
        },
    }
