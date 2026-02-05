"""
Ingest router for loading log files into Bro Hunter.
Provides endpoints for loading directories of Zeek and Suricata logs.
"""
from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel, Field
from pathlib import Path
from typing import Optional, Annotated
import logging
import os

from api.services.log_store import log_store
from api.dependencies.auth import api_key_auth
from api.config import settings

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


def _validate_path(path: str) -> Path:
    """
    Validate and normalize path to prevent directory traversal attacks.

    Args:
        path: User-provided path string

    Returns:
        Normalized Path object

    Raises:
        HTTPException: If path is outside allowed root or is a symlink
    """
    # Resolve to absolute path, following symlinks
    resolved = Path(path).resolve()

    # Check if it's a symlink (security: could point outside allowed root)
    if Path(path).is_symlink():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Symbolic links are not allowed for security reasons",
        )

    # If log root is configured, enforce it
    if settings.log_root:
        log_root = Path(settings.log_root).resolve()

        # Ensure path is within allowed root
        try:
            resolved.relative_to(log_root)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: path must be within {log_root}",
            )

    return resolved


@router.post(
    "/directory",
    response_model=IngestDirectoryResponse,
    summary="Ingest log directory",
    description="Load all Zeek and Suricata log files from a directory into memory for analysis",
)
async def ingest_directory(
    request: IngestDirectoryRequest,
    _: Annotated[str, Depends(api_key_auth)],
) -> IngestDirectoryResponse:
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
        # Validate path to prevent traversal attacks
        validated_path = _validate_path(request.path)
        logger.info(f"Starting directory ingestion: {validated_path}")

        # Load directory
        stats = log_store.load_directory(str(validated_path))

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
async def clear_logs(
    _: Annotated[str, Depends(api_key_auth)],
) -> dict:
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
async def get_status(
    _: Annotated[str, Depends(api_key_auth)],
) -> dict:
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
