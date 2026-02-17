"""Anomaly detection API endpoints."""
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status

from api.dependencies.auth import api_key_auth
from api.services.log_store import log_store
from api.services.baseline_profiler import BaselineProfiler
from api.services.anomaly_detector import AnomalyDetector

router = APIRouter()

_baseline_profiler = BaselineProfiler(log_store)
_anomaly_detector = AnomalyDetector(log_store, _baseline_profiler)


@router.post("/detect")
async def detect_anomalies(_: Annotated[str, Depends(api_key_auth)] = ""):
    """Run anomaly detection over currently loaded traffic."""
    return _anomaly_detector.detect()


@router.get("")
async def list_anomalies():
    """List anomalies from the latest detection run."""
    anomalies = _anomaly_detector.list_anomalies()
    return {
        "total": len(anomalies),
        "anomalies": anomalies,
    }


@router.get("/{anomaly_id}")
async def get_anomaly(anomaly_id: str):
    """Get details for a specific anomaly."""
    anomaly = _anomaly_detector.get_anomaly(anomaly_id)
    if not anomaly:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly not found")
    return anomaly
