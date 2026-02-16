"""Baseline profiling API endpoints."""
from fastapi import APIRouter

from api.services.log_store import log_store
from api.services.baseline_profiler import BaselineProfiler

router = APIRouter()

_baseline_profiler = BaselineProfiler(log_store)


@router.post("/build")
async def build_baseline():
    """Build and persist a baseline profile from currently loaded logs."""
    baseline = _baseline_profiler.build_baseline()
    return {"status": "ok", "baseline": baseline}


@router.get("")
async def get_baseline():
    """Return the currently active baseline profile."""
    baseline = _baseline_profiler.current_baseline or _baseline_profiler._load_from_disk()
    if not baseline:
        return {"status": "no_baseline", "baseline": None}
    return {"status": "ok", "baseline": baseline}


@router.post("/compare")
async def compare_baseline():
    """Compare current traffic against baseline and return deviations."""
    return _baseline_profiler.compare_against_baseline()
