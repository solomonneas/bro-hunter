"""
Report Generation Router - Threat assessment reports in JSON and HTML.
"""
from typing import Optional
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import HTMLResponse

from api.services.log_store import LogStore
from api.services.report_generator import ReportGenerator

router = APIRouter()

_log_store: Optional[LogStore] = None


def set_log_store(store: LogStore):
    global _log_store
    _log_store = store


@router.get("/json")
async def report_json():
    """Generate a JSON threat assessment report."""
    if _log_store is None:
        raise HTTPException(status_code=400, detail="No data loaded. Ingest logs first.")
    generator = ReportGenerator(_log_store)
    return generator.generate_json()


@router.get("/html")
async def report_html():
    """Generate an HTML threat assessment report (viewable in browser)."""
    if _log_store is None:
        raise HTTPException(status_code=400, detail="No data loaded. Ingest logs first.")
    generator = ReportGenerator(_log_store)
    html_content = generator.generate_html()
    return HTMLResponse(content=html_content)
