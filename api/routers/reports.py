"""
Report Generation Router - Threat assessment reports in JSON and HTML.
"""
from typing import Optional
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import HTMLResponse

from api.services.log_store import LogStore, log_store
from api.services.report_generator import ReportGenerator

router = APIRouter()


@router.get("/json")
async def report_json():
    """Generate a JSON threat assessment report."""
    if not log_store.connections and not log_store.dns_queries and not log_store.alerts:
        raise HTTPException(status_code=400, detail="No data loaded. Ingest logs first.")
    generator = ReportGenerator(log_store)
    return generator.generate_json()


@router.get("/html")
async def report_html():
    """Generate an HTML threat assessment report (viewable in browser)."""
    if not log_store.connections and not log_store.dns_queries and not log_store.alerts:
        raise HTTPException(status_code=400, detail="No data loaded. Ingest logs first.")
    generator = ReportGenerator(log_store)
    html_content = generator.generate_html()
    return HTMLResponse(content=html_content)
