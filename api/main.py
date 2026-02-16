"""
Bro Hunter API - FastAPI application entry point.
Provides REST endpoints for network log analysis and threat hunting.
"""
import os
import sys
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.config import settings
from api.routers import analysis, logs, ingest, data, hunt, dns_threat, export, sessions, scoring, intel, reports, analytics, capture, workflow, search, packets, baseline, anomalies, cases, bundles, rules, sigma
from api.routers import settings as settings_router
from api.services.log_store import log_store
from api.services.demo_data import DemoDataService

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Production safety check: refuse to start without an API key in production
# ---------------------------------------------------------------------------
_env = os.environ.get("BROHUNTER_ENV", "development").lower()
if _env == "production" and not settings.api_key:
    logger.critical(
        "FATAL: BROHUNTER_ENV is 'production' but BROHUNTER_API_KEY is not set. "
        "Refusing to start without authentication. "
        "Set BROHUNTER_API_KEY to a secure random value."
    )
    sys.exit(1)

if not settings.api_key:
    logger.warning(
        "BROHUNTER_API_KEY is not set — authentication is disabled (dev mode). "
        "Set BROHUNTER_ENV=production and BROHUNTER_API_KEY for production use."
    )


# Initialize FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Network threat hunting and analysis platform for Zeek (Bro) and Suricata logs",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/status")
async def root():
    """API status endpoint."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "operational",
        "demo_mode": getattr(settings, "demo_mode", False),
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


# Include routers
app.include_router(logs.router, prefix=f"{settings.api_prefix}/logs", tags=["logs"])
app.include_router(
    analysis.router, prefix=f"{settings.api_prefix}/analysis", tags=["analysis"]
)
app.include_router(ingest.router, prefix=f"{settings.api_prefix}/ingest", tags=["ingest"])
app.include_router(data.router, prefix=f"{settings.api_prefix}/data", tags=["data"])
app.include_router(hunt.router, prefix=f"{settings.api_prefix}/hunt", tags=["hunt"])
app.include_router(dns_threat.router, prefix=f"{settings.api_prefix}/hunt", tags=["dns-threats"])
app.include_router(export.router, prefix=f"{settings.api_prefix}/export", tags=["export"])
app.include_router(sessions.router, prefix=f"{settings.api_prefix}/sessions", tags=["sessions"])
app.include_router(scoring.router, prefix=f"{settings.api_prefix}/scoring", tags=["scoring"])
app.include_router(intel.router, prefix=f"{settings.api_prefix}/intel", tags=["intel"])
app.include_router(reports.router, prefix=f"{settings.api_prefix}/reports", tags=["reports"])
app.include_router(cases.router, prefix=f"{settings.api_prefix}/cases", tags=["cases"])
app.include_router(bundles.router, prefix=f"{settings.api_prefix}/cases", tags=["bundles"])
app.include_router(analytics.router, prefix=f"{settings.api_prefix}/analytics", tags=["analytics"])
app.include_router(capture.router, prefix=f"{settings.api_prefix}/capture", tags=["capture"])
app.include_router(workflow.router, prefix=f"{settings.api_prefix}/workflow", tags=["workflow"])
app.include_router(settings_router.router, prefix=f"{settings.api_prefix}/settings", tags=["settings"])
app.include_router(search.router, prefix=f"{settings.api_prefix}/search", tags=["search"])
app.include_router(packets.router, prefix=f"{settings.api_prefix}/packets", tags=["packets"])
app.include_router(baseline.router, prefix=f"{settings.api_prefix}/baseline", tags=["baseline"])
app.include_router(anomalies.router, prefix=f"{settings.api_prefix}/anomalies", tags=["anomalies"])
app.include_router(rules.router, prefix=f"{settings.api_prefix}/rules", tags=["rules"])
app.include_router(sigma.router, prefix=f"{settings.api_prefix}/sigma", tags=["sigma"])


@app.on_event("startup")
async def bootstrap_demo_data():
    """Auto-load bundled sanitized demo data when BROHUNTER_DEMO_MODE=true."""
    if getattr(settings, "demo_mode", False):
        stats = DemoDataService().load_into_store(log_store)
        logger.info("Demo mode enabled. Loaded demo dataset: %s", stats)


# Serve frontend static files in production
_frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "dist")
if os.path.isdir(_frontend_dir):
    from fastapi.responses import FileResponse

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        """Serve frontend SPA — all non-API routes fall through to index.html."""
        file_path = os.path.join(_frontend_dir, full_path)
        if full_path and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(_frontend_dir, "index.html"))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
