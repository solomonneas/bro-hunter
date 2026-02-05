"""
Hunter API - FastAPI application entry point.
Provides REST endpoints for network log analysis and threat hunting.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.config import settings
from api.routers import analysis, logs, ingest, data, hunt


# Initialize FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Network threat hunting and analysis platform for Zeek and Suricata logs",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Root endpoint - API health check."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "operational",
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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
