"""
Workflow Router: PCAP upload-and-analyze pipeline.
"""
from typing import Optional
from fastapi import APIRouter, UploadFile, File, HTTPException, Query, Request

from api.middleware.rate_limit import check_rate_limit, record_upload

from api.services.workflow_manager import WorkflowManager

router = APIRouter()

_manager: Optional[WorkflowManager] = None


def _get_manager() -> WorkflowManager:
    global _manager
    if _manager is None:
        _manager = WorkflowManager()
    return _manager


def _serialize_job(job) -> dict:
    """Convert WorkflowJob to JSON-serializable dict."""
    return {
        "job_id": job.job_id,
        "filename": job.filename,
        "status": job.status.value,
        "progress": job.progress,
        "step": job.step,
        "created_at": job.created_at,
        "completed_at": job.completed_at,
        "error": job.error,
        "results": job.results,
    }


@router.post("/upload-and-analyze")
async def upload_and_analyze(request: Request, file: UploadFile = File(...)):
    """Upload a PCAP file and run the full analysis pipeline."""
    # Rate limit check
    blocked = check_rate_limit(request)
    if blocked:
        raise HTTPException(
            status_code=429,
            detail=blocked["detail"],
            headers={"Retry-After": str(blocked.get("retry_after", 3600))},
        )

    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    # Validate file extension
    valid_exts = (".pcap", ".pcapng", ".cap")
    if not any(file.filename.lower().endswith(ext) for ext in valid_exts):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Accepted: {', '.join(valid_exts)}"
        )

    # Stream file data with size limit enforcement
    max_size = 100 * 1024 * 1024
    chunks = []
    total = 0
    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_size:
            raise HTTPException(status_code=413, detail="File exceeds 100MB limit")
        chunks.append(chunk)
    data = b"".join(chunks)

    manager = _get_manager()
    job = manager.create_job(file.filename, data)
    record_upload(request)
    return _serialize_job(job)


@router.get("/status/{job_id}")
async def get_job_status(job_id: str):
    """Get the status and progress of a workflow job."""
    manager = _get_manager()
    job = manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _serialize_job(job)


@router.get("/jobs")
async def list_jobs(limit: int = Query(default=20, ge=1, le=100)):
    """List recent workflow jobs."""
    manager = _get_manager()
    jobs = manager.list_jobs(limit=limit)
    return {"jobs": [_serialize_job(j) for j in jobs]}
