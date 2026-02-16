"""Tests for workflow manager service."""
import pytest
from unittest.mock import patch, MagicMock

from api.services.workflow_manager import WorkflowManager, JobStatus


@pytest.fixture(autouse=True)
def _no_pipeline(monkeypatch):
    """Prevent tests from spawning real pipeline threads."""
    monkeypatch.setattr(WorkflowManager, "_run_pipeline", lambda self, job_id: None)


class TestWorkflowManager:
    def test_init(self):
        manager = WorkflowManager()
        assert isinstance(manager._jobs, dict)
        assert len(manager._jobs) == 0

    def test_create_job(self):
        manager = WorkflowManager()
        pcap_data = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20  # minimal pcap header
        job = manager.create_job("test.pcap", pcap_data)
        assert job.filename == "test.pcap"
        assert job.job_id is not None
        assert job.status in (JobStatus.QUEUED, JobStatus.PROCESSING)

    def test_get_nonexistent_job(self):
        manager = WorkflowManager()
        assert manager.get_job("nonexistent") is None

    def test_list_jobs_empty(self):
        manager = WorkflowManager()
        jobs = manager.list_jobs()
        assert jobs == []

    def test_list_jobs_with_limit(self):
        manager = WorkflowManager()
        for i in range(5):
            manager.create_job(f"test{i}.pcap", b"\x00" * 24)
        jobs = manager.list_jobs(limit=3)
        assert len(jobs) == 3

    def test_job_has_pcap_path(self):
        manager = WorkflowManager()
        job = manager.create_job("sample.pcap", b"\x00" * 24)
        assert job.pcap_path.endswith("sample.pcap")
