"""Tests for live capture service."""
import pytest
from unittest.mock import patch, MagicMock

from api.services.live_capture import LiveCaptureService, CaptureSession


class TestCaptureSession:
    def test_default_session(self):
        session = CaptureSession(
            session_id="test-1",
            interface="eth0",
            capture_filter="",
            started_at=1700000000.0,
        )
        assert session.status == "running"
        assert session.stopped_at is None
        assert session.packet_count == 0
        assert session.error == ""

    def test_session_with_error(self):
        session = CaptureSession(
            session_id="test-2",
            interface="eth0",
            capture_filter="",
            started_at=1700000000.0,
            status="error",
            error="Permission denied",
        )
        assert session.status == "error"
        assert "Permission" in session.error


class TestCaptureService:
    def test_init(self):
        service = LiveCaptureService()
        assert isinstance(service._sessions, dict)
        assert len(service._sessions) == 0

    def test_list_sessions_empty(self):
        service = LiveCaptureService()
        sessions = service.list_sessions()
        assert sessions == []

    def test_get_nonexistent_session(self):
        service = LiveCaptureService()
        assert service.get_session("nonexistent") is None

    def test_get_pcap_path_nonexistent(self):
        service = LiveCaptureService()
        assert service.get_pcap_path("nonexistent") is None

    def test_stop_nonexistent(self):
        service = LiveCaptureService()
        assert service.stop_capture("nonexistent") is None

    @patch("api.services.live_capture.subprocess.run")
    def test_get_interfaces_returns_list(self, mock_run):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '[{"ifname":"eth0","operstate":"UP","mtu":1500},{"ifname":"lo","operstate":"UNKNOWN","mtu":65536}]'
        mock_run.return_value = mock_result
        service = LiveCaptureService()
        interfaces = service.get_interfaces()
        assert isinstance(interfaces, list)
        assert len(interfaces) == 2
        assert interfaces[0]["name"] == "eth0"
