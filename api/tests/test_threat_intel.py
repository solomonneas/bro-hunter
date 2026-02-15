"""Tests for threat intelligence service."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from api.services.threat_intel import ThreatIntelService, ThreatIntelResult, IntelSummary


class TestLocalBlocklist:
    def test_empty_blocklist(self):
        service = ThreatIntelService()
        # Should not crash with no blocklist file
        assert isinstance(service._local_blocklist, set)

    def test_cache_set_and_get(self):
        service = ThreatIntelService()
        result = ThreatIntelResult(
            indicator="1.2.3.4",
            indicator_type="ip",
            source="test",
            malicious=True,
            confidence=0.9,
        )
        service._cache_set("test:1.2.3.4", result)
        cached = service._cache_get("test:1.2.3.4")
        assert cached is not None
        assert cached.indicator == "1.2.3.4"
        assert cached.malicious is True

    def test_cache_miss(self):
        service = ThreatIntelService()
        assert service._cache_get("nonexistent") is None


class TestGetStatus:
    def test_status_structure(self):
        service = ThreatIntelService()
        status = service.get_status()
        assert "sources" in status
        assert "cache_entries" in status
        assert "cache_ttl_seconds" in status
        assert "abuseipdb" in status["sources"]
        assert "otx" in status["sources"]
        assert "local_blocklist" in status["sources"]

    def test_unconfigured_sources(self):
        service = ThreatIntelService()
        status = service.get_status()
        # Without env vars, both should be unconfigured
        assert status["sources"]["abuseipdb"]["configured"] is False
        assert status["sources"]["otx"]["configured"] is False


class TestIntelSummary:
    def test_empty_summary(self):
        summary = IntelSummary(indicator="1.2.3.4", indicator_type="ip")
        assert summary.is_malicious is False
        assert summary.max_confidence == 0.0
        assert summary.sources_checked == 0

    def test_summary_with_results(self):
        summary = IntelSummary(
            indicator="1.2.3.4",
            indicator_type="ip",
            is_malicious=True,
            max_confidence=0.95,
            sources_checked=2,
            sources_flagged=1,
        )
        assert summary.is_malicious is True
        assert summary.max_confidence == 0.95
