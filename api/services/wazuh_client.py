"""
Minimal Wazuh client for IOC correlation against host alerts.
"""
from __future__ import annotations

import json
import os
from typing import Any
from urllib import parse, request, error


class WazuhClient:
    def __init__(self) -> None:
        self.base_url = os.getenv("WAZUH_URL", "").rstrip("/")
        self.api_key = os.getenv("WAZUH_API_KEY", "")
        self.auth_scheme = os.getenv("WAZUH_AUTH_SCHEME", "Bearer")
        self.alerts_path = os.getenv("WAZUH_ALERTS_PATH", "/alerts")

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"{self.auth_scheme} {self.api_key}",
        }

    def search_alerts_for_ioc(self, ioc_value: str, limit: int = 50) -> dict[str, Any]:
        if not self.configured:
            raise RuntimeError("Wazuh integration is not configured")

        q = parse.quote(ioc_value)
        endpoint = f"{self.base_url}{self.alerts_path}?q={q}&limit={limit}"
        req = request.Request(endpoint, headers=self._headers(), method="GET")

        try:
            with request.urlopen(req, timeout=20) as resp:
                raw = resp.read().decode("utf-8")
                data = json.loads(raw) if raw else {}
                return data
        except error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else str(e)
            raise RuntimeError(f"Wazuh HTTP {e.code}: {body}") from e
        except Exception as e:
            raise RuntimeError(f"Wazuh request failed: {e}") from e


def normalize_wazuh_hits(payload: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    """
    Normalize multiple possible Wazuh response shapes.
    """
    # Common shapes seen in APIs:
    # {"data": {"affected_items": [...]}}
    # {"alerts": [...]}
    # {"items": [...]}
    items: list[dict[str, Any]] = []

    if isinstance(payload.get("data"), dict) and isinstance(payload["data"].get("affected_items"), list):
        items = payload["data"]["affected_items"]
    elif isinstance(payload.get("alerts"), list):
        items = payload["alerts"]
    elif isinstance(payload.get("items"), list):
        items = payload["items"]

    return len(items), items
