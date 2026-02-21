"""
Minimal MISP client for IOC enrichment.
"""
from __future__ import annotations

import json
import os
from typing import Any
from urllib import error, parse, request


class MISPClient:
    def __init__(self) -> None:
        self.base_url = os.getenv("MISP_URL", "").rstrip("/")
        self.api_key = os.getenv("MISP_API_KEY", "")
        self.search_path = os.getenv("MISP_SEARCH_PATH", "/attributes/restSearch")

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": self.api_key,
        }

    def search_attribute(self, value: str, limit: int = 25) -> dict[str, Any]:
        if not self.configured:
            raise RuntimeError("MISP integration is not configured")

        url = f"{self.base_url}{self.search_path}"
        payload = {
            "returnFormat": "json",
            "value": value,
            "limit": limit,
        }
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(url, data=data, headers=self._headers(), method="POST")

        try:
            with request.urlopen(req, timeout=20) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else str(e)
            raise RuntimeError(f"MISP HTTP {e.code}: {body}") from e
        except Exception as e:
            raise RuntimeError(f"MISP request failed: {e}") from e


def normalize_misp_hits(payload: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    """
    Normalize several MISP response shapes to a list of attributes/events.
    """
    # Possible shapes:
    # {"response": {"Attribute": [...]}}
    # {"response": [{"Event": ...}, ...]}
    # {"Attribute": [...]} / {"Event": [...]}
    items: list[dict[str, Any]] = []

    response = payload.get("response")
    if isinstance(response, dict):
        if isinstance(response.get("Attribute"), list):
            items = response["Attribute"]
        elif isinstance(response.get("Event"), list):
            items = response["Event"]
    elif isinstance(response, list):
        items = response
    elif isinstance(payload.get("Attribute"), list):
        items = payload["Attribute"]
    elif isinstance(payload.get("Event"), list):
        items = payload["Event"]

    return len(items), items
