"""Annotation service for analyst notes on hunt entities."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4


class AnnotationsService:
    VALID_TARGET_TYPES = {"threat", "connection", "dns", "beacon", "session", "host"}
    VALID_VERDICTS = {"benign", "suspicious", "malicious", "false-positive"}

    def __init__(self, annotations_path: Optional[Path] = None):
        base_dir = Path(__file__).resolve().parents[2]
        self.annotations_path = annotations_path or (base_dir / "data" / "annotations.json")
        self.annotations_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.annotations_path.exists():
            self.annotations_path.write_text("[]", encoding="utf-8")

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _read_all(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(self.annotations_path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _write_all(self, items: list[dict[str, Any]]) -> None:
        self.annotations_path.write_text(json.dumps(items, indent=2), encoding="utf-8")

    def list_all(
        self,
        *,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        items = self._read_all()
        if target_type:
            items = [item for item in items if item.get("target_type") == target_type]
        if target_id:
            items = [item for item in items if item.get("target_id") == target_id]
        return items

    def list_by_target(self, target_type: str, target_id: str) -> list[dict[str, Any]]:
        return self.list_all(target_type=target_type, target_id=target_id)

    def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        target_type = payload.get("target_type")
        if target_type not in self.VALID_TARGET_TYPES:
            raise ValueError(f"Invalid target_type: {target_type}")

        verdict = payload.get("verdict")
        if verdict is not None and verdict not in self.VALID_VERDICTS:
            raise ValueError(f"Invalid verdict: {verdict}")

        now = self._now_iso()
        item = {
            "id": str(uuid4()),
            "target_type": target_type,
            "target_id": payload["target_id"],
            "content": payload["content"],
            "author": payload.get("author", "analyst"),
            "tags": payload.get("tags", []),
            "verdict": verdict,
            "created_at": now,
            "updated_at": now,
        }
        items = self._read_all()
        items.append(item)
        self._write_all(items)
        return item

    def update(self, annotation_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        items = self._read_all()
        annotation = next((x for x in items if x.get("id") == annotation_id), None)
        if not annotation:
            raise FileNotFoundError(f"Annotation not found: {annotation_id}")

        if "target_type" in payload:
            target_type = payload["target_type"]
            if target_type not in self.VALID_TARGET_TYPES:
                raise ValueError(f"Invalid target_type: {target_type}")
            annotation["target_type"] = target_type

        if "verdict" in payload:
            verdict = payload["verdict"]
            if verdict is not None and verdict not in self.VALID_VERDICTS:
                raise ValueError(f"Invalid verdict: {verdict}")
            annotation["verdict"] = verdict

        for field in ["target_id", "content", "author", "tags"]:
            if field in payload:
                annotation[field] = payload[field]

        annotation["updated_at"] = self._now_iso()
        self._write_all(items)
        return annotation

    def delete(self, annotation_id: str) -> None:
        items = self._read_all()
        filtered = [x for x in items if x.get("id") != annotation_id]
        if len(filtered) == len(items):
            raise FileNotFoundError(f"Annotation not found: {annotation_id}")
        self._write_all(filtered)


annotations_service = AnnotationsService()
