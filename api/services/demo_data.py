"""Demo data helpers for sanitized bundled datasets."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json

from api.services.log_store import LogStore
from api.parsers.zeek_parser import ZeekParser
from api.parsers.unified import normalize_zeek_conn, normalize_zeek_dns


DEMO_DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "demo"


class DemoDataService:
    """Load and query bundled demo logs."""

    def __init__(self, data_dir: Path | None = None):
        self.data_dir = data_dir or DEMO_DATA_DIR

    def load_into_store(self, store: LogStore) -> dict[str, Any]:
        """Load conn/dns logs into the global store for demo mode."""
        store.clear()
        file_count = 0

        conn_path = self.data_dir / "conn.log"
        if conn_path.exists():
            for entry in ZeekParser.parse_file(conn_path, log_type="conn"):
                store._add_connection(normalize_zeek_conn(entry))
            file_count += 1

        dns_path = self.data_dir / "dns.log"
        if dns_path.exists():
            for entry in ZeekParser.parse_file(dns_path, log_type="dns"):
                store._add_dns_query(normalize_zeek_dns(entry))
            file_count += 1

        store.file_count = file_count
        store.total_records = len(store.connections) + len(store.dns_queries) + len(store.alerts)

        return {
            "file_count": store.file_count,
            "record_count": store.total_records,
            "connections": len(store.connections),
            "dns_queries": len(store.dns_queries),
            "alerts": len(store.alerts),
        }

    def read_json_lines(self, filename: str) -> list[dict[str, Any]]:
        """Read a JSON-lines Zeek-style log file from demo data."""
        path = self.data_dir / filename
        if not path.exists():
            return []

        rows: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows

    @staticmethod
    def synthetic_payload(uid: str, max_bytes: int = 4096) -> dict[str, Any]:
        """Generate deterministic synthetic payload for demo mode."""
        seed = hashlib.sha256(uid.encode("utf-8")).digest()
        payload = bytearray()
        while len(payload) < max_bytes:
            payload.extend(seed)
            seed = hashlib.sha256(seed).digest()
        raw = bytes(payload[:max_bytes])

        lines: list[str] = []
        for offset in range(0, len(raw), 16):
            chunk = raw[offset: offset + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{offset:04x}  {hex_part:<47}  {ascii_part}")

        return {
            "uid": uid,
            "bytes": len(raw),
            "truncated": False,
            "format": "hex+ascii",
            "preview": "\n".join(lines),
        }


def sanitize_ip(value: str) -> str:
    """Helper used by the scrubber utility (RFC5737 buckets)."""
    octets = value.split(".")
    if len(octets) != 4:
        return value
    digest = hashlib.md5(value.encode("utf-8")).digest()[0]
    bucket = digest % 3
    if bucket == 0:
        prefix = "192.0.2"
    elif bucket == 1:
        prefix = "198.51.100"
    else:
        prefix = "203.0.113"
    return f"{prefix}.{(digest % 254) + 1}"
