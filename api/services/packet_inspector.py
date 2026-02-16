"""Packet-level inspection service for connection deep dives."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from api.config import settings
from api.services.log_store import log_store
from api.services.demo_data import DemoDataService


class PacketInspector:
    def __init__(self):
        self.demo = DemoDataService()
        self._http_by_uid: dict[str, list[dict[str, Any]]] | None = None
        self._dns_by_uid: dict[str, list[dict[str, Any]]] | None = None
        self._notice_by_uid: dict[str, list[dict[str, Any]]] | None = None

    def _ensure_indexes(self):
        if self._http_by_uid is not None:
            return
        self._http_by_uid = defaultdict(list)
        self._dns_by_uid = defaultdict(list)
        self._notice_by_uid = defaultdict(list)

        for row in self.demo.read_json_lines("http.log"):
            uid = row.get("uid")
            if uid:
                self._http_by_uid[uid].append(row)

        for row in self.demo.read_json_lines("dns.log"):
            uid = row.get("uid")
            if uid:
                self._dns_by_uid[uid].append(row)

        for row in self.demo.read_json_lines("notice.log"):
            uid = row.get("uid")
            if uid:
                self._notice_by_uid[uid].append(row)

    def get_connection_detail(self, uid: str) -> dict[str, Any] | None:
        self._ensure_indexes()
        conn = next((c for c in log_store.connections if c.uid == uid), None)
        if not conn:
            return None

        http = (self._http_by_uid or {}).get(uid, [])
        dns = (self._dns_by_uid or {}).get(uid, [])
        notices = (self._notice_by_uid or {}).get(uid, [])

        total_packets = (conn.pkts_sent or 0) + (conn.pkts_recv or 0)
        total_bytes = (conn.bytes_sent or 0) + (conn.bytes_recv or 0)
        avg_pkt = int(total_bytes / total_packets) if total_packets else 0

        packets: list[dict[str, Any]] = []
        for i in range(max(total_packets, 1)):
            direction = "orig->resp" if i % 2 == 0 else "resp->orig"
            size = avg_pkt if avg_pkt > 0 else (64 + (i % 3) * 32)
            packets.append(
                {
                    "index": i + 1,
                    "timestamp": conn.timestamp.timestamp() + (i * 0.01),
                    "direction": direction,
                    "size": size,
                    "flags": conn.conn_state or "-",
                }
            )

        protocol_details: dict[str, Any] = {
            "http": [
                {
                    "method": h.get("method"),
                    "uri": h.get("uri"),
                    "status": h.get("status_code"),
                    "user_agent": h.get("user_agent"),
                    "content_type": (h.get("resp_mime_types") or [None])[0],
                }
                for h in http
            ],
            "dns": [
                {
                    "query": d.get("query"),
                    "response": ", ".join(d.get("answers", [])) if d.get("answers") else d.get("rcode_name"),
                    "ttl": (d.get("TTLs") or [None])[0],
                }
                for d in dns
            ],
            "tls": [],
            "files": [],
            "raw": {
                "conn_state": conn.conn_state,
                "pkts_sent": conn.pkts_sent,
                "pkts_recv": conn.pkts_recv,
            },
            "notices": notices,
        }

        return {
            "uid": conn.uid,
            "timestamp": conn.timestamp.timestamp(),
            "src": {"ip": conn.src_ip, "port": conn.src_port},
            "dst": {"ip": conn.dst_ip, "port": conn.dst_port},
            "protocol": conn.proto,
            "service": conn.service,
            "duration": conn.duration,
            "bytes_sent": conn.bytes_sent,
            "bytes_recv": conn.bytes_recv,
            "packets": packets,
            "protocol_details": protocol_details,
            "demo_mode": settings.demo_mode,
        }

    def get_flow(self, uid: str) -> list[dict[str, Any]] | None:
        detail = self.get_connection_detail(uid)
        if not detail:
            return None

        events: list[dict[str, Any]] = [
            {
                "timestamp": detail["timestamp"],
                "direction": "orig->resp",
                "type": "connection",
                "summary": "Connection started",
            }
        ]

        for dns in detail["protocol_details"].get("dns", []):
            events.append(
                {
                    "timestamp": detail["timestamp"] + 0.05,
                    "direction": "orig->resp",
                    "type": "dns",
                    "summary": f"DNS query: {dns.get('query') or 'unknown'}",
                }
            )

        for http in detail["protocol_details"].get("http", []):
            events.append(
                {
                    "timestamp": detail["timestamp"] + 0.1,
                    "direction": "orig->resp",
                    "type": "http",
                    "summary": f"HTTP {http.get('method') or 'REQ'} {http.get('uri') or '/'}",
                }
            )

        for notice in detail["protocol_details"].get("notices", []):
            events.append(
                {
                    "timestamp": notice.get("ts", detail["timestamp"] + 0.2),
                    "direction": "resp->orig",
                    "type": "alert",
                    "summary": notice.get("msg") or notice.get("note") or "Notice event",
                }
            )

        events.append(
            {
                "timestamp": detail["timestamp"] + (detail.get("duration") or 0.3),
                "direction": "resp->orig",
                "type": "connection",
                "summary": "Connection ended",
            }
        )

        return sorted(events, key=lambda e: e["timestamp"])

    def get_payload_preview(self, uid: str) -> dict[str, Any] | None:
        conn = next((c for c in log_store.connections if c.uid == uid), None)
        if not conn:
            return None

        max_bytes = 4096
        if settings.demo_mode:
            return self.demo.synthetic_payload(uid, max_bytes=max_bytes)

        return {
            "uid": uid,
            "bytes": 0,
            "truncated": False,
            "format": "hex+ascii",
            "preview": "No payload bytes available for this connection.",
        }


packet_inspector = PacketInspector()
