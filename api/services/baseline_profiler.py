"""Baseline profiling service for traffic behavior modeling."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import ipaddress
import json

import numpy as np

from api.services.log_store import LogStore

BASELINE_FILE = Path(__file__).resolve().parents[2] / "data" / "baseline.json"


class BaselineProfiler:
    """Build and compare traffic baselines from loaded logs."""

    def __init__(self, store: LogStore):
        self.store = store
        self.current_baseline: dict[str, Any] | None = self._load_from_disk()

    @staticmethod
    def _to_ts(value: Any) -> float:
        if isinstance(value, datetime):
            return value.timestamp()
        return float(value or 0.0)

    @staticmethod
    def _is_internal_ip(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _load_from_disk(self) -> dict[str, Any] | None:
        if not BASELINE_FILE.exists():
            return None
        try:
            content = json.loads(BASELINE_FILE.read_text())
            return content if content else None
        except Exception:
            return None

    def _save_to_disk(self, baseline: dict[str, Any]) -> None:
        BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE_FILE.write_text(json.dumps(baseline, indent=2))

    def build_baseline(self) -> dict[str, Any]:
        connections = self.store.connections
        dns_queries = self.store.dns_queries

        if not connections:
            baseline = {
                "built_at": datetime.now(timezone.utc).isoformat(),
                "connection_count": 0,
                "time_range": {"start": 0.0, "end": 0.0},
                "protocol_distribution": {},
                "port_profile": {"top_dst_ports": [], "top_src_ports": []},
                "traffic_volume": {
                    "bytes_per_hour_mean": 0.0,
                    "bytes_per_hour_std": 0.0,
                    "connections_per_hour_mean": 0.0,
                    "connections_per_hour_std": 0.0,
                },
                "duration_stats": {"mean": 0.0, "median": 0.0, "std": 0.0, "p95": 0.0, "p99": 0.0},
                "dns_profile": {
                    "unique_queries_per_hour_mean": 0.0,
                    "avg_query_length": 0.0,
                    "top_queried_domains": [],
                },
                "host_profile": {"internal_hosts": 0, "external_hosts": 0, "top_talkers": []},
            }
            self.current_baseline = baseline
            self._save_to_disk(baseline)
            return baseline

        timestamps = np.array([self._to_ts(c.timestamp) for c in connections], dtype=float)
        start_ts = float(np.min(timestamps))
        end_ts = float(np.max(timestamps))

        proto_counter = Counter((c.proto or "unknown").lower() for c in connections)
        protocol_distribution = {k: round(v / len(connections), 4) for k, v in proto_counter.items()}

        dst_ports = Counter(int(c.dst_port or 0) for c in connections)
        src_ports = Counter(int(c.src_port or 0) for c in connections)

        hour_bytes = defaultdict(int)
        hour_connections = defaultdict(int)
        host_bytes = defaultdict(lambda: {"bytes": 0, "connections": 0})

        durations = []
        for conn in connections:
            ts = self._to_ts(conn.timestamp)
            hour_bucket = int(ts // 3600)
            total_bytes = int(conn.bytes_sent or 0) + int(conn.bytes_recv or 0)

            hour_bytes[hour_bucket] += total_bytes
            hour_connections[hour_bucket] += 1
            host_bytes[conn.src_ip]["bytes"] += total_bytes
            host_bytes[conn.src_ip]["connections"] += 1
            if conn.duration is not None:
                durations.append(float(conn.duration))

        bytes_per_hour = np.array(list(hour_bytes.values()) or [0], dtype=float)
        conns_per_hour = np.array(list(hour_connections.values()) or [0], dtype=float)
        duration_arr = np.array(durations or [0.0], dtype=float)

        dns_hour_unique: dict[int, set[str]] = defaultdict(set)
        domain_counter = Counter()
        query_lengths = []
        for query in dns_queries:
            ts = self._to_ts(query.timestamp)
            hour_bucket = int(ts // 3600)
            dns_hour_unique[hour_bucket].add((query.query or "").lower())
            domain = (query.query or "").lower()
            if domain:
                domain_counter[domain] += 1
                query_lengths.append(len(domain))

        unique_hosts = set()
        internal_hosts = set()
        external_hosts = set()
        for conn in connections:
            for ip in (conn.src_ip, conn.dst_ip):
                unique_hosts.add(ip)
                if self._is_internal_ip(ip):
                    internal_hosts.add(ip)
                else:
                    external_hosts.add(ip)

        baseline = {
            "built_at": datetime.now(timezone.utc).isoformat(),
            "connection_count": len(connections),
            "time_range": {"start": start_ts, "end": end_ts},
            "protocol_distribution": protocol_distribution,
            "port_profile": {
                "top_dst_ports": [{"port": p, "pct": round(c / len(connections), 4)} for p, c in dst_ports.most_common(10)],
                "top_src_ports": [{"port": p, "pct": round(c / len(connections), 4)} for p, c in src_ports.most_common(10)],
            },
            "traffic_volume": {
                "bytes_per_hour_mean": float(np.mean(bytes_per_hour)),
                "bytes_per_hour_std": float(np.std(bytes_per_hour)),
                "connections_per_hour_mean": float(np.mean(conns_per_hour)),
                "connections_per_hour_std": float(np.std(conns_per_hour)),
            },
            "duration_stats": {
                "mean": float(np.mean(duration_arr)),
                "median": float(np.median(duration_arr)),
                "std": float(np.std(duration_arr)),
                "p95": float(np.percentile(duration_arr, 95)),
                "p99": float(np.percentile(duration_arr, 99)),
            },
            "dns_profile": {
                "unique_queries_per_hour_mean": float(np.mean([len(s) for s in dns_hour_unique.values()] or [0])),
                "avg_query_length": float(np.mean(query_lengths or [0])),
                "top_queried_domains": [{"domain": d, "count": c} for d, c in domain_counter.most_common(10)],
            },
            "host_profile": {
                "internal_hosts": len(internal_hosts),
                "external_hosts": len(external_hosts),
                "top_talkers": [
                    {"ip": ip, "bytes": data["bytes"], "connections": data["connections"]}
                    for ip, data in sorted(host_bytes.items(), key=lambda item: item[1]["bytes"], reverse=True)[:10]
                ],
            },
        }

        self.current_baseline = baseline
        self._save_to_disk(baseline)
        return baseline

    def compare_against_baseline(self) -> dict[str, Any]:
        baseline = self.current_baseline or self._load_from_disk()
        if not baseline:
            return {"status": "no_baseline", "deviations": []}

        current = self.build_baseline()
        deviations: list[dict[str, Any]] = []

        checks = [
            (
                "traffic_volume.bytes_per_hour_mean",
                current["traffic_volume"]["bytes_per_hour_mean"],
                baseline["traffic_volume"].get("bytes_per_hour_mean", 0.0),
                baseline["traffic_volume"].get("bytes_per_hour_std", 0.0),
            ),
            (
                "traffic_volume.connections_per_hour_mean",
                current["traffic_volume"]["connections_per_hour_mean"],
                baseline["traffic_volume"].get("connections_per_hour_mean", 0.0),
                baseline["traffic_volume"].get("connections_per_hour_std", 0.0),
            ),
            (
                "duration_stats.mean",
                current["duration_stats"]["mean"],
                baseline["duration_stats"].get("mean", 0.0),
                baseline["duration_stats"].get("std", 0.0),
            ),
            (
                "dns_profile.unique_queries_per_hour_mean",
                current["dns_profile"]["unique_queries_per_hour_mean"],
                baseline["dns_profile"].get("unique_queries_per_hour_mean", 0.0),
                max(1.0, baseline["dns_profile"].get("unique_queries_per_hour_mean", 0.0) * 0.25),
            ),
        ]

        for metric, value, mean, std in checks:
            if std <= 0:
                continue
            z = abs((value - mean) / std)
            if z > 1:
                deviations.append(
                    {
                        "metric": metric,
                        "current": float(value),
                        "baseline": float(mean),
                        "std": float(std),
                        "sigma": float(z),
                        "status": "critical" if z > 2 else "warning",
                    }
                )

        return {
            "status": "ok",
            "baseline_built_at": baseline.get("built_at"),
            "current_built_at": current.get("built_at"),
            "deviations": sorted(deviations, key=lambda d: d["sigma"], reverse=True),
            "baseline": baseline,
            "current": current,
        }


baseline_profiler: BaselineProfiler | None = None
