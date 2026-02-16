"""Trend tracking service for historical threat posture snapshots."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4
import json
import random

from api.services.unified_threat_engine import UnifiedThreatEngine
from api.services.log_store import log_store as global_log_store, LogStore


class TrendTracker:
    """File-backed snapshot storage and trend analytics."""

    def __init__(self, base_dir: Path | None = None):
        project_root = Path(__file__).resolve().parents[2]
        self.base_dir = base_dir or (project_root / "data" / "trends")
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _snapshot_path(self, dt: datetime) -> Path:
        return self.base_dir / dt.strftime("%Y-%m-%d_%H-%M-%S.json")

    def _write_snapshot(self, snapshot: dict[str, Any], when: datetime | None = None) -> dict[str, Any]:
        ts = when or datetime.now(timezone.utc)
        path = self._snapshot_path(ts)
        with path.open("w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
        return snapshot

    def _load_snapshot_file(self, path: Path) -> dict[str, Any] | None:
        try:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _all_snapshots(self) -> list[dict[str, Any]]:
        snapshots: list[dict[str, Any]] = []
        for file in sorted(self.base_dir.glob("*.json")):
            snap = self._load_snapshot_file(file)
            if snap:
                snap["_file"] = str(file)
                snapshots.append(snap)
        snapshots.sort(key=lambda s: s.get("timestamp", ""))
        return snapshots

    def _severity_bucket(self, value: str) -> str:
        v = (value or "").lower()
        if v in {"critical", "high", "medium", "low"}:
            return v
        return "low"

    def take_snapshot(self, log_store: LogStore | None = None) -> dict[str, Any]:
        store = log_store or global_log_store
        engine = UnifiedThreatEngine(store)
        profiles = engine.analyze_all()

        host_scores = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        all_mitre: set[str] = set()
        top_score = 0.0

        for ip, profile in profiles.items():
            level = self._severity_bucket(getattr(profile.threat_level, "value", str(profile.threat_level)))
            severity_counts[level] += 1
            all_mitre.update(profile.mitre_techniques)
            top_score = max(top_score, float(profile.score or 0.0))

            host_scores.append(
                {
                    "ip": ip,
                    "score": round(float(profile.score or 0.0), 3),
                    "threat_level": level,
                    "beacon_count": int(profile.beacon_count or 0),
                    "alert_count": int(profile.alert_count or 0),
                }
            )

        host_scores.sort(key=lambda h: h["score"], reverse=True)

        unique_sources = len({c.src_ip for c in store.connections})
        unique_destinations = len({c.dst_ip for c in store.connections})

        snapshot = {
            "id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_hosts": len(host_scores),
                "total_connections": len(store.connections),
                "total_dns_queries": len(store.dns_queries),
                "total_alerts": len(store.alerts),
                "threats_by_severity": severity_counts,
                "top_threat_score": round(top_score, 3),
                "mitre_techniques_count": len(all_mitre),
                "unique_sources": unique_sources,
                "unique_destinations": unique_destinations,
            },
            "host_scores": host_scores,
            "mitre_techniques": sorted(all_mitre),
        }
        return self._write_snapshot(snapshot)

    def list_snapshots(self) -> list[dict[str, Any]]:
        rows = []
        for snap in self._all_snapshots():
            rows.append(
                {
                    "id": snap.get("id"),
                    "timestamp": snap.get("timestamp"),
                    "summary": snap.get("summary", {}),
                    "host_count": len(snap.get("host_scores", [])),
                    "mitre_count": len(snap.get("mitre_techniques", [])),
                }
            )
        return rows

    def get_snapshot(self, snapshot_id: str) -> dict[str, Any] | None:
        for snap in self._all_snapshots():
            if snap.get("id") == snapshot_id:
                snap.pop("_file", None)
                return snap
        return None

    def delete_snapshot(self, snapshot_id: str) -> bool:
        for snap in self._all_snapshots():
            if snap.get("id") == snapshot_id:
                file_path = snap.get("_file")
                if file_path:
                    Path(file_path).unlink(missing_ok=True)
                    return True
        return False

    def _recent_snapshots(self, days: int = 7) -> list[dict[str, Any]]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, days))
        snaps = []
        for s in self._all_snapshots():
            try:
                ts = datetime.fromisoformat(s.get("timestamp"))
            except Exception:
                continue
            if ts >= cutoff:
                snaps.append(s)
        return snaps

    def get_trend_summary(self, days: int = 7) -> dict[str, Any]:
        snaps = self._recent_snapshots(days)
        daily = []
        for s in snaps:
            summary = s.get("summary", {})
            sev = summary.get("threats_by_severity", {})
            total_threats = sum(int(sev.get(k, 0)) for k in ("critical", "high", "medium", "low"))
            daily.append(
                {
                    "id": s.get("id"),
                    "timestamp": s.get("timestamp"),
                    "date": (s.get("timestamp") or "")[:10],
                    "total_threats": total_threats,
                    "critical": int(sev.get("critical", 0)),
                    "high": int(sev.get("high", 0)),
                    "medium": int(sev.get("medium", 0)),
                    "low": int(sev.get("low", 0)),
                    "top_threat_score": float(summary.get("top_threat_score", 0.0)),
                    "total_hosts": int(summary.get("total_hosts", 0)),
                }
            )

        current = daily[-1] if daily else None
        previous_avg = (
            sum(d["total_threats"] for d in daily[:-1]) / len(daily[:-1])
            if len(daily) > 1
            else 0.0
        )

        return {
            "days": days,
            "snapshot_count": len(daily),
            "current": current,
            "previous_average_threats": round(previous_avg, 2),
            "timeline": daily,
        }

    def get_hosts_changes(self, days: int = 7) -> dict[str, Any]:
        snaps = self._recent_snapshots(days)
        if not snaps:
            return {"days": days, "hosts": []}

        latest = snaps[-1]
        previous = snaps[-2] if len(snaps) > 1 else None

        prev_scores = {
            h.get("ip"): float(h.get("score", 0.0))
            for h in (previous.get("host_scores", []) if previous else [])
        }

        by_host: dict[str, list[dict[str, Any]]] = {}
        for s in snaps:
            for h in s.get("host_scores", []):
                ip = h.get("ip")
                if not ip:
                    continue
                by_host.setdefault(ip, []).append(
                    {
                        "timestamp": s.get("timestamp"),
                        "score": float(h.get("score", 0.0)),
                        "threat_level": h.get("threat_level", "low"),
                    }
                )

        rows = []
        for host in latest.get("host_scores", []):
            ip = host.get("ip")
            current_score = float(host.get("score", 0.0))
            previous_score = prev_scores.get(ip, 0.0)
            delta = round(current_score - previous_score, 3)
            rows.append(
                {
                    "ip": ip,
                    "current_score": round(current_score, 3),
                    "previous_score": round(previous_score, 3),
                    "delta": delta,
                    "threat_level": host.get("threat_level", "low"),
                    "beacon_count": int(host.get("beacon_count", 0)),
                    "alert_count": int(host.get("alert_count", 0)),
                    "trend": by_host.get(ip, []),
                }
            )

        rows.sort(key=lambda r: abs(r["delta"]), reverse=True)
        return {"days": days, "hosts": rows}

    def get_host_trends(self, ip: str, days: int = 7) -> dict[str, Any]:
        snaps = self._recent_snapshots(days)
        points = []
        for s in snaps:
            found = next((h for h in s.get("host_scores", []) if h.get("ip") == ip), None)
            points.append(
                {
                    "timestamp": s.get("timestamp"),
                    "date": (s.get("timestamp") or "")[:10],
                    "score": float(found.get("score", 0.0)) if found else 0.0,
                    "threat_level": found.get("threat_level", "info") if found else "info",
                    "beacon_count": int(found.get("beacon_count", 0)) if found else 0,
                    "alert_count": int(found.get("alert_count", 0)) if found else 0,
                }
            )
        return {"ip": ip, "days": days, "points": points}

    def get_mitre_trends(self, days: int = 7) -> dict[str, Any]:
        snaps = self._recent_snapshots(days)
        if not snaps:
            return {"days": days, "techniques": []}

        latest = set(snaps[-1].get("mitre_techniques", []))
        previous = set(snaps[-2].get("mitre_techniques", [])) if len(snaps) > 1 else set()

        counts: dict[str, int] = {}
        for s in snaps:
            for t in set(s.get("mitre_techniques", [])):
                counts[t] = counts.get(t, 0) + 1

        techniques = []
        for tech in sorted(set(counts.keys()) | latest | previous):
            status = "stable"
            if tech in latest and tech not in previous:
                status = "new"
            elif tech in previous and tech not in latest:
                status = "resolved"
            techniques.append(
                {
                    "technique": tech,
                    "frequency": counts.get(tech, 0),
                    "present_current": tech in latest,
                    "present_previous": tech in previous,
                    "status": status,
                }
            )

        techniques.sort(key=lambda t: (t["frequency"], t["technique"]), reverse=True)
        return {"days": days, "techniques": techniques}

    def seed_demo_trends(self):
        """Create 7 days of realistic demo snapshots if none exist."""
        if self.list_snapshots():
            return

        now = datetime.now(timezone.utc)

        # Base hosts for synthetic progression (days 1-6)
        host_pool = [f"192.0.2.{i}" for i in range(10, 28)]
        mitre_pool = [
            "T1071", "T1071.001", "T1071.004", "T1048.003", "T1059", "T1105", "T1003", "T1027"
        ]

        day_profiles = [
            {"hosts": (3, 5), "score": (0.20, 0.40), "mitre": (1, 3), "sev": (0, 1, 2, 2)},
            {"hosts": (3, 5), "score": (0.22, 0.42), "mitre": (1, 3), "sev": (0, 1, 2, 2)},
            {"hosts": (8, 12), "score": (0.35, 0.80), "mitre": (4, 7), "sev": (2, 3, 3, 2)},
            {"hosts": (8, 12), "score": (0.40, 0.82), "mitre": (4, 8), "sev": (2, 4, 3, 2)},
            {"hosts": (6, 9), "score": (0.28, 0.65), "mitre": (3, 6), "sev": (1, 2, 3, 2)},
            {"hosts": (5, 8), "score": (0.22, 0.55), "mitre": (2, 5), "sev": (0, 2, 3, 2)},
        ]

        rng = random.Random(42)

        for i, profile in enumerate(day_profiles):
            ts = now - timedelta(days=(6 - i))
            count = rng.randint(*profile["hosts"])
            hosts = rng.sample(host_pool, count)
            host_scores = []
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            top_score = 0.0

            for ip in hosts:
                score = round(rng.uniform(*profile["score"]), 3)
                if score >= 0.8:
                    level = "critical"
                elif score >= 0.6:
                    level = "high"
                elif score >= 0.4:
                    level = "medium"
                else:
                    level = "low"
                sev_counts[level] += 1
                top_score = max(top_score, score)
                host_scores.append(
                    {
                        "ip": ip,
                        "score": score,
                        "threat_level": level,
                        "beacon_count": rng.randint(0, 4),
                        "alert_count": rng.randint(0, 6),
                    }
                )

            mitre_count = rng.randint(*profile["mitre"])
            mitre = sorted(rng.sample(mitre_pool, mitre_count))

            snapshot = {
                "id": str(uuid4()),
                "timestamp": ts.isoformat(),
                "summary": {
                    "total_hosts": len(host_scores),
                    "total_connections": rng.randint(120, 360),
                    "total_dns_queries": rng.randint(80, 280),
                    "total_alerts": rng.randint(5, 55),
                    "threats_by_severity": sev_counts,
                    "top_threat_score": round(top_score, 3),
                    "mitre_techniques_count": len(mitre),
                    "unique_sources": len(host_scores),
                    "unique_destinations": rng.randint(12, 40),
                },
                "host_scores": sorted(host_scores, key=lambda h: h["score"], reverse=True),
                "mitre_techniques": mitre,
            }
            self._write_snapshot(snapshot, when=ts)

        # Day 7 should represent current state from live demo data
        self.take_snapshot(global_log_store)
