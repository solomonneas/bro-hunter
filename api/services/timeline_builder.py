"""Build chronological threat timeline events from log store + threat engine."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

from api.parsers.unified import Connection, DnsQuery, Alert

SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class TimelineEvent(BaseModel):
    timestamp: datetime
    type: str = Field(..., description="connection|dns|alert|threat|cluster")
    severity: str = Field(..., description="info|low|medium|high|critical")
    summary: str
    details: dict[str, Any]
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    mitre_techniques: list[str] = Field(default_factory=list)


class TimelineFilters(BaseModel):
    limit: int = 100
    offset: int = 0
    severity_min: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    time_start: Optional[datetime] = None
    time_end: Optional[datetime] = None


def _severity_from_alert(alert: Alert) -> str:
    if alert.severity <= 1:
        return "high"
    if alert.severity == 2:
        return "medium"
    return "low"


def _format_bytes(value: Optional[int]) -> str:
    if not value:
        return "0 B"
    units = ["B", "KB", "MB", "GB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} B"


def _conn_summary(conn: Connection, is_beacon: bool) -> str:
    svc = (conn.service or conn.proto).upper()
    beacon_note = ", beacon pattern" if is_beacon else ""
    return (
        f"{conn.src_ip} → {conn.dst_ip}:{conn.dst_port} "
        f"({svc}, {_format_bytes(conn.bytes_sent)} sent{beacon_note})"
    )


def _dns_summary(dns: DnsQuery, threaty: bool) -> str:
    suffix = " (suspicious)" if threaty else ""
    return f"{dns.src_ip} queried {dns.query or '<empty>'}{suffix}"


def _apply_filters(events: list[TimelineEvent], filters: TimelineFilters) -> list[TimelineEvent]:
    filtered = events

    if filters.severity_min:
        min_rank = SEVERITY_RANK.get(filters.severity_min.lower(), 0)
        filtered = [
            e for e in filtered if SEVERITY_RANK.get(e.severity, 0) >= min_rank
        ]

    if filters.src_ip:
        filtered = [e for e in filtered if e.src_ip == filters.src_ip]

    if filters.dst_ip:
        filtered = [e for e in filtered if e.dst_ip == filters.dst_ip]

    if filters.time_start:
        filtered = [e for e in filtered if e.timestamp >= filters.time_start]

    if filters.time_end:
        filtered = [e for e in filtered if e.timestamp <= filters.time_end]

    return filtered


def _cluster_events(events: list[TimelineEvent], window_seconds: int = 5) -> list[TimelineEvent]:
    if not events:
        return events

    clustered: list[TimelineEvent] = []
    i = 0
    while i < len(events):
        current = events[i]
        if not current.src_ip or not current.dst_ip:
            clustered.append(current)
            i += 1
            continue

        group = [current]
        j = i + 1
        while j < len(events):
            candidate = events[j]
            if (
                candidate.src_ip == current.src_ip
                and candidate.dst_ip == current.dst_ip
                and (candidate.timestamp - group[-1].timestamp).total_seconds() <= window_seconds
            ):
                group.append(candidate)
                j += 1
            else:
                break

        if len(group) > 1:
            max_sev = max(group, key=lambda e: SEVERITY_RANK.get(e.severity, 0)).severity
            all_mitre = sorted({m for item in group for m in item.mitre_techniques})
            clustered.append(
                TimelineEvent(
                    timestamp=group[-1].timestamp,
                    type="cluster",
                    severity=max_sev,
                    summary=f"{len(group)} similar events from {current.src_ip} to {current.dst_ip}",
                    details={
                        "count": len(group),
                        "events": [item.model_dump() for item in group],
                    },
                    src_ip=current.src_ip,
                    dst_ip=current.dst_ip,
                    mitre_techniques=all_mitre,
                )
            )
        else:
            clustered.append(current)

        i = j

    return clustered


def build_timeline(log_store, threat_engine, filters: dict[str, Any] | TimelineFilters) -> list[TimelineEvent]:
    if isinstance(filters, TimelineFilters):
        tf = filters
    else:
        tf = TimelineFilters(**filters)

    profiles = threat_engine.analyze_all()
    beacons = {(b.src_ip, b.dst_ip, b.dst_port) for p in profiles.values() for b in p.beacons}

    events: list[TimelineEvent] = []

    for conn in log_store.connections:
        is_beacon = (conn.src_ip, conn.dst_ip, conn.dst_port) in beacons
        sev = "medium" if is_beacon else "info"
        events.append(
            TimelineEvent(
                timestamp=conn.timestamp,
                type="connection",
                severity=sev,
                summary=_conn_summary(conn, is_beacon),
                details=conn.model_dump(),
                src_ip=conn.src_ip,
                dst_ip=conn.dst_ip,
                mitre_techniques=["T1071"] if is_beacon else [],
            )
        )

    suspicious_domains = {
        t["data"].domain
        for p in profiles.values()
        for t in p.dns_threats
        if hasattr(t["data"], "domain")
    }

    for dns in log_store.dns_queries:
        threaty = dns.query in suspicious_domains
        sev = "medium" if threaty else "low"
        events.append(
            TimelineEvent(
                timestamp=dns.timestamp,
                type="dns",
                severity=sev,
                summary=_dns_summary(dns, threaty),
                details=dns.model_dump(),
                src_ip=dns.src_ip,
                dst_ip=dns.dst_ip,
                mitre_techniques=["T1071.004"] if threaty else [],
            )
        )

    for alert in log_store.alerts:
        events.append(
            TimelineEvent(
                timestamp=alert.timestamp,
                type="alert",
                severity=_severity_from_alert(alert),
                summary=f"IDS alert: {alert.signature}",
                details=alert.model_dump(),
                src_ip=alert.src_ip,
                dst_ip=alert.dst_ip,
                mitre_techniques=[],
            )
        )

    for profile in profiles.values():
        if profile.first_seen <= 0:
            continue
        events.append(
            TimelineEvent(
                timestamp=datetime.fromtimestamp(profile.first_seen, tz=timezone.utc),
                type="threat",
                severity=profile.threat_level.value,
                summary=f"Threat score {profile.score:.2f} for host {profile.ip}",
                details={
                    "ip": profile.ip,
                    "score": profile.score,
                    "confidence": profile.confidence,
                    "reasons": profile.all_reasons,
                },
                src_ip=profile.ip,
                dst_ip=None,
                mitre_techniques=sorted(profile.mitre_techniques),
            )
        )

    events.sort(key=lambda e: e.timestamp)
    events = _cluster_events(events, window_seconds=5)
    events = _apply_filters(events, tf)

    if tf.offset:
        events = events[tf.offset:]
    if tf.limit:
        events = events[:tf.limit]

    return events
