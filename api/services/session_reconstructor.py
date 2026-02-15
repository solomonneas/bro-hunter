"""
Session Reconstructor - Groups related connections into investigable network sessions.

A session is a cluster of connections between the same src_ip <-> dst_ip pair
within a configurable time window (default 5 min gap = new session).
"""
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime, timezone
import hashlib

from api.services.log_store import LogStore


@dataclass
class SessionEvent:
    """A single event within a reconstructed session."""
    timestamp: float
    event_type: str  # connection, dns, alert
    summary: str
    details: Dict = field(default_factory=dict)
    severity: str = "info"


@dataclass
class ReconstructedSession:
    """A reconstructed network session."""
    session_id: str
    src_ip: str
    dst_ip: str
    start_time: float
    end_time: float
    duration_seconds: float
    total_bytes_sent: int = 0
    total_bytes_recv: int = 0
    connection_count: int = 0
    dns_query_count: int = 0
    alert_count: int = 0
    protocols: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    events: List[SessionEvent] = field(default_factory=list)
    threat_score: float = 0.0
    threat_level: str = "info"
    flags: List[str] = field(default_factory=list)


class SessionReconstructor:
    """Reconstructs network sessions from raw connections, DNS, and alerts."""

    def __init__(self, log_store: LogStore, gap_seconds: float = 300.0):
        """
        Args:
            log_store: LogStore with loaded data
            gap_seconds: Time gap that starts a new session (default 5 min)
        """
        self.log_store = log_store
        self.gap_seconds = gap_seconds

    def reconstruct_all(self) -> List[ReconstructedSession]:
        """Reconstruct all sessions from loaded data."""
        # Group connections by src_ip <-> dst_ip pair (bidirectional)
        pair_connections: Dict[str, list] = defaultdict(list)

        for conn in self.log_store.connections:
            pair_key = self._pair_key(conn.src_ip, conn.dst_ip)
            pair_connections[pair_key].append(conn)

        sessions = []

        for pair_key, connections in pair_connections.items():
            # Sort by timestamp
            connections.sort(key=lambda c: c.timestamp or 0.0)

            # Split into sessions based on time gaps
            current_group = [connections[0]]

            for conn in connections[1:]:
                prev_ts = current_group[-1].timestamp or 0.0
                curr_ts = conn.timestamp or 0.0

                if curr_ts - prev_ts > self.gap_seconds:
                    # Gap detected, finalize current session
                    session = self._build_session(current_group)
                    if session:
                        sessions.append(session)
                    current_group = [conn]
                else:
                    current_group.append(conn)

            # Finalize last group
            session = self._build_session(current_group)
            if session:
                sessions.append(session)

        # Enrich sessions with DNS and alerts
        self._enrich_with_dns(sessions)
        self._enrich_with_alerts(sessions)

        # Sort events within each session
        for session in sessions:
            session.events.sort(key=lambda e: e.timestamp)

        # Flag suspicious patterns
        self._flag_suspicious(sessions)

        # Sort sessions by start time (newest first)
        sessions.sort(key=lambda s: s.start_time, reverse=True)

        return sessions

    def get_session(self, session_id: str) -> Optional[ReconstructedSession]:
        """Get a specific session by ID."""
        for session in self.reconstruct_all():
            if session.session_id == session_id:
                return session
        return None

    def _pair_key(self, ip_a: str, ip_b: str) -> str:
        """Create a canonical key for an IP pair (order-independent)."""
        return "|".join(sorted([ip_a, ip_b]))

    def _build_session(self, connections: list) -> Optional[ReconstructedSession]:
        """Build a session from a group of connections."""
        if not connections:
            return None

        first = connections[0]
        src_ip = first.src_ip
        dst_ip = first.dst_ip

        start_time = min(c.timestamp or 0.0 for c in connections)
        end_time = max((c.timestamp or 0.0) + (c.duration or 0.0) for c in connections)
        duration = end_time - start_time

        # Generate deterministic session ID
        id_seed = f"{src_ip}:{dst_ip}:{start_time}"
        session_id = hashlib.sha256(id_seed.encode()).hexdigest()[:16]

        protocols = list(set(c.proto for c in connections if c.proto))
        services = list(set(c.service for c in connections if c.service))
        ports = list(set(c.dst_port for c in connections if c.dst_port))

        total_sent = sum(c.bytes_sent or 0 for c in connections)
        total_recv = sum(c.bytes_recv or 0 for c in connections)

        events = []
        for conn in connections:
            events.append(SessionEvent(
                timestamp=conn.timestamp or 0.0,
                event_type="connection",
                summary=f"{conn.proto or 'tcp'}:{conn.dst_port or '?'} → {conn.service or 'unknown'} ({conn.duration or 0:.1f}s)",
                details={
                    "uid": conn.uid,
                    "proto": conn.proto,
                    "service": conn.service,
                    "duration": conn.duration,
                    "bytes_sent": conn.bytes_sent,
                    "bytes_recv": conn.bytes_recv,
                    "dst_port": conn.dst_port,
                },
                severity="info",
            ))

        return ReconstructedSession(
            session_id=session_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            total_bytes_sent=total_sent,
            total_bytes_recv=total_recv,
            connection_count=len(connections),
            protocols=protocols,
            services=services,
            ports=ports,
            events=events,
        )

    def _enrich_with_dns(self, sessions: List[ReconstructedSession]):
        """Add DNS query events to matching sessions."""
        for query in self.log_store.dns_queries:
            q_ts = query.timestamp or 0.0
            for session in sessions:
                if (query.src_ip == session.src_ip or query.src_ip == session.dst_ip) and \
                   session.start_time - 60 <= q_ts <= session.end_time + 60:
                    session.dns_query_count += 1
                    session.events.append(SessionEvent(
                        timestamp=q_ts,
                        event_type="dns",
                        summary=f"DNS {query.query_type or 'A'}: {query.query or '?'}",
                        details={
                            "query": query.query,
                            "query_type": query.query_type,
                            "answers": getattr(query, "answers", []),
                        },
                        severity="info",
                    ))
                    break  # Each DNS query goes to one session

    def _enrich_with_alerts(self, sessions: List[ReconstructedSession]):
        """Add IDS alert events to matching sessions."""
        for alert in self.log_store.alerts:
            a_ts = alert.timestamp or 0.0
            a_src = alert.src_ip
            a_dst = alert.dest_ip

            for session in sessions:
                ip_match = (a_src == session.src_ip and a_dst == session.dst_ip) or \
                           (a_src == session.dst_ip and a_dst == session.src_ip)
                time_match = session.start_time - 60 <= a_ts <= session.end_time + 60

                if ip_match and time_match:
                    session.alert_count += 1
                    sig = alert.alert.get("signature", "Unknown alert") if hasattr(alert, "alert") and isinstance(alert.alert, dict) else "Unknown alert"
                    severity = alert.alert.get("severity", 3) if hasattr(alert, "alert") and isinstance(alert.alert, dict) else 3
                    sev_map = {1: "critical", 2: "high", 3: "medium"}
                    session.events.append(SessionEvent(
                        timestamp=a_ts,
                        event_type="alert",
                        summary=sig,
                        details={"severity": severity, "category": alert.alert.get("category", "") if hasattr(alert, "alert") and isinstance(alert.alert, dict) else ""},
                        severity=sev_map.get(severity, "medium"),
                    ))
                    break

    def _flag_suspicious(self, sessions: List[ReconstructedSession]):
        """Flag sessions with suspicious patterns."""
        for session in sessions:
            # High data transfer
            total_bytes = session.total_bytes_sent + session.total_bytes_recv
            if total_bytes > 10_000_000:  # 10 MB
                session.flags.append("large_transfer")
                session.threat_score += 0.2

            # Many connections in short time (possible scanning)
            if session.connection_count > 50 and session.duration_seconds < 60:
                session.flags.append("rapid_connections")
                session.threat_score += 0.3

            # Long duration session
            if session.duration_seconds > 3600:  # 1 hour
                session.flags.append("long_session")
                session.threat_score += 0.1

            # Has alerts
            if session.alert_count > 0:
                session.flags.append("has_alerts")
                session.threat_score += 0.3 * session.alert_count

            # Beaconing pattern (regular intervals)
            if session.connection_count >= 5:
                timestamps = sorted(e.timestamp for e in session.events if e.event_type == "connection")
                if len(timestamps) >= 5:
                    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
                    if intervals:
                        avg = sum(intervals) / len(intervals)
                        if avg > 0:
                            variance = sum((i - avg) ** 2 for i in intervals) / len(intervals)
                            cv = (variance ** 0.5) / avg if avg > 0 else 999
                            if cv < 0.3:  # Low coefficient of variation = regular intervals
                                session.flags.append("beaconing_pattern")
                                session.threat_score += 0.4

            # Normalize threat score
            session.threat_score = min(session.threat_score, 1.0)

            # Set threat level
            if session.threat_score >= 0.8:
                session.threat_level = "critical"
            elif session.threat_score >= 0.6:
                session.threat_level = "high"
            elif session.threat_score >= 0.4:
                session.threat_level = "medium"
            elif session.threat_score >= 0.2:
                session.threat_level = "low"
            else:
                session.threat_level = "info"
