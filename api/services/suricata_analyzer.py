"""
Suricata Alert Analysis Engine

Analyzes Suricata IDS/IPS alerts to:
- Score alerts based on severity, category, and context
- Map alerts to MITRE ATT&CK techniques
- Identify attack patterns and campaigns
- Correlate alerts with other threat indicators

Scoring methodology:
- Base severity score from Suricata alert (1-3)
- Category-based adjustments (exploit, malware, etc.)
- Context enrichment (repeated alerts, target criticality)
- MITRE technique mapping based on signature and category
"""

from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
import re

from api.models.suricata import SuricataAlert
from api.models.threat import ThreatLevel, MitreMapping
from api.config.mitre_framework import mitre_framework


@dataclass
class AlertScore:
    """Scored Suricata alert with MITRE mapping."""
    alert: SuricataAlert
    score: float  # 0-100
    confidence: float  # 0-1
    threat_level: ThreatLevel
    reasons: List[str]
    mitre_techniques: List[str]
    mitre_mappings: List[MitreMapping]
    category_score: float
    severity_score: float
    frequency_score: float
    context_score: float


@dataclass
class AlertPattern:
    """Pattern of related alerts indicating a campaign."""
    pattern_type: str  # e.g., "scanning", "exploit_chain", "malware_activity"
    alerts: List[AlertScore]
    src_ips: List[str]
    dst_ips: List[str]
    score: float
    confidence: float
    mitre_techniques: List[str]
    attack_narrative: str


# Suricata severity mapping (1=high, 2=medium, 3=low)
SEVERITY_SCORES = {
    1: 90.0,  # High severity
    2: 60.0,  # Medium severity
    3: 30.0,  # Low severity
}

# Category-based score adjustments
CATEGORY_SCORES = {
    # Critical categories
    "A Network Trojan was detected": 95.0,
    "Exploit": 90.0,
    "Malware Command and Control Activity Detected": 90.0,
    "Potential Corporate Privacy Violation": 85.0,
    "Attempted User Privilege Gain": 85.0,
    "Attempted Administrator Privilege Gain": 90.0,

    # High severity categories
    "Web Application Attack": 75.0,
    "Attempted Information Leak": 70.0,
    "Unsuccessful User Privilege Gain": 65.0,
    "Potentially Bad Traffic": 60.0,
    "Attempted Denial of Service": 70.0,

    # Medium severity categories
    "Misc Attack": 55.0,
    "Attempted Recon": 50.0,
    "Detection of a Network Scan": 45.0,
    "Not Suspicious Traffic": 20.0,
    "Unknown Traffic": 40.0,

    # Info/policy categories
    "Generic Protocol Command Decode": 25.0,
    "Misc activity": 20.0,
    "Generic ICMP event": 15.0,
    "Decode of an RPC Query": 20.0,
}

# Signature-to-MITRE technique mapping patterns
SIGNATURE_MITRE_PATTERNS = [
    # Command & Control
    (r"(C2|C&C|Command and Control|CnC|Beacon|Callback)", ["T1071"]),
    (r"(HTTP|HTTPS|Web)\s+(C2|Beacon|Callback)", ["T1071.001"]),
    (r"DNS\s+(C2|Tunneling|Exfil)", ["T1071.004"]),
    (r"(Encrypted|TLS|SSL)\s+(C2|Channel)", ["T1573"]),
    (r"Proxy", ["T1090"]),

    # Exfiltration
    (r"(Exfil|Data Transfer|Upload)", ["T1041"]),
    (r"DNS\s+Exfil", ["T1048.003"]),
    (r"Large\s+Upload", ["T1041"]),

    # Discovery
    (r"(Port Scan|Network Scan|Service Scan)", ["T1046"]),
    (r"(Host Discovery|Ping Sweep)", ["T1018"]),
    (r"DNS\s+(Enumeration|Recon)", ["T1590.002"]),

    # Initial Access
    (r"(Exploit|CVE-\d{4}-\d{4,}|Vulnerability)", ["T1190"]),
    (r"(RDP|Remote Desktop)", ["T1133", "T1021.001"]),
    (r"SSH\s+(Brute|Attack|Login)", ["T1133", "T1021.004"]),

    # Lateral Movement
    (r"Lateral\s+Movement", ["T1021"]),
    (r"(SMB|Windows File Sharing)", ["T1021"]),

    # Defense Evasion
    (r"(DGA|Domain Generation|Fast.?Flux)", ["T1568", "T1568.002"]),
    (r"Obfuscation", ["T1001"]),

    # Execution
    (r"(Malware|Trojan|RAT|Backdoor)", ["T1071"]),
    (r"(Shellcode|Code Injection)", ["T1059"]),
]

# Category-to-MITRE technique mapping
CATEGORY_MITRE_MAP = {
    "A Network Trojan was detected": ["T1071"],
    "Exploit": ["T1190"],
    "Malware Command and Control Activity Detected": ["T1071", "T1041"],
    "Web Application Attack": ["T1190"],
    "Attempted User Privilege Gain": ["T1004"],
    "Attempted Administrator Privilege Gain": ["T1004"],
    "Attempted Information Leak": ["T1041"],
    "Attempted Denial of Service": ["T1040"],
    "Attempted Recon": ["T1046", "T1018"],
    "Detection of a Network Scan": ["T1046"],
}


class SuricataAnalyzer:
    """
    Analyzes Suricata alerts to generate threat scores and MITRE mappings.

    Features:
    - Alert scoring based on severity, category, frequency
    - MITRE ATT&CK technique mapping
    - Pattern detection for attack campaigns
    - Evidence chain construction
    """

    def __init__(
        self,
        min_score_threshold: float = 40.0,
        frequency_window_seconds: float = 3600.0,  # 1 hour
    ):
        """
        Initialize the analyzer.

        Args:
            min_score_threshold: Minimum score to report (0-100)
            frequency_window_seconds: Time window for frequency analysis
        """
        self.min_score_threshold = min_score_threshold
        self.frequency_window = frequency_window_seconds
        self._alert_cache: List[SuricataAlert] = []

    def analyze_alerts(self, alerts: List[SuricataAlert]) -> List[AlertScore]:
        """
        Analyze a list of Suricata alerts.

        Args:
            alerts: List of Suricata alerts to analyze

        Returns:
            List of scored alerts with MITRE mappings
        """
        self._alert_cache = alerts
        scored_alerts = []

        for alert in alerts:
            score = self._score_alert(alert)
            if score.score >= self.min_score_threshold:
                scored_alerts.append(score)

        # Sort by score descending
        scored_alerts.sort(key=lambda x: x.score, reverse=True)
        return scored_alerts

    def _score_alert(self, alert: SuricataAlert) -> AlertScore:
        """Score a single alert."""
        alert_data = alert.alert
        signature = alert_data.get("signature", "")
        category = alert_data.get("category", "")
        severity = alert_data.get("severity", 3)

        # Component scores
        severity_score = self._get_severity_score(severity)
        category_score = self._get_category_score(category)
        frequency_score = self._get_frequency_score(alert)
        context_score = self._get_context_score(alert)

        # Weighted total score (0-100)
        total_score = (
            severity_score * 0.35 +
            category_score * 0.35 +
            frequency_score * 0.20 +
            context_score * 0.10
        )

        # Confidence based on alert completeness
        confidence = self._calculate_confidence(alert)

        # Threat level
        threat_level = self._score_to_threat_level(total_score)

        # Reasons (explainability)
        reasons = self._build_reasons(
            signature, category, severity,
            severity_score, category_score, frequency_score, context_score
        )

        # MITRE mapping
        mitre_techniques = self._map_to_mitre(signature, category, alert)
        mitre_mappings = self._build_mitre_mappings(alert, mitre_techniques, confidence)

        return AlertScore(
            alert=alert,
            score=total_score,
            confidence=confidence,
            threat_level=threat_level,
            reasons=reasons,
            mitre_techniques=mitre_techniques,
            mitre_mappings=mitre_mappings,
            category_score=category_score,
            severity_score=severity_score,
            frequency_score=frequency_score,
            context_score=context_score,
        )

    def _get_severity_score(self, severity: int) -> float:
        """Get score based on Suricata severity (1=high, 2=med, 3=low)."""
        return SEVERITY_SCORES.get(severity, 30.0)

    def _get_category_score(self, category: str) -> float:
        """Get score based on alert category."""
        return CATEGORY_SCORES.get(category, 40.0)

    def _get_frequency_score(self, alert: SuricataAlert) -> float:
        """
        Score based on alert frequency.

        Repeated alerts from same source to same destination indicate:
        - Persistent attack attempts
        - Successful compromise with ongoing activity
        - Automated attack tools
        """
        signature_id = alert.alert.get("signature_id")
        src_ip = alert.src_ip
        dst_ip = alert.dest_ip

        # Count similar alerts in time window
        similar_count = sum(
            1 for a in self._alert_cache
            if (a.alert.get("signature_id") == signature_id and
                a.src_ip == src_ip and
                a.dest_ip == dst_ip)
        )

        # Score based on frequency
        if similar_count >= 100:
            return 100.0  # Very high frequency
        elif similar_count >= 50:
            return 80.0
        elif similar_count >= 10:
            return 60.0
        elif similar_count >= 5:
            return 40.0
        elif similar_count >= 2:
            return 20.0
        else:
            return 0.0  # Single occurrence

    def _get_context_score(self, alert: SuricataAlert) -> float:
        """
        Score based on contextual information.

        Considers:
        - Protocol (non-standard protocols are more suspicious)
        - Port usage (non-standard ports)
        - Payload characteristics
        """
        score = 0.0

        # Non-standard protocols
        proto = alert.proto.upper()
        if proto not in ["TCP", "UDP", "ICMP"]:
            score += 30.0

        # Non-standard ports for service
        app_proto = alert.app_proto
        dst_port = alert.dest_port
        if app_proto == "http" and dst_port not in [80, 8080]:
            score += 20.0
        elif app_proto == "tls" and dst_port not in [443, 8443]:
            score += 20.0
        elif app_proto == "dns" and dst_port != 53:
            score += 30.0
        elif app_proto == "ssh" and dst_port != 22:
            score += 15.0

        # Has payload
        if alert.payload or alert.payload_printable:
            score += 10.0

        return min(score, 100.0)

    def _calculate_confidence(self, alert: SuricataAlert) -> float:
        """
        Calculate confidence in the alert.

        Higher confidence for:
        - Complete metadata
        - High severity
        - Known attack patterns
        """
        confidence = 0.5  # Base confidence

        # Severity boosts confidence
        severity = alert.alert.get("severity", 3)
        if severity == 1:
            confidence += 0.3
        elif severity == 2:
            confidence += 0.2

        # Complete flow metadata
        if alert.flow_id:
            confidence += 0.1

        # Application layer protocol identified
        if alert.app_proto:
            confidence += 0.1

        return min(confidence, 1.0)

    def _score_to_threat_level(self, score: float) -> ThreatLevel:
        """Convert numeric score to threat level."""
        if score >= 80:
            return ThreatLevel.CRITICAL
        elif score >= 60:
            return ThreatLevel.HIGH
        elif score >= 40:
            return ThreatLevel.MEDIUM
        elif score >= 20:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.INFO

    def _build_reasons(
        self,
        signature: str,
        category: str,
        severity: int,
        severity_score: float,
        category_score: float,
        frequency_score: float,
        context_score: float,
    ) -> List[str]:
        """Build human-readable reasons for the score."""
        reasons = []

        # Severity
        severity_map = {1: "High", 2: "Medium", 3: "Low"}
        reasons.append(f"Severity: {severity_map.get(severity, 'Unknown')} ({severity_score:.0f} pts)")

        # Category
        if category:
            reasons.append(f"Category: {category} ({category_score:.0f} pts)")

        # Frequency
        if frequency_score >= 60:
            reasons.append(f"High frequency: repeated alerts ({frequency_score:.0f} pts)")
        elif frequency_score >= 20:
            reasons.append(f"Multiple occurrences ({frequency_score:.0f} pts)")

        # Context
        if context_score >= 30:
            reasons.append(f"Suspicious context: non-standard port/protocol ({context_score:.0f} pts)")

        # Signature keywords
        if any(kw in signature.lower() for kw in ["exploit", "malware", "trojan", "backdoor"]):
            reasons.append("Signature indicates malicious activity")

        return reasons

    def _map_to_mitre(
        self,
        signature: str,
        category: str,
        alert: SuricataAlert,
    ) -> List[str]:
        """
        Map alert to MITRE ATT&CK techniques.

        Uses both signature pattern matching and category mapping.
        """
        techniques = set()

        # Signature pattern matching
        for pattern, techs in SIGNATURE_MITRE_PATTERNS:
            if re.search(pattern, signature, re.IGNORECASE):
                techniques.update(techs)

        # Category mapping
        if category in CATEGORY_MITRE_MAP:
            techniques.update(CATEGORY_MITRE_MAP[category])

        # Protocol-specific mapping
        app_proto = alert.app_proto
        if app_proto == "dns":
            techniques.add("T1071.004")
        elif app_proto in ["http", "tls"]:
            techniques.add("T1071.001")

        return sorted(list(techniques))

    def _build_mitre_mappings(
        self,
        alert: SuricataAlert,
        technique_ids: List[str],
        confidence: float,
    ) -> List[MitreMapping]:
        """Build full MITRE mapping objects with evidence."""
        mappings = []
        timestamp = self._parse_timestamp(alert.timestamp)

        for tech_id in technique_ids:
            technique = mitre_framework.get_technique(tech_id)
            if not technique:
                continue

            tactics = mitre_framework.get_tactics_for_technique(tech_id)
            tactic = tactics[0] if tactics else None

            evidence = [
                f"Suricata alert: {alert.alert.get('signature', 'Unknown')}",
                f"Source: {alert.src_ip}:{alert.src_port}",
                f"Destination: {alert.dest_ip}:{alert.dest_port}",
                f"Category: {alert.alert.get('category', 'Unknown')}",
            ]

            observed_behaviors = []
            signature = alert.alert.get("signature", "").lower()
            if "exploit" in signature:
                observed_behaviors.append("Exploitation attempt detected")
            if "c2" in signature or "beacon" in signature:
                observed_behaviors.append("Command and control communication")
            if "scan" in signature:
                observed_behaviors.append("Network reconnaissance")

            mapping = MitreMapping(
                technique_id=tech_id,
                technique_name=technique.name,
                tactic=tactic.name if tactic else "Unknown",
                tactic_id=tactic.tactic_id if tactic else "Unknown",
                confidence=confidence,
                evidence=evidence,
                observed_behaviors=observed_behaviors,
                detection_count=1,
                first_detected=timestamp,
                last_detected=timestamp,
                affected_hosts=[alert.src_ip, alert.dest_ip],
            )
            mappings.append(mapping)

        return mappings

    def _parse_timestamp(self, timestamp_str: str) -> float:
        """Parse ISO 8601 timestamp to Unix timestamp."""
        try:
            dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            return dt.timestamp()
        except:
            return 0.0

    def detect_patterns(self, scored_alerts: List[AlertScore]) -> List[AlertPattern]:
        """
        Detect attack patterns from scored alerts.

        Identifies:
        - Scanning campaigns (multiple hosts, same signatures)
        - Exploit chains (multiple techniques, same attacker)
        - Malware activity (persistent C2, same destination)
        """
        patterns = []

        # Group by source IP
        by_src: Dict[str, List[AlertScore]] = defaultdict(list)
        for alert in scored_alerts:
            by_src[alert.alert.src_ip].append(alert)

        # Detect scanning patterns
        for src_ip, alerts in by_src.items():
            if len(alerts) >= 5:
                dst_ips = list(set(a.alert.dest_ip for a in alerts))
                if len(dst_ips) >= 3:
                    # Likely scanning
                    pattern = self._create_scanning_pattern(src_ip, alerts, dst_ips)
                    patterns.append(pattern)

        # Group by destination IP
        by_dst: Dict[str, List[AlertScore]] = defaultdict(list)
        for alert in scored_alerts:
            by_dst[alert.alert.dest_ip].append(alert)

        # Detect targeted attacks
        for dst_ip, alerts in by_dst.items():
            if len(alerts) >= 3:
                # Check for multiple MITRE techniques (attack chain)
                all_techniques = set()
                for alert in alerts:
                    all_techniques.update(alert.mitre_techniques)

                if len(all_techniques) >= 3:
                    pattern = self._create_exploit_chain_pattern(dst_ip, alerts)
                    patterns.append(pattern)

        return patterns

    def _create_scanning_pattern(
        self,
        src_ip: str,
        alerts: List[AlertScore],
        dst_ips: List[str],
    ) -> AlertPattern:
        """Create a scanning pattern."""
        avg_score = sum(a.score for a in alerts) / len(alerts)
        techniques = set()
        for alert in alerts:
            techniques.update(alert.mitre_techniques)

        return AlertPattern(
            pattern_type="scanning",
            alerts=alerts,
            src_ips=[src_ip],
            dst_ips=dst_ips,
            score=min(avg_score + 10, 100),  # Boost for pattern
            confidence=0.8,
            mitre_techniques=sorted(list(techniques)),
            attack_narrative=f"Scanning campaign from {src_ip} targeting {len(dst_ips)} hosts. "
                           f"Detected {len(alerts)} alerts indicating reconnaissance activity.",
        )

    def _create_exploit_chain_pattern(
        self,
        dst_ip: str,
        alerts: List[AlertScore],
    ) -> AlertPattern:
        """Create an exploit chain pattern."""
        src_ips = list(set(a.alert.src_ip for a in alerts))
        avg_score = sum(a.score for a in alerts) / len(alerts)
        techniques = set()
        for alert in alerts:
            techniques.update(alert.mitre_techniques)

        return AlertPattern(
            pattern_type="exploit_chain",
            alerts=alerts,
            src_ips=src_ips,
            dst_ips=[dst_ip],
            score=min(avg_score + 15, 100),  # Higher boost for attack chain
            confidence=0.85,
            mitre_techniques=sorted(list(techniques)),
            attack_narrative=f"Targeted attack against {dst_ip} with {len(techniques)} different techniques. "
                           f"Detected {len(alerts)} alerts indicating a coordinated attack.",
        )
