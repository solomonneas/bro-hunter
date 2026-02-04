"""
Pydantic models for threat intelligence and hunting results.
Provides scoring, indicators, hunt results, and MITRE ATT&CK mappings.
"""
from typing import Optional
from pydantic import BaseModel, Field
from enum import Enum


class ThreatLevel(str, Enum):
    """Threat severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IndicatorType(str, Enum):
    """Types of threat indicators."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    USER_AGENT = "user_agent"
    CERTIFICATE = "certificate"
    BEHAVIOR = "behavior"


class ThreatScore(BaseModel):
    """Threat score with explainability for a single entity."""

    entity: str = Field(..., description="Entity being scored (IP, domain, etc)")
    entity_type: str = Field(..., description="Type of entity")
    score: float = Field(..., ge=0.0, le=1.0, description="Threat score (0-1)")
    level: ThreatLevel = Field(..., description="Threat severity level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence (0-1)")

    # Explainability
    reasons: list[str] = Field(..., description="Why this entity was flagged")
    indicators: list[str] = Field(..., description="Specific indicators observed")
    mitre_techniques: list[str] = Field(
        default=[], description="MITRE ATT&CK technique IDs"
    )

    # Context
    first_seen: float = Field(..., description="First observation timestamp")
    last_seen: float = Field(..., description="Last observation timestamp")
    occurrence_count: int = Field(..., description="Number of occurrences")

    # Related data
    related_ips: list[str] = Field(default=[], description="Related IP addresses")
    related_domains: list[str] = Field(default=[], description="Related domains")
    related_files: list[str] = Field(default=[], description="Related file hashes")


class ThreatIndicator(BaseModel):
    """A single threat indicator observation."""

    indicator_type: IndicatorType = Field(..., description="Type of indicator")
    value: str = Field(..., description="Indicator value")
    description: str = Field(..., description="Human-readable description")
    severity: ThreatLevel = Field(..., description="Indicator severity")

    # Detection metadata
    source: str = Field(..., description="Detection source (zeek/suricata/analysis)")
    detection_time: float = Field(..., description="When indicator was detected")
    log_source: str = Field(..., description="Log type that generated indicator")

    # Context
    context: dict[str, str] = Field(
        default={}, description="Additional context key-value pairs"
    )
    tags: list[str] = Field(default=[], description="Categorization tags")

    # MITRE mapping
    mitre_technique: Optional[str] = Field(
        None, description="MITRE ATT&CK technique ID"
    )
    mitre_tactic: Optional[str] = Field(None, description="MITRE ATT&CK tactic name")


class MitreMapping(BaseModel):
    """MITRE ATT&CK framework technique mapping."""

    technique_id: str = Field(..., description="Technique ID (e.g., T1071.001)")
    technique_name: str = Field(..., description="Technique name")
    tactic: str = Field(..., description="Tactic name (e.g., Command and Control)")
    tactic_id: str = Field(..., description="Tactic ID (e.g., TA0011)")

    # Evidence
    confidence: float = Field(..., ge=0.0, le=1.0, description="Mapping confidence")
    evidence: list[str] = Field(..., description="Evidence supporting this mapping")
    observed_behaviors: list[str] = Field(
        ..., description="Specific observed behaviors"
    )

    # Context
    detection_count: int = Field(..., description="Number of detections")
    first_detected: float = Field(..., description="First detection timestamp")
    last_detected: float = Field(..., description="Last detection timestamp")
    affected_hosts: list[str] = Field(default=[], description="Affected host IPs")


class HuntResult(BaseModel):
    """Result from a threat hunting query or analysis."""

    hunt_id: str = Field(..., description="Unique hunt identifier")
    hunt_name: str = Field(..., description="Hunt name/title")
    hunt_description: str = Field(..., description="What this hunt looks for")
    hypothesis: str = Field(..., description="Threat hypothesis being tested")

    # Results
    total_events_analyzed: int = Field(..., description="Total events processed")
    suspicious_events: int = Field(..., description="Events flagged as suspicious")
    threat_scores: list[ThreatScore] = Field(
        default=[], description="Scored threat entities"
    )
    indicators: list[ThreatIndicator] = Field(
        default=[], description="Detected threat indicators"
    )
    mitre_mappings: list[MitreMapping] = Field(
        default=[], description="MITRE ATT&CK mappings"
    )

    # Timeline
    analysis_start: float = Field(..., description="Analysis start timestamp")
    analysis_end: float = Field(..., description="Analysis end timestamp")
    time_range_start: float = Field(..., description="Log data start timestamp")
    time_range_end: float = Field(..., description="Log data end timestamp")

    # Summary
    summary: str = Field(..., description="Executive summary of findings")
    recommendations: list[str] = Field(
        default=[], description="Recommended actions"
    )
    false_positive_likelihood: Optional[str] = Field(
        None, description="Assessment of false positive risk"
    )

    # Metadata
    analyst: Optional[str] = Field(None, description="Analyst who ran the hunt")
    tags: list[str] = Field(default=[], description="Hunt categorization tags")
    references: list[str] = Field(
        default=[], description="External references and links"
    )
