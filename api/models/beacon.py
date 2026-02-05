"""
Pydantic models for beaconing detection results.
Beaconing is a key indicator of C2 (command and control) communication.
"""
from typing import Optional
from pydantic import BaseModel, Field


class BeaconResult(BaseModel):
    """
    Result from beaconing detection analysis.
    Represents a potential C2 beacon communication pattern.
    """

    src_ip: str = Field(..., description="Source IP address (potential compromised host)")
    dst_ip: str = Field(..., description="Destination IP address (potential C2 server)")
    dst_port: int = Field(..., description="Destination port")
    proto: str = Field(..., description="Protocol (tcp/udp)")

    # Connection statistics
    connection_count: int = Field(..., description="Number of connections observed")
    time_span_seconds: float = Field(..., description="Total time span of observations")

    # Interval analysis
    avg_interval_seconds: float = Field(..., description="Average time between connections")
    median_interval_seconds: float = Field(..., description="Median time between connections")
    min_interval_seconds: float = Field(..., description="Minimum interval observed")
    max_interval_seconds: float = Field(..., description="Maximum interval observed")
    interval_std_dev: float = Field(..., description="Standard deviation of intervals")
    jitter_pct: float = Field(..., description="Jitter percentage (coefficient of variation)")

    # Data size analysis
    data_size_avg: Optional[float] = Field(None, description="Average data size per connection (bytes)")
    data_size_variance: Optional[float] = Field(None, description="Variance in data sizes")

    # Scoring
    beacon_score: float = Field(..., ge=0.0, le=100.0, description="Beacon likelihood score (0-100)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence (0-1)")

    # Explainability
    reasons: list[str] = Field(default_factory=list, description="Why this was flagged as beaconing")

    # MITRE ATT&CK mapping
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs"
    )

    # Timeline
    first_seen: float = Field(..., description="First connection timestamp")
    last_seen: float = Field(..., description="Last connection timestamp")


class BeaconIntervalHistogram(BaseModel):
    """
    Histogram data for interval distribution visualization.
    Used in detailed beacon analysis endpoint.
    """

    bin_edges: list[float] = Field(..., description="Histogram bin edges (seconds)")
    bin_counts: list[int] = Field(..., description="Count of intervals in each bin")
    bin_centers: list[float] = Field(..., description="Center point of each bin")


class BeaconDetailedResult(BeaconResult):
    """
    Extended beacon result with detailed interval analysis.
    Used for the detailed endpoint that returns histogram data.
    """

    interval_histogram: BeaconIntervalHistogram = Field(
        ..., description="Interval distribution histogram"
    )
    all_intervals: list[float] = Field(
        ..., description="All observed intervals (seconds)"
    )
    all_timestamps: list[float] = Field(
        ..., description="All connection timestamps"
    )
    all_data_sizes: list[int] = Field(
        default_factory=list, description="Data sizes for each connection"
    )
